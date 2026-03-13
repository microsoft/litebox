// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SHELL32.dll function implementations
//!
//! This module provides minimal implementations of the Windows Shell API (SHELL32.dll).
//! Functions that interact with the shell or user interface are implemented as headless
//! stubs. `CommandLineToArgvW` provides real parsing of the Windows command-line format.

#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;

// CSIDL constants for SHGetFolderPathW
const CSIDL_DESKTOP: i32 = 0x0000;
const CSIDL_APPDATA: i32 = 0x001A;
const CSIDL_LOCAL_APPDATA: i32 = 0x001C;
const CSIDL_PERSONAL: i32 = 0x0005; // My Documents
const CSIDL_PROFILE: i32 = 0x0028;
const CSIDL_WINDOWS: i32 = 0x0024;
const CSIDL_SYSTEM: i32 = 0x0025;

// COM-style return codes
const S_OK: i32 = 0;
const E_FAIL: i32 = 0x8000_4005u32.cast_signed(); // E_FAIL (0x80004005)

/// `CommandLineToArgvW` — parse a Unicode command-line string into an argv array.
///
/// Implements standard Windows command-line parsing rules:
/// - Arguments are separated by spaces/tabs
/// - Double-quoted strings can contain embedded spaces
/// - A pair of backslashes before a quote is halved; one backslash before a quote escapes it
///
/// Returns a pointer to an array of `*mut u16` pointers (`LPWSTR*`).  The array and all
/// strings within it are allocated in a single block; the caller must free the returned
/// pointer with `LocalFree`.  Returns NULL and sets `ERROR_INVALID_PARAMETER` if
/// `cmd_line` is NULL.
///
/// # Safety
/// `cmd_line` must be a valid null-terminated UTF-16 string or NULL.
/// `p_num_args` must be a valid pointer to an `i32` or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shell32_CommandLineToArgvW(
    cmd_line: *const u16,
    p_num_args: *mut i32,
) -> *mut *mut u16 {
    if cmd_line.is_null() {
        crate::kernel32::kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }

    // SAFETY: cmd_line is checked non-null above; we scan until null terminator.
    let mut len = 0usize;
    while unsafe { *cmd_line.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { core::slice::from_raw_parts(cmd_line, len) };
    let s = String::from_utf16_lossy(slice);

    // Parse using Windows quoting rules
    let args = parse_command_line(&s);
    let num_args = i32::try_from(args.len()).unwrap_or(i32::MAX);

    if !p_num_args.is_null() {
        // SAFETY: p_num_args is checked non-null above.
        unsafe { *p_num_args = num_args };
    }

    if args.is_empty() {
        return core::ptr::null_mut();
    }

    // Encode each arg as UTF-16 null-terminated
    let encoded: Vec<Vec<u16>> = args
        .iter()
        .map(|a| {
            let mut v: Vec<u16> = a.encode_utf16().collect();
            v.push(0); // null terminator
            v
        })
        .collect();

    // Allocate: pointer array (argc+1 entries, last is NULL) + all string data in one block.
    // Use kernel32_HeapAlloc so the block can be freed with LocalFree/HeapFree.
    let ptr_array_bytes = (encoded.len() + 1) * core::mem::size_of::<*mut u16>();
    let data_bytes: usize = encoded.iter().map(|v| v.len() * 2).sum();
    let total = ptr_array_bytes + data_bytes;

    // SAFETY: kernel32_HeapAlloc is safe to call; the returned block must be freed with LocalFree.
    let block = unsafe { crate::kernel32::kernel32_HeapAlloc(core::ptr::null_mut(), 0, total) };
    if block.is_null() {
        return core::ptr::null_mut();
    }

    // Write pointers and strings into the allocated block.
    // SAFETY: block is freshly allocated with enough space for all writes below.
    // HeapAlloc guarantees at least usize alignment, sufficient for *mut u16 pointers.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let ptrs = block.cast::<*mut u16>();
        let mut data_ptr = block.cast::<u8>().add(ptr_array_bytes).cast::<u16>();
        for (i, enc) in encoded.iter().enumerate() {
            *ptrs.add(i) = data_ptr;
            core::ptr::copy_nonoverlapping(enc.as_ptr(), data_ptr, enc.len());
            data_ptr = data_ptr.add(enc.len());
        }
        // NULL-terminate the pointer array (argv[argc] == NULL per Windows contract)
        *ptrs.add(encoded.len()) = core::ptr::null_mut();
        ptrs
    }
}

/// Parse a Windows command-line string into a vector of argument strings.
///
/// Implements the standard Windows command-line parsing algorithm:
/// - Unquoted space/tab separates arguments
/// - `\"` inside or outside a quoted section produces a literal `"`
/// - `2n` backslashes followed by `"` → `n` backslashes + starts/ends quoted section
/// - `2n+1` backslashes followed by `"` → `n` backslashes + literal `"`
/// - Backslashes not followed by `"` are treated literally
fn parse_command_line(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            // Count consecutive backslashes
            let bs_start = i;
            while i < chars.len() && chars[i] == '\\' {
                i += 1;
            }
            let num_bs = i - bs_start;
            if i < chars.len() && chars[i] == '"' {
                // 2n backslashes + quote → n backslashes + toggle/end quote
                for _ in 0..(num_bs / 2) {
                    current.push('\\');
                }
                if num_bs % 2 == 1 {
                    // Odd: literal quote
                    current.push('"');
                } else {
                    // Even: toggle quote mode
                    in_quotes = !in_quotes;
                }
                i += 1; // consume the quote
            } else {
                // Backslashes not before a quote are literal
                for _ in 0..num_bs {
                    current.push('\\');
                }
            }
        } else if c == '"' {
            in_quotes = !in_quotes;
            i += 1;
        } else if (c == ' ' || c == '\t') && !in_quotes {
            if !current.is_empty() {
                args.push(core::mem::take(&mut current));
            }
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
        } else {
            current.push(c);
            i += 1;
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// `SHGetFolderPathW` — retrieve the path of a shell folder identified by its CSIDL.
///
/// Maps common CSIDL values to Linux paths:
/// - `CSIDL_APPDATA` / `CSIDL_LOCAL_APPDATA` → `$HOME/.config`
/// - `CSIDL_PERSONAL` / `CSIDL_PROFILE` → `$HOME`
/// - `CSIDL_DESKTOP` → `$HOME/Desktop`
/// - `CSIDL_WINDOWS` / `CSIDL_SYSTEM` → `/tmp`
/// - Anything else → `$TEMP` or `/tmp`
///
/// Returns `S_OK` (0) on success, `E_FAIL` on failure.
///
/// # Safety
/// `path` must point to a buffer of at least `MAX_PATH` (260) wide characters, or be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shell32_SHGetFolderPathW(
    _hwnd: *mut c_void,
    csidl: i32,
    _token: *mut c_void,
    _flags: u32,
    path: *mut u16,
) -> i32 {
    if path.is_null() {
        return E_FAIL;
    }

    let folder: Option<String> = match csidl & 0xFF {
        c if c == CSIDL_APPDATA || c == CSIDL_LOCAL_APPDATA => Some(
            std::env::var("HOME").map_or_else(|_| "/tmp".to_string(), |h| format!("{h}/.config")),
        ),
        c if c == CSIDL_PERSONAL || c == CSIDL_PROFILE => {
            Some(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
        }
        c if c == CSIDL_DESKTOP => Some(
            std::env::var("HOME")
                .map_or_else(|_| "/tmp/Desktop".to_string(), |h| format!("{h}/Desktop")),
        ),
        c if c == CSIDL_WINDOWS || c == CSIDL_SYSTEM => {
            Some(std::env::temp_dir().to_string_lossy().into_owned())
        }
        _ => Some(std::env::temp_dir().to_string_lossy().into_owned()),
    };

    let Some(folder_path) = folder else {
        return E_FAIL;
    };

    // SAFETY: path is checked non-null above; caller guarantees it has >= 260 elements.
    unsafe { crate::kernel32::copy_utf8_to_wide(&folder_path, path, 260) };
    S_OK
}

/// `ShellExecuteW` — perform an operation on a file.
///
/// Returns a fake HINSTANCE value greater than 32 (indicating success) in headless
/// mode.  No real file operations or process creation is performed.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shell32_ShellExecuteW(
    _hwnd: *mut c_void,
    _operation: *const u16,
    _file: *const u16,
    _parameters: *const u16,
    _directory: *const u16,
    _show_cmd: i32,
) -> *mut c_void {
    // Return value > 32 indicates success per Windows docs.
    33usize as *mut c_void
}

/// `SHCreateDirectoryExW` — create a directory and all intermediate directories.
///
/// Delegates to `CreateDirectoryW` for the final directory component.  Returns 0
/// (ERROR_SUCCESS) on success or the last error code if it fails.
///
/// # Safety
/// `path` must be a valid null-terminated UTF-16 string or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shell32_SHCreateDirectoryExW(
    _hwnd: *mut c_void,
    path: *const u16,
    _security_attributes: *const c_void,
) -> i32 {
    if path.is_null() {
        return 87; // ERROR_INVALID_PARAMETER
    }
    // SAFETY: path is checked non-null above.
    let result = unsafe { crate::kernel32::kernel32_CreateDirectoryW(path, core::ptr::null_mut()) };
    if result != 0 {
        0 // ERROR_SUCCESS
    } else {
        // SAFETY: Always safe to call.
        let err = unsafe { crate::kernel32::kernel32_GetLastError() };
        err.cast_signed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_command_line_simple() {
        let args = parse_command_line("program.exe arg1 arg2");
        assert_eq!(args, vec!["program.exe", "arg1", "arg2"]);
    }

    #[test]
    fn test_parse_command_line_quoted() {
        let args = parse_command_line(r#"program.exe "hello world" arg2"#);
        assert_eq!(args, vec!["program.exe", "hello world", "arg2"]);
    }

    #[test]
    fn test_parse_command_line_empty() {
        let args = parse_command_line("");
        assert_eq!(args.len(), 0);
    }

    #[test]
    fn test_parse_command_line_single() {
        let args = parse_command_line("single");
        assert_eq!(args, vec!["single"]);
    }

    #[test]
    fn test_command_line_to_argv_w_basic() {
        let cmd: Vec<u16> = "prog.exe arg1 arg2\0".encode_utf16().collect();
        let mut num_args: i32 = 0;
        let arg_ptrs = unsafe { shell32_CommandLineToArgvW(cmd.as_ptr(), &raw mut num_args) };
        assert!(!arg_ptrs.is_null());
        assert_eq!(num_args, 3);
        // argv[3] must be NULL (NULL-terminated pointer array per Windows contract)
        let null_sentinel = unsafe { *arg_ptrs.add(3) };
        assert!(null_sentinel.is_null(), "argv[argc] should be NULL");
        // Free via LocalFree (block was allocated with HeapAlloc)
        let result =
            unsafe { crate::kernel32::kernel32_LocalFree(arg_ptrs.cast::<core::ffi::c_void>()) };
        assert!(result.is_null(), "LocalFree should return NULL on success");
    }

    #[test]
    fn test_command_line_to_argv_w_null() {
        let mut num_args: i32 = 0;
        let arg_ptrs = unsafe { shell32_CommandLineToArgvW(core::ptr::null(), &raw mut num_args) };
        assert!(arg_ptrs.is_null());
    }

    #[test]
    fn test_sh_get_folder_path_w_null_path() {
        let result = unsafe {
            shell32_SHGetFolderPathW(
                core::ptr::null_mut(),
                0x001A, // CSIDL_APPDATA
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(result, 0); // E_FAIL
    }

    #[test]
    fn test_sh_get_folder_path_w_appdata() {
        let mut buf = [0u16; 260];
        let result = unsafe {
            shell32_SHGetFolderPathW(
                core::ptr::null_mut(),
                0x001A, // CSIDL_APPDATA
                core::ptr::null_mut(),
                0,
                buf.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0); // S_OK
        assert!(buf[0] != 0); // path written
    }

    #[test]
    fn test_shell_execute_w_returns_success() {
        let result = unsafe {
            shell32_ShellExecuteW(
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                0,
            )
        };
        assert!(result as usize > 32);
    }
}
