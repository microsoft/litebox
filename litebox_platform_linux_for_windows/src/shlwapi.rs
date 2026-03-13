// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SHLWAPI.dll function implementations
//!
//! This module provides implementations of commonly used SHLWAPI path utility
//! functions for the Windows-on-Linux emulation layer.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ── Helper utilities ──────────────────────────────────────────────────────

unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

unsafe fn write_wide_string(dst: *mut u16, s: &str, max_len: usize) {
    if dst.is_null() || max_len == 0 {
        return;
    }
    let wide: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
    let total_len = wide.len();

    // If the full wide string including its null terminator fits, copy it as-is.
    if total_len <= max_len {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), dst, total_len);
        return;
    }

    // Otherwise, truncate to max_len - 1 characters and ensure null termination.
    let copy_len = max_len - 1;
    core::ptr::copy_nonoverlapping(wide.as_ptr(), dst, copy_len);
    *dst.add(copy_len) = 0;
}

/// Returns the length of a null-terminated wide string.
unsafe fn wide_len(ptr: *const u16) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

// ── Path utilities ────────────────────────────────────────────────────────

/// PathFileExistsW - test if a file or directory exists
///
/// Returns 1 (TRUE) if the path exists, 0 (FALSE) otherwise.
///
/// # Safety
/// `path` must be a valid null-terminated wide string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathFileExistsW(path: *const u16) -> i32 {
    if path.is_null() {
        return 0;
    }
    let s = wide_to_string(path);
    i32::from(std::path::Path::new(&s).exists())
}

/// PathCombineW - combine a directory path and a file name into a single path
///
/// Writes the combined path into `dest` (max 260 wide chars). Returns `dest` on success, NULL on failure.
///
/// # Safety
/// `dest` must be a writable buffer of at least 260 wide chars; `dir` and `file` must be valid
/// null-terminated wide strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathCombineW(
    dest: *mut u16,
    dir: *const u16,
    file: *const u16,
) -> *mut u16 {
    if dest.is_null() {
        return core::ptr::null_mut();
    }
    let dir_s = if dir.is_null() {
        String::new()
    } else {
        wide_to_string(dir)
    };
    let file_s = if file.is_null() {
        String::new()
    } else {
        wide_to_string(file)
    };
    let combined = if file_s.starts_with('\\') || file_s.contains(':') {
        file_s
    } else {
        let dir_trimmed = dir_s.trim_end_matches('\\');
        if dir_trimmed.is_empty() {
            file_s
        } else {
            alloc::format!("{dir_trimmed}\\{file_s}")
        }
    };
    write_wide_string(dest, &combined, 260);
    dest
}

/// PathGetFileNameW - return a pointer to the filename portion of a path
///
/// Returns a pointer into `path` pointing just after the last backslash/forward-slash,
/// or the original `path` pointer if no separator is found.
///
/// # Safety
/// `path` must be a valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathGetFileNameW(path: *const u16) -> *const u16 {
    if path.is_null() {
        return path;
    }
    let len = wide_len(path);
    let mut last_sep = None;
    for i in 0..len {
        let c = *path.add(i);
        if c == u16::from(b'\\') || c == u16::from(b'/') {
            last_sep = Some(i);
        }
    }
    match last_sep {
        Some(idx) => path.add(idx + 1),
        None => path,
    }
}

/// PathRemoveFileSpecW - remove the filename from a path, leaving only the directory
///
/// Modifies `path` in-place by NUL-terminating at the last backslash.
/// Returns 1 if the path was modified, 0 otherwise.
///
/// # Safety
/// `path` must be a valid, writable null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathRemoveFileSpecW(path: *mut u16) -> i32 {
    if path.is_null() {
        return 0;
    }
    let len = wide_len(path.cast_const());
    let mut last_sep = None;
    for i in 0..len {
        let c = *path.add(i);
        if c == u16::from(b'\\') || c == u16::from(b'/') {
            last_sep = Some(i);
        }
    }
    let Some(idx) = last_sep else {
        return 0;
    };
    *path.add(idx) = 0;
    1
}

/// PathIsRelativeW - test if a path is relative
///
/// Returns 1 (TRUE) if the path is relative (no drive letter or UNC prefix).
/// Returns 0 (FALSE) if absolute.
///
/// # Safety
/// `path` must be a valid null-terminated wide string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathIsRelativeW(path: *const u16) -> i32 {
    if path.is_null() {
        return 1;
    }
    let len = wide_len(path);
    if len == 0 {
        return 1;
    }
    let first = *path;
    // UNC / rooted path starts with \ or /
    let mut is_abs = first == u16::from(b'\\') || first == u16::from(b'/');
    // Drive-letter path: second character is ':'
    if !is_abs && len >= 2 {
        let second = *path.add(1);
        if second == u16::from(b':') {
            is_abs = true;
        }
    }
    i32::from(!is_abs)
}

/// PathFindExtensionW - find the file extension in a path
///
/// Returns a pointer to the last `.` in the filename portion of `path`,
/// or a pointer to the terminating NUL if no extension is found.
///
/// # Safety
/// `path` must be a valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathFindExtensionW(path: *const u16) -> *const u16 {
    if path.is_null() {
        return path;
    }
    let len = wide_len(path);
    // Find start of filename (after last separator)
    let mut filename_start = 0;
    for i in 0..len {
        let c = *path.add(i);
        if c == u16::from(b'\\') || c == u16::from(b'/') {
            filename_start = i + 1;
        }
    }
    // Find last dot in filename
    let mut last_dot = None;
    for i in filename_start..len {
        if *path.add(i) == u16::from(b'.') {
            last_dot = Some(i);
        }
    }
    match last_dot {
        Some(idx) => path.add(idx),
        None => path.add(len), // point to NUL terminator
    }
}

/// PathStripPathW - remove the directory portion from a path in place
///
/// Modifies `path` in-place, keeping only the filename.
///
/// # Safety
/// `path` must be a valid, writable null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathStripPathW(path: *mut u16) {
    if path.is_null() {
        return;
    }
    let len = wide_len(path.cast_const());
    let mut last_sep = None;
    for i in 0..len {
        let c = *path.add(i);
        if c == u16::from(b'\\') || c == u16::from(b'/') {
            last_sep = Some(i);
        }
    }
    let Some(sep_idx) = last_sep else {
        return;
    };
    // Shift remaining chars to start
    let src_start = sep_idx + 1;
    let move_len = len - src_start + 1; // include NUL
    core::ptr::copy(path.add(src_start), path, move_len);
}

/// PathAddBackslashW - ensure path ends with a backslash
///
/// Appends `\` if the path does not already end with one.
/// Returns a pointer to the new NUL terminator, or the original dest if it already ends with `\`.
///
/// # Safety
/// `path` must be a valid, writable null-terminated wide string with space for one more character.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_PathAddBackslashW(path: *mut u16) -> *mut u16 {
    if path.is_null() {
        return core::ptr::null_mut();
    }
    let len = wide_len(path.cast_const());
    if len == 0 {
        // Empty string: unconditionally append backslash and NUL.
        *path.add(0) = u16::from(b'\\');
        *path.add(1) = 0;
        return path.add(1);
    }
    if *path.add(len - 1) == u16::from(b'\\') {
        path.add(len)
    } else {
        *path.add(len) = u16::from(b'\\');
        *path.add(len + 1) = 0;
        path.add(len + 1)
    }
}

/// StrToIntW - convert a wide string to an integer
///
/// Parses the string as a decimal integer, skipping leading whitespace and handling sign.
///
/// # Safety
/// `str_val` must be a valid null-terminated wide string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_StrToIntW(str_val: *const u16) -> i32 {
    if str_val.is_null() {
        return 0;
    }
    let s = wide_to_string(str_val);
    let trimmed = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (trimmed, neg) = if let Some(t) = trimmed.strip_prefix('-') {
        (t, true)
    } else if let Some(t) = trimmed.strip_prefix('+') {
        (t, false)
    } else {
        (trimmed, false)
    };
    let valid_len = trimmed.chars().take_while(char::is_ascii_digit).count();
    let val = trimmed[..valid_len].parse::<i32>().unwrap_or(0);
    if neg { val.wrapping_neg() } else { val }
}

/// StrCmpIW - case-insensitive wide string comparison
///
/// Returns negative, zero, or positive like strcmp.
///
/// # Safety
/// `s1` and `s2` must be valid null-terminated wide strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shlwapi_StrCmpIW(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    let a = wide_to_string(s1);
    let b = wide_to_string(s2);
    let al: String = a.chars().map(|c| c.to_ascii_lowercase()).collect();
    let bl: String = b.chars().map(|c| c.to_ascii_lowercase()).collect();
    match al.cmp(&bl) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    #[test]
    fn test_path_file_exists_w() {
        let path = to_wide("/tmp");
        assert_eq!(unsafe { shlwapi_PathFileExistsW(path.as_ptr()) }, 1);
        let nopath = to_wide("/nonexistent_path_xyz_litebox");
        assert_eq!(unsafe { shlwapi_PathFileExistsW(nopath.as_ptr()) }, 0);
    }

    #[test]
    fn test_path_combine_w() {
        let dir = to_wide("C:\\foo");
        let file = to_wide("bar.txt");
        let mut dest = vec![0u16; 260];
        let result =
            unsafe { shlwapi_PathCombineW(dest.as_mut_ptr(), dir.as_ptr(), file.as_ptr()) };
        assert!(!result.is_null());
        let s = String::from_utf16_lossy(&dest[..dest.iter().position(|&c| c == 0).unwrap()]);
        assert_eq!(s, "C:\\foo\\bar.txt");
    }

    #[test]
    fn test_path_get_file_name_w() {
        let path = to_wide("C:\\foo\\bar\\baz.txt");
        let result = unsafe { shlwapi_PathGetFileNameW(path.as_ptr()) };
        let len = unsafe { wide_len(result) };
        let s = String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(result, len) });
        assert_eq!(s, "baz.txt");
    }

    #[test]
    fn test_path_remove_file_spec_w() {
        let mut path = to_wide("C:\\foo\\bar\\baz.txt");
        let r = unsafe { shlwapi_PathRemoveFileSpecW(path.as_mut_ptr()) };
        assert_eq!(r, 1);
        let len = unsafe { wide_len(path.as_ptr()) };
        let s = String::from_utf16_lossy(&path[..len]);
        assert_eq!(s, "C:\\foo\\bar");
    }

    #[test]
    fn test_path_is_relative_w() {
        let abs = to_wide("C:\\foo\\bar");
        let rel = to_wide("foo\\bar");
        unsafe {
            assert_eq!(shlwapi_PathIsRelativeW(abs.as_ptr()), 0);
            assert_eq!(shlwapi_PathIsRelativeW(rel.as_ptr()), 1);
        }
    }

    #[test]
    fn test_path_find_extension_w() {
        let path = to_wide("C:\\foo\\bar.txt");
        let ext_ptr = unsafe { shlwapi_PathFindExtensionW(path.as_ptr()) };
        let len = unsafe { wide_len(ext_ptr) };
        let s = String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(ext_ptr, len) });
        assert_eq!(s, ".txt");
    }

    #[test]
    fn test_path_strip_path_w() {
        let mut path = to_wide("C:\\foo\\bar.txt");
        unsafe { shlwapi_PathStripPathW(path.as_mut_ptr()) };
        let len = unsafe { wide_len(path.as_ptr()) };
        let s = String::from_utf16_lossy(&path[..len]);
        assert_eq!(s, "bar.txt");
    }

    #[test]
    fn test_path_add_backslash_w() {
        let mut path = to_wide("C:\\foo");
        unsafe { shlwapi_PathAddBackslashW(path.as_mut_ptr()) };
        let len = unsafe { wide_len(path.as_ptr()) };
        let s = String::from_utf16_lossy(&path[..len]);
        assert_eq!(s, "C:\\foo\\");
    }

    #[test]
    fn test_str_to_int_w() {
        let s = to_wide("  -42rest");
        unsafe {
            assert_eq!(shlwapi_StrToIntW(s.as_ptr()), -42);
        }
    }

    #[test]
    fn test_str_cmp_i_w() {
        let a = to_wide("Hello");
        let b = to_wide("hello");
        unsafe {
            assert_eq!(shlwapi_StrCmpIW(a.as_ptr(), b.as_ptr()), 0);
        }
    }
}
