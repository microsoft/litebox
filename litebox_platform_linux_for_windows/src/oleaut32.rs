// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OLEAUT32.dll and Windows Runtime error API function implementations
//!
//! Provides minimal stubs for OLE Automation and WinRT error APIs.
//! In the headless Windows-on-Linux emulation environment, COM/OLE
//! error-info objects are not supported; these functions return
//! appropriate "not available" results.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_ptr_alignment)] // BSTR alloc uses align=4 ≥ align of u16

extern crate alloc;
use alloc::alloc::{Layout, alloc, dealloc};
use core::ptr;

// ── COM HRESULT constants ────────────────────────────────────────────────────

/// S_OK — operation succeeded
const S_OK: u32 = 0;
/// S_FALSE — operation succeeded but result is "empty" / "not available"
const S_FALSE: u32 = 1;

// ── OLEAUT32: COM error info (GetErrorInfo / SetErrorInfo) ───────────────────

/// `GetErrorInfo(dwReserved, pperrinfo) -> HRESULT`
///
/// In headless mode no COM error-info object is ever installed, so this
/// function always sets `*pperrinfo = NULL` and returns `S_FALSE` (1).
///
/// # Safety
///
/// `pp_err_info`, if non-null, must point to a valid `*mut u8` that may be
/// written by this function.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-geterrorinfo>
pub unsafe extern "C" fn oleaut32_get_error_info(
    _dw_reserved: u32,
    pp_err_info: *mut *mut u8,
) -> u32 {
    if !pp_err_info.is_null() {
        *pp_err_info = ptr::null_mut();
    }
    S_FALSE
}

/// `SetErrorInfo(dwReserved, perrinfo) -> HRESULT`
///
/// Accepts (and ignores) any error-info pointer; always returns `S_OK`.
///
/// # Safety
///
/// This function is safe to call with any argument values; the pointer is
/// ignored.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-seterrorinfo>
pub unsafe extern "C" fn oleaut32_set_error_info(_dw_reserved: u32, _p_err_info: *mut u8) -> u32 {
    S_OK
}

// ── OLEAUT32: BSTR functions ─────────────────────────────────────────────────
//
// A BSTR is a length-prefixed wide string.  The caller-visible pointer points
// to the first character; the 4-byte length (in bytes, not including the NUL)
// is stored immediately before it.
//
// Memory layout:
//   [ 4-byte length ] [ wchar data ... ] [ NUL terminator ]
//                     ^  BSTR pointer points here

/// `SysFreeString(bstr)`
///
/// Frees a BSTR that was previously allocated with `SysAllocString*`.
/// Handles `NULL` gracefully (no-op).
///
/// # Safety
///
/// `bstr`, if non-null, must have been allocated by `SysAllocString` or
/// `SysAllocStringLen`.
///
/// # Panics
///
/// Panics if the BSTR layout cannot be constructed (should never happen for
/// valid BSTRs).
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysfreestring>
pub unsafe extern "C" fn oleaut32_sys_free_string(bstr: *mut u16) {
    if bstr.is_null() {
        return;
    }
    // The allocation starts 4 bytes before the visible pointer
    let raw = bstr.cast::<u8>().sub(4);
    // Recover the byte-length stored in the prefix
    let byte_len = u32::from_le_bytes([*raw, *raw.add(1), *raw.add(2), *raw.add(3)]) as usize;
    // Total allocation: 4 (prefix) + byte_len + 2 (NUL u16)
    let total = 4 + byte_len + 2;
    let layout = Layout::from_size_align(total, 4).expect("BSTR layout must be valid");
    dealloc(raw, layout);
}

/// `SysStringLen(bstr) -> UINT`
///
/// Returns the number of *characters* (not bytes) in the BSTR, or 0 for NULL.
///
/// # Safety
///
/// `bstr`, if non-null, must point to a valid BSTR allocated by
/// `SysAllocString` or `SysAllocStringLen` (i.e., must have a valid 4-byte
/// length prefix just before the pointer).
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysstringlen>
pub unsafe extern "C" fn oleaut32_sys_string_len(bstr: *const u16) -> u32 {
    if bstr.is_null() {
        return 0;
    }
    // The 4-byte byte-length prefix sits just before the visible pointer
    let raw = bstr.cast::<u8>().sub(4);
    let byte_len = u32::from_le_bytes([*raw, *raw.add(1), *raw.add(2), *raw.add(3)]);
    // Convert bytes to characters (UTF-16 units are 2 bytes each)
    byte_len / 2
}

/// `SysAllocString(psz) -> BSTR`
///
/// Allocates a BSTR from a null-terminated wide string.  Returns NULL on
/// allocation failure or if `psz` is NULL.
///
/// # Safety
///
/// `psz`, if non-null, must point to a valid null-terminated UTF-16 string.
///
/// # Panics
///
/// Panics if the BSTR layout cannot be constructed (should never happen for
/// reasonable string lengths).
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysallocstring>
pub unsafe extern "C" fn oleaut32_sys_alloc_string(psz: *const u16) -> *mut u16 {
    if psz.is_null() {
        return ptr::null_mut();
    }
    let mut len = 0usize;
    while *psz.add(len) != 0 {
        len += 1;
    }
    // byte_len = number of UTF-16 code units × 2 (excludes NUL)
    let byte_len = len * 2;
    // Allocation: 4-byte prefix + data bytes + 2-byte NUL
    let total = 4 + byte_len + 2;
    let layout = Layout::from_size_align(total, 4).expect("BSTR layout must be valid");
    let raw = alloc(layout);
    if raw.is_null() {
        return ptr::null_mut();
    }
    // Write the 4-byte length prefix (byte count, little-endian)
    let byte_len_u32 = byte_len as u32;
    raw.copy_from_nonoverlapping(byte_len_u32.to_le_bytes().as_ptr(), 4);
    // Copy the wide-string data
    let data_ptr = raw.add(4).cast::<u16>();
    data_ptr.copy_from_nonoverlapping(psz, len);
    // Write the NUL terminator
    *data_ptr.add(len) = 0;
    data_ptr
}

/// `SysAllocStringLen(strIn, ui) -> BSTR`
///
/// Allocates a BSTR of exactly `ui` wide characters, optionally copying from
/// `strIn`.  Returns NULL on failure.
///
/// # Safety
///
/// `str_in`, if non-null, must point to a valid wide-character buffer of at
/// least `ui` elements.
///
/// # Panics
///
/// Panics if the BSTR layout cannot be constructed (should never happen for
/// reasonable string lengths).
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysallocstringlen>
pub unsafe extern "C" fn oleaut32_sys_alloc_string_len(str_in: *const u16, ui: u32) -> *mut u16 {
    let len = ui as usize;
    let byte_len = len * 2;
    let total = 4 + byte_len + 2;
    let layout = Layout::from_size_align(total, 4).expect("BSTR layout must be valid");
    let raw = alloc(layout);
    if raw.is_null() {
        return ptr::null_mut();
    }
    let byte_len_u32 = byte_len as u32;
    raw.copy_from_nonoverlapping(byte_len_u32.to_le_bytes().as_ptr(), 4);
    let data_ptr = raw.add(4).cast::<u16>();
    if str_in.is_null() {
        // Zero-initialize
        ptr::write_bytes(data_ptr, 0, len);
    } else {
        data_ptr.copy_from_nonoverlapping(str_in, len);
    }
    *data_ptr.add(len) = 0;
    data_ptr
}

// ── api-ms-win-core-winrt-error: Windows Runtime error origination ───────────

/// `RoOriginateErrorW(error, cchMax, message) -> BOOL`
///
/// Originates a WinRT error with an associated error message.  In headless mode
/// this is a no-op; returns FALSE (not stored).
///
/// # Safety
///
/// `message`, if non-null, must point to a valid UTF-16 string.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/roerrorapi/nf-roerrorapi-rooriginateerrorw>
pub unsafe extern "C" fn winrt_ro_originate_error_w(
    _error: u32,
    _cch_max: u32,
    _message: *const u16,
) -> i32 {
    // FALSE — error was not originated (headless, no WinRT runtime)
    0
}

/// `RoOriginateError(error, message) -> BOOL`
///
/// Headless stub; returns FALSE.
///
/// # Safety
///
/// This function ignores all pointer arguments; safe to call with any values.
pub unsafe extern "C" fn winrt_ro_originate_error(_error: u32, _message: *mut u8) -> i32 {
    0
}

/// `RoGetErrorReportingFlags(pflags) -> HRESULT`
///
/// Headless stub; sets flags to 0 and returns S_OK.
///
/// # Safety
///
/// `pflags`, if non-null, must point to a valid `u32` that may be written.
pub unsafe extern "C" fn winrt_ro_get_error_reporting_flags(pflags: *mut u32) -> u32 {
    if !pflags.is_null() {
        *pflags = 0;
    }
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_error_info_returns_s_false() {
        let mut ptr: *mut u8 = core::ptr::null_mut();
        let hr = unsafe { oleaut32_get_error_info(0, &raw mut ptr) };
        assert_eq!(
            hr, S_FALSE,
            "GetErrorInfo must return S_FALSE in headless mode"
        );
        assert!(ptr.is_null(), "GetErrorInfo must set *pperrinfo = NULL");
    }

    #[test]
    fn test_set_error_info_returns_s_ok() {
        let hr = unsafe { oleaut32_set_error_info(0, core::ptr::null_mut()) };
        assert_eq!(hr, S_OK, "SetErrorInfo must return S_OK");
    }

    #[test]
    fn test_sys_free_string_null() {
        // Freeing NULL must not crash
        unsafe { oleaut32_sys_free_string(core::ptr::null_mut()) };
    }

    #[test]
    fn test_sys_alloc_and_free_string() {
        // Allocate a BSTR from a short wide string
        let wide: Vec<u16> = "hello\0".encode_utf16().collect();
        let bstr = unsafe { oleaut32_sys_alloc_string(wide.as_ptr()) };
        assert!(!bstr.is_null(), "SysAllocString must return non-NULL");

        let len = unsafe { oleaut32_sys_string_len(bstr) };
        assert_eq!(len, 5, "SysStringLen must return character count (5)");

        // Free must not crash
        unsafe { oleaut32_sys_free_string(bstr) };
    }

    #[test]
    fn test_sys_string_len_null() {
        let len = unsafe { oleaut32_sys_string_len(core::ptr::null()) };
        assert_eq!(len, 0, "SysStringLen(NULL) must return 0");
    }

    #[test]
    fn test_ro_originate_error_w_returns_false() {
        let result = unsafe { winrt_ro_originate_error_w(0x8000_4000, 0, core::ptr::null()) };
        assert_eq!(result, 0, "RoOriginateErrorW must return FALSE");
    }
}
