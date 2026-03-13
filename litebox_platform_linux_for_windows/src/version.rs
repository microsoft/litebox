// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VERSION.dll function implementations
//!
//! This module provides minimal stub implementations of the Windows Version API
//! (`VERSION.dll`).  Version resources are not available in the Linux emulation
//! environment, so all functions return values indicating that no version
//! information is present.

#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;

/// `GetFileVersionInfoSizeW` — return the size of a file's version-information resource.
///
/// Always returns 0 because version resources are not available in the emulated
/// environment.  `lpdw_handle` is set to 0 if non-null.
///
/// # Safety
/// `filename` is not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn version_GetFileVersionInfoSizeW(
    _filename: *const u16,
    lpdw_handle: *mut u32,
) -> u32 {
    if !lpdw_handle.is_null() {
        // SAFETY: lpdw_handle is checked non-null above.
        unsafe { *lpdw_handle = 0 };
    }
    0
}

/// `GetFileVersionInfoW` — retrieve version information for a file.
///
/// Always returns FALSE (0) because version resources are not available.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn version_GetFileVersionInfoW(
    _filename: *const u16,
    _handle: u32,
    _len: u32,
    _data: *mut c_void,
) -> i32 {
    0 // FALSE
}

/// `VerQueryValueW` — retrieve specified version-information from the specified resource.
///
/// Always returns FALSE (0) because version resources are not available.
///
/// # Safety
/// `lp_buffer` and `pu_len` are set to null/0 if non-null; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn version_VerQueryValueW(
    _block: *const c_void,
    _sub_block: *const u16,
    lp_buffer: *mut *mut c_void,
    pu_len: *mut u32,
) -> i32 {
    if !lp_buffer.is_null() {
        // SAFETY: lp_buffer is checked non-null above.
        unsafe { *lp_buffer = core::ptr::null_mut() };
    }
    if !pu_len.is_null() {
        // SAFETY: pu_len is checked non-null above.
        unsafe { *pu_len = 0 };
    }
    0 // FALSE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_file_version_info_size_w_returns_zero() {
        let filename: Vec<u16> = "test.exe\0".encode_utf16().collect();
        let mut handle: u32 = 99;
        let result = unsafe { version_GetFileVersionInfoSizeW(filename.as_ptr(), &raw mut handle) };
        assert_eq!(result, 0);
        assert_eq!(handle, 0);
    }

    #[test]
    fn test_get_file_version_info_w_returns_false() {
        let filename: Vec<u16> = "test.exe\0".encode_utf16().collect();
        let result =
            unsafe { version_GetFileVersionInfoW(filename.as_ptr(), 0, 0, core::ptr::null_mut()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_ver_query_value_w_returns_false() {
        let subblock: Vec<u16> = "\\\0".encode_utf16().collect();
        let mut buf: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut len: u32 = 99;
        let result = unsafe {
            version_VerQueryValueW(
                core::ptr::null(),
                subblock.as_ptr(),
                &raw mut buf,
                &raw mut len,
            )
        };
        assert_eq!(result, 0);
        assert!(buf.is_null());
        assert_eq!(len, 0);
    }
}
