// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! USERENV.dll function implementations
//!
//! This module provides minimal implementations of the Windows User Environment
//! API (USERENV.dll).
//!
//! Supported APIs:
//! - `GetUserProfileDirectoryW` — retrieve the profile directory for a user token

#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::cast_possible_truncation)]

/// `GetUserProfileDirectoryW(hToken, lpProfileDir, lpcchSize) -> BOOL`
///
/// Returns the home directory path for the user associated with `h_token` as a
/// null-terminated UTF-16 string.
///
/// On Linux, the profile directory is the value of the `HOME` environment
/// variable (falling back to `/root` if `HOME` is unset).
///
/// - If `lp_profile_dir` is NULL or the buffer is too small, the required
///   buffer size (in UTF-16 code units, including the null terminator) is
///   written to `*lpcc_size` and 0 (FALSE) is returned.
/// - Otherwise the path is written to `lp_profile_dir`, `*lpcc_size` is set
///   to the number of UTF-16 code units written (including the null
///   terminator), and 1 (TRUE) is returned.
///
/// `h_token` is accepted but ignored; the current process's `HOME` is always
/// used.
///
/// # Safety
///
/// - `lpcc_size` must be a valid pointer to a `u32`.
/// - `lp_profile_dir`, when non-null, must point to a writable buffer of at
///   least `*lpcc_size` UTF-16 code units.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getuserprofiledirectoryw>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn userenv_GetUserProfileDirectoryW(
    _h_token: *mut core::ffi::c_void,
    lp_profile_dir: *mut u16,
    lpcc_size: *mut u32,
) -> u32 {
    if lpcc_size.is_null() {
        return 0;
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let mut utf16: Vec<u16> = home.encode_utf16().collect();
    utf16.push(0); // null terminator

    let required = utf16.len() as u32;
    let provided = unsafe { *lpcc_size };

    if lp_profile_dir.is_null() || provided < required {
        unsafe { *lpcc_size = required };
        return 0; // FALSE — caller must retry with larger buffer
    }

    // SAFETY: lp_profile_dir points to a buffer of at least `required` u16 elements
    // (verified by the provided >= required check above), and utf16 is a valid slice.
    unsafe {
        core::ptr::copy_nonoverlapping(utf16.as_ptr(), lp_profile_dir, utf16.len());
        *lpcc_size = required;
    }
    1 // TRUE
}
