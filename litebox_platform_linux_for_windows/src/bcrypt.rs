// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! bcryptprimitives.dll function implementations
//!
//! This module provides minimal implementations of the Windows CNG
//! (Cryptography Next Generation) primitive APIs.
//!
//! Supported APIs:
//! - `ProcessPrng` — fill a buffer with cryptographically random bytes

#![allow(unsafe_op_in_unsafe_fn)]

/// `ProcessPrng(pbData, cbData) -> BOOL`
///
/// Fills `pb_data` with `cb_data` cryptographically random bytes sourced from
/// the Linux `getrandom(2)` syscall.  Returns 1 (TRUE) on success, 0 (FALSE)
/// on failure.
///
/// # Safety
///
/// `pb_data` must point to a writable buffer of at least `cb_data` bytes,
/// or be NULL when `cb_data` is 0.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/seccng/processprng>
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcrypt_ProcessPrng(pb_data: *mut u8, cb_data: u32) -> u32 {
    if cb_data == 0 {
        return 1; // nothing to fill — success
    }
    if pb_data.is_null() {
        return 0; // NULL buffer with non-zero length — failure
    }

    let buf = unsafe { core::slice::from_raw_parts_mut(pb_data, cb_data as usize) };

    // Fill the buffer in chunks; getrandom can return fewer bytes than requested
    // (though in practice it fills fully for reasonable sizes).
    let mut filled = 0usize;
    while filled < buf.len() {
        // SAFETY: buf[filled..] is a valid writable slice within `buf`.
        let ret = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr().cast(),
                buf.len() - filled,
                0, // flags: blocking, no GRND_NONBLOCK
            )
        };
        if ret <= 0 {
            return 0; // syscall error or unexpected empty read
        }
        filled += ret.cast_unsigned();
    }
    1
}
