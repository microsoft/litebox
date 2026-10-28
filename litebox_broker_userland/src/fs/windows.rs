// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows host file I/O directly between a file and a buffer's [`RawBytes`],
//! with no bounce buffer.
//!
//! Only a buffer whose bytes are one contiguous part transfers directly, with
//! one `ReadFile` or `WriteFile` given the offset in an `OVERLAPPED`: one
//! positioned read or write, as the bounce path makes through std's
//! `seek_read` or `seek_write`.
//!
//! [`RawBytes`]: litebox_platform::buffer::RawBytes

use std::fs::File;
use std::io::{Error, Result};
use std::os::windows::io::AsRawHandle;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, ERROR_IO_PENDING};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::core::BOOL;

/// Reads from `file` at `offset` directly into `buf` with one `ReadFile`.
///
/// Returns `None` without reading unless `buf` is one contiguous part of raw
/// bytes.
pub(crate) fn read_at(file: &File, buf: &mut dyn ReadBuffer, offset: u64) -> Option<Result<usize>> {
    let mut result = None;
    let length = buf.len();
    buf.read_direct_at(0, length, &mut |parts| {
        let [part] = parts else { return 0 };
        let read = transfer(offset, part.len(), |length, transferred, overlapped| {
            // SAFETY: `part` is raw bytes that are writable for `length` bytes
            // and that the kernel fills without Rust references to them;
            // `transfer` passes valid `transferred` and `overlapped` and never
            // returns while the read may still use them.
            unsafe {
                ReadFile(
                    file.as_raw_handle(),
                    part.as_ptr(),
                    length,
                    transferred,
                    overlapped,
                )
            }
        });
        // Like `seek_read`, a read at or past the end reads nothing.
        let read = match read {
            Err(error) if error.raw_os_error() == Some(ERROR_HANDLE_EOF.cast_signed()) => Ok(0),
            read => read,
        };
        *result.insert(read).as_ref().unwrap_or(&0)
    })?;
    result
}

/// Writes `buf` to `file` at `offset` directly with one `WriteFile`.
///
/// Returns `None` without writing unless `buf` is one contiguous part of raw
/// bytes.
pub(crate) fn write_at(file: &File, buf: &dyn WriteBuffer, offset: u64) -> Option<Result<usize>> {
    let mut result = None;
    buf.write_direct_at(0, buf.len(), &mut |parts| {
        let [part] = parts else { return 0 };
        let written = transfer(offset, part.len(), |length, transferred, overlapped| {
            // SAFETY: `part` is raw bytes that are readable for `length` bytes
            // and that the kernel reads without Rust references to them;
            // `transfer` passes valid `transferred` and `overlapped` and never
            // returns while the write may still use them.
            unsafe {
                WriteFile(
                    file.as_raw_handle(),
                    part.as_ptr(),
                    length,
                    transferred,
                    overlapped,
                )
            }
        });
        *result.insert(written).as_ref().unwrap_or(&0)
    })?;
    result
}

/// Makes `call`, a `ReadFile` or `WriteFile` passed the length to transfer
/// (`length` clamped at `u32::MAX`, as std does), where to store how many bytes
/// it transferred, and an `OVERLAPPED` holding `offset`, and returns how many
/// bytes it transferred.
fn transfer(
    offset: u64,
    length: usize,
    call: impl FnOnce(u32, *mut u32, *mut OVERLAPPED) -> BOOL,
) -> Result<usize> {
    let mut overlapped = OVERLAPPED::default();
    // Splits the offset into its low and high halves.
    #[allow(clippy::cast_possible_truncation)]
    {
        overlapped.Anonymous.Anonymous.Offset = offset as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    }
    let length = u32::try_from(length).unwrap_or(u32::MAX);
    let mut transferred = 0;
    if call(length, &raw mut transferred, &raw mut overlapped) != 0 {
        return Ok(transferred as usize);
    }
    let error = Error::last_os_error();
    // On a file open for asynchronous I/O, the call would go on using
    // `overlapped` and the buffer after returning, so abort, as std does when
    // such a call doesn't complete; `LocalFs` opens files only for synchronous
    // I/O.
    if error.raw_os_error() == Some(ERROR_IO_PENDING.cast_signed()) {
        std::process::abort();
    }
    Err(error)
}
