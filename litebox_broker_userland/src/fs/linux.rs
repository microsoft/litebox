// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux host file I/O directly between a file and a buffer's [`RawBytes`],
//! with no bounce buffer.
//!
//! Only a buffer whose bytes are one contiguous part transfers directly, with
//! the one `pread` or `pwrite` the bounce path would make. A vectored call
//! would not behave the same: for a file whose driver lacks vectored I/O, such
//! as many procfs files, Linux reads or writes each iovec separately.
//!
//! [`RawBytes`]: litebox_platform::buffer::RawBytes

use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::fd::AsRawFd;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

/// Reads from `file` at `offset` directly into `buf` with one `pread`.
///
/// Returns `None` without reading unless `buf` is one contiguous part of raw
/// bytes.
pub(super) fn read_at(file: &File, buf: &mut dyn ReadBuffer, offset: u64) -> Option<Result<usize>> {
    let mut result = None;
    let length = buf.len();
    buf.read_direct_at(0, length, &mut |parts| {
        let [part] = parts else { return 0 };
        let read = transfer(offset, |offset| {
            // SAFETY: `part` is raw bytes that are writable for the call and
            // that the kernel fills without Rust references to them.
            unsafe { libc::pread(file.as_raw_fd(), part.as_ptr().cast(), part.len(), offset) }
        });
        *result.insert(read).as_ref().unwrap_or(&0)
    })?;
    result
}

/// Writes `buf` to `file` at `offset` directly with one `pwrite`.
///
/// Returns `None` without writing unless `buf` is one contiguous part of raw
/// bytes.
pub(super) fn write_at(file: &File, buf: &dyn WriteBuffer, offset: u64) -> Option<Result<usize>> {
    let mut result = None;
    buf.write_direct_at(0, buf.len(), &mut |parts| {
        let [part] = parts else { return 0 };
        let written = transfer(offset, |offset| {
            // SAFETY: `part` is raw bytes that are readable for the call and
            // that the kernel reads without Rust references to them.
            unsafe { libc::pwrite(file.as_raw_fd(), part.as_ptr().cast(), part.len(), offset) }
        });
        *result.insert(written).as_ref().unwrap_or(&0)
    })?;
    result
}

/// Makes `call`, a positioned system call passed `offset`, and returns how many
/// bytes it transferred.
fn transfer(offset: u64, call: impl FnOnce(libc::off_t) -> libc::ssize_t) -> Result<usize> {
    let offset = libc::off_t::try_from(offset).map_err(|_| Error::from(ErrorKind::InvalidInput))?;
    usize::try_from(call(offset)).map_err(|_| Error::last_os_error())
}
