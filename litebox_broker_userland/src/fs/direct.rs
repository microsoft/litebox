// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host file I/O directly between a file and a buffer's [`RawBytes`], with no
//! bounce buffer.

use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::fd::AsRawFd;

use litebox_platform::buffer::{RawBytes, ReadBuffer, WriteBuffer};

/// Reads from `file` at `offset` directly into `buf` with one `preadv`.
///
/// Returns `None` without reading if `buf` is not [`RawBytes`].
pub(super) fn read_at(file: &File, buf: &mut dyn ReadBuffer, offset: u64) -> Option<Result<usize>> {
    let mut result = Ok(0);
    let length = buf.len();
    buf.read_direct_at(0, length, &mut |parts| {
        result = transfer(parts, offset, |iovecs, count, offset| {
            // SAFETY: `iovecs` holds `count` iovecs, each spanning raw bytes
            // that are writable for the call and that the kernel fills
            // without Rust references to them.
            unsafe { libc::preadv(file.as_raw_fd(), iovecs, count, offset) }
        });
        *result.as_ref().unwrap_or(&0)
    })?;
    Some(result)
}

/// Writes `buf` to `file` at `offset` directly with one `pwritev`.
///
/// Returns `None` without writing if `buf` is not [`RawBytes`].
pub(super) fn write_at(file: &File, buf: &dyn WriteBuffer, offset: u64) -> Option<Result<usize>> {
    let mut result = Ok(0);
    buf.write_direct_at(0, buf.len(), &mut |parts| {
        result = transfer(parts, offset, |iovecs, count, offset| {
            // SAFETY: `iovecs` holds `count` iovecs, each spanning raw bytes
            // that are readable for the call and that the kernel reads
            // without Rust references to them.
            unsafe { libc::pwritev(file.as_raw_fd(), iovecs, count, offset) }
        });
        *result.as_ref().unwrap_or(&0)
    })?;
    Some(result)
}

/// Transfers `parts` at `offset` with `call`, a vectored system call passed
/// iovecs for them, their count, and the offset.
///
/// One call transfers at most [`libc::UIO_MAXIOV`] parts, so any beyond them
/// are left for a later one, as after any other short transfer.
fn transfer(
    parts: &[RawBytes<'_>],
    offset: u64,
    call: impl FnOnce(*const libc::iovec, libc::c_int, libc::off_t) -> libc::ssize_t,
) -> Result<usize> {
    let offset = libc::off_t::try_from(offset).map_err(|_| Error::from(ErrorKind::InvalidInput))?;
    let iovecs: Vec<_> = parts
        .iter()
        .take(usize::try_from(libc::UIO_MAXIOV).expect("UIO_MAXIOV is positive"))
        .map(|part| libc::iovec {
            iov_base: part.as_ptr().cast(),
            iov_len: part.len(),
        })
        .collect();
    let count = libc::c_int::try_from(iovecs.len()).expect("at most UIO_MAXIOV parts");
    usize::try_from(call(iovecs.as_ptr(), count, offset)).map_err(|_| Error::last_os_error())
}
