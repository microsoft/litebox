// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-local stdio adapter for the `test-stdio` feature.

// TODO: Replace this test adapter with broker-backed stdio integration.

use litebox::stdio::StdioOutputStream;
use litebox_common_macos::errno::Errno;
use litebox_shim_macos::Stdio;

pub(crate) struct HostStdio;
impl Stdio for HostStdio {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        // SAFETY: buf is a live shim-owned mutable slice, not a guest pointer.
        host_io_result(unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) })
    }
    fn write(&self, stream: StdioOutputStream, buf: &[u8]) -> Result<usize, Errno> {
        let fd = match stream {
            StdioOutputStream::Stdout => 1,
            StdioOutputStream::Stderr => 2,
        };
        // SAFETY: buf is a live shim-owned slice, not a guest pointer.
        host_io_result(unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) })
    }
}

fn host_io_result(result: isize) -> Result<usize, Errno> {
    if let Ok(size) = usize::try_from(result) {
        return Ok(size);
    }
    Err(match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EINTR) => Errno::EINTR,
        Some(libc::EAGAIN) => Errno::EAGAIN,
        Some(libc::EBADF) => Errno::EBADF,
        Some(libc::EPIPE) => Errno::EPIPE,
        Some(libc::ENOSPC) => Errno::ENOSPC,
        Some(libc::EINVAL) => Errno::EINVAL,
        _ => Errno::EIO,
    })
}
