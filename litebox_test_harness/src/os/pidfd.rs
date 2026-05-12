// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Small safe wrapper around Linux pidfds for harness handlers.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// Owned pidfd.
pub struct Pidfd {
    fd: OwnedFd,
}

impl Pidfd {
    /// Opens a pidfd for `pid` using `pidfd_open(2)`.
    pub fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: syscall returns a fresh fd on success, or -1 with errno set.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pidfd_open returned a valid fd owned by this process.
        let fd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
        Ok(Self { fd })
    }

    /// Polls for pidfd readability (target process exit).
    pub fn poll(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` points to one valid pollfd entry.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(rc > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP)) != 0)
    }
}

impl AsRawFd for Pidfd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for Pidfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
