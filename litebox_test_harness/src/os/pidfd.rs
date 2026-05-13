// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin idiomatic wrapper over `pidfd_open(2)` for handler bodies.
//!
//! Mirrors the shape of [`crate::os::eventfd`] and other `os::*`
//! wrappers: a handle that owns the underlying fd, raw + borrowed
//! accessors for SCM transfer, and the operations the test scenarios
//! actually need (`poll_exit_in`).

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// Owned pidfd descriptor watching a target process.
pub struct Pidfd {
    fd: OwnedFd,
}

impl Pidfd {
    /// `pidfd_open(target_pid, 0)`. The returned pidfd becomes
    /// readable when the target process exits.
    ///
    /// # Errors
    /// `io::Error` from the `pidfd_open(2)` syscall (e.g. `ESRCH`
    /// for a non-existent PID, `EPERM` for unauthorised access).
    pub fn open(target_pid: u32) -> Result<Self, std::io::Error> {
        Self::open_with_flags(target_pid, 0)
    }

    /// `pidfd_open(target_pid, flags)`. Use this for `PIDFD_NONBLOCK`
    /// or other modern flag values.
    ///
    /// # Errors
    /// As for [`Self::open`].
    pub fn open_with_flags(target_pid: u32, flags: u32) -> Result<Self, std::io::Error> {
        // SAFETY: pidfd_open returns a fresh fd on success or -1 with
        // errno on failure; we wrap as OwnedFd for RAII closure.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, target_pid as libc::pid_t, flags) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: raw is a freshly returned owned descriptor.
            fd: unsafe { OwnedFd::from_raw_fd(raw as i32) },
        })
    }

    /// Wrap an owned pidfd received via SCM_RIGHTS from another
    /// process. The caller is responsible for ensuring the fd is
    /// genuinely a pidfd.
    #[must_use]
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// `poll(pidfd, POLLIN, timeout_ms)`. Returns `Ok(true)` if the
    /// target process exit fires within the timeout, `Ok(false)` on
    /// timeout, `Err(io::Error)` on poll failure.
    ///
    /// pidfd's POLLIN fires exactly once on exit (and stays ready
    /// thereafter), so a poll that returns POLLIN is the canonical
    /// exit-detection probe.
    ///
    /// # Errors
    /// `io::Error` from `poll(2)`.
    pub fn poll_exit_in(&self, timeout_ms: i32) -> Result<bool, std::io::Error> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: pfd is a valid initialised pollfd; len 1 matches
            // the single-element array.
            let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 {
                return Ok(false);
            }
            return Ok(pfd.revents & libc::POLLIN != 0);
        }
    }
}

impl AsFd for Pidfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Pidfd {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}
