// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-mediated external file descriptors.
//!
//! `ExternalFd` is the narrow bridge for file descriptors that originate
//! outside Litebox's broker-hosted fd model: initial runner-owned stdio and
//! explicit host/guest pipe bridges. Internal fork/exec migration channels use
//! broker-backed pipe, socketpair, and PTY descriptors instead.

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use litebox::{
    event::{Events, IOPollable},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
};
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;

/// Marker type for the external-fd FD subsystem.
pub(crate) struct ExternalFdSubsystem;

impl FdEnabledSubsystem for ExternalFdSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::ExternalFd;

    type Entry = ExternalFd;
}

/// Whether this endpoint is for reading or writing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalFdDirection {
    Read,
    Write,
    /// Bidirectional external handles, such as explicit host socket bridges.
    ReadWrite,
}

/// A file descriptor entry backed by a real host OS pipe.
///
/// Holds a raw host file descriptor and a direction.  The shim's `sys_read` /
/// `sys_write` dispatch to `read_external_fd` / `write_external_fd`, which call
/// the platform's host I/O methods.
pub(crate) struct ExternalFd {
    /// Raw host OS file descriptor.  Owned by this entry; closed on drop via
    /// the platform.
    host_fd: AtomicI32,
    /// Whether this endpoint is a read or write end.
    pub(crate) direction: ExternalFdDirection,
    /// Guest-visible open status flags for fcntl(F_GETFL/F_SETFL).
    status: AtomicU32,
}

impl ExternalFd {
    /// Create a new external-fd entry.
    pub(crate) fn new(host_fd: i32, direction: ExternalFdDirection) -> Self {
        let access = match direction {
            ExternalFdDirection::Read => OFlags::RDONLY,
            ExternalFdDirection::Write => OFlags::WRONLY,
            ExternalFdDirection::ReadWrite => OFlags::RDWR,
        };
        Self {
            host_fd: AtomicI32::new(host_fd),
            direction,
            status: AtomicU32::new(access.bits()),
        }
    }

    /// Return the raw host file descriptor.
    pub(crate) fn raw_fd(&self) -> i32 {
        self.host_fd.load(Ordering::Relaxed)
    }

    /// Return guest-visible open status flags.
    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits_truncate(self.status.load(Ordering::Relaxed)) & OFlags::STATUS_FLAGS_MASK
    }

    /// Update guest-visible open status flags.
    pub(crate) fn set_status(&self, flags: OFlags) {
        let access = self.get_status() & (OFlags::RDONLY | OFlags::WRONLY | OFlags::RDWR);
        self.status.store(
            (access | (flags & OFlags::STATUS_FLAGS_MASK)).bits(),
            Ordering::Relaxed,
        );
    }

    /// Atomically take the host fd, replacing it with -1.
    /// Returns the old fd value. Subsequent `raw_fd()` calls return -1.
    pub(crate) fn take_fd(&self) -> i32 {
        self.host_fd.swap(-1, Ordering::AcqRel)
    }
}

impl FdEnabledSubsystemEntry for ExternalFd {
    // No ref counting needed — each FD entry owns its host fd.
    // on_dup/on_close use defaults (no-op).
}

// SAFETY: The host_fd is an integer handle, safe to share across threads.
// The AtomicI32 provides the necessary synchronization.

impl IOPollable for ExternalFd {
    fn register_observer(
        &self,
        _observer: alloc::sync::Weak<dyn litebox::event::observer::Observer<Events>>,
        _mask: Events,
    ) {
        // External-fd FDs do not support asynchronous observer notifications.
        // Callers should use periodic polling via needs_host_poll().
    }

    fn check_io_events(&self) -> Events {
        // Poll the real host fd to determine readiness instead of always
        // returning ready.  Without this, epoll_wait(timeout=0) always
        // reports this fd as ready, causing Node.js's libuv event loop
        // to spin at 100% CPU.
        let fd = self.host_fd.load(Ordering::Relaxed);
        if fd < 0 {
            return Events::HUP;
        }

        // Use raw poll(2) syscall to check readiness.
        // struct pollfd { fd: i32, events: i16, revents: i16 }
        let mut pfd: [u8; 8] = [0; 8];
        // fd (i32 at offset 0)
        pfd[0..4].copy_from_slice(&fd.to_ne_bytes());
        // events (i16 at offset 4): POLLIN(1) | POLLOUT(4)
        pfd[4..6].copy_from_slice(&5i16.to_ne_bytes());
        // revents (i16 at offset 6): 0
        // poll(fds, nfds=1, timeout=0)
        let ret =
            unsafe { syscalls::syscall3(syscalls::Sysno::poll, pfd.as_mut_ptr() as usize, 1, 0) };
        if ret.is_err() || matches!(ret, Ok(0)) {
            return Events::empty();
        }
        let revents = i16::from_ne_bytes([pfd[6], pfd[7]]);
        let mut events = Events::empty();
        if revents & 1 != 0 {
            // POLLIN
            events |= Events::IN;
        }
        if revents & 4 != 0 {
            // POLLOUT
            events |= Events::OUT;
        }
        if revents & 16 != 0 {
            // POLLHUP
            events |= Events::HUP;
        }
        if revents & 8 != 0 {
            // POLLERR
            events |= Events::ERR;
        }
        events
    }

    fn needs_host_poll(&self) -> bool {
        true
    }
}

/// Read from a external-fd FD into the guest buffer.
///
/// Returns the number of bytes read, or an errno.
pub(crate) fn read_external_fd(
    platform: &'static Platform,
    fd: &ExternalFd,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    if fd.direction == ExternalFdDirection::Write {
        return Err(Errno::EBADF);
    }
    let raw = fd.raw_fd();
    if raw < 0 {
        return Err(Errno::EBADF);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    platform.read_host_fd(raw, buf)
}

/// Write from the guest buffer to a external-fd FD.
///
/// Returns the number of bytes written, or an errno.
pub(crate) fn write_external_fd(
    platform: &'static Platform,
    fd: &ExternalFd,
    buf: &[u8],
) -> Result<usize, Errno> {
    if fd.direction == ExternalFdDirection::Read {
        return Err(Errno::EBADF);
    }
    let raw = fd.raw_fd();
    if raw < 0 {
        return Err(Errno::EBADF);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    platform.write_host_fd(raw, buf)
}
