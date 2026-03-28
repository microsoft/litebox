// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-backed pipe file descriptors for cross-host-process fork.
//!
//! When delayed fork migrates a child to a new host process, in-memory pipe
//! ring buffers cannot span the process boundary.  Both parent and child
//! replace their virtual pipe endpoints with `HostPipeFd` entries that do
//! direct host `read(2)` / `write(2)` on a real OS pipe.
//!
//! These descriptors are installed transparently at the same guest FD numbers
//! so that guest code sees no difference.
//!
//! ## Known v1 Limitations
//!
//! - Only `read`, `write`, and `close` are supported.  Other fd operations
//!   (dup, readv/writev, poll/epoll, fcntl) are not yet handled and will
//!   fall through to EBADF.
//! - Dup'd pipe endpoints are bridged independently rather than sharing a
//!   single OS pipe, which could break aliased-fd semantics.
//! - `O_NONBLOCK` and `FD_CLOEXEC` flags are not preserved across bridging.
//! - Data already buffered in virtual pipe ring buffers before bridge creation
//!   is silently lost.  The OS pipe starts empty, so any unread data written
//!   before `commit_delayed_fork` will not be delivered.

use core::sync::atomic::{AtomicI32, Ordering};

use litebox::{
    event::{Events, IOPollable},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
};
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;

/// Marker type for the host-pipe FD subsystem.
pub(crate) struct HostPipeSubsystem;

impl FdEnabledSubsystem for HostPipeSubsystem {
    type Entry = HostPipeFd;
}

/// Whether this endpoint is for reading or writing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPipeDirection {
    Read,
    Write,
}

/// A file descriptor entry backed by a real host OS pipe.
///
/// Holds a raw host file descriptor and a direction.  The shim's `sys_read` /
/// `sys_write` dispatch to `read_host_pipe` / `write_host_pipe`, which call
/// the platform's host I/O methods.
pub(crate) struct HostPipeFd {
    /// Raw host OS file descriptor.  Owned by this entry; closed on drop via
    /// the platform.
    host_fd: AtomicI32,
    /// Whether this endpoint is a read or write end.
    pub(crate) direction: HostPipeDirection,
}

impl HostPipeFd {
    /// Create a new host-pipe entry.
    pub(crate) fn new(host_fd: i32, direction: HostPipeDirection) -> Self {
        Self {
            host_fd: AtomicI32::new(host_fd),
            direction,
        }
    }

    /// Return the raw host file descriptor.
    pub(crate) fn raw_fd(&self) -> i32 {
        self.host_fd.load(Ordering::Relaxed)
    }

    /// Atomically take the host fd, replacing it with -1.
    /// Returns the old fd value. Subsequent `raw_fd()` calls return -1.
    pub(crate) fn take_fd(&self) -> i32 {
        self.host_fd.swap(-1, Ordering::AcqRel)
    }
}

impl FdEnabledSubsystemEntry for HostPipeFd {
    // No ref counting needed — each FD entry owns its host fd.
    // on_dup/on_close use defaults (no-op).
}

// SAFETY: The host_fd is an integer handle, safe to share across threads.
// The AtomicI32 provides the necessary synchronization.

impl IOPollable for HostPipeFd {
    fn register_observer(
        &self,
        _observer: alloc::sync::Weak<dyn litebox::event::observer::Observer<Events>>,
        _mask: Events,
    ) {
        // Host-pipe FDs do not support asynchronous observer notifications.
        // Callers should use periodic polling.
    }

    fn check_io_events(&self) -> Events {
        match self.direction {
            // Read ends are always considered readable (the kernel manages
            // blocking on the actual host read).
            HostPipeDirection::Read => Events::IN,
            // Write ends are always considered writable.
            HostPipeDirection::Write => Events::OUT,
        }
    }

    fn needs_host_poll(&self) -> bool {
        true
    }
}

/// Read from a host-pipe FD into the guest buffer.
///
/// Returns the number of bytes read, or an errno.
pub(crate) fn read_host_pipe(
    platform: &'static Platform,
    fd: &HostPipeFd,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    if fd.direction != HostPipeDirection::Read {
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

/// Write from the guest buffer to a host-pipe FD.
///
/// Returns the number of bytes written, or an errno.
pub(crate) fn write_host_pipe(
    platform: &'static Platform,
    fd: &HostPipeFd,
    buf: &[u8],
) -> Result<usize, Errno> {
    if fd.direction != HostPipeDirection::Write {
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
