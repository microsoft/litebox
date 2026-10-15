// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native Linux process cloning for broker-adopted runners.

use std::io::{Error, Result};
use std::os::fd::{FromRawFd, OwnedFd};

/// Result of cloning the calling process.
pub enum ProcessClone {
    /// The original process receives the cloned process ID.
    Parent {
        /// Host process ID of the clone.
        process_id: u32,
        /// Stable reference used for parent-side failure cleanup.
        process: OwnedFd,
    },
    /// The cloned process resumes on the calling thread.
    Child,
}

/// Clones the calling process with copy-on-write memory and makes the caller's parent own it.
///
/// `CLONE_PARENT` makes an out-of-process runner's broker the clone's host parent, allowing the
/// broker to supervise and reap the process directly. The clone contains only the calling thread.
///
/// # Safety
///
/// The caller must ensure every other relevant thread is quiescent and that the child immediately
/// enters a clone-safe bootstrap path. The child inherits synchronization and runtime state whose
/// owners may no longer exist, so calling arbitrary code before rebuilding that state can deadlock.
pub unsafe fn clone_current_process() -> Result<ProcessClone> {
    let flags = libc::CLONE_PARENT | libc::CLONE_PIDFD | libc::SIGCHLD;
    let mut pidfd = -1i32;
    // SAFETY: A null child stack gives clone fork-like copy-on-write semantics. The remaining null
    // optional arguments are valid, and `pidfd` is writable for the CLONE_PIDFD result.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone,
            flags,
            0usize,
            &raw mut pidfd,
            core::ptr::null_mut::<libc::pid_t>(),
            0usize,
        )
    };
    match result {
        -1 => Err(Error::last_os_error()),
        0 => Ok(ProcessClone::Child),
        process_id => {
            let process_id = u32::try_from(process_id)
                .map_err(|_| Error::other("clone returned an invalid process ID"))?;
            if pidfd < 0 {
                return Err(Error::other("clone returned an invalid pidfd"));
            }
            // SAFETY: CLONE_PIDFD returned a new descriptor owned by this process.
            let process = unsafe { OwnedFd::from_raw_fd(pidfd) };
            Ok(ProcessClone::Parent {
                process_id,
                process,
            })
        }
    }
}
