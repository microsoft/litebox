// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native Linux process cloning for broker-adopted runners.

use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use litebox::platform::{
    ForkError, ForkResult as ProviderForkResult, ProcessHandle, ProcessProvider,
};

/// Owned native child resources used by [`ProcessProvider`].
pub struct ClonedProcess {
    process_id: u32,
    process: OwnedFd,
}

impl ProcessProvider for crate::LinuxUserland {
    type ProcessHandle = ClonedProcess;
    type ProcessError = Error;

    unsafe fn fork_process()
    -> core::result::Result<ProviderForkResult<ClonedProcess>, ForkError<Error>> {
        // SAFETY: The caller guarantees quiescence and a clone-safe child bootstrap.
        match unsafe { fork_process() } {
            Ok(ForkResult::Parent {
                process_id,
                process,
            }) => Ok(ProviderForkResult::Parent(ClonedProcess {
                process_id,
                process,
            })),
            Ok(ForkResult::Child) => Ok(ProviderForkResult::Child),
            Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => Err(ForkError::Unsupported),
            Err(error) => Err(ForkError::Failed(error)),
        }
    }

    unsafe fn prepare_forked_process() -> Result<()> {
        // SAFETY: The caller is the sole cloned thread and never returns to the copied stack.
        unsafe { crate::reset_current_thread_after_process_clone() };
        // SAFETY: The clone deliberately retains only standard input, output, and error.
        if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl ProcessHandle for ClonedProcess {
    type Error = Error;

    fn process_id(&self) -> Result<u32> {
        Ok(self.process_id)
    }

    fn resume(&self) -> Result<()> {
        // Linux creates the clone running.
        Ok(())
    }

    fn terminate(&self) -> Result<()> {
        // SAFETY: The owned pidfd identifies this clone even if its process ID is reused.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.process.as_raw_fd(),
                libc::SIGKILL,
                core::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Result of cloning the calling process.
pub enum ForkResult {
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
pub unsafe fn fork_process() -> Result<ForkResult> {
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
        0 => Ok(ForkResult::Child),
        process_id => {
            let process_id = u32::try_from(process_id)
                .map_err(|_| Error::other("clone returned an invalid process ID"))?;
            if pidfd < 0 {
                return Err(Error::other("clone returned an invalid pidfd"));
            }
            // SAFETY: CLONE_PIDFD returned a new descriptor owned by this process.
            let process = unsafe { OwnedFd::from_raw_fd(pidfd) };
            Ok(ForkResult::Parent {
                process_id,
                process,
            })
        }
    }
}
