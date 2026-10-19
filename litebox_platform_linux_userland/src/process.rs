// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native Linux process operations.

use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use litebox::platform::{
    ForkError, ForkResult as ProviderForkResult, ProcessHandle, ProcessProvider,
};

/// A handle to a process created by [`ProcessProvider::fork_process`].
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

    unsafe fn prepare_fork_child() -> Result<()> {
        // SAFETY: The caller is the sole cloned thread and never returns to the copied stack.
        unsafe { crate::reset_current_thread_after_process_clone() };
        Ok(())
    }
}

/// Closes every descriptor above the standard streams except those in `keep`.
///
/// # Safety
///
/// The caller must be the sole thread of a newly cloned process, and nothing may use the closed
/// descriptors afterwards.
pub unsafe fn close_descriptors_except(keep: &[RawFd]) -> Result<()> {
    let close_range = |first: u32, last: u32| {
        // SAFETY: The caller guarantees no surviving code uses the closed descriptors.
        if first <= last && unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    };
    let mut keep: Vec<u32> = keep
        .iter()
        .filter_map(|&fd| u32::try_from(fd).ok())
        .filter(|&fd| fd > 2)
        .collect();
    keep.sort_unstable();
    let mut first = 3;
    for fd in keep {
        if fd > first {
            close_range(first, fd - 1)?;
        }
        first = fd + 1;
    }
    close_range(first, u32::MAX)
}

/// Moves `fd` to descriptor number `target`, which must be free.
///
/// This duplicates to the lowest free number at or above `target` with `F_DUPFD_CLOEXEC`, the
/// one duplication a native fork-capable runner's syscall filter permits, and fails if that is
/// not `target`.
pub fn move_descriptor(fd: OwnedFd, target: RawFd) -> Result<OwnedFd> {
    if fd.as_raw_fd() == target {
        return Ok(fd);
    }
    // SAFETY: `fd` is a live descriptor, and F_DUPFD_CLOEXEC creates a new descriptor that this
    // function then owns.
    let moved = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, target) };
    if moved < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `fcntl` returned a new descriptor that nothing else owns.
    let moved = unsafe { OwnedFd::from_raw_fd(moved) };
    if moved.as_raw_fd() != target {
        return Err(Error::other("descriptor target is in use"));
    }
    Ok(moved)
}

/// Reports whether the host lets a broker adopt native fork children of this runner.
///
/// The broker takes its end of the child's control socket pair with `pidfd_getfd`, which needs
/// that system call, a dumpable runner, and a Yama `ptrace_scope` that allows a parent to inspect
/// its child. This must run before the runner's syscall filter is installed.
pub fn native_fork_supported() -> bool {
    if std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .is_ok_and(|scope| scope.trim().parse::<u32>().is_ok_and(|scope| scope >= 2))
    {
        return false;
    }
    // SAFETY: PR_GET_DUMPABLE takes no pointers.
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } != 1 {
        return false;
    }
    // SAFETY: `pidfd_open` takes no pointers.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
    let Ok(pidfd) = RawFd::try_from(pidfd) else {
        return false;
    };
    if pidfd < 0 {
        return false;
    }
    // SAFETY: `pidfd_open` returned a new descriptor that nothing else owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    // SAFETY: Duplicating this process's own pidfd takes no pointers.
    let copy = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            pidfd.as_raw_fd(),
            pidfd.as_raw_fd(),
            0u32,
        )
    };
    match RawFd::try_from(copy) {
        Ok(copy) if copy >= 0 => {
            // SAFETY: `pidfd_getfd` returned a new descriptor that nothing else owns.
            drop(unsafe { OwnedFd::from_raw_fd(copy) });
            true
        }
        _ => false,
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

/// Result returned by [`fork_process`].
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
/// This does not run libc's fork handlers or repair its cached thread identity; child-side thread
/// interruption must use fresh kernel thread IDs rather than inherited pthread identities.
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
