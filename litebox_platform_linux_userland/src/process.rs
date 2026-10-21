// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native Linux process operations.

use std::convert::Infallible;
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// Usable size of a [`CloneStack`], matching Linux's default main-thread `RLIMIT_STACK`.
const CLONE_STACK_SIZE: usize = 8 << 20;
/// Size of the inaccessible guard below a [`CloneStack`], a multiple of every x86_64 and aarch64
/// page size.
const CLONE_STACK_GUARD_SIZE: usize = 64 << 10;
const CLONE_STACK_MAPPING_SIZE: usize = CLONE_STACK_GUARD_SIZE + CLONE_STACK_SIZE;

/// Mapping base of the [`CloneStack`] this process started on, or zero if it is not a native fork
/// clone.
static CURRENT_CLONE_STACK: AtomicUsize = AtomicUsize::new(0);

/// A fresh stack for a native fork clone to continue on.
///
/// The clone's only thread starts on a copy of the stack it forked on, under every frame of its
/// parent's runtime; continuing there would deepen the stack with each generation of a fork chain
/// until it overflows. Map it before cloning, so a failure is reported before any clone exists.
///
/// A clone still inherits the stack mappings of its parent's other threads. If it forked on one of
/// them rather than on the thread its parent started on, it also keeps that thread's stack, which
/// holds the TLS the clone still uses.
pub struct CloneStack(crate::GuardedStack);

impl CloneStack {
    /// Maps an 8 MiB stack, reserving no memory until it is touched, above a 64 KiB inaccessible
    /// guard.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the mapping or its guard cannot be set up.
    pub fn map() -> Result<Self> {
        crate::GuardedStack::map(
            CLONE_STACK_GUARD_SIZE,
            CLONE_STACK_SIZE,
            libc::MAP_NORESERVE | libc::MAP_STACK,
        )
        .map(Self)
    }

    /// Continues the calling thread with `f` on this stack after unmapping the clone stack the
    /// parent process continued on, if any, abandoning the calling frames.
    ///
    /// `f` is `'static` because the calling frames may be on the unmapped stack.
    ///
    /// # Safety
    ///
    /// The caller must be the sole thread of a newly cloned process. Nothing may use the calling
    /// frames afterwards, or anything on the stack the parent process continued on as a clone.
    pub unsafe fn run_freeing_parent_stack<F: FnOnce() -> Infallible + 'static>(self, f: F) -> ! {
        // This process runs on the mapping from now on; the next generation of a fork chain unmaps
        // it.
        let stack = core::mem::ManuallyDrop::new(self.0);
        let f = Box::into_raw(Box::new(f)).cast::<()>();
        // SAFETY: `stack.top()` is the 16-byte-aligned end of a fresh stack that nothing uses, and
        // `clone_stack_entry::<F>` takes the mapping base and `f`, a `Box<F>`. The caller
        // guarantees the rest of `clone_stack_entry`'s requirements.
        unsafe {
            crate::arch::switch_stack(stack.top(), stack.mapping_base(), f, clone_stack_entry::<F>)
        }
    }
}

/// Records that this process runs on the [`CloneStack`] mapped at `base`, unmaps the one its
/// parent continued on, if any, and runs `f`.
///
/// # Safety
///
/// `f` must come from `Box::<F>::into_raw`, the calling thread must have left the stack its parent
/// continued on, and the caller must meet [`CloneStack::run_freeing_parent_stack`]'s requirements.
unsafe extern "C" fn clone_stack_entry<F: FnOnce() -> Infallible>(base: usize, f: *mut ()) -> ! {
    // SAFETY: The caller passes `f` from `Box::<F>::into_raw`.
    let f = unsafe { *Box::from_raw(f.cast::<F>()) };
    let parent_stack_base = CURRENT_CLONE_STACK.swap(base, Ordering::Relaxed);
    if parent_stack_base != 0 {
        // SAFETY: The caller guarantees that nothing uses the stack the parent continued on. Its
        // thread is either absent from this clone or this thread, which has left it.
        unsafe {
            libc::munmap(
                parent_stack_base as *mut libc::c_void,
                CLONE_STACK_MAPPING_SIZE,
            )
        };
    }
    match f() {}
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

#[cfg(test)]
mod tests {
    use super::*;

    fn is_mapped(address: usize) -> bool {
        let page = address & !(CLONE_STACK_GUARD_SIZE - 1);
        // SAFETY: `msync` only queries the range, which it rejects with ENOMEM if unmapped.
        unsafe { libc::msync(page as *mut libc::c_void, 1, libc::MS_ASYNC) == 0 }
    }

    /// Runs `f` in a forked child, whose only thread may switch stacks, and returns its status.
    fn in_forked_child(f: fn() -> libc::c_int) -> libc::c_int {
        // SAFETY: `libc::fork` runs glibc's fork handlers, so the single-threaded child may
        // allocate, and it `_exit`s without returning to the harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "{}", Error::last_os_error());
        if pid == 0 {
            // SAFETY: `_exit` ends the child without running the harness's handlers.
            unsafe { libc::_exit(f()) };
        }
        let mut status = 0;
        // SAFETY: `pid` is this process's unreaped child, and `status` is writable.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        status
    }

    #[test]
    fn clones_continue_on_a_fresh_stack_and_free_their_parents() {
        const MAP_FAILED: libc::c_int = 1;
        const NOT_ON_NEW_STACK: libc::c_int = 2;
        const PARENT_STACK_MAPPED: libc::c_int = 3;
        let status = in_forked_child(|| {
            let Ok(first) = CloneStack::map() else {
                return MAP_FAILED;
            };
            let first_base = first.0.mapping_base();
            // SAFETY: The forked child has only this thread, and nothing uses the calling frames.
            unsafe {
                first.run_freeing_parent_stack(move || {
                    let local = 0u8;
                    if !(first_base..first_base + CLONE_STACK_MAPPING_SIZE)
                        .contains(&core::ptr::from_ref(&local).addr())
                    {
                        libc::_exit(NOT_ON_NEW_STACK);
                    }
                    // The next generation of a fork chain starts on this stack.
                    let Ok(second) = CloneStack::map() else {
                        libc::_exit(MAP_FAILED);
                    };
                    second.run_freeing_parent_stack(move || {
                        let freed = !is_mapped(first_base + CLONE_STACK_GUARD_SIZE);
                        libc::_exit(if freed { 0 } else { PARENT_STACK_MAPPED });
                    })
                })
            }
        });
        let failure = match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
            Some(0) => return,
            Some(MAP_FAILED) => "a clone stack could not be mapped",
            Some(NOT_ON_NEW_STACK) => "the first clone did not run on its new stack",
            Some(PARENT_STACK_MAPPED) => "the second clone did not unmap its parent's stack",
            _ => "the clone stack child did not exit normally",
        };
        panic!("{failure} (status {status:#x})");
    }
}
