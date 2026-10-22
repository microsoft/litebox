// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native Linux process operations.

use std::cell::Cell;
use std::convert::Infallible;
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

thread_local! {
    /// An address near the stack pointer at which this thread first entered the guest, or zero if
    /// it has not. A process clone inherits its forking thread's value.
    static GUEST_ENTRY_STACK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Records the stack depth at which this thread first entered the guest, unless it has already,
/// directly or as the thread a process clone copied.
pub(crate) fn record_first_guest_entry_depth() {
    if GUEST_ENTRY_STACK_DEPTH.get() == 0 {
        let marker = 0u8;
        GUEST_ENTRY_STACK_DEPTH.set(core::ptr::from_ref(&marker).addr());
    }
}

/// Continues the calling thread with `f` at the stack depth at which it first entered the guest,
/// abandoning every frame below that depth and reusing their memory.
///
/// A native fork clone's only thread starts on a copy of the stack it forked on, under every frame
/// of its parent's runtime; continuing there would deepen the stack with each generation of a fork
/// chain until it overflows. Rewinding to the depth the clone inherits keeps every generation at
/// the same depth. If the thread never entered the guest, `f` runs in place.
///
/// `f` is `'static` because the calling frames' memory is reused.
///
/// # Safety
///
/// The caller must be the sole thread of a newly cloned process. Nothing may use the calling
/// frames, or any frame of the thread below the depth at which it first entered the guest,
/// afterwards.
pub unsafe fn rewind_stack_and_run<F: FnOnce() -> Infallible + 'static>(f: F) -> ! {
    let base = GUEST_ENTRY_STACK_DEPTH.get();
    if base == 0 {
        match f() {}
    }
    let f = Box::into_raw(Box::new(f)).cast::<()>();
    // SAFETY: The aligned `base` lies within this thread's stack, below the data that outlives its
    // frames, and the caller guarantees that nothing uses the frames there.
    // `rewound_stack_entry::<F>` takes `f`, a `Box<F>`.
    unsafe { crate::arch::switch_stack(base & !0xf, f, rewound_stack_entry::<F>) }
}

/// Runs `f` on the stack [`rewind_stack_and_run`] rewound.
///
/// # Safety
///
/// `f` must come from `Box::<F>::into_raw`.
unsafe extern "C" fn rewound_stack_entry<F: FnOnce() -> Infallible>(f: *mut ()) -> ! {
    // SAFETY: The caller passes `f` from `Box::<F>::into_raw`.
    let f = unsafe { *Box::from_raw(f.cast::<F>()) };
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

    /// Runs `f` in a forked child, whose only thread may rewind its stack, and returns its status.
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

    /// Calls `f` from `depth` frames, each holding 1 KiB, below the caller.
    #[inline(never)]
    fn deeper(depth: usize, f: &mut dyn FnMut()) {
        let frame = core::hint::black_box([0u8; 1024]);
        if depth == 0 {
            f();
        } else {
            deeper(depth - 1, f);
        }
        core::hint::black_box(frame);
    }

    fn stack_address() -> usize {
        let marker = 0u8;
        core::hint::black_box(core::ptr::from_ref(&marker).addr())
    }

    #[test]
    fn clones_rewind_to_the_same_depth_in_every_generation() {
        const NOT_REWOUND: libc::c_int = 1;
        const DEPTH_CHANGED: libc::c_int = 2;
        let status = in_forked_child(|| {
            record_first_guest_entry_depth();
            let base = GUEST_ENTRY_STACK_DEPTH.get();
            // Each generation starts below the frames of the one before, as a fork does.
            let mut first_generation = || {
                // SAFETY: The forked child has only this thread, and nothing uses the frames.
                unsafe {
                    rewind_stack_and_run(move || {
                        if !(base - 4096..base).contains(&stack_address()) {
                            libc::_exit(NOT_REWOUND);
                        }
                        let mut second_generation = || {
                            rewind_stack_and_run(move || {
                                let rewound = (base - 4096..base).contains(&stack_address());
                                libc::_exit(if rewound { 0 } else { DEPTH_CHANGED })
                            })
                        };
                        // Like a clone bootstrapping, this generation enters the guest deeper than
                        // it started, but the next one inherits the depth it was rewound to.
                        deeper(8, &mut || {
                            record_first_guest_entry_depth();
                            deeper(64, &mut second_generation);
                        });
                        unreachable!()
                    })
                }
            };
            deeper(64, &mut first_generation);
            unreachable!()
        });
        let failure = match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
            Some(0) => return,
            Some(NOT_REWOUND) => "the first generation did not rewind to the recorded depth",
            Some(DEPTH_CHANGED) => "the second generation started at a different depth",
            _ => "the rewinding child did not exit normally",
        };
        panic!("{failure} (status {status:#x})");
    }

    #[test]
    fn rewind_without_guest_entry_runs_in_place() {
        let status = in_forked_child(|| {
            // SAFETY: The forked child has only this thread, and the continuation exits at once.
            unsafe { rewind_stack_and_run(|| libc::_exit(0)) }
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the in-place child failed (status {status:#x})"
        );
    }
}
