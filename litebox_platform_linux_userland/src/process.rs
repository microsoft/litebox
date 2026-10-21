// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native Linux process operations.

use std::convert::Infallible;
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;
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
/// Size of the inaccessible guard below a [`CloneStack`], a multiple of every Linux page size.
const CLONE_STACK_GUARD_SIZE: usize = 64 << 10;
const CLONE_STACK_MAPPING_SIZE: usize = CLONE_STACK_GUARD_SIZE + CLONE_STACK_SIZE;

/// Base address of the [`CloneStack`] this process runs on, or zero if it is not a native fork
/// clone.
static CURRENT_CLONE_STACK: AtomicUsize = AtomicUsize::new(0);

/// A fresh stack for a native fork clone to continue on.
///
/// The clone's only thread starts on a copy of the stack it forked on, under every frame of its
/// parent's runtime. Continuing there would deepen the stack with each generation of a fork chain
/// until it overflows. Each clone instead switches to a new stack and unmaps the one its parent ran
/// on, if that was a clone stack too, so the stack a generation leaves behind is never inherited.
///
/// The parent maps the stack before cloning, so a failure is reported before any clone exists. The
/// clone inherits the untouched mapping and [runs](Self::run) on it; the parent drops its copy.
pub struct CloneStack {
    base: NonNull<libc::c_void>,
}

impl CloneStack {
    /// Maps a new stack.
    pub fn map() -> Result<Self> {
        // SAFETY: An anonymous private mapping at a kernel-chosen address affects no existing
        // memory.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                CLONE_STACK_MAPPING_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_STACK,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }
        let Some(base) = NonNull::new(base) else {
            return Err(Error::other("mmap returned a null stack"));
        };
        let stack = Self { base };
        // SAFETY: The guard lies within the mapping this function just created.
        if unsafe { libc::mprotect(base.as_ptr(), CLONE_STACK_GUARD_SIZE, libc::PROT_NONE) } < 0 {
            return Err(Error::last_os_error());
        }
        Ok(stack)
    }

    /// Continues the calling thread with `f` on this stack, abandoning the calling frames.
    ///
    /// Before running `f`, this unmaps the clone stack the parent ran on, if any.
    ///
    /// # Safety
    ///
    /// The caller must be the sole thread of a newly cloned process. Nothing may use the calling
    /// frames afterwards, or anything on the stack the parent process continued on as a clone.
    pub unsafe fn run(self, f: Box<dyn FnOnce() -> Infallible>) -> ! {
        let base = self.base.as_ptr() as usize;
        core::mem::forget(self);
        let top = base + CLONE_STACK_MAPPING_SIZE;
        // A thin pointer, for the assembly.
        let f = Box::into_raw(Box::new(f));
        // SAFETY: `top` is the 16-byte-aligned end of a fresh stack that nothing uses, and
        // `on_clone_stack` takes ownership of `f`.
        unsafe { switch_stack(top, base, f) }
    }
}

impl Drop for CloneStack {
    fn drop(&mut self) {
        // SAFETY: This value exclusively owns the mapping, which nothing runs on.
        unsafe { libc::munmap(self.base.as_ptr(), CLONE_STACK_MAPPING_SIZE) };
    }
}

/// Moves the stack pointer to `top`, then calls [`on_clone_stack`] with `base` and `f`.
#[unsafe(naked)]
unsafe extern "C" fn switch_stack(
    top: usize,
    base: usize,
    f: *mut Box<dyn FnOnce() -> Infallible>,
) -> ! {
    #[cfg(target_arch = "x86_64")]
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor ebp, ebp",
        "mov rdi, rsi",
        "mov rsi, rdx",
        "call {entry}",
        "ud2",
        entry = sym on_clone_stack,
    );
    #[cfg(target_arch = "aarch64")]
    core::arch::naked_asm!(
        "mov sp, x0",
        "mov x29, xzr",
        "mov x30, xzr",
        "mov x0, x1",
        "mov x1, x2",
        "bl {entry}",
        "brk #1",
        entry = sym on_clone_stack,
    );
}

extern "C" fn on_clone_stack(base: usize, f: *mut Box<dyn FnOnce() -> Infallible>) -> ! {
    // SAFETY: From `Box::into_raw` in `CloneStack::run`.
    let f = unsafe { Box::from_raw(f) };
    let parent = CURRENT_CLONE_STACK.swap(base, Ordering::Relaxed);
    if parent != 0 {
        // SAFETY: `CloneStack::run`'s caller guarantees that nothing uses the stack the parent
        // continued on: the clone's only thread just left the frames it holds.
        unsafe { libc::munmap(parent as *mut libc::c_void, CLONE_STACK_MAPPING_SIZE) };
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
    fn in_forked_child(f: fn() -> bool) -> libc::c_int {
        // SAFETY: The child only makes system calls and `_exit`s, never returning to the harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "{}", Error::last_os_error());
        if pid == 0 {
            // SAFETY: `_exit` ends the child without running the harness's handlers.
            unsafe { libc::_exit(i32::from(!f())) };
        }
        let mut status = 0;
        // SAFETY: `pid` is this process's unreaped child, and `status` is writable.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        status
    }

    #[test]
    fn clones_continue_on_a_fresh_stack_and_free_their_parents() {
        let status = in_forked_child(|| {
            let Ok(first) = CloneStack::map() else {
                return false;
            };
            let first_base = first.base.as_ptr() as usize;
            // SAFETY: The forked child has only this thread, and nothing uses the calling frames.
            unsafe {
                first.run(Box::new(move || {
                    let local = 0u8;
                    let on_first = (first_base..first_base + CLONE_STACK_MAPPING_SIZE)
                        .contains(&core::ptr::from_ref(&local).addr());
                    // The next generation of a fork chain starts on this stack.
                    let Ok(second) = CloneStack::map() else {
                        libc::_exit(2);
                    };
                    second.run(Box::new(move || {
                        let freed = !is_mapped(first_base + CLONE_STACK_GUARD_SIZE);
                        libc::_exit(if on_first && freed { 0 } else { 3 });
                    }))
                }))
            }
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "clone stack child failed with status {status:#x}"
        );
    }
}
