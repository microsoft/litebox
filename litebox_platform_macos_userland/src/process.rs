// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Native macOS process operations.
//!
//! A runner continues a native fork child created by [`ProcessProvider::fork_process`] as follows,
//! without returning or unwinding through the copied parent runtime:
//!
//! 1. [`ProcessProvider::prepare_fork_child`].
//! 2. Keep using the platform instance inherited from the parent: its page table describes the
//!    inherited guest mappings that `LinuxShimBuilder::new_for_native_fork` retains, which a
//!    fresh instance from `MacosUserlandWithPageSize::new` would not own.
//! 3. Build the new runtime and run the guest on a thread created in the child, with guest
//!    signals blocked on the forking thread. `std`'s thread parker uses a per-thread dispatch
//!    semaphore that does not survive `fork`, so the forking thread, which may have parked before
//!    the fork, traps if it parks again; it may only join that thread (`pthread_join`).
//! 4. End with `libc::_exit`, skipping the destructors and `atexit` handlers of state copied from
//!    the multithreaded parent.
//!
//! A runner may auto-reap its children (`SIGCHLD` ignored or `SA_NOCLDWAIT`): the broker observes
//! adopted clones with `kqueue`, and [`ProcessHandle::terminate`] never needs the zombie.

use std::io::{Error, Read as _, Result};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;

use litebox::platform::{
    ForkError, ForkResult as ProviderForkResult, ProcessHandle, ProcessProvider,
};
use zerocopy::{FromBytes as _, IntoBytes as _};

use crate::{MacosUserlandWithPageSize, PAGE_TABLES};

/// `audit_token_t` from `<bsm/audit.h>`: an opaque process identity that, unlike a process ID,
/// names one process even after it is reaped and its ID reused.
///
/// `litebox_broker_userland`'s macOS runner module declares the same FFI for the broker side.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct AuditToken([u32; 8]);

impl AuditToken {
    /// Index of the process ID (`audit_token_to_pid`).
    const PID: usize = 5;
}

/// `TASK_AUDIT_TOKEN` and `TASK_AUDIT_TOKEN_COUNT` from `<mach/task_info.h>`.
const TASK_AUDIT_TOKEN: libc::task_flavor_t = 15;
const TASK_AUDIT_TOKEN_COUNT: libc::mach_msg_type_number_t = 8;

unsafe extern "C" {
    /// `proc_signal_with_audittoken` from `<libproc.h>`. Returns zero or an `errno` value, which
    /// is `ESRCH` once the process has exited.
    fn proc_signal_with_audittoken(token: *mut AuditToken, signal: libc::c_int) -> libc::c_int;
}

/// A handle to a process created by [`ProcessProvider::fork_process`].
#[derive(Debug)]
pub struct ClonedProcess {
    process_id: u32,
    /// Identifies the clone even after it exits and is reaped, as a runner that auto-reaps its
    /// children does, so [`ProcessHandle::terminate`] never signals a process that reused its ID.
    token: AuditToken,
}

impl<const PAGE_SIZE: usize> ProcessProvider for MacosUserlandWithPageSize<PAGE_SIZE> {
    type ProcessHandle = ClonedProcess;
    type ProcessError = Error;

    /// Forks with libc `fork`, whose child handlers reset libSystem state such as Mach ports and
    /// malloc locks. The child starts running.
    ///
    /// Returns [`ForkError::Unsupported`] while a 4 KiB page table has a host page that mixes live
    /// shared and private guest pages, which a child could not share exactly. Otherwise, makes the
    /// child share every shared page; a 4 KiB host page stays shared even if `fork` then fails.
    ///
    /// The child reports its audit token before anything else, while it certainly holds its
    /// process ID, and exits at once if it cannot.
    unsafe fn fork_process()
    -> core::result::Result<ProviderForkResult<ClonedProcess>, ForkError<Error>> {
        // Hold every page table so that the child never inherits one locked mid-update.
        let tables = PAGE_TABLES.lock().unwrap();
        let mut guards: Vec<_> = tables.iter().map(|pages| pages.lock().unwrap()).collect();
        if guards.iter().any(|pages| pages.has_mixed_host_pages()) {
            return Err(ForkError::Unsupported);
        }
        let (mut parent_end, child_end) = UnixStream::pair().map_err(ForkError::Failed)?;
        for pages in &mut guards {
            pages.seal_shared_host_pages();
        }
        // SAFETY: the caller guarantees quiescence and a clone-safe child bootstrap.
        let process_id = unsafe { libc::fork() };
        let fork_error = Error::last_os_error();
        drop(guards);
        drop(tables);
        if process_id == 0 {
            drop(parent_end);
            let mut token = AuditToken([0; 8]);
            let mut count = TASK_AUDIT_TOKEN_COUNT;
            // SAFETY: `token` is writable storage of `count` naturals for this flavor.
            let result = unsafe {
                #[expect(deprecated, reason = "libc suggests the mach2 crate, not a dependency")]
                libc::task_info(
                    libc::mach_task_self(),
                    TASK_AUDIT_TOKEN,
                    (&raw mut token).cast(),
                    &raw mut count,
                )
            };
            let report = token.0.as_bytes();
            // A single write of a few bytes to an empty socket buffer is never partial.
            // SAFETY: `report` is readable for its length.
            if result != libc::KERN_SUCCESS
                || unsafe {
                    libc::write(child_end.as_raw_fd(), report.as_ptr().cast(), report.len())
                } != report.len().cast_signed()
            {
                // SAFETY: the child has run no guest or runner code; `_exit` skips the copied
                // runtime's teardown.
                unsafe { libc::_exit(libc::EXIT_FAILURE) };
            }
            drop(child_end);
            return Ok(ProviderForkResult::Child);
        }
        drop(child_end);
        let process_id = u32::try_from(process_id).map_err(|_| ForkError::Failed(fork_error))?;
        let mut report = [0u8; size_of::<AuditToken>()];
        let error = match parent_end.read_exact(&mut report) {
            Ok(()) => {
                let process = ClonedProcess {
                    process_id,
                    token: AuditToken(<[u32; 8]>::read_from_bytes(&report).unwrap()),
                };
                if process.token.0[AuditToken::PID] == process_id {
                    return Ok(ProviderForkResult::Parent(process));
                }
                process.terminate().err().unwrap_or_else(|| {
                    Error::other("fork child reported another process's audit token")
                })
            }
            // The child exits by itself when it cannot report.
            Err(error) => error,
        };
        // Reap the failed child unless this process auto-reaps, in which case `waitpid` would
        // wait for every other child to exit. With other threads quiescent, no other child of
        // this process can have reused its ID.
        if !auto_reaps_children() {
            // SAFETY: a null status pointer is valid.
            unsafe { libc::waitpid(process_id.cast_signed(), core::ptr::null_mut(), 0) };
        }
        Err(ForkError::Failed(error))
    }

    unsafe fn prepare_fork_child() -> Result<()> {
        // SAFETY: the caller is the sole forked thread and never returns to the copied frames.
        unsafe { crate::reset_thread_state_after_fork() };
        Ok(())
    }
}

impl ProcessHandle for ClonedProcess {
    type Error = Error;

    fn process_id(&self) -> Result<u32> {
        Ok(self.process_id)
    }

    fn resume(&self) -> Result<()> {
        // libc `fork` creates the clone running.
        Ok(())
    }

    /// Kills the clone, or succeeds if it has already exited.
    fn terminate(&self) -> Result<()> {
        let mut token = self.token;
        // SAFETY: `token` is a live audit token; the kernel rejects it once its process is gone.
        match unsafe { proc_signal_with_audittoken(&raw mut token, libc::SIGKILL) } {
            0 | libc::ESRCH => Ok(()),
            error => Err(Error::from_raw_os_error(error)),
        }
    }
}

/// Whether the kernel reaps this process's exited children without `waitpid`, because `SIGCHLD`
/// is ignored or has `SA_NOCLDWAIT`.
fn auto_reaps_children() -> bool {
    // SAFETY: `sigaction` is plain integer fields; zero is a valid representation.
    let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
    // SAFETY: a null new action only queries; `action` is writable.
    let result = unsafe { libc::sigaction(libc::SIGCHLD, core::ptr::null(), &raw mut action) };
    result == 0
        && (action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0)
}

/// Runs `child` in a native fork child created by [`ProcessProvider::fork_process`], which exits
/// with its result or 101 if it panics, and returns the child's wait status.
#[cfg(test)]
pub(crate) fn in_fork_child(child: impl FnOnce() -> i32) -> i32 {
    // SAFETY: the test thread stays in host code, and the child exits without returning to the
    // harness.
    match unsafe { crate::MacosUserland::fork_process() } {
        Ok(ProviderForkResult::Child) => {
            let status =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(child)).unwrap_or(101);
            // SAFETY: `_exit` ends the child without running the harness's handlers.
            unsafe { libc::_exit(status) }
        }
        Ok(ProviderForkResult::Parent(process)) => {
            let mut status = 0;
            // SAFETY: the clone is this process's unreaped child, and `status` is writable.
            let reaped =
                unsafe { libc::waitpid(process.process_id.cast_signed(), &raw mut status, 0) };
            assert_eq!(reaped, process.process_id.cast_signed());
            status
        }
        Err(error) => panic!("fork_process failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllocationOptions, FixedAddressBehavior, MacosUserland, MemoryRegionPermissions};
    use litebox::platform::PageManagementProvider as _;
    use litebox::platform::page_mgmt::{AllocationDirection, PageReservation as _};

    const RW: MemoryRegionPermissions =
        MemoryRegionPermissions::READ.union(MemoryRegionPermissions::WRITE);

    #[test]
    fn terminate_kills_the_clone_and_tolerates_its_reuse_free_exit() {
        // SAFETY: the test thread stays in host code; the child only pauses.
        let process = match unsafe { MacosUserland::fork_process() } {
            Ok(ProviderForkResult::Child) => loop {
                // SAFETY: `pause` takes no arguments; SIGKILL ends the child.
                unsafe { libc::pause() };
            },
            Ok(ProviderForkResult::Parent(process)) => process,
            Err(error) => panic!("fork_process failed: {error}"),
        };
        let pid = process.process_id().unwrap().cast_signed();
        process.resume().unwrap();
        process.terminate().unwrap();
        let mut status = 0;
        // SAFETY: `pid` is this process's unreaped child, and `status` is writable.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
            "status {status:#x}"
        );
        // A reaped clone's token names no process, whatever reuses its ID.
        process.terminate().unwrap();
    }

    #[test]
    fn only_shared_pages_are_shared_with_fork_children_until_replaced() {
        let platform = MacosUserland::new();
        let allocate = |options| {
            // SAFETY: a hint replaces nothing.
            unsafe {
                platform.reserve_and_commit_pages(
                    core::iter::empty,
                    crate::TASK_ADDR_MIN..crate::TASK_ADDR_MIN + crate::HOST_PAGE_SIZE,
                    RW,
                    options,
                    FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
                )
            }
            .unwrap()
            .range()
        };
        let shared = allocate(AllocationOptions::SHARED);
        let private = allocate(AllocationOptions::empty());
        let (shared_byte, private_byte) = (shared.start as *mut u8, private.start as *mut u8);
        let write_both = move || {
            // SAFETY: both pages are writable and owned by this test.
            unsafe {
                shared_byte.write_volatile(1);
                private_byte.write_volatile(1);
            }
            0
        };
        // Changing protections must not unshare the pages.
        // SAFETY: nothing accesses the shared page while it is read-only.
        unsafe {
            platform
                .protect_pages(
                    core::iter::empty,
                    shared.clone(),
                    MemoryRegionPermissions::READ,
                )
                .unwrap();
            platform
                .protect_pages(core::iter::empty, shared.clone(), RW)
                .unwrap();
        }
        assert_eq!(in_fork_child(write_both), 0);
        // SAFETY: both pages are readable and owned by this test.
        unsafe {
            assert_eq!(shared_byte.read_volatile(), 1, "shared page was copied");
            assert_eq!(private_byte.read_volatile(), 0, "private page was shared");
            shared_byte.write_volatile(0);
        }

        // SAFETY: the test owns the shared page, which has no other users.
        unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                shared.clone(),
                RW,
                AllocationOptions::empty(),
                FixedAddressBehavior::Replace,
            )
        }
        .unwrap();
        assert_eq!(in_fork_child(write_both), 0);
        // SAFETY: the page is readable and owned by this test.
        assert_eq!(
            unsafe { shared_byte.read_volatile() },
            0,
            "private replacement stayed shared"
        );
        // SAFETY: the test owns both idle pages.
        unsafe {
            platform.release_pages(shared).unwrap();
            platform.release_pages(private).unwrap();
        }
    }

    #[test]
    #[cfg(feature = "subpage_compat")]
    fn forking_with_a_mixed_host_page_is_unsupported() {
        const PAGE: usize = 4096;
        const CHILD_ENV: &str = "LITEBOX_MACOS_MIXED_HOST_PAGE_FORK_TEST";
        // Every fork checks and seals every registered page table, so the mixed host page must
        // not coexist with other tests' forks in one test process.
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process::tests::forking_with_a_mixed_host_page_is_unsupported",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{output:?}"
            );
            return;
        }

        let platform = crate::MacosUserland4K::new();
        // SAFETY: a hint replaces nothing.
        let shared = unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                crate::TASK_ADDR_MIN..crate::TASK_ADDR_MIN + PAGE,
                RW,
                AllocationOptions::SHARED,
                FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
            )
        }
        .unwrap()
        .range();
        let private = shared.end..shared.end + PAGE;
        // SAFETY: NoReplace takes only the free guest page beside the test's shared one.
        unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                private.clone(),
                RW,
                AllocationOptions::empty(),
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();
        // SAFETY: the test thread stays in host code; the check fails before forking.
        assert!(matches!(
            unsafe { crate::MacosUserland4K::fork_process() },
            Err(ForkError::Unsupported)
        ));

        // SAFETY: the test owns the idle private page.
        unsafe { platform.release_pages(private) }.unwrap();
        let byte = shared.start as *mut u8;
        let status = in_fork_child(|| {
            // SAFETY: the shared page is writable and owned by this test.
            unsafe { byte.write_volatile(1) };
            0
        });
        assert_eq!(status, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { byte.read_volatile() }, 1, "shared page was copied");
        // SAFETY: the test owns the idle shared page.
        unsafe { platform.release_pages(shared) }.unwrap();
    }
}
