// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process clones (see `litebox_common_vm_abi`, `CloneKind::Process`), for
//! the shim's native `fork` ([`ProcessProvider`]).
//!
//! A clone is a copy of the whole process, the runner's state included, with
//! only the calling thread. [`VmUserland::fork_process`] holds the runner's
//! global locks across the clone (the thread records', the platform timers',
//! and the heap's), as `fork` handlers would, so that the clone copies none
//! that another thread, which may be preempted anywhere, holds mid-update.
//! The clone forgets what is the parent's alone: the other threads, the
//! platform timers, and the notification receiver (its broker association is
//! its own). Its one thread is its main thread, but still on the stack the
//! clone was made on (e.g., another thread's, with no guard page), which its
//! runner must leave ([`crate::thread::run_on_main_stack`]) before it spawns
//! threads.

use crate::{VmUserland, kcall, thread, timer};
use core::sync::atomic::Ordering;
use litebox::platform::{ForkError, ForkResult, ProcessHandle, ProcessProvider};
use litebox_common_vm_abi::Status;

/// A process clone, which runs only once the kernel adopts it as the runner of
/// a child its parent starts.
pub struct ClonedProcess(u64);

impl ClonedProcess {
    /// Its ID, which `litebox_common_vm_abi::encode_clone_descriptor`
    /// describes to the broker.
    pub fn id(&self) -> u64 {
        self.0
    }
}

impl ProcessHandle for ClonedProcess {
    type Error = Status;

    /// Its ID, as it has no host process.
    fn process_id(&self) -> Result<u32, Status> {
        u32::try_from(self.0).map_err(|_| Status::InvalidArgument)
    }

    /// Nothing: the kernel runs the clone once adopted.
    fn resume(&self) -> Result<(), Status> {
        Ok(())
    }

    /// Nothing: it never runs unless adopted, and the kernel ends it once the
    /// process makes another clone or exits.
    fn terminate(&self) -> Result<(), Status> {
        Ok(())
    }
}

impl ProcessProvider for VmUserland {
    type ProcessHandle = ClonedProcess;
    type ProcessError = Status;

    /// See the [module](self) docs.
    unsafe fn fork_process() -> Result<ForkResult<ClonedProcess>, ForkError<Status>> {
        // In the order other paths take them: the heap's under either of the
        // others, which are never taken together. The timers' and the heap's
        // are spin locks, but the kernel resumes the caller first (see
        // `litebox_shim_vm_kernel`'s `sched`): another thread spins on them
        // only if the caller is preempted before releasing them, and only
        // until it has used more CPU than the caller: no deadlock.
        let threads = thread::lock_threads();
        let timers = timer::lock_timers();
        #[cfg(target_os = "none")]
        let cloned = crate::start::with_heap_locked(kcall::clone_process);
        // Host builds (e.g., tests) have `std`'s heap.
        #[cfg(not(target_os = "none"))]
        let cloned = kcall::clone_process();
        match cloned {
            Ok(Some(clone)) => Ok(ForkResult::Parent(ClonedProcess(clone))),
            Ok(None) => {
                threads.forget();
                timers.forget();
                crate::TIMED_WAIT
                    .receiver
                    .store(core::ptr::null_mut(), Ordering::Release);
                Ok(ForkResult::Child)
            }
            Err(status) => Err(ForkError::Failed(status)),
        }
    }

    /// Nothing: [`Self::fork_process`] prepares the child, but for its stack,
    /// which its runner leaves itself (see the [module](self) docs).
    unsafe fn prepare_fork_child() -> Result<(), Status> {
        Ok(())
    }
}
