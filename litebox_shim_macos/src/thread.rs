// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest thread lifecycle: creation, registration with the process, the
//! exit model, and termination.
//!
//! Like XNU, the first `exit` (or fatal signal) records the process status
//! and interrupts every other thread; each ends at its next shim entry, and
//! blocked waits end. A thread's `Task` is its kernel thread: dropping it
//! kills the thread's control port and removes the thread from the process.
//! When the last thread goes without an exit, the process exits with status 0
//! (`thread_terminate_self` -> `proc_exit`).

use crate::{
    GlobalState, GuestThread, MacosShimEntrypoints, Process, ShimPlatform, Task, ThreadId,
    ThreadState, syscalls::file::FilesState,
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use litebox::sync::Mutex;
use litebox_common_linux::PtRegs;
use litebox_common_macos::TaskParams;
use litebox_platform::sync::RawMutex as _;

/// `task_threadmax`: XNU refuses a task more threads (`thread_create`'s
/// `KERN_FAILURE`, `ENOMEM` from `bsdthread_create`). The value is the host's
/// `kern.num_taskthreads`, which XNU scales from memory at boot.
pub(crate) const TASK_THREADMAX: u32 = 4096;

impl<P: ShimPlatform> Task<P> {
    /// The process's first thread.
    pub(crate) fn new_main(
        global: Arc<GlobalState<P>>,
        files: Arc<FilesState<P>>,
        params: TaskParams,
        process: Process<P>,
    ) -> Self {
        Self::new_thread(global, files, params, process, true, 0)
            .expect("the first thread is below task_threadmax")
    }

    /// A new thread of `self`'s process, inheriting the creator's signal
    /// mask (`uthread_alloc`). It starts with the TSD base `tsd_base`.
    /// `None` when the process has `TASK_THREADMAX` threads.
    pub(crate) fn try_new_sibling(&self, tsd_base: usize) -> Option<Self> {
        let task = Self::new_thread(
            Arc::clone(&self.global),
            Arc::clone(&self.files),
            self.params,
            self.process.clone(),
            false,
            self.thread.guest.signal_mask.load(Ordering::Relaxed),
        )?;
        task.thread.start.set(Some(tsd_base));
        task.thread
            .guest
            .tsd_base
            .store(tsd_base, Ordering::Relaxed);
        Some(task)
    }

    /// [`Self::try_new_sibling`] below the thread limit.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn new_sibling(&self, tsd_base: usize) -> Self {
        self.try_new_sibling(tsd_base)
            .expect("below task_threadmax")
    }

    fn new_thread(
        global: Arc<GlobalState<P>>,
        files: Arc<FilesState<P>>,
        params: TaskParams,
        process: Process<P>,
        is_main: bool,
        signal_mask: u32,
    ) -> Option<Self> {
        // Admission: the live count is checked and taken under the registry
        // lock before anything is allocated; the Task's Drop returns it.
        {
            let _threads = process.0.threads.lock();
            let live = process.0.live_threads.underlying_atomic();
            let count = live.load(Ordering::Relaxed);
            if count >= TASK_THREADMAX {
                return None;
            }
            live.store(count + 1, Ordering::Release);
        }
        let id = global.next_thread_id.fetch_add(1, Ordering::Relaxed);
        let port = global.ipc.lock().new_thread_port(id);
        let guest = Arc::new(GuestThread {
            id,
            port,
            is_main,
            signal_mask: AtomicU32::new(signal_mask),
            no_signals: AtomicBool::new(false),
            cancel_disabled: AtomicBool::new(false),
            policy: Mutex::new(crate::syscalls::thread::ThreadPolicy::DEFAULT),
            tsd_base: AtomicUsize::new(0),
            interrupt: Mutex::new(None),
        });
        process.0.threads.lock().insert(id, Arc::clone(&guest));
        let thread = ThreadState {
            guest,
            wait_state: litebox::event::wait::WaitState::new(global.platform),
            start: core::cell::Cell::new(None),
            terminated: core::cell::Cell::new(false),
            user_join: core::cell::Cell::new(None),
            error_bits: core::cell::Cell::new(0),
            #[cfg(test)]
            platform_yields: core::cell::Cell::new(0),
        };
        Some(Self {
            global,
            files,
            params,
            process,
            thread,
        })
    }

    /// The guest thread `id` of this process, if it has not terminated.
    pub(crate) fn guest_thread(&self, id: ThreadId) -> Option<Arc<GuestThread<P>>> {
        self.process.0.threads.lock().get(&id).cloned()
    }

    /// Visit every live guest thread of this process.
    pub(crate) fn for_each_thread(&self, mut f: impl FnMut(&GuestThread<P>)) {
        for thread in self.process.0.threads.lock().values() {
            f(thread);
        }
    }

    /// End the process with `status` (`exit1`): the first exit wins, and
    /// every other thread is interrupted so it ends at its next shim entry.
    pub(crate) fn exit_process(&self, status: i32) {
        if !self.process.record_exit(status) {
            return;
        }
        let others: alloc::vec::Vec<_> = self
            .process
            .0
            .threads
            .lock()
            .values()
            .filter(|thread| thread.id != self.thread.guest.id)
            .cloned()
            .collect();
        for thread in others {
            if let Some(handle) = &*thread.interrupt.lock() {
                handle.interrupt();
            }
        }
    }

    /// The thread's first shim entry: make it interruptible and install the
    /// state `bsdthread_create` gave it.
    pub(crate) fn start_thread(&self) {
        *self.thread.guest.interrupt.lock() = Some(self.thread.wait_state.thread_handle());
        if let Some(tsd_base) = self.thread.start.take() {
            use litebox::platform::ArchSpecificRegister;
            let platform = self.global.platform;
            // thread_create gives a thread zeroed floating-point state.
            litebox::platform::GuestVectorStateProvider::set_guest_vector_state(
                platform,
                &litebox_common_linux::GuestVectorState::default(),
            );
            if platform
                .set_arch_specific_register(&ArchSpecificRegister::TpidrroEl0, tsd_base)
                .is_err()
            {
                litebox_util_log::error!("cannot set a new guest thread's TSD base");
                self.exit_process(128 + litebox_common_macos::SIGSEGV);
            }
        }
    }
}

impl<P: ShimPlatform> Drop for Task<P> {
    fn drop(&mut self) {
        let guest = &self.thread.guest;
        // thread_terminate_self, then thread_deallocate_complete: the thread
        // leaves the task; a user join is published and its joiners woken
        // while the port still names the thread (pthread_shims.c
        // bsdthread_terminate), then the saved port name is released
        // (uthread_joiner_wake) and the port dies.
        self.process.0.threads.lock().remove(&guest.id);
        if let Some((address, port)) = self.thread.user_join.take() {
            self.wake_user_joiner(address, port);
            let _ = self.global.ipc.lock().deallocate(port);
        }
        self.global.ipc.lock().thread_port_died(guest.port);
        let last = {
            let _threads = self.process.0.threads.lock();
            let live = self.process.0.live_threads.underlying_atomic();
            let count = live.load(Ordering::Relaxed) - 1;
            if count == 0 {
                // The last thread ended without exit: proc_exit with status 0.
                self.process.record_exit(0);
            }
            live.store(count, Ordering::Release);
            count == 0
        };
        if last {
            self.process.0.live_threads.wake_all();
        }
    }
}

/// A thread created by `bsdthread_create`, handed to the platform to run.
pub(crate) struct NewThread<P: ShimPlatform>(pub(crate) Task<P>);

impl<P: ShimPlatform> litebox::shim::InitThread for NewThread<P> {
    type ExecutionContext = PtRegs;

    fn init(self: Box<Self>) -> Box<dyn litebox::shim::EnterShim<ExecutionContext = PtRegs>> {
        Box::new(MacosShimEntrypoints {
            task: self.0,
            _not_send: core::marker::PhantomData,
        })
    }
}
