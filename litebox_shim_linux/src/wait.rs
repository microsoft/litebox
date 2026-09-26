// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{ShimFS, ShimPlatform, Task};

pub(crate) struct WaitState<Platform: ShimPlatform>(litebox::event::wait::WaitState<Platform>);

impl<Platform: ShimPlatform> WaitState<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }

    /// Returns the thread handle used to interrupt waits.
    pub(crate) fn thread_handle(&self) -> litebox::event::wait::ThreadHandle<Platform> {
        self.0.thread_handle()
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Returns a wait context to use to perform interruptible waits.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.0.context().with_check_for_interrupt(self)
    }

    /// Marks that the task has just returned from running guest code.
    pub(crate) fn enter_from_guest(&self) {
        self.wait_state.0.finish_running_guest();
    }

    /// Prepares to return to run guest code. Returns `false` if the task should
    /// exit instead.
    #[must_use]
    pub(crate) fn prepare_to_run_guest(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
        // The safe `ptrace` stop rendezvous: this is the one point every guest thread reaches,
        // after every syscall/exception/interrupt return and strictly before guest re-entry,
        // with its vCPU lane already released and `ctx` holding its complete, authoritative
        // logical register state -- see `syscalls::ptrace`'s module documentation. A no-op
        // (single atomic load) when untraced or not currently stop-requested; ahead of the fork
        // gate below so a tracer observing a stop never has to reason about a concurrent `fork`
        // interleaving with it.
        #[cfg(target_arch = "aarch64")]
        self.ptrace_rendezvous(ctx);
        // A sibling `fork` in flight must not see this thread touch guest
        // memory (see `Process::fork_gate`); park here, before re-entering
        // guest code, until the forker's turn completes. No-op single load
        // when no fork is in flight.
        self.park_while_fork_gate_closed();
        // A member of a shared address space whose turn another member is waiting for hands
        // it over here, before touching guest memory again (see `Task::quiesce_and_hand_off`).
        self.yield_address_space_to_waiters();
        self.wait_state.0.prepare_to_run_guest(|| {
            self.global.platform.take_pending_signals(|signal| {
                self.queue_signals(signal);
            });
            #[cfg(feature = "alarm_fallback")]
            self.check_alarm_deadline();
            self.process_signals(ctx);
            // After delivery, so that an `rt_sigsuspend` handler frame captured the temporary
            // mask rather than the one being put back here.
            self.restore_saved_signal_mask();
            !self.is_exiting()
        })
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::event::wait::CheckForInterrupt
    for Task<Platform, FS>
{
    fn check_for_interrupt(&self) -> bool {
        // See `Process::fork_gate`: a woken waiter passes through here before
        // re-blocking, which is what lets a forking sibling park a thread that
        // was asleep in a futex/epoll/read wait. Parking blocks on a raw
        // (non-interruptible) word, satisfying this hook's no-interruptible-
        // wait contract.
        self.park_while_fork_gate_closed();
        self.yield_address_space_to_waiters();
        self.global.platform.take_pending_signals(|sig| {
            self.queue_signals(sig);
        });
        #[cfg(feature = "alarm_fallback")]
        self.check_alarm_deadline();
        self.is_exiting() || self.has_pending_signals()
    }

    /// Hands a shared guest address space to whichever other guest process wants it, for as long
    /// as this task is asleep.
    ///
    /// This is the hook that lets a `fork`ed child and its parent make progress in turn instead
    /// of the parent being suspended for the child's whole lifetime; see
    /// `syscalls::process::SharedAddressSpace`. It is a no-op -- a single predictable branch --
    /// for the overwhelmingly common case of a task that has never `fork`ed.
    fn yield_while_blocking(&self) {
        self.release_address_space();
    }

    fn resume_after_blocking(&self) {
        self.acquire_address_space();
    }
}
