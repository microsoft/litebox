// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{Platform, ShimFS, Task};

pub(crate) struct WaitState(litebox::event::wait::WaitState<Platform>);

impl WaitState {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }

    /// Returns the thread handle used to interrupt waits.
    pub(crate) fn thread_handle(&self) -> litebox::event::wait::ThreadHandle<Platform> {
        self.0.thread_handle()
    }
}

impl<FS: ShimFS> Task<FS> {
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
    pub(crate) fn prepare_to_run_guest(
        &self,
        ctx: &mut litebox_common_linux::ExecutionContext,
    ) -> bool {
        // If another thread is forking, park this thread until the fork
        // completes. This prevents us from accessing memory pages that are
        // being CoW-protected.
        self.park_for_vfork_if_requested();

        self.wait_state.0.prepare_to_run_guest(|| {
            use litebox::platform::SignalProvider as _;
            self.global.platform.take_pending_signals(|signal| {
                self.queue_signals(signal);
            });
            let _ = self.drain_one_local_control_plane_message();
            self.check_alarm_deadline();
            self.process_signals(ctx);
            #[cfg(all(feature = "trace_syscalls", target_arch = "x86_64"))]
            litebox::log_println!(
                self.global.platform,
                "[TRACE] prepare resume: pid={} tid={} rip={:#x} rcx={:#x} r11={:#x} rsp={:#x} rax={:#x}",
                self.pid,
                self.tid,
                ctx.rip,
                ctx.rcx,
                ctx.r11,
                ctx.rsp,
                ctx.rax,
            );
            #[cfg(all(feature = "trace_syscalls", target_arch = "x86"))]
            litebox::log_println!(
                self.global.platform,
                "[TRACE] prepare resume: pid={} tid={} eip={:#x} ecx={:#x} esp={:#x} eax={:#x}",
                self.pid,
                self.tid,
                ctx.eip,
                ctx.ecx,
                ctx.esp,
                ctx.eax,
            );
            !self.is_exiting() && !self.local_task_terminated.get()
        })
    }

    /// Checks whether this thread should park for a vfork and, if so,
    /// blocks until the forking thread clears the park flag.
    ///
    /// Two conditions can cause parking:
    /// - Per-thread `is_suspended` flag (set by `park_other_threads` for
    ///   threads that existed at park time).
    /// - Process-wide `vfork_park` futex (catches threads created after
    ///   parking started that were not flagged individually).
    ///
    /// The vfork **child** shares the parent's `ProcessState` (and thus
    /// sees `vfork_park=1`), but must NOT park — it is the only thread
    /// allowed to run during the vfork window. Identified by having a
    /// `fork_context`.
    pub(crate) fn park_for_vfork_if_requested(&self) {
        use core::sync::atomic::Ordering;
        use litebox::platform::RawMutex as _;

        // The vfork child must keep running — it will signal vfork_done
        // on exec/exit to unblock the parent.
        if self.fork_context.borrow().is_some() {
            return;
        }

        // If we have a deferred park claim from the transport spin loop,
        // settle it here: block until vfork is done, then decrement
        // parked_count (the lie already incremented it).
        if self.deferred_vfork_park.get() {
            let ps = self.process_state.borrow();
            loop {
                let v = ps
                    .vfork_parking
                    .park
                    .underlying_atomic()
                    .load(Ordering::Acquire);
                if v == 0 || self.is_exiting() {
                    break;
                }
                let _ = ps.vfork_parking.park.block(v);
            }
            ps.vfork_parking
                .parked_count
                .underlying_atomic()
                .fetch_sub(1, Ordering::Release);
            ps.vfork_parking.parked_count.wake_all();
            self.deferred_vfork_park.set(false);
            return;
        }

        let ps = self.process_state.borrow();

        // Fast path: either suspension signal must force a park. Most threads
        // observe `park=1`, but `park_other_threads` sets per-thread
        // `is_suspended` before publishing `park`, so a sibling interrupted in
        // that narrow window can reach this checkpoint with `is_suspended=true`
        // and `park=0`.
        if ps
            .vfork_parking
            .park
            .underlying_atomic()
            .load(Ordering::Acquire)
            == 0
            && !self.is_suspended()
        {
            return;
        }

        // Close the setup window described above. Do not count ourselves as
        // parked until the process-wide futex is published; otherwise we could
        // increment and immediately decrement while `park` is still 0, letting
        // the forker miss our park entirely.
        while ps
            .vfork_parking
            .park
            .underlying_atomic()
            .load(Ordering::Acquire)
            == 0
        {
            if !self.is_suspended() || self.is_exiting() {
                return;
            }
            core::hint::spin_loop();
        }

        // Before doing a normal park (which increments parked_count), try
        // to claim an outstanding deferred lie. If a lie exists, parked_count
        // was already incremented by try_deferred_park — we must NOT increment
        // again, or the forking thread would see an inflated count and proceed
        // before all threads are truly parked.
        let claimed_lie = loop {
            let current = ps.vfork_parking.deferred_lie_count.load(Ordering::Acquire);
            if current == 0 {
                break false;
            }
            if ps
                .vfork_parking
                .deferred_lie_count
                .compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break true;
            }
        };

        if !claimed_lie {
            // Normal park: announce that we are parked.
            ps.vfork_parking
                .parked_count
                .underlying_atomic()
                .fetch_add(1, Ordering::Release);
            ps.vfork_parking.parked_count.wake_all();
        }

        // Block until the forking thread clears the park flag or the
        // process begins exiting (exit_group wakes vfork_park).
        loop {
            let v = ps
                .vfork_parking
                .park
                .underlying_atomic()
                .load(Ordering::Acquire);
            if v == 0 || self.is_exiting() {
                break;
            }
            let _ = ps.vfork_parking.park.block(v);
        }

        // Announce that we have unparked (whether we did a normal park or
        // claimed a lie, we decrement parked_count).
        ps.vfork_parking
            .parked_count
            .underlying_atomic()
            .fetch_sub(1, Ordering::Release);
        ps.vfork_parking.parked_count.wake_all();
    }
}

impl<FS: ShimFS> litebox::event::wait::CheckForInterrupt for Task<FS> {
    fn check_for_interrupt(&self) -> bool {
        use litebox::platform::SignalProvider as _;
        self.global.platform.take_pending_signals(|sig| {
            self.queue_signals(sig);
        });
        self.check_alarm_deadline();

        let local_mailbox_needs_another_pass = self.drain_one_local_control_plane_message();
        if local_mailbox_needs_another_pass {
            self.wait_state.thread_handle().interrupt();
        }

        // Drain cross-process signals (e.g. SIGCHLD) into the process's
        // shared pending queue so that `has_pending_signals()` sees them.
        // Without this, a child exit wakes the condvar via `interrupt()` but
        // the thread goes back to sleep because the signal is only in the
        // global queue — causing multi-second stalls in epoll_pwait/futex
        // waits.
        self.drain_cross_process_signals();

        self.is_exiting() || self.has_pending_signals() || self.is_suspended()
    }
}
