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
    pub(crate) fn prepare_to_run_guest(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
        self.wait_state.0.prepare_to_run_guest(|| {
            use litebox::platform::SignalProvider as _;
            self.global.platform.take_pending_signals(|signal| {
                self.take_pending_signals(signal);
            });
            // Poll the alarm deadline when the platform does not support
            // `TimerProvider` (i.e., no proactive timer interrupt).
            if !<Platform as litebox::platform::TimerProvider>::SUPPORTS_TIMER {
                self.check_alarm_deadline();
            }
            self.process_signals(ctx);
            !self.is_exiting()
        })
    }
}

impl<FS: ShimFS> litebox::event::wait::CheckForInterrupt for Task<FS> {
    fn check_for_interrupt(&self) -> bool {
        use litebox::platform::SignalProvider as _;
        self.global.platform.take_pending_signals(|sig| {
            self.take_pending_signals(sig);
        });
        // Poll the alarm deadline when the platform does not support
        // `TimerProvider` (i.e., no proactive timer interrupt).
        if !<Platform as litebox::platform::TimerProvider>::SUPPORTS_TIMER {
            self.check_alarm_deadline();
        }
        self.is_exiting() || self.has_pending_signals()
    }
}
