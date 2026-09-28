// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{ShimPlatform, Task};

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

impl<Platform: ShimPlatform> Task<Platform> {
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
            self.queue_async_signals();
            self.process_signals(ctx);
            !self.is_exiting()
        })
    }

    /// Queues the signals raised outside this thread: platform signals, the fallback alarm's
    /// `SIGALRM`, and `SIGCHLD` for terminated children.
    fn queue_async_signals(&self) {
        self.global.platform.take_pending_signals(|signal| {
            self.queue_signals(signal);
        });
        #[cfg(feature = "alarm_fallback")]
        self.check_alarm_deadline();
        self.check_for_child_terminations();
    }
}

impl<Platform: ShimPlatform> litebox::event::wait::CheckForInterrupt for Task<Platform> {
    fn check_for_interrupt(&self) -> bool {
        self.queue_async_signals();
        self.is_exiting() || self.has_pending_signals()
    }
}
