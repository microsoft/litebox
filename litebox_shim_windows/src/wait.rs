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
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Returns a wait context to use to perform interruptible waits.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.0.context().with_check_for_interrupt(self)
    }

    /// Publishes the handle used by other threads to interrupt this one.
    ///
    /// Must be called from the task's own thread.
    pub(crate) fn publish_thread_handle(&self) {
        self.thread_object
            .publish_wait_handle(self.wait_state.0.thread_handle());
    }

    /// Marks that the task has just returned from running guest code.
    pub(crate) fn enter_from_guest(&self) {
        self.wait_state.0.finish_running_guest();
    }

    /// Prepares to return to run guest code. Returns `false` if the task should
    /// exit instead.
    #[must_use]
    pub(crate) fn prepare_to_run_guest(&self, _ctx: &mut litebox_common_linux::PtRegs) -> bool {
        self.wait_state.0.prepare_to_run_guest(|| {
            // TODO(windows-apc): deliver pending user-mode APCs and alerts here.
            !self.thread_object.is_exiting()
        })
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::event::wait::CheckForInterrupt
    for Task<Platform, FS>
{
    fn check_for_interrupt(&self) -> bool {
        self.thread_object.is_exiting()
    }
}
