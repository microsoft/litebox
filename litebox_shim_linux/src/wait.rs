// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::syscalls::signal::SyscallRestart;
use crate::{ShimPlatform, Task};
use litebox_common_linux::errno::Errno;

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

    /// Prepares to return to run guest code, restarting the interrupted syscall `ctx` returns from
    /// if `restart` is set. Returns `false` if the task should exit instead.
    #[must_use]
    pub(crate) fn prepare_to_run_guest(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
        restart: Option<SyscallRestart>,
    ) -> bool {
        self.wait_state.0.prepare_to_run_guest(|| {
            self.queue_async_signals();
            self.process_signals(ctx, restart);
            !self.is_exiting()
        })
    }

    /// Queues the signals raised outside this thread: platform signals, the fallback alarm's
    /// `SIGALRM`, `SIGCHLD` for terminated children, and signals other processes sent.
    fn queue_async_signals(&self) {
        self.global.platform.take_pending_signals(|signal| {
            self.queue_signals(signal);
        });
        #[cfg(feature = "alarm_fallback")]
        self.check_alarm_deadline();
        self.check_for_child_terminations();
        self.check_for_received_signals();
    }
}

/// Converts the error of a failed wait with an optional `timeout`.
///
/// Like Linux (e.g., `sock_intr_errno`), an interrupted wait with a timeout fails with `EINTR`
/// instead of restarting, since restarting it would restart its whole timeout.
pub(crate) fn wait_errno(timeout: Option<core::time::Duration>, error: impl Into<Errno>) -> Errno {
    let errno = error.into();
    if timeout.is_some() {
        errno.without_restart()
    } else {
        errno
    }
}

impl<Platform: ShimPlatform> litebox::event::wait::CheckForInterrupt for Task<Platform> {
    fn check_for_interrupt(&self) -> bool {
        self.queue_async_signals();
        self.is_exiting() || self.has_pending_signals()
    }
}
