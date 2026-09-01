// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_on_events()`.

use alloc::sync::Weak;

use litebox::event::Events;
use litebox::event::observer::Observer;
use litebox::event::polling::TryOpError;

use crate::{ShimFS, ShimPlatform, Task};

struct WaitInterrupt<'a, Platform: ShimPlatform, FS: ShimFS> {
    task: &'a Task<Platform, FS>,
    alertable: bool,
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::event::wait::CheckForInterrupt
    for WaitInterrupt<'_, Platform, FS>
{
    fn check_for_interrupt(&self) -> bool {
        self.task.thread_object.is_exiting()
            || (self.alertable && self.task.thread_object.take_pending_thread_alert())
    }
}

pub(crate) struct WaitState<Platform: ShimPlatform>(litebox::event::wait::WaitState<Platform>);

impl<Platform: ShimPlatform> WaitState<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn with_io_completion_worker_suspended<R>(&self, wait: impl FnOnce() -> R) -> R {
        self.suspend_io_completion_worker();
        let _resume_worker = litebox::utils::defer(|| self.resume_io_completion_worker());
        wait()
    }

    /// Returns a wait context to use to perform interruptible waits.
    fn wait_cx<'a>(
        &'a self,
        interrupt: &'a WaitInterrupt<'a, Platform, FS>,
    ) -> litebox::event::wait::WaitContext<'a, Platform> {
        self.wait_state
            .0
            .context()
            .with_check_for_interrupt(interrupt)
    }

    pub(crate) fn wait_on_events<R, E>(
        &self,
        nonblock: bool,
        alertable: bool,
        timeout: Option<core::time::Duration>,
        events: Events,
        register_observer: impl FnOnce(Weak<dyn Observer<Events>>, Events) -> Result<(), E>,
        mut try_op: impl FnMut() -> Result<R, TryOpError<E>>,
    ) -> Result<R, TryOpError<E>> {
        match try_op() {
            Err(TryOpError::TryAgain) if !nonblock => {}
            ret => return ret,
        }

        // The core helper probes again before blocking, so readiness racing with this point can
        // briefly release the IOCP slot without a host block. Exact accounting requires a hook
        // around WaitContext's platform block; keep this approximation local to the Windows shim.
        self.with_io_completion_worker_suspended(|| {
            let interrupt = WaitInterrupt {
                task: self,
                alertable,
            };
            let wait_context = self.wait_cx(&interrupt).with_timeout(timeout);
            wait_context.wait_on_events(false, events, register_observer, try_op)
        })
    }

    pub(crate) fn wait_until(
        &self,
        timeout: Option<core::time::Duration>,
        mut ready: impl FnMut() -> bool,
    ) -> Result<(), litebox::event::wait::WaitError> {
        if ready() {
            return Ok(());
        }
        self.with_io_completion_worker_suspended(|| {
            let interrupt = WaitInterrupt {
                task: self,
                alertable: false,
            };
            self.wait_cx(&interrupt)
                .with_timeout(timeout)
                .wait_until(ready)
        })
    }

    pub(crate) fn sleep(
        &self,
        alertable: bool,
        timeout: core::time::Duration,
    ) -> litebox::event::wait::WaitError {
        self.with_io_completion_worker_suspended(|| {
            let interrupt = WaitInterrupt {
                task: self,
                alertable,
            };
            self.wait_cx(&interrupt).with_timeout(timeout).sleep()
        })
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
        if self.thread_object.is_suspended() {
            let _ = self.wait_until(None, || !self.thread_object.is_suspended());
        }
        self.wait_state.0.prepare_to_run_guest(|| {
            // TODO(windows-apc): deliver pending user-mode APCs here.
            !self.thread_object.is_exiting()
        })
    }
}
