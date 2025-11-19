//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{Platform, Task};

pub(crate) struct WaitState(litebox::event::wait::WaitState<Platform>);

impl WaitState {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }
}

impl Task {
    /// Returns a wait context to use to perform interruptible waits.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.0.context().with_check_for_interrupt(self)
    }
}

impl litebox::event::wait::CheckForInterrupt for Task {
    fn check_for_interrupt(&self) -> bool {
        // TODO: interrupt on signals, process exit, that kind of thing.
        false
    }
}
