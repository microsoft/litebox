use crate::platform::{
    ImmediatelyWokenUp, Instant as _, RawMutex, RawMutexProvider, TimeProvider, UnblockedOrTimedOut,
};
use alloc::sync::Arc;
use core::sync::atomic::Ordering::SeqCst;
use core::sync::atomic::Ordering::{Relaxed, Release};

pub struct Waker<Platform: RawMutexProvider> {
    state: Arc<Platform::RawMutex>,
}

pub type Waiter<'a, Platform> = &'a dyn GetWaitState<Platform>;

pub struct WaitState<Platform: RawMutexProvider> {
    state: Arc<Platform::RawMutex>,
}

impl<Platform: RawMutexProvider> WaitState<Platform> {
    pub fn new(platform: &Platform) -> Self {
        Self {
            state: Arc::new(platform.new_raw_mutex()),
        }
    }
}

pub trait GetWaitState<Platform: RawMutexProvider> {
    fn wait_state(&self) -> &WaitState<Platform>;
    fn can_wait(&self) -> bool;
}

const NOT_WAITING: u32 = 0;
const WAITING: u32 = 1;

impl<Platform: RawMutexProvider> Waker<Platform> {
    pub fn wake(&self) {
        if self.state.underlying_atomic().swap(NOT_WAITING, Release) == WAITING {
            self.state.wake_one();
        }
    }
}

pub enum WaitError {
    Interrupted,
    TimedOut,
}

impl<Platform: RawMutexProvider> GetWaitState<Platform> for WaitState<Platform> {
    fn wait_state(&self) -> &WaitState<Platform> {
        self
    }

    fn can_wait(&self) -> bool {
        true
    }
}

impl<Platform: RawMutexProvider + TimeProvider> dyn GetWaitState<Platform> + '_ {
    pub fn waker(&self) -> Waker<Platform> {
        Waker {
            state: self.wait_state().state.clone(),
        }
    }

    pub fn wait_or_timeout<R>(
        &self,
        platform: &Platform,
        duration: Option<core::time::Duration>,
        mut f: impl FnMut() -> Option<R>,
    ) -> Result<R, WaitError> {
        let start_time = platform.now();
        let raw_mutex = self.wait_state().state.as_ref();
        let r = loop {
            raw_mutex.underlying_atomic().store(WAITING, SeqCst);
            if let Some(ret) = f() {
                break Ok(ret);
            }
            if !self.can_wait() {
                break Err(WaitError::Interrupted);
            }
            if let Some(duration) = duration {
                let remaining_time =
                    duration.saturating_sub(platform.now().duration_since(&start_time));
                match raw_mutex.block_or_timeout(WAITING, remaining_time) {
                    Ok(UnblockedOrTimedOut::Unblocked) | Err(ImmediatelyWokenUp) => {}
                    Ok(UnblockedOrTimedOut::TimedOut) => break Err(WaitError::TimedOut),
                }
            } else {
                let _ = raw_mutex.block(WAITING);
            };
        };
        raw_mutex.underlying_atomic().store(NOT_WAITING, Relaxed);
        r
    }
}
