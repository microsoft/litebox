use alloc::task::Wake;

use crate::{
    platform::{Instant as _, RawMutex, TimeProvider, UnblockedOrTimedOut},
    sync::RawSyncPrimitivesProvider,
};
use alloc::sync::Arc;
use core::{
    pin::pin,
    sync::atomic::Ordering,
    task::{Context, Waker},
    time::Duration,
};

/// An executor that can run a single future.
pub struct Executor<Platform: RawSyncPrimitivesProvider> {
    platform: &'static Platform,
    state: Arc<ExecutorState<Platform>>,
    waker: Waker,
}

impl<Platform: RawSyncPrimitivesProvider> Executor<Platform> {
    pub(super) fn new_from_synchronization(sync: &super::Synchronization<Platform>) -> Self {
        let state = Arc::new(ExecutorState(sync.platform.new_raw_mutex()));
        let waker = Waker::from(state.clone());
        Self {
            platform: sync.platform,
            state,
            waker,
        }
    }
}

struct ExecutorState<Platform: RawSyncPrimitivesProvider>(Platform::RawMutex);

impl<Platform: RawSyncPrimitivesProvider> Wake for ExecutorState<Platform> {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.underlying_atomic().store(1, Ordering::Release);
        self.0.wake_one();
    }
}

pub struct TimedOut;

impl<Platform: RawSyncPrimitivesProvider> Executor<Platform> {
    /// Runs `future` to completion or until `timeout` elapses.
    pub fn run_or_timeout<F>(
        &mut self,
        timeout: Option<Duration>,
        future: F,
    ) -> Result<F::Output, TimedOut>
    where
        F: Future,
        Platform: TimeProvider,
    {
        let start_time = timeout.map(|_| self.platform.now());
        let mut cx = Context::from_waker(&self.waker);
        let mut future = pin!(future);
        loop {
            self.state.0.underlying_atomic().store(0, Ordering::Relaxed);
            match future.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(r) => break Ok(r),
                core::task::Poll::Pending => {
                    if let Some((timeout, start_time)) = timeout.zip(start_time.as_ref()) {
                        self.wait_timeout(start_time, timeout)?;
                    } else {
                        let _ = self.state.0.block(0);
                    }
                }
            }
        }
    }

    fn wait_timeout(&self, start_time: &Platform::Instant, timeout: Duration) -> Result<(), TimedOut>
    where
        Platform: TimeProvider,
    {
        let since = self.platform.now().duration_since(&start_time);
        let timeout = timeout.saturating_sub(since);
        match self.state.0.block_or_timeout(0, timeout) {
            Ok(UnblockedOrTimedOut::Unblocked) | Err(_) => Ok(())
            Ok(UnblockedOrTimedOut::TimedOut) => {
                Err(TimedOut)
            }
        }
    }

    /// Runs `future` to completion.
    pub fn run<F>(&mut self, future: F) -> F::Output
    where
        F: Future,
    {
        let mut cx = Context::from_waker(&self.waker);
        let mut future = pin!(future);
        loop {
            self.state.0.underlying_atomic().store(0, Ordering::Relaxed);
            match future.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(r) => break r,
                core::task::Poll::Pending => {
                    let _ = self.state.0.block(0);
                }
            }
        }
    }
}
