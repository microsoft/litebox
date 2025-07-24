//! Polling-related functionality

use alloc::sync::{Arc, Weak};
use thiserror::Error;

use super::{
    Events,
    observer::{Observer, Subject},
};
use crate::{
    LiteBox,
    platform::{
        ImmediatelyWokenUp, Instant as _, RawMutex as _, TimeProvider, UnblockedOrTimedOut,
    },
    sync::RawSyncPrimitivesProvider,
};

/// A pollable entity that can be observed for events.
///
/// This supports polling, waiting (with optional timeouts), and notifications for observers.
pub struct Pollee<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    inner: Arc<PolleeInner<Platform>>,
    litebox: LiteBox<Platform>,
}

struct PolleeInner<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    subject: Subject<Events, Events, Platform>,
}

/// The result of a tried operation.
#[derive(Error, Debug)]
pub enum TryOpError<E> {
    #[error("operation should be retried")]
    TryAgain,
    #[error("operation timed out")]
    TimedOut,
    #[error(transparent)]
    Other(E),
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Pollee<Platform> {
    /// Create a new pollee.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let inner = Arc::new(PolleeInner {
            subject: Subject::new(litebox.sync()),
        });
        Self {
            inner,
            litebox: litebox.clone(),
        }
    }

    /// Run `try_op` until it returns a non-`TryAgain` result.
    ///
    /// This function runs indefinitely unless a `timeout` is provided, in which case, it can return
    /// with a `TimedOut` error.
    ///
    /// The `check` function is used to reduce the number of times `try_op` is run. Specifically, if
    /// `check` returns `false`, then it means that it is not worth attempting to run `try_op` and
    /// that we can wait (for a notification to arrive, via [`Self::notify_observers`]) until
    /// `check` returns `true` again. Note that `try_op` can be (sometimes) run even if `check` is
    /// false; it is not to be taken as a pre-requisite to running `try_op` but merely used as a way
    /// to reduce the number of times `try_op` is invoked.
    pub fn wait_or_timeout<R, E>(
        &self,
        timeout: Option<core::time::Duration>,
        mut try_op: impl FnMut() -> Result<R, TryOpError<E>>,
        check: impl Fn() -> bool,
    ) -> Result<R, TryOpError<E>> {
        // Try first without waiting
        match try_op() {
            Err(TryOpError::TryAgain) => {}
            ret => return ret,
        }

        // Return immediately if the timeout is zero.
        if timeout.is_some_and(|d| d.is_zero()) {
            return Err(TryOpError::TimedOut);
        }

        let start_time = self.litebox.x.platform.now();
        let poller = Arc::new(Poller::new(&self.litebox));
        self.register_observer(Arc::downgrade(&poller) as _, Events::all());

        loop {
            if !check() {
                let remaining_time = timeout.map(|t| {
                    t.saturating_sub(self.litebox.x.platform.now().duration_since(&start_time))
                });
                poller
                    .wait_or_timeout(remaining_time)
                    .map_err(|TimedOut| TryOpError::TimedOut)?;
            }
            // We always run `try_op` whether `check` returns true or false; we simply delay running
            // `try_op` for a little while if `check` has returned `false`.
            match try_op() {
                Err(TryOpError::TryAgain) => {}
                ret => return ret,
            }
        }
    }

    /// Register an observer for events that satisfy the given `filter`.
    pub fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.inner
            .subject
            .register_observer(observer, filter | Events::ALWAYS_POLLED);
    }

    /// Unregister an observer.
    pub fn unregister_observer(&self, observer: Weak<dyn Observer<Events>>) {
        self.inner.subject.unregister_observer(observer);
    }

    /// Notify all registered observers with the given events.
    pub fn notify_observers(&self, events: Events) {
        self.inner.subject.notify_observers(events);
    }
}

/// Private observer, used solely to help implement `Pollee::wait_or_timeout`
struct Poller<Platform: RawSyncPrimitivesProvider> {
    condvar: Platform::RawMutex,
}

/// A trivial zero-sized error returned by `Poller::wait_or_timeout`
struct TimedOut;

impl<Platform: RawSyncPrimitivesProvider> Poller<Platform> {
    /// Create a new poller.
    fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            condvar: litebox.x.platform.new_raw_mutex(),
        }
    }

    /// Wait for the poller to be notified.
    ///
    /// If the timeout is not `None`, it will be updated to the remaining time after waiting.
    fn wait_or_timeout(&self, timeout: Option<core::time::Duration>) -> Result<(), TimedOut> {
        if timeout.is_some_and(|t| t.is_zero()) {
            return Err(TimedOut);
        }
        let futex = self.condvar.underlying_atomic();
        if futex.swap(0, core::sync::atomic::Ordering::Relaxed) == 0 {
            if let Some(timeout) = timeout {
                match self.condvar.block_or_timeout(0, timeout) {
                    Ok(UnblockedOrTimedOut::TimedOut) => Err(TimedOut),
                    Ok(UnblockedOrTimedOut::Unblocked) | Err(ImmediatelyWokenUp) => Ok(()),
                }
            } else {
                let _ = self.condvar.block(0);
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> Observer<Events> for Poller<Platform> {
    fn on_events(&self, _events: &Events) {
        self.condvar
            .underlying_atomic()
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.condvar.wake_one();
    }
}
