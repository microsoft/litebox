//! Polling-related functionality

use alloc::sync::{Arc, Weak};
use thiserror::Error;

use super::{
    Events,
    observer::{Observer, Subject},
};
use crate::{
    LiteBox,
    platform::TimeProvider,
    sync::{
        RawSyncPrimitivesProvider,
        waiter::{WaitError, Waiter, Waker},
    },
};

/// A pollable entity that can be observed for events.
///
/// This supports polling, waiting (with optional timeouts), and notifications for observers.
pub struct Pollee<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    subject: Subject<Events, Events, Platform>,
}

/// The result of a tried operation.
#[derive(Error, Debug)]
pub enum TryOpError<E> {
    #[error("operation should be retried")]
    TryAgain,
    #[error("operation timed out")]
    TimedOut,
    #[error("operation interrupted")]
    Interrupted,
    #[error(transparent)]
    Other(E),
}

pub struct TryAgain;

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Pollee<Platform> {
    /// Create a new pollee.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            subject: Subject::new(litebox.sync()),
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
        waiter: Waiter<Platform>,
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

        let poller = Arc::new(Poller::new(waiter.waker()));
        self.register_observer(Arc::downgrade(&poller) as _, Events::all());

        let r = waiter.wait_or_timeout(timeout, || {
            if !check() {
                return None;
            }
            match try_op() {
                Err(TryOpError::TryAgain) => None,
                r => Some(r),
            }
        });
        r.map_err(|err| match err {
            WaitError::Interrupted => TryOpError::Interrupted,
            WaitError::TimedOut => TryOpError::TimedOut,
        })?
    }

    /// Register an observer for events that satisfy the given `filter`.
    pub fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.subject
            .register_observer(observer, filter | Events::ALWAYS_POLLED);
    }

    /// Unregister an observer.
    pub fn unregister_observer(&self, observer: Weak<dyn Observer<Events>>) {
        self.subject.unregister_observer(observer);
    }

    /// Notify all registered observers with the given events.
    pub fn notify_observers(&self, events: Events) {
        self.subject.notify_observers(events);
    }
}

/// Private observer, used solely to help implement `Pollee::wait_or_timeout`
struct Poller<Platform: RawSyncPrimitivesProvider> {
    waker: Waker<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> Poller<Platform> {
    /// Create a new poller.
    fn new(waker: Waker<Platform>) -> Self {
        Self { waker }
    }
}

impl<Platform: RawSyncPrimitivesProvider> Observer<Events> for Poller<Platform> {
    fn on_events(&self, _events: &Events) {
        self.waker.wake();
    }
}
