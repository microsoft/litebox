//! Polling-related functionality

use alloc::sync::Weak;
use thiserror::Error;

use super::{
    Events,
    observer::{Observer, Subject},
};
use crate::{
    LiteBox,
    event::wait::{WaitContext, WaitError},
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// A pollable entity that can be observed for events.
///
/// This supports polling, waiting, and notifications for observers.
pub struct Pollee<Platform: RawSyncPrimitivesProvider> {
    subject: Subject<Events, Events, Platform>,
}

/// The result of a tried operation.
#[derive(Error, Debug)]
pub enum TryOpError<E> {
    #[error("operation should be retried")]
    TryAgain,
    #[error("wait error")]
    WaitError(WaitError),
    #[error(transparent)]
    Other(E),
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> WaitContext<'_, Platform> {
    /// Run `try_op` until it returns a non-`TryAgain` result, waiting after
    /// each `TryAgain`.
    ///
    /// If `nonblock` is true, returns `TryAgain` instead of waiting. In this
    /// case, `try_op` is called exactly once and `check` is not used.
    ///
    /// `check` is used to determine whether `try_op` is likely to succeed. If
    /// `check` returns `true`, the wait is skipped and `try_op` is called again
    /// immediately. If `check` returns `false`, then the thread will block
    /// until notified via a call to [`Observer::on_events`] on the observer
    /// passed to `register_observer`.
    pub fn wait_on_events<R, E>(
        &self,
        nonblock: bool,
        mut try_op: impl FnMut() -> Result<R, TryOpError<E>>,
        check: impl Fn() -> bool,
        register_observer: impl FnOnce(Weak<dyn Observer<Events>>, Events),
    ) -> Result<R, TryOpError<E>>
    where
        Platform: RawSyncPrimitivesProvider + TimeProvider,
    {
        let mut register_observer = Some(register_observer);
        loop {
            match try_op() {
                Err(TryOpError::TryAgain) => {}
                ret => return ret,
            }
            if nonblock {
                return Err(TryOpError::TryAgain);
            }
            if let Some(register_observer) = register_observer.take() {
                register_observer(self.waker().observer(), Events::all());
            }
            match self.wait(&check) {
                Ok(()) => {}
                Err(err) => return Err(TryOpError::WaitError(err)),
            }
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Pollee<Platform> {
    /// Create a new pollee.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            subject: Subject::new(litebox.sync()),
        }
    }

    /// Run `try_op` until it returns a non-`TryAgain` result, waiting after
    /// each `TryAgain`.
    ///
    /// If `nonblock` is true, returns `TryAgain` instead of waiting. In this
    /// case, `try_op` is called exactly once and `check` is not used.
    ///
    /// `check` is used to determine whether `try_op` is likely to succeed. If
    /// `check` returns `true`, the wait is skipped and `try_op` is called again
    /// immediately. If `check` returns `false`, then the thread will block
    /// until notified via [`notify_observers`](Self::notify_observers).
    pub fn wait<R, E>(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        try_op: impl FnMut() -> Result<R, TryOpError<E>>,
        check: impl Fn() -> bool,
    ) -> Result<R, TryOpError<E>> {
        cx.wait_on_events(nonblock, try_op, check, |observer, filter| {
            self.register_observer(observer, filter);
        })
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
