//! Polling-related functionality

use core::sync::atomic::AtomicBool;

use alloc::sync::{Arc, Weak};
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
    WaitError(#[source] WaitError),
    #[error(transparent)]
    Other(E),
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> WaitContext<'_, Platform> {
    /// Run `try_op` until it returns a non-`TryAgain` result, waiting after
    /// each `TryAgain`.
    ///
    /// If `nonblock` is true, returns `TryAgain` instead of waiting.
    ///
    /// If `try_op` returns `TryAgain`, the thread will be woken to try again
    /// when the observer, registered via the call to `register_observer`, is
    /// called with events that match the given `events` filter (or an event in
    /// `Events::ALWAYS_POLLED`).
    pub fn wait_on_events<R, E>(
        &self,
        nonblock: bool,
        events: Events,
        register_observer: impl FnOnce(Weak<dyn Observer<Events>>, Events) -> Result<(), E>,
        mut try_op: impl FnMut() -> Result<R, TryOpError<E>>,
    ) -> Result<R, TryOpError<E>>
    where
        Platform: RawSyncPrimitivesProvider + TimeProvider,
    {
        // Try once before allocating and registering the observer.
        match try_op() {
            Err(TryOpError::TryAgain) if !nonblock => {}
            ret => return ret,
        }
        let observer = Arc::new(PolleeObserver::new(self.waker().clone()));
        // FUTURE: have `register_observer` return the current ready events so
        // that we can skip calling `try_op` again if we are not yet ready.
        register_observer(
            Arc::downgrade(&observer) as _,
            events | Events::ALWAYS_POLLED,
        )
        .map_err(TryOpError::Other)?;
        loop {
            match try_op() {
                Err(TryOpError::TryAgain) => {}
                ret => return ret,
            }
            match self.wait_until(|| observer.is_ready()) {
                Ok(()) => {}
                Err(err) => return Err(TryOpError::WaitError(err)),
            }
            // Reset the observer before calling [`try_op`] again so that we
            // don't miss a wakeup.
            observer.reset();
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
    /// If `nonblock` is true, returns `TryAgain` instead of waiting.
    ///
    /// If `try_op` returns `TryAgain`, the thread will be woken to try again
    /// when [`notify_observers`](Self::notify_observers) is called with events
    /// that match the given `events` filter (or an event in
    /// `Events::ALWAYS_POLLED`).
    pub fn wait<R, E>(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        events: Events,
        try_op: impl FnMut() -> Result<R, TryOpError<E>>,
    ) -> Result<R, TryOpError<E>> {
        cx.wait_on_events(
            nonblock,
            events,
            |observer, filter| {
                self.register_observer(observer, filter);
                Ok(())
            },
            try_op,
        )
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

/// Private observer, used solely to help implement [`WaitContext::wait_on_events`].
struct PolleeObserver<Platform: RawSyncPrimitivesProvider> {
    ready: AtomicBool,
    waker: super::wait::Waker<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> PolleeObserver<Platform> {
    fn new(waker: super::wait::Waker<Platform>) -> Self {
        Self {
            ready: AtomicBool::new(false),
            waker,
        }
    }

    fn reset(&self) {
        self.ready
            .store(false, core::sync::atomic::Ordering::SeqCst);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(core::sync::atomic::Ordering::SeqCst)
    }
}

impl<Platform: RawSyncPrimitivesProvider> Observer<Events> for PolleeObserver<Platform> {
    fn on_events(&self, _events: &Events) {
        self.ready
            .store(true, core::sync::atomic::Ordering::Release);
        self.waker.wake();
    }
}
