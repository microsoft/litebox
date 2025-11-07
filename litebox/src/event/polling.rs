//! Polling-related functionality

use alloc::sync::Weak;
use core::{future::poll_fn, task::Poll};
use thiserror::Error;

use super::{
    Events,
    observer::{Observer, Subject},
};
use crate::{
    LiteBox,
    sync::{Mutex, RawSyncPrimitivesProvider},
};

/// A pollable entity that can be observed for events.
///
/// This supports polling, waiting, and notifications for observers.
pub struct Pollee<Platform: RawSyncPrimitivesProvider> {
    subject: Subject<Events, Events, Platform>,
    waker: Mutex<Platform, Option<core::task::Waker>>,
}

/// The result of a tried operation.
#[derive(Error, Debug)]
pub enum TryOpError<E> {
    #[error("operation should be retried")]
    TryAgain,
    #[error(transparent)]
    Other(E),
}

impl<Platform: RawSyncPrimitivesProvider> Pollee<Platform> {
    /// Create a new pollee.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            subject: Subject::new(litebox.sync()),
            waker: litebox.sync().new_mutex(None),
        }
    }

    /// Run `try_op` until it returns a non-`TryAgain` result.
    ///
    /// The `check` function is used to reduce the number of times `try_op` is run. Specifically, if
    /// `check` returns `false`, then it means that it is not worth attempting to run `try_op` and
    /// that we can wait (for a notification to arrive, via [`Self::notify_observers`]) until
    /// `check` returns `true` again. Note that `try_op` can be (sometimes) run even if `check` is
    /// false; it is not to be taken as a pre-requisite to running `try_op` but merely used as a way
    /// to reduce the number of times `try_op` is invoked.
    pub async fn wait<R, E>(
        &self,
        mut try_op: impl FnMut() -> Result<R, TryOpError<E>>,
        check: impl Fn() -> bool,
    ) -> Result<R, E> {
        poll_fn(|cx| {
            loop {
                match try_op() {
                    Ok(ret) => return Poll::Ready(Ok(ret)),
                    Err(TryOpError::TryAgain) => {}
                    Err(TryOpError::Other(e)) => return Poll::Ready(Err(e)),
                }
                self.waker.lock().replace(cx.waker().clone());
                if !check() {
                    return Poll::Pending;
                }
            }
        })
        .await
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
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
