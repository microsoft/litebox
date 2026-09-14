// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Polling-related functionality

use core::sync::atomic::AtomicBool;

use alloc::sync::{Arc, Weak};
use thiserror::Error;

use super::{
    Events,
    observer::{Observer, Subject},
};
use crate::{
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
        #[cfg(any(test, feature = "ordering_stress"))]
        crate::ordering_stress::waiter_registered();
        loop {
            match try_op() {
                Err(TryOpError::TryAgain) => {}
                ret => return ret,
            }
            match self.wait_until(|| {
                let ready = observer.is_ready();
                #[cfg(any(test, feature = "ordering_stress"))]
                crate::ordering_stress::record_waiter_done(ready);
                ready
            }) {
                Ok(()) => {}
                Err(err) => return Err(TryOpError::WaitError(err)),
            }
            // Reset the observer before calling [`try_op`] again so that we
            // don't miss a wakeup.
            observer.reset();
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Default for Pollee<Platform> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Pollee<Platform> {
    /// Create a new pollee.
    pub fn new() -> Self {
        Self {
            subject: Subject::new(),
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
        #[cfg(any(test, feature = "ordering_stress"))]
        crate::ordering_stress::waker_rendezvous();
        self.ready
            .store(true, core::sync::atomic::Ordering::Release);
        self.waker.wake();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{Pollee, TryOpError};
    use crate::LiteBox;
    use crate::event::Events;
    use crate::event::wait::{WaitError, WaitState};
    use crate::platform::mock::MockPlatform;
    use alloc::sync::Arc;
    use core::convert::Infallible;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    /// Reproduces the store-buffering hazard in the polling notify path, the sibling of
    /// the futex one in [`crate::sync::futex`]: `PolleeObserver::on_events` publishes
    /// `ready` with a `Release` store (a plain `mov` on x86) and then calls `wake`, whose
    /// `fetch_update` reads the thread state, while the waiter stores `WAITING` and then
    /// loads `ready`. Both sides can read the other's stale value, so the notifier skips
    /// the wake on `RUNNING_IN_HOST` while the waiter blocks on a stale `ready == false`.
    /// Ignored because it is probabilistic; run with `LITEBOX_POLL_STRESS_ITERS` to
    /// control the iteration count.
    #[test]
    #[ignore = "probabilistic weak-memory stress test"]
    fn stress_registered_poller_does_not_miss_notification() {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let pollee = Arc::new(Pollee::<MockPlatform>::new());
        let iterations = std::env::var("LITEBOX_POLL_STRESS_ITERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000_000);
        crate::ordering_stress::activate();
        let iteration_start = Arc::new(Barrier::new(3));
        let iteration_finish = Arc::new(Barrier::new(3));
        let waiter_timed_out = Arc::new(AtomicBool::new(false));

        let waiter = {
            let pollee = Arc::clone(&pollee);
            let iteration_start = Arc::clone(&iteration_start);
            let iteration_finish = Arc::clone(&iteration_finish);
            let waiter_timed_out = Arc::clone(&waiter_timed_out);
            thread::spawn(move || {
                for _ in 0..iterations {
                    iteration_start.wait();
                    // The pre-registration probe and the first in-loop probe must report
                    // `TryAgain` so the waiter always reaches the racing `wait_until`; a
                    // later probe reports success so a delivered notification ends the wait.
                    let mut probes = 0u32;
                    let result: Result<(), TryOpError<Infallible>> = pollee.wait(
                        &WaitState::new(platform)
                            .context()
                            .with_timeout(Duration::from_millis(20)),
                        false,
                        Events::IN,
                        || {
                            probes += 1;
                            if probes <= 2 {
                                Err(TryOpError::TryAgain)
                            } else {
                                Ok(())
                            }
                        },
                    );
                    waiter_timed_out.store(
                        matches!(result, Err(TryOpError::WaitError(WaitError::TimedOut))),
                        Ordering::Relaxed,
                    );
                    iteration_finish.wait();
                }
            })
        };

        let notifier = {
            let pollee = Arc::clone(&pollee);
            let iteration_start = Arc::clone(&iteration_start);
            let iteration_finish = Arc::clone(&iteration_finish);
            thread::spawn(move || {
                for _ in 0..iterations {
                    iteration_start.wait();
                    while !crate::ordering_stress::waiter_is_registered() {
                        core::hint::spin_loop();
                    }
                    pollee.notify_observers(Events::IN);
                    iteration_finish.wait();
                }
            })
        };

        let mut both_old = 0;
        let mut lost_wakeups = 0;

        for _ in 0..iterations {
            crate::ordering_stress::begin_round();
            waiter_timed_out.store(false, Ordering::Relaxed);
            iteration_start.wait();
            crate::ordering_stress::wait_until_parked();
            crate::ordering_stress::release();
            iteration_finish.wait();
            if crate::ordering_stress::observed_both_old() {
                both_old += 1;
            }
            if waiter_timed_out.load(Ordering::Relaxed) {
                lost_wakeups += 1;
            }
        }

        waiter.join().unwrap();
        notifier.join().unwrap();
        crate::ordering_stress::deactivate();
        std::eprintln!("iterations={iterations} both_old={both_old} lost_wakeups={lost_wakeups}");
        assert_eq!(both_old, 0, "the polling notify path saw both old values");
        assert_eq!(
            lost_wakeups, 0,
            "a registered poller missed its notification"
        );
    }
}
