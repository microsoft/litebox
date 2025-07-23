//! Polling-related functionality

// TODO(jayb|2025/07/18): Check all the `pub` declarations here, and then start removing the things
// from the shim `event.rs` and migrate all of those over. I also need to add/fix doc comments
// across everything here.

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

    /// Register the `observer` (if specified) and then poll for `check` with the given `mask`.
    ///
    /// NOTE(jb): I am not sure I am happy with this function, but this is what was in the shim.
    /// Currently, it does not seem obvious why this cannot just be inlined into places that use it.
    /// Inlining it into all such places does cause some duplication, but more effort seems to be
    /// needed to actually figure out a good interface here, rather than just one that removes the
    /// duplication in the trivial way, because at least as it stands, this is _too_ specific to
    /// seem useful.
    ///
    /// TODO(jb): Rename before making the PR.
    pub fn poll(
        &self,
        mask: Events,
        observer: Option<Weak<dyn Observer<Events>>>,
        check: impl FnOnce() -> Events,
    ) -> Events {
        let mask = mask | Events::ALWAYS_POLLED;

        if let Some(observer) = observer {
            self.register_observer(observer, mask);
        }

        check() & mask
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

        let mut remaining_time = timeout;
        let poller = Arc::new(Poller::new(&self.litebox));
        self.register_observer(Arc::downgrade(&poller) as _, Events::all());

        loop {
            if !check() {
                poller
                    .wait_or_timeout(&mut remaining_time)
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

struct Poller<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    condvar: Platform::RawMutex,
    litebox: LiteBox<Platform>,
}

struct TimedOut;

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Poller<Platform> {
    /// Create a new poller.
    fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            condvar: litebox.x.platform.new_raw_mutex(),
            litebox: litebox.clone(),
        }
    }

    /// Wait for the poller to be notified.
    fn wait(&self) -> bool {
        self.do_wait(None)
    }

    /// Wait for the poller to be notified.
    ///
    /// If the timeout is not `None`, it will be updated to the remaining time after waiting.
    fn wait_or_timeout(&self, timeout: &mut Option<core::time::Duration>) -> Result<(), TimedOut> {
        let ret = match timeout {
            Some(timeout) => {
                if timeout.is_zero() {
                    return Err(TimedOut);
                }

                let start_time = self.litebox.x.platform.now();
                let res = self.do_wait(Some(*timeout));
                *timeout = timeout
                    .checked_sub(start_time.duration_since(&self.litebox.x.platform.now()))
                    .unwrap_or_default();
                res
            }
            None => self.wait(),
        };
        if ret { Ok(()) } else { Err(TimedOut) }
    }

    fn do_wait(&self, timeout: Option<core::time::Duration>) -> bool {
        let futex = self.condvar.underlying_atomic();
        if futex.swap(0, core::sync::atomic::Ordering::Relaxed) == 0 {
            if let Some(timeout) = timeout {
                match self.condvar.block_or_timeout(0, timeout) {
                    Ok(UnblockedOrTimedOut::TimedOut) => false,
                    Ok(UnblockedOrTimedOut::Unblocked) | Err(ImmediatelyWokenUp) => true,
                }
            } else {
                let _ = self.condvar.block(0);
                true
            }
        } else {
            true
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Observer<Events> for Poller<Platform> {
    fn on_events(&self, _events: &Events) {
        self.condvar
            .underlying_atomic()
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.condvar.wake_one();
    }
}
