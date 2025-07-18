//! Polling-related functionality

// TODO(jayb|2025/07/18): Check all the `pub` declarations here, and then start removing the things
// from the shim `event.rs` and migrate all of those over. I also need to add/fix doc comments
// across everything here.

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

pub struct Pollee<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    inner: alloc::sync::Arc<PolleeInner<Platform>>,
    litebox: LiteBox<Platform>,
}

struct PolleeInner<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    subject: Subject<Events, Events, Platform>,
}

pub enum TryOpError<E> {
    TryAgain,
    TimedOut,
    Other(E),
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Pollee<Platform> {
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let inner = alloc::sync::Arc::new(PolleeInner {
            subject: Subject::new(litebox.sync()),
        });
        Self {
            inner,
            litebox: litebox.clone(),
        }
    }

    /// Poll the pollee with the given mask of events and register the poller.
    ///
    /// NOTE(jb): I am not sure I am happy with the design of this interface, need to fix it up
    /// before making the PR.
    pub fn poll<F>(
        &self,
        mask: Events,
        observer: Option<alloc::sync::Weak<dyn Observer<Events>>>,
        check: F,
    ) -> Events
    where
        F: FnOnce() -> Events,
    {
        let mask = mask | Events::ALWAYS_POLLED;

        if let Some(observer) = observer {
            self.register_observer(observer, mask);
        }

        check() & mask
    }

    /// Wait until `try_op` returns a non-EAGAIN result or timeout.
    /// If the `timeout` is None, it will wait indefinitely.
    ///
    /// NOTE(jb): I am not sure I am happy with the design of this interface, need to fix it up
    /// before making the PR.
    pub fn wait_or_timeout<F, C, R, E>(
        &self,
        mask: Events,
        timeout: Option<core::time::Duration>,
        mut try_op: F,
        check: C,
    ) -> Result<R, TryOpError<E>>
    where
        F: FnMut() -> Result<R, TryOpError<E>>,
        C: FnOnce() -> Events,
    {
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
        let poller = alloc::sync::Arc::new(Poller::new(&self.litebox));
        let revents = self.poll(mask, Some(alloc::sync::Arc::downgrade(&poller) as _), check);
        if revents.is_empty() {
            poller
                .wait_or_timeout(&mut remaining_time)
                .map_err(|TimedOut| TryOpError::TimedOut)?;
        }

        loop {
            match try_op() {
                Err(TryOpError::TryAgain) => {}
                ret => return ret,
            }

            poller
                .wait_or_timeout(&mut remaining_time)
                .map_err(|TimedOut| TryOpError::TimedOut)?;
        }
    }

    pub fn register_observer(
        &self,
        observer: alloc::sync::Weak<dyn Observer<Events>>,
        filter: Events,
    ) {
        self.inner
            .subject
            .register_observer(observer, filter | Events::ALWAYS_POLLED);
    }

    pub fn unregister_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>) {
        self.inner.subject.unregister_observer(observer);
    }

    pub fn notify_observers(&self, events: Events) {
        self.inner.subject.notify_observers(events);
    }
}

pub struct Poller<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    condvar: Platform::RawMutex,
    litebox: LiteBox<Platform>,
}

struct TimedOut;

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Poller<Platform> {
    fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            condvar: litebox.x.platform.new_raw_mutex(),
            litebox: litebox.clone(),
        }
    }

    fn wait(&self) -> bool {
        self.do_wait(None)
    }

    /// Wait for the poller to be notified.
    /// If the timeout is not None, it will be updated to the remaining time after waiting.
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
