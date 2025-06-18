use alloc::collections::btree_map::BTreeMap;
use litebox::platform::RawMutex as _;
use litebox::platform::RawMutexProvider;
use litebox::{
    event::Events,
    platform::{Instant as _, TimeProvider as _},
};
use litebox_common_linux::errno::Errno;

trait EventsFilter<E>: Send + Sync + 'static {
    fn filter(&self, event: &E) -> bool;
}

impl EventsFilter<Events> for Events {
    fn filter(&self, events: &Events) -> bool {
        self.intersects(*events)
    }
}

pub(crate) trait Observer<E>: Send + Sync {
    fn on_events(&self, events: &E);
}

struct ObserverKey<E> {
    observer: alloc::sync::Weak<dyn Observer<E>>,
}

impl<E> PartialEq for ObserverKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.observer.ptr_eq(&other.observer)
    }
}

impl<E> Eq for ObserverKey<E> {}

impl<E> PartialOrd for ObserverKey<E> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<E> Ord for ObserverKey<E> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.observer
            .as_ptr()
            .cast::<()>()
            .cmp(&other.observer.as_ptr().cast::<()>())
    }
}

impl<E> ObserverKey<E> {
    fn upgrade(&self) -> Option<alloc::sync::Arc<dyn Observer<E>>> {
        self.observer.upgrade()
    }
}

/// A Subject notifies interesting events to registered observers.
struct Subject<E, F: EventsFilter<E>> {
    /// A table that maintains all interesting observers.
    observers: spin::Mutex<BTreeMap<ObserverKey<E>, F>>,
    /// Number of observers.
    nums: core::sync::atomic::AtomicUsize,
}

impl<E, F: EventsFilter<E>> Subject<E, F> {
    fn new() -> Self {
        Self {
            observers: spin::Mutex::new(BTreeMap::new()),
            nums: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<E>>, filter: F) {
        let mut observers = self.observers.lock();
        if observers.insert(ObserverKey { observer }, filter).is_none() {
            self.nums
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }

    fn unregister_observer(&self, observer: alloc::sync::Weak<dyn Observer<E>>) {
        let mut observers = self.observers.lock();
        if observers.remove(&ObserverKey { observer }).is_some() {
            self.nums
                .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        }
    }

    fn notify_observers(&self, events: E) {
        if self.nums.load(core::sync::atomic::Ordering::Relaxed) == 0 {
            return;
        }

        let mut observers = self.observers.lock();
        observers.retain(|observer, filter| {
            if let Some(observer) = observer.upgrade() {
                if filter.filter(&events) {
                    observer.on_events(&events);
                }
                true
            } else {
                self.nums
                    .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
                false
            }
        });
    }
}

pub(crate) struct Pollee {
    inner: alloc::sync::Arc<PolleeInner>,
}

struct PolleeInner {
    subject: Subject<Events, Events>,
}

impl Pollee {
    pub(crate) fn new(init_events: Events) -> Self {
        let inner = alloc::sync::Arc::new(PolleeInner {
            subject: Subject::new(),
        });
        Self { inner }
    }

    /// Poll the pollee with the given mask of events and register the poller.
    pub(crate) fn poll<F>(
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
    pub fn wait_or_timeout<F, C, R>(
        &self,
        mask: Events,
        timeout: Option<core::time::Duration>,
        mut try_op: F,
        check: C,
    ) -> Result<R, Errno>
    where
        F: FnMut() -> Result<R, Errno>,
        C: FnOnce() -> Events,
    {
        // Try first without waiting
        match try_op() {
            Err(Errno::EAGAIN) => {}
            ret => return ret,
        }

        // Return immediately if the timeout is zero.
        if timeout.is_some_and(|d| d.is_zero()) {
            return Err(Errno::ETIMEDOUT);
        }

        let mut remaining_time = timeout;
        let poller = alloc::sync::Arc::new(Poller::new());
        let revents = self.poll(mask, Some(alloc::sync::Arc::downgrade(&poller) as _), check);
        if revents.is_empty() {
            poller.wait_or_timeout(&mut remaining_time)?;
        }

        loop {
            match try_op() {
                Err(Errno::EAGAIN) => {}
                ret => return ret,
            }

            poller.wait_or_timeout(&mut remaining_time)?;
        }
    }

    pub(crate) fn register_observer(
        &self,
        observer: alloc::sync::Weak<dyn Observer<Events>>,
        filter: Events,
    ) {
        self.inner
            .subject
            .register_observer(observer, filter | Events::ALWAYS_POLLED);
    }

    pub(crate) fn unregister_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>) {
        self.inner.subject.unregister_observer(observer);
    }

    pub(crate) fn notify_observers(&self, events: Events) {
        self.inner.subject.notify_observers(events);
    }
}

pub(crate) struct Poller {
    condvar: <litebox_platform_multiplex::Platform as RawMutexProvider>::RawMutex,
}

impl Poller {
    fn new() -> Self {
        Self {
            condvar: litebox_platform_multiplex::platform().new_raw_mutex(),
        }
    }

    fn wait(&self) -> bool {
        self.do_wait(None)
    }

    /// Wait for the poller to be notified.
    /// If the timeout is not None, it will be updated to the remaining time after waiting.
    pub fn wait_or_timeout(&self, timeout: &mut Option<core::time::Duration>) -> Result<(), Errno> {
        let ret = match timeout {
            Some(timeout) => {
                if timeout.is_zero() {
                    return Err(Errno::ETIMEDOUT);
                }

                let start_time = litebox_platform_multiplex::platform().now();
                let res = unsafe { self.do_wait(Some(*timeout)) };
                *timeout = timeout
                    .checked_sub(
                        start_time.duration_since(&litebox_platform_multiplex::platform().now()),
                    )
                    .unwrap_or_default();
                res
            }
            None => self.wait(),
        };
        if ret { Ok(()) } else { Err(Errno::ETIMEDOUT) }
    }

    fn do_wait(&self, timeout: Option<core::time::Duration>) -> bool {
        let futex = self.condvar.underlying_atomic();
        if futex.swap(0, core::sync::atomic::Ordering::Relaxed) == 0 {
            if let Some(timeout) = timeout {
                match self.condvar.block_or_timeout(0, timeout) {
                    Ok(litebox::platform::UnblockedOrTimedOut::TimedOut) => false,
                    Ok(litebox::platform::UnblockedOrTimedOut::Unblocked)
                    | Err(litebox::platform::ImmediatelyWokenUp) => true,
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

impl Observer<Events> for Poller {
    fn on_events(&self, events: &Events) {
        self.condvar
            .underlying_atomic()
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.condvar.wake_one();
    }
}
