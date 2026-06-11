// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Observer pattern utilities for event handling.

use alloc::collections::btree_map::BTreeMap;
use alloc::sync::{Arc, Weak};

#[cfg(not(feature = "loom"))]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "loom")]
use loom::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

/// A trait for filtering events of type `E`.
pub trait EventsFilter<E>: Send + Sync + 'static {
    /// Returns `true` if the event should be processed.
    fn filter(&self, event: &E) -> bool;
}

impl EventsFilter<super::Events> for super::Events {
    fn filter(&self, events: &Self) -> bool {
        self.intersects(*events)
    }
}

/// A trait for observers that can be notified of events.
pub trait Observer<E>: Send + Sync {
    /// Called when events of interest occur.
    fn on_events(&self, events: &E);
}

/// A key for managing observers with weak references.
///
/// This wrapper exists primarily to support `PartialOrd`/`Ord` on the `Weak` stored within it.
struct ObserverKey<E> {
    observer: Weak<dyn Observer<E>>,
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
    /// Create a new observer key from a weak reference.
    fn new(observer: Weak<dyn Observer<E>>) -> Self {
        Self { observer }
    }

    /// Attempt to upgrade the weak reference to a strong reference.
    fn upgrade(&self) -> Option<Arc<dyn Observer<E>>> {
        self.observer.upgrade()
    }
}

/// A Subject notifies interesting events to registered observers.
pub struct Subject<E, F: EventsFilter<E>, Platform: RawSyncPrimitivesProvider> {
    /// A table that maintains all interesting observers.
    observers: Mutex<Platform, BTreeMap<ObserverKey<E>, F>>,
    /// Number of observers.
    ///
    /// This is used purely for fast-path optimizations.
    nums: AtomicUsize,
}

impl<E, F: EventsFilter<E> + Default, Platform: RawSyncPrimitivesProvider> Default
    for Subject<E, F, Platform>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<E, F: EventsFilter<E>, Platform: RawSyncPrimitivesProvider> Subject<E, F, Platform> {
    /// Create a new subject.
    pub fn new() -> Self {
        Self {
            observers: Mutex::new(BTreeMap::new()),
            nums: AtomicUsize::new(0),
        }
    }

    /// Remove entries whose weak references are no longer alive, decrementing
    /// `nums` for each pruned entry.
    ///
    /// Called under the lock during registration to eagerly reclaim stale
    /// entries from observers that were dropped without being explicitly
    /// unregistered. `notify_observers` also calls this to prune before
    /// dispatching events.
    fn prune_dead_observers(&self, observers: &mut BTreeMap<ObserverKey<E>, F>) {
        observers.retain(|observer, _| {
            if observer.upgrade().is_some() {
                true
            } else {
                self.nums.fetch_sub(1, Ordering::Relaxed);
                false
            }
        });
    }

    /// Register an observer with the given filter.
    pub fn register_observer(&self, observer: Weak<dyn Observer<E>>, filter: F) {
        let mut observers = self.observers.lock();
        self.prune_dead_observers(&mut observers);
        if observers
            .insert(ObserverKey::new(observer), filter)
            .is_none()
        {
            self.nums.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Unregister an observer.
    pub fn unregister_observer(&self, observer: Weak<dyn Observer<E>>) {
        let mut observers = self.observers.lock();
        if observers.remove(&ObserverKey::new(observer)).is_some() {
            self.nums.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Notify all observers of the given events.
    pub fn notify_observers(&self, events: E) {
        if self.nums.load(Ordering::Relaxed) == 0 {
            return;
        }

        let mut observers = self.observers.lock();
        self.prune_dead_observers(&mut observers);
        for (observer, filter) in observers.iter() {
            if let Some(observer) = observer.upgrade()
                && filter.filter(&events)
            {
                observer.on_events(&events);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{Observer, Subject};
    use crate::{event::Events, platform::mock::MockPlatform};

    struct TestObserver {
        notifications: AtomicUsize,
    }

    impl Observer<Events> for TestObserver {
        fn on_events(&self, _events: &Events) {
            self.notifications.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn register_observer_prunes_dead_entries() {
        let subject = Subject::<Events, Events, MockPlatform>::new();

        let stale = Arc::new(TestObserver {
            notifications: AtomicUsize::new(0),
        });
        subject.register_observer(Arc::downgrade(&stale) as _, Events::IN);
        assert_eq!(subject.nums.load(Ordering::Relaxed), 1);
        assert_eq!(subject.observers.lock().len(), 1);
        drop(stale);

        let fresh = Arc::new(TestObserver {
            notifications: AtomicUsize::new(0),
        });
        subject.register_observer(Arc::downgrade(&fresh) as _, Events::OUT);
        {
            let observers = subject.observers.lock();
            let registered = observers
                .keys()
                .next()
                .and_then(super::ObserverKey::upgrade)
                .expect("dead observer should be pruned during registration");
            let fresh_observer: Arc<dyn Observer<Events>> = fresh.clone();
            assert!(Arc::ptr_eq(&registered, &fresh_observer));
            assert_eq!(subject.nums.load(Ordering::Relaxed), 1);
            assert_eq!(observers.len(), 1);
        }
        subject.notify_observers(Events::OUT);

        assert_eq!(fresh.notifications.load(Ordering::Relaxed), 1);
    }
}
