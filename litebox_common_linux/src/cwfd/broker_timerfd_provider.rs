// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted timerfd operations.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Plain no_std representation of Linux `itimerspec`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrokerTimerfdSpec {
    pub interval_sec: u64,
    pub interval_nsec: u64,
    pub value_sec: u64,
    pub value_nsec: u64,
}

/// Trait abstraction over broker-hosted timerfd state.
pub trait BrokerTimerfdProvider: BrokerSubscribable {
    /// Creates a broker-hosted timerfd for `clockid` and raw timerfd `flags`.
    fn create_timerfd(&self, clockid: i32, flags: u32) -> Result<u64, BrokerOpError>;

    /// Arms or disarms a broker-hosted timerfd with raw `timerfd_settime` flags.
    fn settime_timerfd(
        &self,
        handle: u64,
        new_value: BrokerTimerfdSpec,
        flags: u32,
    ) -> Result<(), BrokerOpError>;

    /// Returns the remaining time and interval for a broker-hosted timerfd.
    fn gettime_timerfd(&self, handle: u64) -> Result<BrokerTimerfdSpec, BrokerOpError>;

    /// Reads and clears the accumulated expiration count.
    fn read_timerfd(&self, handle: u64) -> Result<u64, BrokerOpError>;
}

#[cfg(feature = "std")]
pub mod test_util {
    //! In-process test double for shim/unit tests that need a
    //! [`BrokerTimerfdProvider`] without a real broker connection.

    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use crate::cwfd::broker_subscribable::BrokerSubscribable;
    use crate::cwfd::notification_frame::NOTIFY_EVENT_IN;

    use super::{BrokerEventCallback, BrokerOpError, BrokerTimerfdProvider, BrokerTimerfdSpec};

    #[derive(Debug, Default)]
    struct TimerEntry {
        spec: BrokerTimerfdSpec,
        expirations: u64,
        refcount: u32,
        next_subscription_id: u64,
        subscriptions: BTreeMap<u64, SubscriptionEntry>,
    }

    #[derive(Clone)]
    struct SubscriptionEntry {
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    }

    impl core::fmt::Debug for SubscriptionEntry {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SubscriptionEntry")
                .field("events_mask", &self.events_mask)
                .finish_non_exhaustive()
        }
    }

    #[derive(Debug)]
    struct Inner {
        next_handle: u64,
        timers: BTreeMap<u64, TimerEntry>,
    }

    impl Default for Inner {
        fn default() -> Self {
            Self {
                next_handle: 1,
                timers: BTreeMap::new(),
            }
        }
    }

    /// Reusable, broker-free [`BrokerTimerfdProvider`] implementation for tests.
    ///
    /// The double deliberately does not run a wall-clock event loop. Tests drive
    /// expiration manually with [`Self::fire_timerfd`], matching the current
    /// broker-held timerfd phase boundary where firing is explicit.
    #[derive(Debug, Default)]
    pub struct TestBrokerTimerfdProvider {
        inner: Mutex<Inner>,
    }

    impl TestBrokerTimerfdProvider {
        pub fn new() -> Self {
            Self::default()
        }

        /// Manually accrues `expirations` on `handle`.
        ///
        /// A transition from not-readable to readable invokes all matching
        /// callbacks with `NOTIFY_EVENT_IN`, matching broker level-triggered
        /// wake semantics.
        pub fn fire_timerfd(&self, handle: u64, expirations: u64) -> Result<(), BrokerOpError> {
            if expirations == 0 {
                return Ok(());
            }
            let callbacks = {
                let mut inner = self
                    .inner
                    .lock()
                    .expect("TestBrokerTimerfdProvider poisoned");
                let timer = inner
                    .timers
                    .get_mut(&handle)
                    .ok_or(BrokerOpError::UnknownHandle)?;
                let was_readable = timer.expirations > 0;
                timer.expirations = timer.expirations.saturating_add(expirations);
                if was_readable {
                    Vec::new()
                } else {
                    matching_callbacks(timer)
                }
            };
            for callback in callbacks {
                callback.on_events(NOTIFY_EVENT_IN);
            }
            Ok(())
        }

        pub fn is_live(&self, handle: u64) -> bool {
            self.inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned")
                .timers
                .contains_key(&handle)
        }

        pub fn refcount(&self, handle: u64) -> u32 {
            self.inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned")
                .timers
                .get(&handle)
                .map(|timer| timer.refcount)
                .unwrap_or(0)
        }

        pub fn subscription_count(&self, handle: u64) -> Result<usize, BrokerOpError> {
            let inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let timer = inner
                .timers
                .get(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            Ok(timer.subscriptions.len())
        }
    }

    impl BrokerSubscribable for TestBrokerTimerfdProvider {
        fn subscribe(
            &self,
            handle: u64,
            events_mask: u32,
            callback: Arc<dyn BrokerEventCallback>,
        ) -> Result<u64, BrokerOpError> {
            let (subscription_id, initial_callback) = {
                let mut inner = self
                    .inner
                    .lock()
                    .expect("TestBrokerTimerfdProvider poisoned");
                let timer = inner
                    .timers
                    .get_mut(&handle)
                    .ok_or(BrokerOpError::UnknownHandle)?;
                let subscription_id = timer.next_subscription_id;
                timer.next_subscription_id = timer
                    .next_subscription_id
                    .checked_add(1)
                    .ok_or(BrokerOpError::InvalidValue)?;
                let initial_callback = (timer.expirations > 0
                    && events_mask & NOTIFY_EVENT_IN != 0)
                    .then(|| Arc::clone(&callback));
                timer.subscriptions.insert(
                    subscription_id,
                    SubscriptionEntry {
                        events_mask,
                        callback,
                    },
                );
                (subscription_id, initial_callback)
            };
            if let Some(callback) = initial_callback {
                callback.on_events(NOTIFY_EVENT_IN);
            }
            Ok(subscription_id)
        }

        fn unsubscribe(&self, handle: u64, subscription_id: u64) {
            let mut inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            if let Some(timer) = inner.timers.get_mut(&handle) {
                timer.subscriptions.remove(&subscription_id);
            }
        }

        fn release(&self, handle: u64) {
            let mut inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let Some(timer) = inner.timers.get_mut(&handle) else {
                return;
            };
            timer.refcount = timer.refcount.saturating_sub(1);
            if timer.refcount == 0 {
                inner.timers.remove(&handle);
            }
        }

        fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
            let mut inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let timer = inner
                .timers
                .get_mut(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            timer.refcount = timer
                .refcount
                .checked_add(1)
                .ok_or(BrokerOpError::InvalidValue)?;
            Ok(())
        }

        fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
            let inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let timer = inner
                .timers
                .get(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            Ok(if timer.expirations > 0 {
                NOTIFY_EVENT_IN
            } else {
                0
            })
        }
    }

    impl BrokerTimerfdProvider for TestBrokerTimerfdProvider {
        fn create_timerfd(&self, _clockid: i32, _flags: u32) -> Result<u64, BrokerOpError> {
            let mut inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let handle = inner.next_handle;
            inner.next_handle = inner
                .next_handle
                .checked_add(1)
                .ok_or(BrokerOpError::InvalidValue)?;
            inner.timers.insert(
                handle,
                TimerEntry {
                    refcount: 1,
                    ..TimerEntry::default()
                },
            );
            Ok(handle)
        }

        fn settime_timerfd(
            &self,
            handle: u64,
            new_value: BrokerTimerfdSpec,
            _flags: u32,
        ) -> Result<(), BrokerOpError> {
            let mut inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let timer = inner
                .timers
                .get_mut(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            timer.spec = new_value;
            timer.expirations = 0;
            Ok(())
        }

        fn gettime_timerfd(&self, handle: u64) -> Result<BrokerTimerfdSpec, BrokerOpError> {
            let inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let timer = inner
                .timers
                .get(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            Ok(timer.spec)
        }

        fn read_timerfd(&self, handle: u64) -> Result<u64, BrokerOpError> {
            let mut inner = self
                .inner
                .lock()
                .expect("TestBrokerTimerfdProvider poisoned");
            let timer = inner
                .timers
                .get_mut(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            if timer.expirations == 0 {
                return Err(BrokerOpError::WouldBlock);
            }
            let expirations = timer.expirations;
            timer.expirations = 0;
            Ok(expirations)
        }
    }

    fn matching_callbacks(timer: &TimerEntry) -> Vec<Arc<dyn BrokerEventCallback>> {
        timer
            .subscriptions
            .values()
            .filter(|subscription| subscription.events_mask & NOTIFY_EVENT_IN != 0)
            .map(|subscription| Arc::clone(&subscription.callback))
            .collect()
    }
}
