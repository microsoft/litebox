// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted eventfd state.
//!
//! [`EventfdState`] is the canonical broker-side state for one Linux
//! eventfd. Workers reference it via opaque [`StateHandle`]s; reads,
//! writes, and pollability are mediated by RPCs over the TCP control
//! socket, while broker-pushed wake notifications travel via the
//! per-worker notification ring (Phase B-Step3 infrastructure).
//!
//! # Linux eventfd semantics (Phase B-Step4 scope)
//!
//! - A `u64` counter, starting at `initial` (caller-supplied at create).
//! - `write(val)` adds `val` to the counter. Errors:
//!     * `InvalidWriteValue` if `val == u64::MAX` (Linux returns
//!       EINVAL).
//!     * `WouldBlock` if `counter + val` would exceed `u64::MAX - 1`
//!       (Linux blocks in this case — we expose `WouldBlock` and let
//!       the worker decide whether to retry).
//! - `read()`:
//!     * Returns `WouldBlock` if `counter == 0` (Linux blocks; we
//!       surface and let the worker decide).
//!     * In default mode: returns the counter and resets to 0.
//!     * In semaphore mode: returns 1 and decrements counter by 1.
//! - Pollability:
//!     * `EPOLLIN` ready ⟺ counter > 0.
//!     * `EPOLLOUT` ready ⟺ counter < `u64::MAX - 1`.
//!     * `EPOLLERR` / `EPOLLHUP` not used by eventfd in standard Linux
//!       semantics; left for future-proofing.
//!
//! After each mutating op, the broker computes the new ready-event
//! set and calls [`SubscriptionList::notify`] with it. Subscribers
//! whose `events_mask` matches receive a notification frame.
//!
//! # Concurrency
//!
//! The counter is a `Mutex<u64>`. Notify is called inside the lock
//! scope (after updating the counter, before releasing) so observers
//! see a coherent state transition. Holding the lock across the
//! subscription-list iteration is acceptable: notifications are
//! per-subscription `Arc<Mutex<NotificationSender>>` writes, each
//! microsecond-scale; the eventfd counter lock is local to one
//! state instance.
//!
//! # Phase boundary
//!
//! Phase B-Step4: broker-side state with observer dispatch. No IPC
//! integration yet — the state-service dispatcher (Step 6) wires
//! Register / Read / Write / Subscribe RPCs into these methods.

use core::any::Any;
use std::sync::{Arc, Mutex};

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// The largest legal counter value. Linux eventfd refuses to accept a
/// write that would push the counter past `u64::MAX - 1`; reads can
/// see at most `u64::MAX - 1` in default mode.
pub const EVENTFD_MAX: u64 = u64::MAX - 1;

/// Errors returned by the eventfd op methods.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EventfdError {
    /// Linux eventfd semantics: this op would block. Worker decides
    /// whether to retry, return EAGAIN to guest, or pin a thread.
    #[error("eventfd op would block")]
    WouldBlock,

    /// `write(u64::MAX)` — Linux returns EINVAL for this specific
    /// value (sentinel used internally by the kernel).
    #[error("eventfd write value {0} is invalid (== u64::MAX)")]
    InvalidWriteValue(u64),
}

/// Broker-hosted state for one Linux eventfd.
#[derive(Debug)]
pub struct EventfdState {
    inner: Mutex<EventfdInner>,
    semaphore: bool,
    subscriptions: SubscriptionList,
}

#[derive(Debug)]
struct EventfdInner {
    counter: u64,
}

impl EventfdState {
    /// Creates a new eventfd state with `initial` counter and the
    /// given mode (`semaphore = true` → semaphore-style read).
    pub fn new(initial: u64, semaphore: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(EventfdInner { counter: initial }),
            semaphore,
            subscriptions: SubscriptionList::new(),
        })
    }

    /// Reads the counter per Linux eventfd semantics. Returns
    /// [`EventfdError::WouldBlock`] if the counter is 0.
    pub fn read(&self) -> Result<u64, EventfdError> {
        let mut inner = self.inner.lock().expect("EventfdState poisoned");
        if inner.counter == 0 {
            return Err(EventfdError::WouldBlock);
        }
        let value = if self.semaphore {
            inner.counter -= 1;
            1
        } else {
            let v = inner.counter;
            inner.counter = 0;
            v
        };
        // After read, OUT may have become ready (counter dropped below MAX).
        // IN: counter may have become 0 (no longer ready).
        let events = current_events_unlocked(inner.counter);
        // Drop lock before notify to avoid lock-order issues with
        // sender mutexes.
        drop(inner);
        if events != 0 {
            self.subscriptions.notify(events);
        }
        Ok(value)
    }

    /// Writes (adds `val` to the counter) per Linux eventfd semantics.
    /// Returns [`EventfdError::WouldBlock`] if the add would exceed
    /// [`EVENTFD_MAX`], or [`EventfdError::InvalidWriteValue`] if
    /// `val == u64::MAX`.
    pub fn write(&self, val: u64) -> Result<(), EventfdError> {
        if val == u64::MAX {
            return Err(EventfdError::InvalidWriteValue(val));
        }
        let mut inner = self.inner.lock().expect("EventfdState poisoned");
        // EVENTFD_MAX is the maximum *post-write* counter value.
        let new_counter = inner.counter.checked_add(val).filter(|&c| c <= EVENTFD_MAX);
        let new_counter = match new_counter {
            Some(c) => c,
            None => return Err(EventfdError::WouldBlock),
        };
        inner.counter = new_counter;
        let events = current_events_unlocked(inner.counter);
        drop(inner);
        if events != 0 {
            self.subscriptions.notify(events);
        }
        Ok(())
    }

    /// Returns the current counter value without modifying it.
    /// Intended for tests and broker telemetry.
    pub fn current_value(&self) -> u64 {
        self.inner.lock().expect("EventfdState poisoned").counter
    }

    /// Returns the currently-ready events (`NOTIFY_EVENT_IN` and/or
    /// `NOTIFY_EVENT_OUT`) given the current counter.
    pub fn current_events(&self) -> u32 {
        let counter = self.inner.lock().expect("EventfdState poisoned").counter;
        current_events_unlocked(counter)
    }

    /// Subscribes to events. Forwards to the underlying
    /// [`SubscriptionList`]. Immediately also pushes an initial
    /// notification for whichever subscribed events are currently
    /// ready — this matches Linux level-triggered poll semantics
    /// where calling `epoll_ctl(ADD)` on an already-readable fd
    /// surfaces a wake on the next `epoll_wait`.
    pub fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        // Compute snapshot of current state under lock so we don't
        // race against a concurrent write between the registration
        // and the priming send.
        let inner = self.inner.lock().expect("EventfdState poisoned");
        let now_events = current_events_unlocked(inner.counter);
        drop(inner);

        self.subscriptions
            .add(subscription_id, events_mask, sender)?;

        // After successful add, prime the new subscription if any of
        // its events are already ready.
        let initial = now_events & events_mask;
        if initial != 0 {
            // Notify with the full current mask — the subscription
            // list will filter to this subscription's mask anyway.
            // (Other subscriptions also see the same events, which
            // is correct: their state hasn't changed since they were
            // last notified.)
            //
            // To avoid a spurious notification storm we'd need a
            // per-subscription "last-delivered" mark. Punt to a
            // later optimisation if it matters.
            self.subscriptions.notify(now_events);
        }
        Ok(())
    }

    /// Unsubscribes by id.
    pub fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subscriptions.remove(subscription_id)
    }

    /// Returns the number of live subscriptions. Test / telemetry.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

/// Computes the epoll-style ready-event mask for a given eventfd
/// counter value. `EPOLLIN` ⟺ counter > 0; `EPOLLOUT` ⟺ counter
/// < EVENTFD_MAX.
fn current_events_unlocked(counter: u64) -> u32 {
    let mut events = 0u32;
    if counter > 0 {
        events |= NOTIFY_EVENT_IN;
    }
    if counter < EVENTFD_MAX {
        events |= NOTIFY_EVENT_OUT;
    }
    events
}

impl StateObject for EventfdState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Eventfd
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        EventfdState::subscribe(self, subscription_id, events_mask, sender)
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        EventfdState::unsubscribe(self, subscription_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::notification_ring::NotificationReceiver;
    use litebox_common_linux::shmem_ring::ShmemRingPair;

    fn make_pair() -> (Arc<Mutex<NotificationSender>>, NotificationReceiver) {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        let (broker_writer, _unused) = pair.into_parts();
        let (_unused, worker_reader) = ShmemRingPair::open(tx_fd, rx_fd).expect("ring open");
        (
            Arc::new(Mutex::new(NotificationSender::new(broker_writer))),
            NotificationReceiver::new(worker_reader),
        )
    }

    #[test]
    fn new_counter_initialises_to_passed_value() {
        let s = EventfdState::new(0, false);
        assert_eq!(s.current_value(), 0);
        let s = EventfdState::new(42, false);
        assert_eq!(s.current_value(), 42);
    }

    #[test]
    fn write_adds_to_counter() {
        let s = EventfdState::new(0, false);
        s.write(5).unwrap();
        assert_eq!(s.current_value(), 5);
        s.write(7).unwrap();
        assert_eq!(s.current_value(), 12);
    }

    #[test]
    fn write_max_value_returns_invalid() {
        let s = EventfdState::new(0, false);
        match s.write(u64::MAX) {
            Err(EventfdError::InvalidWriteValue(v)) if v == u64::MAX => {}
            other => panic!("expected InvalidWriteValue, got {other:?}"),
        }
    }

    #[test]
    fn write_overflow_returns_wouldblock() {
        let s = EventfdState::new(EVENTFD_MAX - 5, false);
        s.write(5).unwrap();
        assert_eq!(s.current_value(), EVENTFD_MAX);
        match s.write(1) {
            Err(EventfdError::WouldBlock) => {}
            other => panic!("expected WouldBlock, got {other:?}"),
        }
        // Counter unchanged on WouldBlock.
        assert_eq!(s.current_value(), EVENTFD_MAX);
    }

    #[test]
    fn read_zero_returns_wouldblock() {
        let s = EventfdState::new(0, false);
        match s.read() {
            Err(EventfdError::WouldBlock) => {}
            other => panic!("expected WouldBlock, got {other:?}"),
        }
    }

    #[test]
    fn read_default_mode_returns_counter_and_resets() {
        let s = EventfdState::new(0, false);
        s.write(7).unwrap();
        let got = s.read().unwrap();
        assert_eq!(got, 7);
        assert_eq!(s.current_value(), 0);
    }

    #[test]
    fn read_semaphore_mode_returns_one_and_decrements() {
        let s = EventfdState::new(3, true);
        assert_eq!(s.read().unwrap(), 1);
        assert_eq!(s.current_value(), 2);
        assert_eq!(s.read().unwrap(), 1);
        assert_eq!(s.current_value(), 1);
        assert_eq!(s.read().unwrap(), 1);
        assert_eq!(s.current_value(), 0);
        match s.read() {
            Err(EventfdError::WouldBlock) => {}
            other => panic!("expected WouldBlock at empty, got {other:?}"),
        }
    }

    #[test]
    fn current_events_reflects_counter() {
        let s = EventfdState::new(0, false);
        assert_eq!(s.current_events(), NOTIFY_EVENT_OUT); // not readable, writable
        s.write(1).unwrap();
        assert_eq!(s.current_events(), NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);
        // Push to max: no longer writable, still readable.
        s.write(EVENTFD_MAX - 1).unwrap();
        assert_eq!(s.current_events(), NOTIFY_EVENT_IN);
    }

    #[test]
    fn subscribe_priming_delivers_initial_ready_events() {
        // Subscribe to a state whose counter is already > 0; the
        // subscription should get a priming notification for IN.
        let s = EventfdState::new(5, false);
        let (sender, mut receiver) = make_pair();
        s.subscribe(1, NOTIFY_EVENT_IN, sender).unwrap();
        let f = receiver.recv().unwrap();
        assert_eq!(f.subscription_id(), 1);
        assert_eq!(f.events(), NOTIFY_EVENT_IN);
    }

    #[test]
    fn subscribe_no_priming_when_not_ready() {
        // Subscribe to IN on a state whose counter is 0 — no priming.
        let s = EventfdState::new(0, false);
        let (sender, mut receiver) = make_pair();
        s.subscribe(1, NOTIFY_EVENT_IN, sender).unwrap();

        // Then write — should notify.
        s.write(1).unwrap();
        let f = receiver.recv().unwrap();
        assert_eq!(f.subscription_id(), 1);
        assert_eq!(f.events(), NOTIFY_EVENT_IN);
    }

    #[test]
    fn write_then_read_each_notifies() {
        let s = EventfdState::new(0, false);
        let (sender, mut receiver) = make_pair();
        s.subscribe(7, NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT, sender)
            .unwrap();
        // Priming: counter=0 → only OUT ready.
        let f = receiver.recv().unwrap();
        assert_eq!(f.events(), NOTIFY_EVENT_OUT);

        // Write 5 → IN+OUT ready.
        s.write(5).unwrap();
        let f = receiver.recv().unwrap();
        assert_eq!(f.events(), NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);

        // Read drains → counter=0, only OUT ready.
        let v = s.read().unwrap();
        assert_eq!(v, 5);
        let f = receiver.recv().unwrap();
        assert_eq!(f.events(), NOTIFY_EVENT_OUT);
    }

    #[test]
    fn multiple_subscribers_each_get_their_notification() {
        let s = EventfdState::new(0, false);
        let (s1, mut r1) = make_pair();
        let (s2, mut r2) = make_pair();
        s.subscribe(10, NOTIFY_EVENT_IN, s1).unwrap();
        s.subscribe(20, NOTIFY_EVENT_IN, s2).unwrap();
        // No priming because counter=0.

        s.write(1).unwrap();
        let f1 = r1.recv().unwrap();
        let f2 = r2.recv().unwrap();
        assert_eq!(f1.subscription_id(), 10);
        assert_eq!(f2.subscription_id(), 20);
    }

    #[test]
    fn unsubscribe_stops_notifications() {
        let s = EventfdState::new(0, false);
        let (sender, mut receiver) = make_pair();
        s.subscribe(1, NOTIFY_EVENT_IN, sender).unwrap();
        s.unsubscribe(1).unwrap();
        assert_eq!(s.subscription_count(), 0);

        // Mutate state, expect no notification.
        s.write(1).unwrap();

        // Drop the state to close the broker side; the receiver
        // should observe EOF, not a frame.
        drop(s);
        match receiver.recv() {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected EOF, got {other:?}"),
        }
    }

    #[test]
    fn state_object_tag_is_eventfd() {
        let s = EventfdState::new(0, false);
        // Cast to dyn StateObject to exercise the trait impl.
        let dyn_ref: &dyn StateObject = &*s;
        assert_eq!(dyn_ref.subsystem_tag(), SubsystemTag::Eventfd);
    }

    #[test]
    fn state_object_downcasts_to_concrete_type() {
        let s = EventfdState::new(7, false);
        let dyn_ref: &dyn StateObject = &*s;
        let concrete = dyn_ref
            .as_any()
            .downcast_ref::<EventfdState>()
            .expect("downcast");
        assert_eq!(concrete.current_value(), 7);
    }
}
