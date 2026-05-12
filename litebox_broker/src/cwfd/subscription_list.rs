// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-state-object subscription list and notification dispatch.
//!
//! Broker-hosted state objects (eventfd, timerfd, signalfd, TCP socket,
//! ...) accept zero or more *subscriptions* from worker processes.
//! Each subscription pins a `(subscription_id, events_mask, ring sender)`
//! triple: when the state changes in a way that matches `events_mask`,
//! the broker pushes one [`NotificationFrame`] to that worker's
//! notification ring via the captured sender.
//!
//! [`SubscriptionList`] is the reusable building block for that
//! observer pattern. Each concrete `StateObject` impl
//! (`EventfdState`, `TcpSocketState`, ...) embeds one and calls
//! [`SubscriptionList::notify`] from its state-mutation paths. Adding
//! new state-object types doesn't reinvent the subscription bookkeeping.
//!
//! # Concurrency
//!
//! Internally synchronised via a single [`std::sync::Mutex`]. The list
//! is small (one entry per worker holding a reference to this state),
//! so lock contention isn't expected. Notifications are sent under
//! the lock: the lock is held only for the iteration; each individual
//! `send` acquires the per-sender mutex independently. If contention
//! ever becomes an issue the list can be sharded or moved to an
//! `RwLock` with separate per-entry mutexes.
//!
//! # Phase boundary
//!
//! Phase B-Step3c — adds the observer mechanism without yet wiring
//! it into any concrete state type. Step 4 will use it from inside
//! `EventfdState`.

use std::sync::{Arc, Mutex};

use litebox_common_linux::notification_frame::{NOTIFY_EVENT_MASK_ALL, NotificationFrame};
use litebox_common_linux::notification_ring::NotificationSender;

/// Errors returned by [`SubscriptionList::add`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubscribeError {
    /// A subscription with the same `subscription_id` is already
    /// present on this state object. Worker bug — ids are
    /// worker-allocated and must be unique per-worker.
    #[error("subscription id {0} already registered on this state")]
    DuplicateId(u64),

    /// `events_mask` carried bits outside
    /// [`NOTIFY_EVENT_MASK_ALL`].
    #[error(
        "subscribe events_mask 0x{events_mask:08x} contains bits outside mask 0x{NOTIFY_EVENT_MASK_ALL:08x}"
    )]
    UnknownEventBits { events_mask: u32 },
}

/// Errors returned by [`SubscriptionList::remove`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UnsubscribeError {
    /// No subscription with the given id exists.
    #[error("no subscription with id {0} on this state")]
    UnknownId(u64),
}

/// One subscription entry. Wraps an `Arc<Mutex<NotificationSender>>`
/// because the sender is shared (one notification ring per worker;
/// many state objects may hold subscriptions referencing the same
/// worker, all needing to write to that worker's ring).
struct Subscription {
    id: u64,
    events_mask: u32,
    sender: Arc<Mutex<NotificationSender>>,
}

/// A simple observer list for a single broker-hosted state object.
/// See module-level docs for the model.
pub struct SubscriptionList {
    entries: Mutex<Vec<Subscription>>,
}

impl Default for SubscriptionList {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for SubscriptionList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let entries = self.entries.lock().expect("SubscriptionList poisoned");
        f.debug_struct("SubscriptionList")
            .field("len", &entries.len())
            .finish()
    }
}

impl SubscriptionList {
    /// Creates an empty list.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Adds a subscription. Returns [`SubscribeError::DuplicateId`]
    /// if a subscription with `id` already exists, or
    /// [`SubscribeError::UnknownEventBits`] if `events_mask` carries
    /// bits outside [`NOTIFY_EVENT_MASK_ALL`].
    pub fn add(
        &self,
        id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        if events_mask & !NOTIFY_EVENT_MASK_ALL != 0 {
            return Err(SubscribeError::UnknownEventBits { events_mask });
        }
        let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
        if entries.iter().any(|s| s.id == id) {
            return Err(SubscribeError::DuplicateId(id));
        }
        entries.push(Subscription {
            id,
            events_mask,
            sender,
        });
        Ok(())
    }

    /// Removes the subscription with `id`. Returns
    /// [`UnsubscribeError::UnknownId`] if no such subscription
    /// exists.
    pub fn remove(&self, id: u64) -> Result<(), UnsubscribeError> {
        let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
        let initial_len = entries.len();
        entries.retain(|s| s.id != id);
        if entries.len() == initial_len {
            return Err(UnsubscribeError::UnknownId(id));
        }
        Ok(())
    }

    /// Notifies every subscription whose `events_mask` intersects
    /// `events`. For each matching subscription, pushes a
    /// [`NotificationFrame`] carrying `(subscription_id, masked_events)`
    /// to that subscription's sender.
    ///
    /// Errors writing to a sender are logged via `tracing::warn` but
    /// do NOT propagate — a single dead worker must not block
    /// notifications to other workers subscribed to the same state.
    /// The dead subscription is left in the list; the worker's
    /// teardown path is responsible for issuing `unsubscribe`. If a
    /// caller wants to GC dead subscriptions sooner it can call
    /// [`Self::retain_live`] periodically.
    pub fn notify(&self, events: u32) {
        let entries = self.entries.lock().expect("SubscriptionList poisoned");
        for sub in entries.iter() {
            let matched = events & sub.events_mask;
            if matched == 0 {
                continue;
            }
            let frame = NotificationFrame::fixed(sub.id, matched);
            // Lock the sender briefly to write one frame. Hold time
            // bounded by the size of the notification frame plus
            // futex syscall — microseconds in the steady state.
            let mut sender = sub.sender.lock().expect("NotificationSender poisoned");
            if let Err(err) = sender.send(&frame) {
                tracing::warn!(
                    subscription_id = sub.id,
                    error = %err,
                    "notification send failed; leaving subscription in list",
                );
            }
        }
    }

    /// Returns the number of live subscriptions. Intended for tests
    /// and telemetry.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("SubscriptionList poisoned")
            .len()
    }

    /// Returns true if there are no subscriptions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes any subscription whose sender's `Arc` strong count is
    /// 1 (i.e. only the list itself holds a reference). Intended for
    /// periodic GC of subscriptions whose worker has died.
    pub fn retain_live(&self) {
        let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
        entries.retain(|s| Arc::strong_count(&s.sender) > 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
    use litebox_common_linux::notification_ring::NotificationReceiver;
    use litebox_common_linux::shmem_ring::ShmemRingPair;

    /// Build one `(sender, receiver)` pair plus an `Arc<Mutex<>>`-wrapped
    /// sender suitable for adding to a SubscriptionList.
    fn make_pair() -> (Arc<Mutex<NotificationSender>>, NotificationReceiver) {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        let (broker_writer, _broker_reader_unused) = pair.into_parts();
        let (_worker_writer_unused, worker_reader) =
            ShmemRingPair::open(tx_fd, rx_fd).expect("ring open");
        (
            Arc::new(Mutex::new(NotificationSender::new(broker_writer))),
            NotificationReceiver::new(worker_reader),
        )
    }

    #[test]
    fn add_then_notify_delivers_frame() {
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, Arc::clone(&sender)).unwrap();
        list.notify(NOTIFY_EVENT_IN);
        let frame = receiver.recv().expect("recv");
        assert_eq!(frame.subscription_id(), 1);
        assert_eq!(frame.events(), NOTIFY_EVENT_IN);
    }

    #[test]
    fn notify_filters_by_events_mask() {
        let list = SubscriptionList::new();
        let (sender_in, mut receiver_in) = make_pair();
        let (sender_out, mut receiver_out) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender_in).unwrap();
        list.add(2, NOTIFY_EVENT_OUT, sender_out).unwrap();

        list.notify(NOTIFY_EVENT_IN);
        let frame = receiver_in.recv().unwrap();
        assert_eq!(frame.subscription_id(), 1);
        // receiver_out has nothing yet — recv would block. Test by
        // sending a sentinel through OUT and confirming it arrives
        // BEFORE any IN-only notification.
        list.notify(NOTIFY_EVENT_OUT);
        let frame_out = receiver_out.recv().unwrap();
        assert_eq!(frame_out.subscription_id(), 2);
        assert_eq!(frame_out.events(), NOTIFY_EVENT_OUT);
    }

    #[test]
    fn notify_with_partial_match_delivers_only_matched_bits() {
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender).unwrap();
        // Notify with IN|OUT — subscription only wants IN.
        list.notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 1);
        // Only the IN bit, not OUT.
        assert_eq!(frame.events(), NOTIFY_EVENT_IN);
    }

    #[test]
    fn add_duplicate_id_errors() {
        let list = SubscriptionList::new();
        let (sender, _r) = make_pair();
        list.add(7, NOTIFY_EVENT_IN, Arc::clone(&sender)).unwrap();
        match list.add(7, NOTIFY_EVENT_OUT, sender) {
            Err(SubscribeError::DuplicateId(7)) => {}
            other => panic!("expected DuplicateId(7), got {other:?}"),
        }
    }

    #[test]
    fn add_unknown_event_bits_errors() {
        let list = SubscriptionList::new();
        let (sender, _r) = make_pair();
        match list.add(1, 0x8000_0000, sender) {
            Err(SubscribeError::UnknownEventBits {
                events_mask: 0x8000_0000,
            }) => {}
            other => panic!("expected UnknownEventBits, got {other:?}"),
        }
    }

    #[test]
    fn remove_unknown_id_errors() {
        let list = SubscriptionList::new();
        match list.remove(42) {
            Err(UnsubscribeError::UnknownId(42)) => {}
            other => panic!("expected UnknownId(42), got {other:?}"),
        }
    }

    #[test]
    fn remove_then_notify_does_not_deliver() {
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender).unwrap();
        assert_eq!(list.len(), 1);
        list.remove(1).unwrap();
        assert_eq!(list.len(), 0);
        list.notify(NOTIFY_EVENT_IN);

        // Receiver should NOT have anything. Drop the broker side and
        // confirm EOF rather than a frame.
        drop(list);
        match receiver.recv() {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected EOF, got {other:?}"),
        }
    }

    #[test]
    fn multiple_subscriptions_each_get_their_frame() {
        let list = SubscriptionList::new();
        let (sender1, mut receiver1) = make_pair();
        let (sender2, mut receiver2) = make_pair();
        let (sender3, mut receiver3) = make_pair();
        list.add(10, NOTIFY_EVENT_IN, sender1).unwrap();
        list.add(20, NOTIFY_EVENT_IN, sender2).unwrap();
        list.add(30, NOTIFY_EVENT_IN, sender3).unwrap();

        list.notify(NOTIFY_EVENT_IN);
        let f1 = receiver1.recv().unwrap();
        let f2 = receiver2.recv().unwrap();
        let f3 = receiver3.recv().unwrap();
        assert_eq!(f1.subscription_id(), 10);
        assert_eq!(f2.subscription_id(), 20);
        assert_eq!(f3.subscription_id(), 30);
        for f in [f1, f2, f3] {
            assert_eq!(f.events(), NOTIFY_EVENT_IN);
        }
    }

    #[test]
    fn retain_live_drops_subscriptions_whose_sender_is_only_in_list() {
        let list = SubscriptionList::new();

        // sender1: caller drops its Arc immediately — list is sole holder.
        let (sender1, _r1) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender1).unwrap();
        // sender2: caller retains its Arc.
        let (sender2, _r2) = make_pair();
        list.add(2, NOTIFY_EVENT_IN, Arc::clone(&sender2)).unwrap();

        assert_eq!(list.len(), 2);
        list.retain_live();
        // Subscription 1's sender was held only by the list (strong=1) → dropped.
        // Subscription 2's sender is held by us too (strong=2) → kept.
        assert_eq!(list.len(), 1);

        // Make sure surviving subscription still delivers.
        let (_keep, mut receiver2) = (sender2, _r2);
        list.notify(NOTIFY_EVENT_IN);
        let f = receiver2.recv().unwrap();
        assert_eq!(f.subscription_id(), 2);
    }

    #[test]
    fn empty_list_notify_is_noop() {
        let list = SubscriptionList::new();
        list.notify(NOTIFY_EVENT_IN);
        assert!(list.is_empty());
    }
}
