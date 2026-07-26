// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded, coalescing readiness publication state for one broker association.
//!
//! Backend readiness sources and the notification transport have very different
//! blocking behavior. A source discovers a readiness change while holding
//! backend state and must never wait for notification-ring capacity; the
//! notification ring is a bounded shared region whose producer blocks when the
//! local endpoint stops draining it.
//!
//! [`ReadinessPublisher`] separates the two. Sources call [`publish`] to record
//! the authoritative flags for an object, which only updates in-memory state.
//! [`publish_readiness`] owns the notification channel and repeatedly claims
//! pending updates, sends them, and reports completion.
//!
//! Because [`BrokerNotification::Readiness`] is a hint to re-check state rather
//! than an ordered transition, repeated updates for one handle collapse into a
//! single notification carrying the newest flags. Updates that arrive while a
//! notification is in flight are not lost: each entry carries a generation that
//! identifies its newest change, and a claim is confirmed only while the
//! generation it was taken from is still current.
//!
//! This type is transport-neutral and performs no transport I/O, so it holds no
//! thread, timer, or wake primitive and never waits for notification-ring
//! capacity. Deployments own those and wake their publisher whenever
//! [`publish`] reports [`PublishOutcome::Queued`].
//!
//! [`publish`]: ReadinessPublisher::publish
//! [`BrokerNotification::Readiness`]: litebox_broker_protocol::message::BrokerNotification::Readiness

use alloc::collections::VecDeque;

use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{BrokerNotification, ReadinessNotification};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_transport::channel::HostNotificationChannel;
use spin::mutex::SpinMutex;
use thiserror::Error;

/// Maximum number of objects one association tracks readiness for.
///
/// This matches the default broker-core reference limit, so a source that
/// retires an object as its backend resource is released stays well inside it.
/// It exists so that a source which does not, or a deployment that raises the
/// core limit, cannot grow publication state without limit.
pub const MAX_TRACKED_READINESS_OBJECTS: usize = 4096;

/// Error returned when readiness state cannot record an update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ReadinessPublishError {
    /// The association already tracks [`MAX_TRACKED_READINESS_OBJECTS`] objects.
    #[error("broker association already tracks the maximum number of readiness objects")]
    TooManyObjects,
}

/// Outcome of recording one readiness update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The update queued work the publisher may not know about yet, so the
    /// deployment must wake its publisher.
    Queued,
    /// The update needs no wake: it either matched the newest recorded state or
    /// joined a notification that is already queued or in flight, which carries
    /// the newest flags when it is published.
    Coalesced,
    /// The publisher is closed and the update was discarded.
    Closed,
}

/// One readiness notification claimed for publication.
///
/// The claim borrows the publisher it came from, so it cannot be confirmed
/// against a different one, and it is not `Copy`, so it cannot be replayed.
/// Dropping it without calling [`confirm`] requeues the update it carried, so
/// a send that fails or unwinds leaves the object publishable again. The
/// requeue is skipped when the update is no longer the current one to send:
/// retirement, closure, and a newer recorded change all supersede it.
///
/// [`confirm`]: Self::confirm
#[derive(Debug)]
pub(crate) struct PendingReadiness<'publisher> {
    publisher: &'publisher ReadinessPublisher,
    notification: ReadinessNotification,
    generation: u64,
}

impl PendingReadiness<'_> {
    /// Notification to send on the association notification channel.
    pub(crate) const fn notification(&self) -> ReadinessNotification {
        self.notification
    }

    /// Reports that the notification reached the notification channel.
    ///
    /// The pending mark is cleared only when the object still holds the
    /// generation the claim was taken from. Any change recorded while the
    /// notification was in flight leaves the object pending, including a change
    /// that returned to the published flags, because the local endpoint samples
    /// authoritative state independently and may have observed the intermediate
    /// value.
    pub(crate) fn confirm(self) {
        let mut state = self.publisher.state.lock();
        if let Some(entry) = state.entries.get_mut(&self.notification.handle)
            && entry.generation == self.generation
        {
            entry.dirty = false;
        }
        drop(state);
        core::mem::forget(self);
    }
}

impl Drop for PendingReadiness<'_> {
    fn drop(&mut self) {
        let mut state = self.publisher.state.lock();
        // A newer change has already requeued the object, and a retired or
        // closed publisher has nothing left to publish. The queued check is
        // defensive rather than load bearing, so no test can distinguish it: a
        // matching generation means no publication since this claim was taken,
        // and only publication or a requeue can queue the object, so a matching
        // generation already implies the object is unqueued.
        if let Some(entry) = state.entries.get_mut(&self.notification.handle)
            && entry.generation == self.generation
            && !entry.queued
        {
            entry.queued = true;
            state.queue.push_back(self.notification.handle);
        }
    }
}

/// Coalescing readiness publication state shared by backend sources and one
/// notification publisher.
#[derive(Debug)]
pub struct ReadinessPublisher {
    state: SpinMutex<PublisherState>,
}

#[derive(Debug)]
struct PublisherState {
    entries: HashMap<ObjectHandle, ReadinessEntry>,
    queue: VecDeque<ObjectHandle>,
    /// Generation to hand to the next recorded change.
    ///
    /// Generations are allocated publisher-wide rather than per object so that
    /// an object re-registered under a recycled handle cannot reuse a value a
    /// still-unconfirmed claim was taken from. Values are skipped freely; only
    /// their distinctness matters, which holds unless the counter wraps all the
    /// way back to a value a claim is still holding. That needs `2^64` recorded
    /// changes to elapse while one send is in flight, so it is treated as
    /// unreachable.
    next_generation: u64,
    closed: bool,
}

#[derive(Debug)]
struct ReadinessEntry {
    /// Newest authoritative flags recorded by a backend source.
    readiness: ReadinessFlags,
    /// Identifies the recorded change, and is replaced whenever one arrives.
    ///
    /// Confirmation compares this rather than the published flags because a
    /// notification only tells the local endpoint to re-check; the endpoint
    /// then samples authoritative state itself and may observe a value the
    /// publisher never sent. Flags that change and return to the published
    /// value are therefore still a change the endpoint must be told about.
    generation: u64,
    /// A change has not yet been confirmed as published.
    dirty: bool,
    /// The handle currently sits in `queue`.
    queued: bool,
}

impl Default for ReadinessPublisher {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadinessPublisher {
    /// Creates empty readiness publication state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SpinMutex::new(PublisherState {
                entries: HashMap::new(),
                queue: VecDeque::new(),
                next_generation: 0,
                closed: false,
            }),
        }
    }

    /// Records the authoritative readiness of one object.
    ///
    /// This never waits for notification-ring capacity, so backend sources may
    /// call it while holding their own state. The caller must wake the
    /// publisher when the outcome is [`PublishOutcome::Queued`].
    pub fn publish(
        &self,
        handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) -> Result<PublishOutcome, ReadinessPublishError> {
        let mut state = self.state.lock();
        if state.closed {
            return Ok(PublishOutcome::Closed);
        }
        let generation = state.next_generation;
        if let Some(entry) = state.entries.get_mut(&handle) {
            if entry.readiness == readiness {
                // Either the local endpoint already knows this value or a
                // claim carrying it is queued or in flight.
                return Ok(PublishOutcome::Coalesced);
            }
            entry.readiness = readiness;
            entry.generation = generation;
            entry.dirty = true;
            let already_queued = entry.queued;
            entry.queued = true;
            state.next_generation = generation.wrapping_add(1);
            if already_queued {
                return Ok(PublishOutcome::Coalesced);
            }
        } else {
            if state.entries.len() >= MAX_TRACKED_READINESS_OBJECTS {
                return Err(ReadinessPublishError::TooManyObjects);
            }
            state.entries.insert(
                handle,
                ReadinessEntry {
                    readiness,
                    generation,
                    dirty: true,
                    queued: true,
                },
            );
            state.next_generation = generation.wrapping_add(1);
        }
        state.queue.push_back(handle);
        Ok(PublishOutcome::Queued)
    }

    /// Claims the next pending readiness notification, if any.
    ///
    /// The claim leaves the object marked pending until it is confirmed, so a
    /// change recorded while it is in flight is republished rather than lost.
    /// A claim that is dropped unconfirmed requeues the object, so a failed or
    /// unwinding send leaves the update publishable by a later publisher.
    #[must_use]
    pub(crate) fn take_pending(&self) -> Option<PendingReadiness<'_>> {
        let mut state = self.state.lock();
        while let Some(handle) = state.queue.pop_front() {
            let Some(entry) = state.entries.get_mut(&handle) else {
                continue;
            };
            entry.queued = false;
            if !entry.dirty {
                continue;
            }
            let notification = ReadinessNotification {
                handle,
                readiness: entry.readiness,
            };
            let generation = entry.generation;
            drop(state);
            return Some(PendingReadiness {
                publisher: self,
                notification,
                generation,
            });
        }
        None
    }

    /// Drops readiness state for an object whose backend resource is retired.
    ///
    /// Notifications already claimed for the object stay valid to send. A
    /// notification that arrives after retirement is ignored by the local
    /// endpoint, or, if the handle has since been recycled, is treated as a
    /// spurious hint to re-check the new object.
    pub fn retire(&self, handle: ObjectHandle) {
        let mut state = self.state.lock();
        if state.entries.remove(&handle).is_some() {
            state.queue.retain(|queued| *queued != handle);
        }
    }

    /// Closes publication permanently and discards pending state.
    ///
    /// Later updates are discarded and no further claim is produced, so a
    /// publisher woken during association teardown observes [`is_closed`] and
    /// stops.
    ///
    /// [`is_closed`]: Self::is_closed
    pub fn close(&self) {
        let mut state = self.state.lock();
        state.closed = true;
        state.entries.clear();
        state.queue.clear();
    }

    /// Reports whether publication is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.lock().closed
    }

    /// Number of objects with recorded readiness state.
    #[must_use]
    pub fn tracked_objects(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Number of queue slots holding work, which must never exceed the number
    /// of tracked objects.
    #[cfg(test)]
    fn queued_updates(&self) -> usize {
        self.state.lock().queue.len()
    }
}

/// Publishes coalesced readiness updates until publication closes.
///
/// This is the single owner of `channel`. Sending may block when the local
/// endpoint stops draining the notification transport; backend sources calling
/// [`ReadinessPublisher::publish`] are unaffected because they never touch the
/// channel.
///
/// `wait_for_work` parks the caller while nothing is pending. It must return
/// once [`ReadinessPublisher::publish`] reports [`PublishOutcome::Queued`] or
/// [`ReadinessPublisher::close`] runs, so association teardown always ends the
/// loop. Deployments that must also interrupt an in-progress send do so through
/// their transport, which fails the blocked send.
///
/// Returns `Ok(())` once publication is closed and no claim is outstanding. A
/// failed send returns its error with the claimed update left publishable, so
/// resuming on a replacement channel does not lose the notification; the
/// requeue raises no wake of its own, so a deployment that resumes must call
/// this again rather than wait for one.
pub fn publish_readiness<Channel: HostNotificationChannel>(
    publisher: &ReadinessPublisher,
    channel: &mut Channel,
    mut wait_for_work: impl FnMut(),
) -> Result<(), Channel::Error> {
    loop {
        if let Some(pending) = publisher.take_pending() {
            channel.send_notification(&BrokerNotification::Readiness(pending.notification()))?;
            pending.confirm();
            continue;
        }
        if publisher.is_closed() {
            return Ok(());
        }
        wait_for_work();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deadline for every test wait, so a regression fails instead of hanging.
    const TEST_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);
    const HANDLE: ObjectHandle = ObjectHandle(7);
    const OTHER_HANDLE: ObjectHandle = ObjectHandle(9);

    fn publish(publisher: &ReadinessPublisher, handle: ObjectHandle, readiness: ReadinessFlags) {
        publisher.publish(handle, readiness).unwrap();
    }

    fn drain(publisher: &ReadinessPublisher) -> alloc::vec::Vec<ReadinessNotification> {
        let mut drained = alloc::vec::Vec::new();
        while let Some(pending) = publisher.take_pending() {
            drained.push(pending.notification());
            pending.confirm();
        }
        drained
    }

    #[test]
    fn repeating_known_readiness_publishes_nothing() {
        let publisher = ReadinessPublisher::new();
        assert_eq!(
            publisher.publish(HANDLE, ReadinessFlags::READ).unwrap(),
            PublishOutcome::Queued
        );
        drain(&publisher);

        assert_eq!(
            publisher.publish(HANDLE, ReadinessFlags::READ).unwrap(),
            PublishOutcome::Coalesced
        );

        assert!(publisher.take_pending().is_none());
    }

    #[test]
    fn queued_updates_collapse_to_the_newest_flags() {
        let publisher = ReadinessPublisher::new();

        publish(&publisher, HANDLE, ReadinessFlags::READ);
        assert_eq!(
            publisher
                .publish(HANDLE, ReadinessFlags::READ | ReadinessFlags::WRITE)
                .unwrap(),
            PublishOutcome::Coalesced
        );
        publish(&publisher, HANDLE, ReadinessFlags::HANGUP);

        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::HANGUP,
            }]
        );
    }

    #[test]
    fn updates_during_publication_are_republished() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);

        let pending = publisher.take_pending().unwrap();
        assert_eq!(
            publisher.publish(HANDLE, ReadinessFlags::WRITE).unwrap(),
            PublishOutcome::Queued
        );
        pending.confirm();

        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::WRITE,
            }]
        );
    }

    #[test]
    fn readiness_that_returns_to_the_claimed_value_is_still_republished() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        let pending = publisher.take_pending().unwrap();

        // The local endpoint re-checks authoritative state on its own after a
        // notification, so it may sample the intermediate value. Returning to
        // the claimed value is therefore still a change it must be told about,
        // which is why confirmation compares generations and not flags.
        publish(&publisher, HANDLE, ReadinessFlags::WRITE);
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        pending.confirm();

        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::READ,
            }]
        );
    }

    #[test]
    fn retiring_an_object_drops_its_queued_update() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        publish(&publisher, OTHER_HANDLE, ReadinessFlags::WRITE);

        publisher.retire(HANDLE);

        assert_eq!(publisher.tracked_objects(), 1);
        // The queued slot goes with the object; leaving it behind would let a
        // local grow the queue without bound by cycling objects.
        assert_eq!(publisher.queued_updates(), 1);
        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: OTHER_HANDLE,
                readiness: ReadinessFlags::WRITE,
            }]
        );
    }

    #[test]
    fn confirming_a_retired_object_does_not_resurrect_it() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        let pending = publisher.take_pending().unwrap();

        publisher.retire(HANDLE);
        pending.confirm();

        assert_eq!(publisher.tracked_objects(), 0);
        assert!(publisher.take_pending().is_none());
    }

    #[test]
    fn a_reused_handle_starts_from_unknown_readiness() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        drain(&publisher);

        publisher.retire(HANDLE);

        assert_eq!(
            publisher.publish(HANDLE, ReadinessFlags::READ).unwrap(),
            PublishOutcome::Queued
        );
    }

    #[test]
    fn confirming_a_stale_claim_keeps_the_new_update() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        let stale = publisher.take_pending().unwrap();

        // The object is retired and the handle is recycled for a new object
        // while the first claim is still in flight.
        publisher.retire(HANDLE);
        publish(&publisher, HANDLE, ReadinessFlags::WRITE);
        stale.confirm();

        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::WRITE,
            }]
        );
    }

    #[test]
    fn closing_discards_state_and_later_updates() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);

        publisher.close();

        assert!(publisher.is_closed());
        assert!(publisher.take_pending().is_none());
        assert_eq!(
            publisher.publish(HANDLE, ReadinessFlags::WRITE).unwrap(),
            PublishOutcome::Closed
        );
        assert_eq!(publisher.tracked_objects(), 0);
    }

    #[test]
    fn tracking_is_bounded() {
        let publisher = ReadinessPublisher::new();
        for index in 0..MAX_TRACKED_READINESS_OBJECTS {
            publish(&publisher, ObjectHandle(index as u64), ReadinessFlags::READ);
        }

        assert_eq!(
            publisher.publish(ObjectHandle(u64::MAX), ReadinessFlags::READ),
            Err(ReadinessPublishError::TooManyObjects)
        );

        // Retiring an object makes room again.
        publisher.retire(ObjectHandle(0));
        assert_eq!(
            publisher.publish(ObjectHandle(u64::MAX), ReadinessFlags::READ),
            Ok(PublishOutcome::Queued)
        );
    }

    #[test]
    fn repeated_updates_queue_one_claim_per_object() {
        let publisher = ReadinessPublisher::new();
        for round in 1..=8u32 {
            for handle in 0..4u64 {
                publish(&publisher, ObjectHandle(handle), ReadinessFlags(round));
            }
        }

        let drained = drain(&publisher);

        assert_eq!(drained.len(), 4);
        assert!(
            drained
                .iter()
                .all(|notification| notification.readiness == ReadinessFlags(8))
        );
    }

    /// Notification channel that hands each notification to the test thread and
    /// then blocks until the test releases it, modelling a full ring.
    struct GatedChannel {
        sent: std::sync::mpsc::SyncSender<BrokerNotification>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl HostNotificationChannel for GatedChannel {
        type Error = &'static str;

        fn send_notification(
            &mut self,
            notification: &BrokerNotification,
        ) -> Result<(), Self::Error> {
            self.sent
                .send(notification.clone())
                .map_err(|_| "test receiver dropped")?;
            self.release.recv().map_err(|_| "test releaser dropped")
        }
    }

    struct FailingChannel;

    impl HostNotificationChannel for FailingChannel {
        type Error = &'static str;

        fn send_notification(
            &mut self,
            _notification: &BrokerNotification,
        ) -> Result<(), Self::Error> {
            Err("notification channel failed")
        }
    }

    struct PanickingChannel;

    impl HostNotificationChannel for PanickingChannel {
        type Error = &'static str;

        fn send_notification(
            &mut self,
            _notification: &BrokerNotification,
        ) -> Result<(), Self::Error> {
            panic!("notification channel panicked")
        }
    }

    fn readiness_of(notification: &BrokerNotification) -> ReadinessNotification {
        let BrokerNotification::Readiness(readiness) = notification;
        *readiness
    }

    /// Runs publication on its own thread and reports its result through a
    /// channel, so a loop that never ends fails a test on the deadline instead
    /// of blocking it forever.
    fn spawn_publication(
        publisher: std::sync::Arc<ReadinessPublisher>,
        mut channel: GatedChannel,
        mut wait_for_work: impl FnMut() + Send + 'static,
    ) -> std::sync::mpsc::Receiver<Result<(), &'static str>> {
        let (finished, finish) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = finished.send(publish_readiness(
                &publisher,
                &mut channel,
                &mut wait_for_work,
            ));
        });
        finish
    }

    fn expect_publication_ended(finish: &std::sync::mpsc::Receiver<Result<(), &'static str>>) {
        finish
            .recv_timeout(TEST_TIMEOUT)
            .expect("publication must end")
            .expect("publication must end without a channel error");
    }

    #[test]
    fn queued_updates_publish_in_order_until_the_waiter_closes() {
        let publisher = std::sync::Arc::new(ReadinessPublisher::new());
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        publish(&publisher, OTHER_HANDLE, ReadinessFlags::WRITE);
        let (sent, received) = std::sync::mpsc::sync_channel(4);
        let (releaser, release) = std::sync::mpsc::channel();
        for _ in 0..2 {
            releaser.send(()).unwrap();
        }
        let channel = GatedChannel { sent, release };
        let closing = std::sync::Arc::clone(&publisher);

        let finish = spawn_publication(publisher, channel, move || closing.close());
        expect_publication_ended(&finish);

        let drained: alloc::vec::Vec<_> = received.try_iter().map(|n| readiness_of(&n)).collect();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].handle, HANDLE);
        assert_eq!(drained[1].handle, OTHER_HANDLE);
    }

    #[test]
    fn closing_ends_a_parked_publisher() {
        let publisher = std::sync::Arc::new(ReadinessPublisher::new());
        let (sent, _received) = std::sync::mpsc::sync_channel(1);
        let (_releaser, release) = std::sync::mpsc::channel();
        let channel = GatedChannel { sent, release };
        let parked = std::sync::Arc::clone(&publisher);
        let (parked_sender, parked_receiver) = std::sync::mpsc::channel();

        let finish = spawn_publication(parked, channel, move || {
            // Reporting from inside the wait is what proves the publisher
            // reached it, so closing is what ends it rather than a queue it
            // already found closed.
            let _ = parked_sender.send(());
            std::thread::sleep(core::time::Duration::from_millis(1));
        });
        parked_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("publication must park before it is closed");
        publisher.close();

        expect_publication_ended(&finish);
    }

    #[test]
    fn updates_recorded_while_a_send_blocks_are_published_afterwards() {
        let publisher = std::sync::Arc::new(ReadinessPublisher::new());
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        let (sent, received) = std::sync::mpsc::sync_channel(0);
        let (releaser, release) = std::sync::mpsc::channel();
        let channel = GatedChannel { sent, release };
        let publishing = std::sync::Arc::clone(&publisher);
        let finish = spawn_publication(publishing, channel, || {
            std::thread::sleep(core::time::Duration::from_millis(1));
        });

        // The first notification is now in flight and cannot be confirmed yet.
        assert_eq!(
            readiness_of(&received.recv_timeout(TEST_TIMEOUT).unwrap()).readiness,
            ReadinessFlags::READ
        );
        assert_eq!(
            publisher.publish(HANDLE, ReadinessFlags::HANGUP).unwrap(),
            PublishOutcome::Queued
        );
        releaser.send(()).unwrap();

        assert_eq!(
            readiness_of(&received.recv_timeout(TEST_TIMEOUT).unwrap()).readiness,
            ReadinessFlags::HANGUP
        );
        releaser.send(()).unwrap();
        publisher.close();
        expect_publication_ended(&finish);
    }

    #[test]
    fn a_failed_send_stops_publication_and_reports_the_channel_error() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);

        let error = publish_readiness(&publisher, &mut FailingChannel, || {
            unreachable!("a failed send must not park the publisher")
        })
        .unwrap_err();

        assert_eq!(error, "notification channel failed");

        // The claim was dropped by the failed send rather than confirmed, so
        // the update it carried is still publishable on a replacement channel.
        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::READ,
            }]
        );
    }

    #[test]
    fn an_abandoned_claim_returns_its_update_to_the_queue() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);

        drop(publisher.take_pending().unwrap());

        // Republishing the same flags coalesces, so nothing else can rescue the
        // update if abandoning the claim strands it.
        assert_eq!(
            publisher.publish(HANDLE, ReadinessFlags::READ).unwrap(),
            PublishOutcome::Coalesced
        );
        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::READ,
            }]
        );
    }

    #[test]
    fn abandoning_a_stale_claim_requeues_nothing() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        let stale = publisher.take_pending().unwrap();

        publish(&publisher, HANDLE, ReadinessFlags::WRITE);
        let newer = publisher.take_pending().unwrap();

        // Taking the newer update leaves the object unqueued, so its generation
        // is all that marks the older claim as superseded. Without that
        // comparison the older claim requeues an object whose current update is
        // already in flight, publishing the same readiness twice.
        assert_eq!(publisher.queued_updates(), 0);
        drop(stale);
        assert_eq!(publisher.queued_updates(), 0);

        // A change recorded while that newer claim is still out queues the
        // object again, and abandoning the claim must not queue it a second
        // time.
        publish(&publisher, HANDLE, ReadinessFlags::READ);
        assert_eq!(publisher.queued_updates(), 1);
        drop(newer);
        assert_eq!(publisher.queued_updates(), 1);

        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::READ,
            }]
        );
    }

    #[test]
    fn a_panicking_send_returns_its_update_to_the_queue() {
        let publisher = ReadinessPublisher::new();
        publish(&publisher, HANDLE, ReadinessFlags::READ);

        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(alloc::boxed::Box::new(|_| {}));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = publish_readiness(&publisher, &mut PanickingChannel, || {
                unreachable!("a panicking send must not park the publisher")
            });
        }));
        std::panic::set_hook(previous_hook);

        assert!(unwound.is_err());

        // Unwinding past the claim runs its drop, which must leave the update
        // publishable rather than stranded.
        assert_eq!(
            drain(&publisher),
            [ReadinessNotification {
                handle: HANDLE,
                readiness: ReadinessFlags::READ,
            }]
        );
    }
}
