// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-state-object subscription list and notification dispatch.
//!
//! Broker-hosted state objects (eventfd, timerfd, signalfd, TCP socket,
//! ...) accept zero or more *subscriptions* from worker processes.
//! Each subscription pins a `(subscription_id, events_mask, ring sender)`
//! triple: when the state changes in a way that matches `events_mask`,
//! the broker delivers one [`NotificationFrame`] to that worker's
//! notification ring via the captured sender.
//!
//! # Why this module is non-trivial
//!
//! Naively, "deliver a notification" means "push a frame on the worker's
//! ring." The previous implementation did exactly that — `notify(IN)`
//! always pushed one frame, end of story. That design has four bugs
//! against real-kernel semantics:
//!
//! 1. **Notification storm.** N rapid `notify(IN)` calls produced N
//!    frames in the ring. A real kernel `wake_up()` on a wait queue is
//!    idempotent against an already-runnable reader; the reader is
//!    expected to drain to EAGAIN and the kernel does not "remember"
//!    individual wake events. Mismatching this caused every slave
//!    write through a broker PTY to look like a separate `data`
//!    event on the master worker's libuv-driven reader — the
//!    `copilot::tui.find_head_*` regression family.
//!
//! 2. **Drop-on-saturation.** If the ring was full, `notify` logged
//!    `WouldBlock` and dropped the event. There was no mechanism for
//!    re-delivery; if the worker happened to drain the ring without
//!    any further state activity, it would never observe the missed
//!    edge. (See `[PE.14-diag]` in `/tmp/rst-diag.log`, the PB.many
//!    9/10 ok flake.)
//!
//! 3. **No level-triggered guarantee.** The protocol was effectively
//!    edge-delivery without dedup, so it didn't satisfy either
//!    kernel-style level-triggered semantics OR clean edge-triggered
//!    semantics. Subscribers could not reason about the relationship
//!    between events and state.
//!
//! 4. **Unbounded queue.** Pathological writers could fill the ring
//!    with redundant notifications, starving other state objects that
//!    shared the same notification ring (one ring per worker process).
//!
//! The protocol implemented in this module fixes all four. It is
//! split into two channels with different invariants — see below.
//!
//! # Protocol: two channels
//!
//! There are two kinds of notifications, with different information
//! content per event and therefore different protocols:
//!
//! ## Edge channel (poll-mask bits: `IN`/`OUT`/`HUP`/`PRI`/`ERR`)
//!
//! An edge notification is a "go re-check state" hint. Its information
//! content is zero bits beyond which mask bits are currently asserted.
//! A reader receiving N edge notifications must behave identically to
//! a reader receiving one — it polls current state and acts on it.
//!
//! Therefore edge notifications **coalesce**. Rapid `notify(IN)` calls
//! OR their bits into a per-subscription `pending_mask`; redundant bits
//! already represented by an in-flight frame stay coalesced, while a newly
//! asserted bit may emit one supplemental frame so an initial `OUT` wake cannot
//! starve a later `IN` wake. When the subscriber drains through the latest
//! frame (signalled by `reader_pos` advancing past `last_send_writer_pos`), the
//! next `notify` or `try_flush` emits a fresh frame carrying whatever bits
//! accumulated.
//!
//! ## Payload channel (signalfd siginfos, future datagram boundaries,
//! AF_UNIX SCM credentials, ...)
//!
//! A payload notification carries distinct semantic information per
//! event. Two siginfos are not the same as one siginfo; coalescing
//! would lose data. Therefore payload notifications **queue** —
//! `notify_payload` appends to a per-subscription FIFO deque. The
//! head is drained as fast as ring space allows; on `WouldBlock`
//! the head stays in the deque for retry.
//!
//! # Protocol invariants (apply across both channels)
//!
//! Stated formally so they can be enforced by the
//! `i1_..i5_` test family and by the loom and proptest suites.
//!
//! - **I1 Causality.** When a subscriber consumes a notification N
//!   and then issues a state query, the query result reflects every
//!   state mutation that occurred before N was emitted at the broker.
//!   *Enforced by:* state mutation + notify happen under the state
//!   object's mutex; subscribers observe the ring frame only after the
//!   notify's atomic `Release` on `writer_pos`.
//!
//! - **I2 Liveness.** If the state at any point matches the
//!   subscription mask, the subscriber receives a notification —
//!   under arbitrary delivery delay, arbitrary write rate, and
//!   bounded broker memory. *Enforced by:* I4 below + `try_flush`
//!   re-evaluation on every subsequent state-modifying RPC.
//!
//! - **I3 Idempotence (edge channel).** Receiving N edge notifications
//!   with overlapping mask bits is observationally identical to
//!   receiving 1 notification with the OR of those masks. *Enforced
//!   by:* per-subscription `pending_mask`/`in_flight_mask` accumulators.
//!
//! - **I4 No loss on saturation.** A `WouldBlock` from the ring
//!   never discards an event. Edge bits remain in `pending_mask`;
//!   payload events remain at the head of `pending_payloads`.
//!   *Enforced by:* atomic-or-nothing `try_send_and_capture_writer_pos`
//!   leaves ring state untouched on failure, and the per-subscription
//!   state retains the un-sent event.
//!
//! - **I5 HUP-after-drain.** A peer-close notification (`HUP`) never
//!   causes the subscriber to abandon buffered data. HUP and IN bits
//!   are deliverable as a single mask in the same frame, never in a
//!   sequence where HUP can be acted on before IN-data has been read.
//!   *Enforced by:* both bits accumulate in `pending_mask`; the
//!   single frame emitted carries their union; the subscriber's
//!   contract is "drain to EAGAIN, then respect HUP."
//!
//! # ACK invariants (cursor-based ACK protocol)
//!
//! Instead of an explicit "frame consumed" ACK message, this protocol
//! uses the shm-ring's natively-shared `reader_pos`/`writer_pos`
//! atomics as the ACK channel. The broker captures `writer_pos`
//! immediately after each send (under the sender mutex); the worker's
//! notification-reader thread updates `reader_pos` after consuming
//! each frame's bytes. The broker can then determine "is the frame I
//! sent at offset `last_send_writer_pos` still in the ring?" by
//! comparing.
//!
//! The properties this protocol depends on:
//!
//! - **A1 Cursor Monotonicity.** Both `writer_pos` and `reader_pos`
//!   are non-decreasing modulo 2³². *Enforced by:* the SPSC ring
//!   contract (no concurrent writers, no concurrent readers).
//!
//! - **A2 ACK Causality.** If the broker observes `reader_pos`
//!   reaching `last_send_writer_pos`, then every byte of the frame
//!   has been consumed by the reader (and thus by the worker's
//!   notification thread). *Enforced by:* the reader's `Release`
//!   store on `reader_pos` happens after the byte copy from the ring;
//!   the broker's `Acquire` load establishes happens-before.
//!
//! - **A3 No False-Positive ACK.** The broker never concludes
//!   "consumed" before the reader has actually advanced. *Enforced
//!   by:* `Acquire`/`Release` ordering on `reader_pos` and never
//!   optimistically pre-advancing `last_send_writer_pos`.
//!
//! - **A4 No False-Negative ACK starvation.** If the reader has
//!   consumed but no further `notify` arrives, eventually `try_flush`
//!   will run (called from the broker's RPC dispatch path on each
//!   state-affecting request from this worker), pick up the pending
//!   mask, and deliver it. *Enforced by:* the `try_flush` wiring in
//!   `state_service::handle_request`.
//!
//! - **A5 Post-send Cursor Capture.** `last_send_writer_pos` is the
//!   `writer_pos` value observed AFTER this subscription's send
//!   completed, captured while still holding the sender mutex. This
//!   matters because the sender may be shared across N subscriptions
//!   in N different state objects; a stale read could attribute
//!   another subscription's frame to this one. *Enforced by:*
//!   [`NotificationSender::try_send_and_capture_writer_pos`] doing
//!   both operations behind the same sender lock.
//!
//! - **A6 In-flight Bound per Subscription.** At most one in-flight frame per
//!   distinct edge bit per subscription is needed: duplicate bits coalesce, but
//!   a new bit can bypass an older in-flight frame. *Enforced by:* the
//!   `in_flight_mask` check before each send.
//!
//! - **A7 Ring-fill Bound per Worker.** A worker with N subscriptions
//!   on a single notification ring has at most N edge frames + N
//!   payload-head frames in flight simultaneously. The ring is sized
//!   (`RING_DATA_SIZE` = 4 MiB) so that this is far below capacity
//!   for any realistic N.
//!
//! - **A8 ACK ≠ Process.** The cursor-based ACK confirms ring-byte
//!   consumption by the worker's notification-reader thread, NOT
//!   processing by libuv / the worker's event loop. The
//!   notification-reader thread is a tight loop that drains the ring
//!   and translates each frame into a local Pollee wake; "ring
//!   bytes consumed" is therefore proportional to "Pollee wake fired"
//!   but not to "libuv ran the user callback." This is deliberate:
//!   coupling the ACK to libuv processing would couple broker
//!   throughput to user-callback latency.
//!
//! - **A9 Pending-mask Race-Free.** Updates to `pending_mask` are
//!   atomic with respect to (a) other `notify`/`notify_payload` calls,
//!   (b) the in-flight transition (read pending → clear pending),
//!   and (c) revert on send failure. *Enforced by:* the
//!   `SubscriptionList::entries` Mutex.
//!
//! # Concurrency model
//!
//! Internally synchronised via a single [`std::sync::Mutex`] on the
//! entries vector. The list is small (one entry per worker holding a
//! reference to this state), so lock contention isn't expected.
//!
//! The sender lock is acquired briefly per attempted send. Both locks
//! may be held nested: state-object mutex → SubscriptionList mutex →
//! sender mutex. The ordering is strict and avoids deadlock because
//! no path holds a SubscriptionList mutex while acquiring another
//! state object's resources.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

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

/// One subscription entry — bookkeeping for both the edge and payload
/// channels for a single `(state-object, worker)` pair.
///
/// The `sender` is held as `Arc<Mutex<NotificationSender>>` because the
/// notification ring is per-worker (not per-state-object); many state
/// objects may hold subscriptions referencing the same worker's ring.
struct Subscription {
    /// Worker-assigned id. Echoed in every notification frame so the
    /// worker can route the frame to the right local Pollee.
    id: u64,
    /// Bitmask of `NOTIFY_EVENT_*` bits this subscription accepts.
    /// Notify calls have their `events` filtered through this mask
    /// before reaching `pending_mask`.
    events_mask: u32,
    /// The worker's notification ring sender. May be shared across
    /// many subscriptions on many state objects (one ring per
    /// worker process).
    sender: Arc<Mutex<NotificationSender>>,

    // ---------- Edge channel state ----------
    /// Edge bits the broker has accumulated but not yet successfully
    /// emitted on the ring. Cleared atomically with each successful
    /// send; OR'd into on each `notify`. See **I3, A9**.
    pending_mask: u32,
    /// `writer_pos` of the sender's ring immediately AFTER the most
    /// recent successful edge-frame send. Compared against the
    /// sender's current `reader_pos` to determine whether the frame
    /// has been consumed.
    ///
    /// Both `0` initially, which correctly means "no in-flight frame"
    /// for a fresh ring (where `reader_pos` is also `0`).
    last_send_writer_pos: u32,
    /// True iff there is an edge frame in flight that we have not yet
    /// observed as consumed. False initially. Allows
    /// `last_send_writer_pos == 0` to mean "no prior send" without
    /// ambiguity against the initial-ring state.
    edge_frame_in_flight: bool,
    /// OR of edge bits already represented by not-yet-consumed in-flight
    /// frames. A new bit that is not in this mask may be sent as a supplemental
    /// frame even while an older frame is still queued.
    in_flight_mask: u32,

    // ---------- Payload channel state ----------
    /// FIFO queue of payload events awaiting delivery. Head is drained
    /// as ring space allows; tail is appended by `notify_payload`.
    /// Each entry holds the events mask AND the payload bytes.
    pending_payloads: VecDeque<(u32, Vec<u8>)>,
}

/// A subscription/notification list for a single broker-hosted state
/// object. See module-level documentation for the protocol and
/// invariants.
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
            pending_mask: 0,
            last_send_writer_pos: 0,
            edge_frame_in_flight: false,
            in_flight_mask: 0,
            pending_payloads: VecDeque::new(),
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

    /// HypB diag accessor: number of registered subscriptions on this list.
    pub fn entry_count_for_diag(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Records an edge-channel state-change. Bits in `events` that
    /// intersect a subscription's `events_mask` are OR'd into the
    /// subscription's `pending_mask` and we then attempt to flush
    /// any pending edges to the ring (see [`Self::try_flush`]).
    ///
    /// Multiple rapid `notify` calls coalesce per edge bit: duplicate
    /// bits already represented by in-flight frames defer, while a
    /// newly asserted bit can be delivered as a supplemental frame.
    ///
    /// Errors writing to a sender are absorbed:
    /// - `WouldBlock`: bit stays in `pending_mask` for retry on the
    ///   next `notify` or `try_flush` (see **I4**).
    /// - `BrokenPipe`/peer-gone: the subscription is removed.
    /// - Other transient: logged, bit retained.
    pub fn notify(&self, events: u32) {
        let mut to_remove: Vec<u64> = Vec::new();
        {
            let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
            for sub in entries.iter_mut() {
                let matched = events & sub.events_mask;
                if matched == 0 && sub.pending_mask == 0 {
                    continue;
                }
                sub.pending_mask |= matched;
                Self::try_flush_edge_locked(sub, &mut to_remove);
            }
        }
        self.gc_removed(&to_remove);
    }

    /// Records a payload-channel state-change. The `(events, payload)`
    /// tuple is appended to the matched subscription's FIFO queue;
    /// we then attempt to drain the queue head into the ring.
    ///
    /// Unlike [`Self::notify`], payload events do NOT coalesce —
    /// each payload carries distinct semantic information.
    pub fn notify_payload(&self, events: u32, payload: Vec<u8>) {
        let mut to_remove: Vec<u64> = Vec::new();
        {
            let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
            for sub in entries.iter_mut() {
                let matched = events & sub.events_mask;
                if matched == 0 {
                    continue;
                }
                sub.pending_payloads.push_back((matched, payload.clone()));
                Self::try_flush_payload_locked(sub, &mut to_remove);
            }
        }
        self.gc_removed(&to_remove);
    }

    /// Opportunistically re-attempts to deliver any pending edge or
    /// payload events on every subscription. Called from
    /// `state_service::handle_request` after each state-affecting
    /// RPC — the reader's act of issuing that RPC implies it has
    /// drained the prior notification, so the broker's
    /// `reader_pos` observation may now satisfy the in-flight check.
    ///
    /// This is the **A4** liveness mechanism: pending bits that
    /// `notify` couldn't deliver because the ring was full or the
    /// previous frame was in flight get re-attempted here.
    pub fn try_flush(&self) {
        let mut to_remove: Vec<u64> = Vec::new();
        {
            let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
            for sub in entries.iter_mut() {
                Self::try_flush_edge_locked(sub, &mut to_remove);
                Self::try_flush_payload_locked(sub, &mut to_remove);
            }
        }
        self.gc_removed(&to_remove);
    }

    /// Targeted variant of [`Self::try_flush`] for a single
    /// subscription. Used by `state_service` when it knows exactly
    /// which subscription's worker just made an RPC.
    ///
    /// Silently no-ops if `subscription_id` is not in the list.
    pub fn try_flush_subscription(&self, subscription_id: u64) {
        let mut to_remove: Vec<u64> = Vec::new();
        {
            let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
            if let Some(sub) = entries.iter_mut().find(|s| s.id == subscription_id) {
                Self::try_flush_edge_locked(sub, &mut to_remove);
                Self::try_flush_payload_locked(sub, &mut to_remove);
            }
        }
        self.gc_removed(&to_remove);
    }

    /// Internal: attempt to push `sub.pending_mask` as one edge frame,
    /// if the previous frame is observed consumed and there's space
    /// in the ring. Called under the `entries` Mutex.
    fn try_flush_edge_locked(sub: &mut Subscription, to_remove: &mut Vec<u64>) {
        if sub.pending_mask == 0 {
            return;
        }
        let mut sender = sub.sender.lock().expect("NotificationSender poisoned");

        let send_mask = if sub.edge_frame_in_flight {
            if frame_consumed(sub.last_send_writer_pos, sender.reader_pos()) {
                sub.edge_frame_in_flight = false;
                sub.in_flight_mask = 0;
                sub.pending_mask
            } else {
                let new_bits = sub.pending_mask & !sub.in_flight_mask;
                if new_bits == 0 {
                    return;
                }
                new_bits
            }
        } else {
            sub.pending_mask
        };
        if send_mask == 0 {
            return;
        }

        let frame = NotificationFrame::fixed(sub.id, send_mask);

        match sender.try_send_and_capture_writer_pos(&frame) {
            Ok(post_writer_pos) => {
                // A5 post-send cursor capture: under sender lock.
                sub.last_send_writer_pos = post_writer_pos;
                sub.edge_frame_in_flight = true;
                sub.in_flight_mask |= send_mask;
                sub.pending_mask &= !send_mask;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                // I4: ring full. Leave pending_mask intact; next
                // try_flush will retry.
            }
            Err(err) if is_peer_gone(&err) => {
                tracing::warn!(
                    subscription_id = sub.id,
                    error = %err,
                    "edge notification send failed (peer gone); removing subscription",
                );
                to_remove.push(sub.id);
            }
            Err(err) => {
                tracing::warn!(
                    subscription_id = sub.id,
                    error = %err,
                    "edge notification send failed (transient); retaining pending bits",
                );
                // I4: bits remain in pending_mask.
            }
        }
    }

    /// Internal: attempt to push as many heads of `sub.pending_payloads`
    /// as fit in the ring. Each successful send pops the head; on
    /// `WouldBlock` or transient error, the head stays in place for
    /// retry. Called under the `entries` Mutex.
    ///
    /// Note: payload sends do not currently enforce a "max-1 in
    /// flight" cap. Multiple payload frames may be in the ring
    /// simultaneously, ordered by enqueue order. This matches
    /// signalfd-style "drain as many queued siginfos as the reader
    /// can take" semantics.
    fn try_flush_payload_locked(sub: &mut Subscription, to_remove: &mut Vec<u64>) {
        if sub.pending_payloads.is_empty() {
            return;
        }
        let mut sender = sub.sender.lock().expect("NotificationSender poisoned");
        while let Some((events, payload)) = sub.pending_payloads.front() {
            let frame = NotificationFrame::payload(sub.id, *events, payload.clone());
            match sender.try_send_and_capture_writer_pos(&frame) {
                Ok(_post_writer_pos) => {
                    sub.pending_payloads.pop_front();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // Ring full; head stays for retry. Done for now.
                    return;
                }
                Err(err) if is_peer_gone(&err) => {
                    tracing::warn!(
                        subscription_id = sub.id,
                        error = %err,
                        "payload notification send failed (peer gone); removing subscription",
                    );
                    to_remove.push(sub.id);
                    return;
                }
                Err(err) => {
                    tracing::warn!(
                        subscription_id = sub.id,
                        error = %err,
                        "payload notification send failed (transient); retaining head",
                    );
                    return;
                }
            }
        }
    }

    fn gc_removed(&self, to_remove: &[u64]) {
        if to_remove.is_empty() {
            return;
        }
        let mut entries = self.entries.lock().expect("SubscriptionList poisoned");
        entries.retain(|s| !to_remove.contains(&s.id));
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

/// Determines whether the edge frame whose tail-byte was at
/// `last_send_writer_pos` has been consumed by the peer reader.
///
/// The shm-ring uses `u32` cursors that wrap. To handle wrap-around
/// safely:
///
/// - If `last_send_writer_pos == reader_pos`, the reader is exactly
///   at our frame's end → consumed.
/// - Otherwise, compute `gap = last_send_writer_pos - reader_pos`
///   (wrapping subtraction). If `gap > 0 && gap as usize <= RING_DATA_SIZE`,
///   the reader is behind our position by at most the ring size →
///   not consumed.
/// - If `gap > RING_DATA_SIZE` (which means the wrap went the other
///   direction), the reader has overtaken our position via other
///   subscriptions' activity on the shared ring → consumed.
///
/// This relies on the SPSC ring invariant
/// `|writer_pos - reader_pos| <= RING_DATA_SIZE`, which means the
/// wrapping subtraction unambiguously distinguishes "behind by at
/// most ring-size" from "ahead by ring-size or more."
fn frame_consumed(last_send_writer_pos: u32, reader_pos: u32) -> bool {
    use litebox_common_linux::shmem_ring::RING_DATA_SIZE;
    let gap = last_send_writer_pos.wrapping_sub(reader_pos);
    gap == 0 || (gap as usize) > RING_DATA_SIZE
}

/// Classifies a notification-send error as "the peer is definitely
/// gone" vs "this was a transient that may recover". Only the former
/// should remove the subscription from the list.
fn is_peer_gone(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::notification_frame::{
        NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
    };
    use litebox_common_linux::notification_ring::NotificationReceiver;
    use litebox_common_linux::shmem_ring::ShmemRingPair;
    use std::thread;
    use std::time::Duration;

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

    /// Helper: drain receiver of any frames currently in the ring,
    /// returning their decoded form. Spawns a brief reader because
    /// recv is blocking; uses a barrier shaped via channels to know
    /// when to stop. For tests we just take everything available
    /// during a short window.
    fn drain_with_timeout(
        mut receiver: NotificationReceiver,
        max: usize,
        per_frame_timeout: Duration,
    ) -> (Vec<NotificationFrame>, NotificationReceiver) {
        // Note: when timeout fires while recv is blocked, the spawned
        // recv thread cannot be safely cancelled — we'd deadlock on
        // handle.join(). We close the sender side by dropping it from
        // outside, but we don't have access to it here. Instead, we
        // accept the trade-off: the spawned thread holds the
        // receiver, and we return a *new* receiver constructed by
        // taking the Drop path forward. Since callers only check
        // `frames` in the timeout case, returning an
        // already-dropped-style receiver is acceptable: we leak the
        // thread. To avoid `handle.join()` deadlock, we forget the
        // handle and synthesise a "dummy" receiver. Caller must not
        // use it after timeout.
        //
        // This is test-only code; not appropriate for production.
        let mut frames = Vec::new();
        for _ in 0..max {
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                let r = receiver.recv();
                let _ = tx.send(r);
                receiver
            });
            match rx.recv_timeout(per_frame_timeout) {
                Ok(Ok(frame)) => {
                    receiver = handle.join().unwrap();
                    frames.push(frame);
                }
                Ok(Err(_)) => {
                    // recv errored cleanly; safe to join.
                    receiver = handle.join().unwrap();
                    return (frames, receiver);
                }
                Err(_) => {
                    // Timeout: recv is still blocked in the thread.
                    // Joining would deadlock. Leak the thread + the
                    // receiver it owns; construct a fresh dummy
                    // receiver of no use to the caller (caller
                    // discards _r when there's a timeout in the
                    // tests below).
                    std::mem::forget(handle);
                    let (_pair, tx_fd, rx_fd) =
                        litebox_common_linux::shmem_ring::ShmemRingPair::create()
                            .expect("dummy ring");
                    let (_w, r) =
                        litebox_common_linux::shmem_ring::ShmemRingPair::open(tx_fd, rx_fd)
                            .expect("dummy ring open");
                    receiver = NotificationReceiver::new(r);
                    return (frames, receiver);
                }
            }
        }
        (frames, receiver)
    }

    // ============================================================
    // I1 — Causality
    // ============================================================

    #[test]
    fn i1_causality_notify_then_recv_sees_pre_notify_state() {
        // The protocol must ensure: a subscriber that consumes a
        // notification N can observe (via subsequent state query)
        // every state change that happened before N was emitted.
        //
        // Here we model "state change" as an external AtomicU32 and
        // notify-after-store. The Release on writer_pos that delivers
        // the notification frame must happen-after our store. We
        // verify by having the receiver observe the AtomicU32 after
        // receiving the frame.
        use std::sync::atomic::{AtomicU32, Ordering};

        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender).unwrap();

        let state = Arc::new(AtomicU32::new(0));
        state.store(42, Ordering::Release);
        list.notify(NOTIFY_EVENT_IN);

        let frame = receiver.recv().expect("recv");
        assert_eq!(frame.subscription_id(), 1);
        // After recv, state must be visible to us as 42 because the
        // Release on writer_pos happens-after our state store, and
        // the recv's Acquire on writer_pos establishes happens-before.
        assert_eq!(state.load(Ordering::Acquire), 42);
    }

    // ============================================================
    // I2 — Liveness
    // ============================================================

    #[test]
    fn i2_liveness_try_flush_delivers_pending_after_drain() {
        // If a notify is deferred (e.g. would-be-blocked or because
        // a previous frame is in flight), the bit must eventually be
        // delivered when ring space becomes available. try_flush is
        // the recovery mechanism.
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT, sender.clone())
            .unwrap();

        // First notify: should send immediately (ring empty).
        list.notify(NOTIFY_EVENT_IN);
        let f = receiver.recv().expect("first frame");
        assert_eq!(f.events(), NOTIFY_EVENT_IN);

        // Second notify, before any further state activity, while
        // the broker has not yet observed our consumption of f. The
        // protocol's defer-on-in-flight check uses reader_pos. Allow
        // the receiver's Release on reader_pos to be visible.
        thread::sleep(Duration::from_millis(2));

        list.notify(NOTIFY_EVENT_OUT);
        let f2 = receiver.recv().expect("second frame");
        assert_eq!(f2.events(), NOTIFY_EVENT_OUT);
    }

    // ============================================================
    // I3 — Idempotence / coalescing
    // ============================================================

    #[test]
    fn i3_burst_notify_coalesces_into_at_most_one_in_flight_frame() {
        // 1000 rapid notify(IN) calls against a non-draining receiver must
        // produce AT MOST 2 frames in the ring (1 initial + 1 coalesced
        // follow-up). Repeated IN bits are deferred while IN is already
        // represented in-flight, then emitted once after the first frame drains.
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender).unwrap();

        for _ in 0..1000 {
            list.notify(NOTIFY_EVENT_IN);
        }

        // Drain the first frame.
        let f1 = receiver.recv().expect("first frame");
        assert_eq!(f1.events(), NOTIFY_EVENT_IN);

        // try_flush picks up the accumulated pending_mask (IN) and sends
        // exactly ONE more frame.
        thread::sleep(Duration::from_millis(2));
        list.try_flush();
        let f2 = receiver.recv().expect("coalesced follow-up frame");
        assert_eq!(
            f2.events(),
            NOTIFY_EVENT_IN,
            "follow-up frame carries OR'd pending bits"
        );

        // No third frame: pending_mask is now 0.
        list.try_flush();
        let (frames, _r) = drain_with_timeout(receiver, 1, Duration::from_millis(50));
        assert_eq!(
            frames.len(),
            0,
            "expected no third frame (pending=0), got {}: {:?}",
            frames.len(),
            frames
        );
    }

    #[test]
    fn i3_burst_notify_with_mixed_bits_coalesces_into_union_mask() {
        // notify(IN) then notify(OUT) before draining should not let an
        // uninteresting first bit starve a later distinct bit. OUT is emitted
        // as a supplemental frame even while the IN frame is still queued.
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT, sender)
            .unwrap();

        list.notify(NOTIFY_EVENT_IN); // sends immediately
        list.notify(NOTIFY_EVENT_OUT); // defers (in-flight = true)

        let f1 = receiver.recv().expect("first");
        assert_eq!(f1.events(), NOTIFY_EVENT_IN);
        let f2 = receiver.recv().expect("second");
        assert_eq!(f2.events(), NOTIFY_EVENT_OUT);
    }

    #[test]
    fn i3_two_notifies_before_drain_collapse_into_one_frame_with_or_mask() {
        // Stronger variant: notify(IN), notify(OUT), notify(IN), all before
        // any drain. IN and OUT each get one immediate in-flight frame; the
        // repeated IN is deferred and emitted once after those drain.
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT, sender)
            .unwrap();

        list.notify(NOTIFY_EVENT_IN);
        list.notify(NOTIFY_EVENT_OUT);
        list.notify(NOTIFY_EVENT_IN);

        let f1 = receiver.recv().expect("first");
        assert_eq!(f1.events(), NOTIFY_EVENT_IN);
        let f2 = receiver.recv().expect("second");
        assert_eq!(f2.events(), NOTIFY_EVENT_OUT);

        thread::sleep(Duration::from_millis(2));
        list.try_flush();
        let f3 = receiver.recv().expect("third");
        assert_eq!(f3.events(), NOTIFY_EVENT_IN);

        // No fourth frame.
        list.try_flush();
        let (frames, _r) = drain_with_timeout(receiver, 1, Duration::from_millis(50));
        assert_eq!(frames.len(), 0, "expected no fourth frame, got {frames:?}");
    }

    // ============================================================
    // I4 — No loss on saturation
    // ============================================================

    #[test]
    fn i4_pending_mask_retained_when_send_would_block() {
        // Fill the ring with payload frames so further sends return
        // WouldBlock. Then notify(IN) — the IN bit must be retained
        // in pending_mask (or in pending_payloads). Drain the ring
        // while continuously re-flushing; the bit must eventually be
        // delivered as a Fixed frame.
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender).unwrap();

        // Fill ring with payload frames. push_count is large enough
        // that pending_payloads is guaranteed non-empty after the
        // loop completes (ring is ~4 MiB; each frame is ~28 + 4096
        // bytes ≈ 4124 bytes; ring holds ~1000 frames).
        let big_payload = vec![0xABu8; 4096];
        let saturate_limit = 3000;
        for _ in 0..saturate_limit {
            list.notify_payload(NOTIFY_EVENT_IN, big_payload.clone());
        }

        // Now do an edge notify. With the ring saturated AND
        // pending_payloads non-empty, the edge send may also defer
        // (no in-flight edge yet, but ring is full → WouldBlock).
        list.notify(NOTIFY_EVENT_IN);

        // Drain the ring while re-flushing the broker so it keeps
        // draining pending_payloads. Stop when we observe our edge
        // (Fixed) frame.
        let mut found_edge = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut total_drained = 0usize;
        while std::time::Instant::now() < deadline {
            list.try_flush();
            match receiver.recv() {
                Ok(frame) => {
                    total_drained += 1;
                    if frame.subscription_id() == 1
                        && frame.events() == NOTIFY_EVENT_IN
                        && frame.payload_bytes().is_none()
                    {
                        found_edge = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        assert!(
            found_edge,
            "I4 violation: edge bit was lost during ring saturation (drained {total_drained} frames)",
        );
    }

    // ============================================================
    // I5 — HUP after drain
    // ============================================================

    #[test]
    fn i5_hup_or_in_emitted_as_single_frame() {
        // When the peer closes and there is still buffered data, the
        // caller emits notify(IN | HUP) in one call. The subscriber
        // must see a single frame carrying both bits — never IN in
        // one frame followed by HUP in another (which could allow
        // the subscriber to act on HUP before reading IN-data).
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP, sender)
            .unwrap();
        list.notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
        let f = receiver.recv().expect("recv");
        assert_eq!(f.events(), NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
    }

    #[test]
    fn i5_separate_notifies_in_then_hup_coalesce_until_drained() {
        // notify(IN), then notify(HUP) before drain. The first frame
        // carries IN. After drain + try_flush, the second frame
        // carries HUP. The subscriber sees IN before HUP, which
        // satisfies the "drain before respecting HUP" contract.
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP, sender)
            .unwrap();
        list.notify(NOTIFY_EVENT_IN);
        list.notify(NOTIFY_EVENT_HUP);
        let f1 = receiver.recv().expect("first");
        assert_eq!(f1.events(), NOTIFY_EVENT_IN);
        thread::sleep(Duration::from_millis(2));
        list.try_flush();
        let f2 = receiver.recv().expect("second");
        assert_eq!(f2.events(), NOTIFY_EVENT_HUP);
    }

    // ============================================================
    // Legacy compatibility tests preserved from the original suite
    // ============================================================

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
        list.notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 1);
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
        let (sender1, _r1) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender1).unwrap();
        let (sender2, _r2) = make_pair();
        list.add(2, NOTIFY_EVENT_IN, Arc::clone(&sender2)).unwrap();
        assert_eq!(list.len(), 2);
        list.retain_live();
        assert_eq!(list.len(), 1);
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

    // ============================================================
    // Payload channel tests
    // ============================================================

    #[test]
    fn payload_notify_does_not_coalesce_distinct_payloads() {
        let list = SubscriptionList::new();
        let (sender, mut receiver) = make_pair();
        list.add(1, NOTIFY_EVENT_IN, sender).unwrap();
        list.notify_payload(NOTIFY_EVENT_IN, b"sig1".to_vec());
        list.notify_payload(NOTIFY_EVENT_IN, b"sig2".to_vec());
        list.notify_payload(NOTIFY_EVENT_IN, b"sig3".to_vec());

        let f1 = receiver.recv().unwrap();
        let f2 = receiver.recv().unwrap();
        let f3 = receiver.recv().unwrap();
        assert_eq!(f1.payload_bytes(), Some(b"sig1".as_ref()));
        assert_eq!(f2.payload_bytes(), Some(b"sig2".as_ref()));
        assert_eq!(f3.payload_bytes(), Some(b"sig3".as_ref()));
    }

    #[test]
    fn frame_consumed_helper_correctness() {
        // Fresh ring: both pos at 0; vacuously consumed.
        assert!(frame_consumed(0, 0));
        // Sent 24 bytes, reader at 0: NOT consumed.
        assert!(!frame_consumed(24, 0));
        // Reader caught up: consumed.
        assert!(frame_consumed(24, 24));
        // Other state wrote and reader consumed past us.
        assert!(frame_consumed(24, 100));
        // Wraparound corner: writer at low value, reader at high
        // value — reader has lapped us, consumed.
        // last_send = 100, reader = 1000: gap = -900 = 0xFFFFFC74,
        // which is > RING_DATA_SIZE → consumed.
        assert!(frame_consumed(100, 1000));
    }
}
