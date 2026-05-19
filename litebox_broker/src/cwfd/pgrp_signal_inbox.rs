// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side pgrp signal notification inbox.
//!
//! `subscription_id`s are worker-local, so this structure keys subscribers by
//! `(pgid, conn_id)` and stores the worker's `subscription_id` only as the
//! routing id to put in broker→worker notification frames.
//!
//! # Invariants
//!
//! PG.1: cleanup logs (without panicking) if a worker disconnects after this
//! inbox failed to enqueue any signal notification for one of its subscriptions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_IN, NOTIFY_EVENT_MASK_ALL, NotificationFrame,
};
use litebox_common_linux::notification_ring::NotificationSender;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubscribeError {
    #[error("connection {conn_id} already subscribed to pgid {pgid}")]
    DuplicateConnection { pgid: u32, conn_id: u64 },
    #[error("events_mask 0x{events_mask:08x} contains unknown notification bits")]
    UnknownEventBits { events_mask: u32 },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UnsubscribeError {
    #[error("connection {conn_id} is not subscribed to pgid {pgid}")]
    UnknownConnection { pgid: u32, conn_id: u64 },
}

struct PgrpSubscription {
    subscription_id: u64,
    signal_mask: u32,
    events_mask: u32,
    sender: Arc<Mutex<NotificationSender>>,
    deliveries_sent: AtomicU64,
    deliveries_dropped: AtomicU64,
}

pub struct PgrpSignalInbox {
    subscriptions: Mutex<HashMap<u32, HashMap<u64, Arc<PgrpSubscription>>>>,
}

impl Default for PgrpSignalInbox {
    fn default() -> Self {
        Self::new()
    }
}

impl PgrpSignalInbox {
    pub fn new() -> Self {
        Self {
            subscriptions: Mutex::new(HashMap::new()),
        }
    }

    pub fn subscribe(
        &self,
        pgid: u32,
        conn_id: u64,
        sub_id: u64,
        signal_mask: u32,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        if events_mask & !NOTIFY_EVENT_MASK_ALL != 0 {
            return Err(SubscribeError::UnknownEventBits { events_mask });
        }
        let mut subscriptions = self
            .subscriptions
            .lock()
            .expect("PgrpSignalInbox subscriptions poisoned");
        let by_conn = subscriptions.entry(pgid).or_default();
        if by_conn.contains_key(&conn_id) {
            return Err(SubscribeError::DuplicateConnection { pgid, conn_id });
        }
        by_conn.insert(
            conn_id,
            Arc::new(PgrpSubscription {
                subscription_id: sub_id,
                signal_mask,
                events_mask,
                sender,
                deliveries_sent: AtomicU64::new(0),
                deliveries_dropped: AtomicU64::new(0),
            }),
        );
        Ok(())
    }

    pub fn unsubscribe(&self, pgid: u32, conn_id: u64) -> Result<(), UnsubscribeError> {
        let mut subscriptions = self
            .subscriptions
            .lock()
            .expect("PgrpSignalInbox subscriptions poisoned");
        let Some(by_conn) = subscriptions.get_mut(&pgid) else {
            return Err(UnsubscribeError::UnknownConnection { pgid, conn_id });
        };
        if by_conn.remove(&conn_id).is_none() {
            return Err(UnsubscribeError::UnknownConnection { pgid, conn_id });
        }
        if by_conn.is_empty() {
            subscriptions.remove(&pgid);
        }
        Ok(())
    }

    pub fn cleanup_connection(&self, conn_id: u64) {
        let mut subscriptions = self
            .subscriptions
            .lock()
            .expect("PgrpSignalInbox subscriptions poisoned");
        subscriptions.retain(|pgid, by_conn| {
            if let Some(sub) = by_conn.remove(&conn_id) {
                let sent = sub.deliveries_sent.load(Ordering::Relaxed);
                let dropped = sub.deliveries_dropped.load(Ordering::Relaxed);
                if dropped > 0 || sent > 0 {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0);
                    eprintln!(
                        "[PG.1-invariant] ts={ts} SIGNAL INBOX UNDELIVERED conn_id={} pgid={} sent={} dropped={} — worker disconnected with unprocessed signals",
                        conn_id, pgid, sent, dropped
                    );
                }
            }
            !by_conn.is_empty()
        });
    }

    pub fn deliver(&self, pgid: u32, signum: u32, siginfo: &[u8]) -> usize {
        let mut payload = Vec::with_capacity(8 + siginfo.len());
        payload.extend_from_slice(&(pgid as i32).to_le_bytes());
        payload.extend_from_slice(&(signum as i32).to_le_bytes());
        payload.extend_from_slice(siginfo);

        let targets = {
            let subscriptions = self
                .subscriptions
                .lock()
                .expect("PgrpSignalInbox subscriptions poisoned");
            let mut targets = subscriptions
                .get(&pgid)
                .into_iter()
                .flat_map(|by_conn| by_conn.values())
                .filter(|sub| signal_matches(sub.signal_mask, signum))
                .filter_map(|sub| {
                    let matched_events = sub.events_mask & NOTIFY_EVENT_IN;
                    (matched_events != 0).then(|| Arc::clone(sub))
                })
                .collect::<Vec<_>>();
            if targets.is_empty() {
                // PR-3 has only a per-worker local pgid view. During remote exec,
                // the master worker can briefly hold a stale foreground pgid;
                // broadcast standard signals to subscribed workers rather than
                // dropping SIGWINCH until PR-4 adds broker-side setpgid tracking.
                targets = subscriptions
                    .values()
                    .flat_map(|by_conn| by_conn.values())
                    .filter(|sub| signal_matches(sub.signal_mask, signum))
                    .filter_map(|sub| {
                        let matched_events = sub.events_mask & NOTIFY_EVENT_IN;
                        (matched_events != 0).then(|| Arc::clone(sub))
                    })
                    .collect();
            }
            targets
        };

        let mut delivered = 0;
        for sub in targets {
            let events = sub.events_mask & NOTIFY_EVENT_IN;
            let frame = NotificationFrame::payload(sub.subscription_id, events, payload.clone());
            let mut sender = sub.sender.lock().expect("NotificationSender poisoned");
            if let Err(err) = sender.send(&frame) {
                sub.deliveries_dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(subscription_id = sub.subscription_id, pgid, signum, error = %err, "pgrp signal notification send failed");
                continue;
            }
            sub.deliveries_sent.fetch_add(1, Ordering::Relaxed);
            delivered += 1;
        }
        delivered
    }

    pub fn subscription_count(&self) -> usize {
        self.subscriptions
            .lock()
            .expect("PgrpSignalInbox subscriptions poisoned")
            .values()
            .map(HashMap::len)
            .sum()
    }
}

fn signal_matches(signal_mask: u32, signum: u32) -> bool {
    signum < u32::BITS && (signal_mask & (1u32 << signum)) != 0
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
    fn subscribe_deliver_notifies_two_connections_with_same_sub_id() {
        let inbox = PgrpSignalInbox::new();
        let (sender_a, mut receiver_a) = make_pair();
        let (sender_b, mut receiver_b) = make_pair();
        let signal_mask = 1u32 << 28;

        inbox
            .subscribe(42, 100, 1, signal_mask, NOTIFY_EVENT_IN, sender_a)
            .unwrap();
        inbox
            .subscribe(42, 200, 1, signal_mask, NOTIFY_EVENT_IN, sender_b)
            .unwrap();

        let siginfo = [0xAB; 128];
        assert_eq!(inbox.deliver(42, 28, &siginfo), 2);

        for receiver in [&mut receiver_a, &mut receiver_b] {
            let frame = receiver.recv().unwrap();
            assert_eq!(frame.subscription_id(), 1);
            assert_eq!(frame.events(), NOTIFY_EVENT_IN);
            let payload = frame.payload_bytes().unwrap();
            assert_eq!(&payload[0..4], &42i32.to_le_bytes());
            assert_eq!(&payload[4..8], &28i32.to_le_bytes());
            assert_eq!(&payload[8..], &siginfo);
        }
    }

    #[test]
    fn unsubscribe_and_cleanup_remove_entries() {
        let inbox = PgrpSignalInbox::new();
        let (sender_a, _receiver_a) = make_pair();
        let (sender_b, _receiver_b) = make_pair();
        inbox
            .subscribe(7, 10, 1, 1u32 << 2, NOTIFY_EVENT_IN, sender_a)
            .unwrap();
        inbox
            .subscribe(8, 10, 2, 1u32 << 2, NOTIFY_EVENT_IN, sender_b)
            .unwrap();
        assert_eq!(inbox.subscription_count(), 2);
        inbox.unsubscribe(7, 10).unwrap();
        assert_eq!(inbox.subscription_count(), 1);
        inbox.cleanup_connection(10);
        assert_eq!(inbox.subscription_count(), 0);
    }
}
