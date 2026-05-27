// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted process identity and exit state.
//!
//! Each Linux guest process in a sandbox is represented by a
//! [`ProcessState`] entry in the broker's process-only
//! [`BrokerStateRegistry`] instance (sibling to the existing
//! fd-state registry). The [`StateHandle.id()`] of a `Process`-tagged
//! entry IS the globally-unique guest pid — workers receive it via
//! `RegisterProcess` and use the low 32 bits as the Linux pid.
//!
//! Phase G extends the original pid-allocation payload with broker-owned
//! exit state and a subscription list. Workers may subscribe to process
//! exit before or after the target exits; a late subscriber receives a
//! priming notification and the SubscribeProcessExit response carries the
//! cached exit code snapshot.

use core::any::Any;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

const PROCESS_EXIT_EVENTS: u32 = NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP;

/// Cached process-exit state owned by the broker.
#[derive(Debug, Clone)]
pub struct ProcessExitState {
    /// Linux wait-style exit code recorded by the exiting worker.
    pub exit_code: i32,
    /// Broker-local timestamp for diagnostics and future wait ordering.
    pub exited_at: Instant,
}

/// Broker-hosted state for one guest process.
#[derive(Debug)]
pub struct ProcessState {
    exit_state: Mutex<Option<ProcessExitState>>,
    subscription_list: SubscriptionList,
}

impl Drop for ProcessState {
    fn drop(&mut self) {
        // PE.9 invariant: always-on. A leak here means eager per-conn
        // unsubscribe isn't running for this state.
        assert!(
            self.subscription_list.is_empty(),
            "ProcessState dropped with {} live exit subscription(s) — \
             eager per-conn unsubscribe not running",
            self.subscription_list.len()
        );
    }
}

impl Default for ProcessState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessState {
    pub fn new() -> Self {
        Self {
            exit_state: Mutex::new(None),
            subscription_list: SubscriptionList::new(),
        }
    }

    /// Convenience constructor that wraps the new state in an `Arc`
    /// for direct hand-off to
    /// [`crate::state_registry::BrokerStateRegistry::register`].
    pub fn arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Returns the broker's cached exit state, if any.
    pub fn exit_state(&self) -> Option<ProcessExitState> {
        self.exit_state
            .lock()
            .expect("ProcessState exit_state poisoned")
            .clone()
    }

    /// Marks the process exited. The first caller stores the exit code
    /// and wakes subscribers; duplicate marks are idempotent.
    pub fn mark_exited(&self, exit_code: i32) -> ProcessExitState {
        let mut guard = self
            .exit_state
            .lock()
            .expect("ProcessState exit_state poisoned");
        if let Some(existing) = guard.as_ref() {
            return existing.clone();
        }

        let state = ProcessExitState {
            exit_code,
            exited_at: Instant::now(),
        };
        *guard = Some(state.clone());
        drop(guard);

        self.subscription_list
            .notify_payload(PROCESS_EXIT_EVENTS, exit_code.to_le_bytes().to_vec());
        state
    }

    /// Subscribes to process-exit readiness. Returns the current exit
    /// snapshot so callers can close subscribe/exit races without
    /// waiting for a separate notification frame.
    pub fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<Option<ProcessExitState>, SubscribeError> {
        let snapshot = self.exit_state();
        self.subscription_list
            .add(subscription_id, events_mask, sender)?;
        if let Some(state) = snapshot.as_ref() {
            self.subscription_list
                .notify_payload(PROCESS_EXIT_EVENTS, state.exit_code.to_le_bytes().to_vec());
        }
        Ok(snapshot)
    }

    /// Unsubscribes by id.
    pub fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subscription_list.remove(subscription_id)
    }

    /// Returns the number of live subscriptions. Test / telemetry.
    pub fn subscription_count(&self) -> usize {
        self.subscription_list.len()
    }
}

impl StateObject for ProcessState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Process
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
        ProcessState::subscribe(self, subscription_id, events_mask, sender).map(|_| ())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        ProcessState::unsubscribe(self, subscription_id)
    }

    fn current_events(&self) -> u32 {
        if self.exit_state().is_some() {
            PROCESS_EXIT_EVENTS
        } else {
            0
        }
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
    fn subsystem_tag_is_process() {
        let s = ProcessState::new();
        assert_eq!(s.subsystem_tag(), SubsystemTag::Process);
    }

    #[test]
    fn subscribe_then_exit_notifies() {
        let s = ProcessState::new();
        let (sender, mut receiver) = make_pair();
        assert!(
            s.subscribe(7, PROCESS_EXIT_EVENTS, sender)
                .unwrap()
                .is_none()
        );

        s.mark_exited(23);
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 7);
        assert_eq!(frame.events(), PROCESS_EXIT_EVENTS);
        assert_eq!(frame.payload_bytes(), Some(&23i32.to_le_bytes()[..]));
        s.unsubscribe(7).unwrap();
    }

    #[test]
    fn late_subscribe_gets_snapshot_and_priming_notification() {
        let s = ProcessState::new();
        s.mark_exited(42);
        let (sender, mut receiver) = make_pair();
        let snapshot = s
            .subscribe(9, PROCESS_EXIT_EVENTS, sender)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.exit_code, 42);

        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 9);
        assert_eq!(frame.events(), PROCESS_EXIT_EVENTS);
        assert_eq!(frame.payload_bytes(), Some(&42i32.to_le_bytes()[..]));
        s.unsubscribe(9).unwrap();
    }

    #[test]
    fn duplicate_mark_is_idempotent() {
        let s = ProcessState::new();
        let first = s.mark_exited(1);
        let second = s.mark_exited(2);
        assert_eq!(first.exit_code, 1);
        assert_eq!(second.exit_code, 1);
        assert_eq!(s.exit_state().unwrap().exit_code, 1);
    }

    #[test]
    fn unsubscribe_stops_exit_notifications() {
        let s = ProcessState::new();
        let (sender, mut receiver) = make_pair();
        s.subscribe(1, PROCESS_EXIT_EVENTS, sender).unwrap();
        s.unsubscribe(1).unwrap();
        assert_eq!(s.subscription_count(), 0);
        s.mark_exited(5);
        drop(s);
        match receiver.recv() {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected EOF, got {other:?}"),
        }
    }
}
