// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side pgrp signal inbox glue.
//!
//! The callback stores the latest broker payload before dispatching. This mirrors
//! design option (a): payload replacement races are benign for the current
//! standard-signal use (SIGWINCH and job-control signals) because the shim's
//! pending-signal queues coalesce standard signals at delivery time.

use litebox_common_linux::cwfd::notification_frame::{NOTIFY_EVENT_IN, NotificationFrame};
use litebox_common_linux::{
    broker_eventfd::NotificationDispatcher, fd_token_client::FdTokenClient,
};
use std::sync::{Arc, Mutex};

pub type SignalDelivery = dyn Fn(i32, i32, &[u8]) + Send + Sync;

pub struct WorkerSignalInboxCallback {
    latest_payload: Mutex<Option<Vec<u8>>>,
    deliver: Arc<SignalDelivery>,
}

impl WorkerSignalInboxCallback {
    pub fn new(deliver: Arc<SignalDelivery>) -> Self {
        Self {
            latest_payload: Mutex::new(None),
            deliver,
        }
    }
}

impl litebox_common_linux::broker_eventfd::NotificationCallback for WorkerSignalInboxCallback {
    fn on_frame(&self, frame: &NotificationFrame) {
        if let Some(payload) = frame.payload_bytes() {
            *self
                .latest_payload
                .lock()
                .expect("signal inbox payload mutex poisoned") = Some(payload.to_vec());
        }
        self.on_events(frame.events());
    }

    fn on_events(&self, events: u32) {
        if events & NOTIFY_EVENT_IN == 0 {
            return;
        }
        let Some(payload) = self
            .latest_payload
            .lock()
            .expect("signal inbox payload mutex poisoned")
            .take()
        else {
            tracing::warn!(events, "signal inbox notification missing payload");
            return;
        };
        if payload.len() < 8 {
            tracing::warn!(len = payload.len(), "short signal inbox payload");
            return;
        }
        let pgid = i32::from_le_bytes(payload[0..4].try_into().expect("slice length checked"));
        let signum = i32::from_le_bytes(payload[4..8].try_into().expect("slice length checked"));
        (self.deliver)(pgid, signum, &payload[8..]);
    }
}

pub struct RunnerBrokerPgrpSignalProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerPgrpSignalProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }

    pub fn subscribe(
        &self,
        pgid: u32,
        signal_mask: u32,
        callback: Arc<WorkerSignalInboxCallback>,
    ) -> Result<u64, litebox_common_linux::fd_token_client::ClientError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        self.dispatcher.register_callback(subscription_id, callback);
        if let Err(err) =
            self.client
                .subscribe_signal_inbox(pgid, signal_mask, subscription_id, NOTIFY_EVENT_IN)
        {
            self.dispatcher.unregister_callback(subscription_id);
            return Err(err);
        }
        Ok(subscription_id)
    }

    pub fn unsubscribe(&self, pgid: u32, subscription_id: u64) {
        self.dispatcher.unregister_callback(subscription_id);
        if let Err(err) = self.client.unsubscribe_signal_inbox(pgid, subscription_id) {
            tracing::warn!(pgid, subscription_id, error = %err, "signal inbox unsubscribe failed");
        }
    }
}
