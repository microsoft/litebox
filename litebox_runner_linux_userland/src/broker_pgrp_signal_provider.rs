// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side pgrp signal inbox glue.
//!
//! The callback stores the latest broker payload before dispatching. This mirrors
//! design option (a): payload replacement races are benign for the current
//! standard-signal use (SIGWINCH and job-control signals) because the shim's
//! pending-signal queues coalesce standard signals at delivery time.

use litebox_common_linux::cwfd::broker_pgrp_signal_provider::{
    BrokerPgrpSignalCallback, BrokerPgrpSignalProvider,
};
use litebox_common_linux::cwfd::broker_subscribable::BrokerOpError;
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
}

impl BrokerPgrpSignalProvider for RunnerBrokerPgrpSignalProvider {
    fn subscribe_pgrp_signal(
        &self,
        pgid: u32,
        signal_mask: u32,
        callback: Arc<dyn BrokerPgrpSignalCallback>,
    ) -> Result<u64, BrokerOpError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        let subscribed_pgid = i32::try_from(pgid).map_err(|_| BrokerOpError::InvalidValue)?;
        let deliver = Arc::new(move |_payload_pgid, signum, siginfo: &[u8]| {
            callback.on_signal(subscribed_pgid, signum, siginfo);
        });
        let inbox_callback = Arc::new(WorkerSignalInboxCallback::new(deliver));
        self.dispatcher
            .register_callback(subscription_id, inbox_callback);
        if let Err(err) =
            self.client
                .subscribe_signal_inbox(pgid, signal_mask, subscription_id, NOTIFY_EVENT_IN)
        {
            self.dispatcher.unregister_callback(subscription_id);
            return Err(client_err_to_broker_err(err));
        }
        Ok(subscription_id)
    }

    fn unsubscribe_pgrp_signal(&self, pgid: u32, subscription_id: u64) {
        self.dispatcher.unregister_callback(subscription_id);
        if let Err(err) = self.client.unsubscribe_signal_inbox(pgid, subscription_id) {
            tracing::warn!(pgid, subscription_id, error = %err, "signal inbox unsubscribe failed");
        }
    }

    fn deliver_pgrp_signal(&self, pgid: u32, signum: u32) -> Result<(), BrokerOpError> {
        self.client
            .deliver_signal_inbox(pgid, signum)
            .map_err(client_err_to_broker_err)
    }
}

fn client_err_to_broker_err(
    err: litebox_common_linux::fd_token_client::ClientError,
) -> BrokerOpError {
    use litebox_common_linux::fd_token_client::ClientError;

    match err {
        ClientError::WouldBlock => BrokerOpError::WouldBlock,
        ClientError::InvalidValue { .. } => BrokerOpError::InvalidValue,
        ClientError::UnknownHandle { .. } => BrokerOpError::UnknownHandle,
        ClientError::Io(_)
        | ClientError::Protocol(_)
        | ClientError::UnexpectedOpcode { .. }
        | ClientError::BrokerRejectedProtocol
        | ClientError::DuplicateSubscription(_)
        | ClientError::UnknownSubscription(_)
        | ClientError::SubsystemMismatch
        | ClientError::NoNotificationRing
        | ClientError::PermissionDenied
        | ClientError::ProtocolNotSupported
        | ClientError::BrokerInternal { .. }
        | ClientError::OtherStatus { .. }
        | ClientError::UnexpectedFdAttachment { .. }
        | ClientError::MissingFdAttachment { .. }
        | ClientError::ShortRead { .. }
        | ClientError::CmsgTruncated
        | ClientError::OperationIo { .. } => BrokerOpError::Io,
    }
}
