// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerTimerfdProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::broker_timerfd_provider::{
    BrokerEventCallback, BrokerOpError, BrokerTimerfdProvider, BrokerTimerfdSpec,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerTimerfdProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerTimerfdProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable
    for RunnerBrokerTimerfdProvider
{
    fn subscribe(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        let bridge: Arc<dyn NotificationCallback> = Arc::new(CallbackBridge { inner: callback });
        self.dispatcher.register_callback(subscription_id, bridge);
        match self
            .client
            .subscribe_eventfd(handle, subscription_id, events_mask)
        {
            Ok(()) => Ok(subscription_id),
            Err(e) => {
                self.dispatcher.unregister_callback(subscription_id);
                Err(client_err_to_broker_err(e))
            }
        }
    }

    fn unsubscribe(&self, handle: u64, subscription_id: u64) {
        self.dispatcher.unregister_callback(subscription_id);
        if let Err(e) = self.client.unsubscribe(handle, subscription_id) {
            tracing::warn!(handle, subscription_id, error = %e, "timerfd unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "timerfd release failed; broker handle may leak");
        }
    }

    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
        self.client
            .dup_handle(handle)
            .map_err(client_err_to_broker_err)
    }

    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
        self.client
            .query_events(handle)
            .map_err(client_err_to_broker_err)
    }
}

impl BrokerTimerfdProvider for RunnerBrokerTimerfdProvider {
    fn create_timerfd(&self, clockid: i32, flags: u32) -> Result<u64, BrokerOpError> {
        self.client
            .create_timerfd(clockid, flags)
            .map_err(client_err_to_broker_err)
    }

    fn settime_timerfd(
        &self,
        handle: u64,
        new_value: BrokerTimerfdSpec,
        flags: u32,
    ) -> Result<(), BrokerOpError> {
        self.client
            .set_timerfd(handle, new_value, flags)
            .map_err(client_err_to_broker_err)
    }

    fn gettime_timerfd(&self, handle: u64) -> Result<BrokerTimerfdSpec, BrokerOpError> {
        self.client
            .get_timerfd(handle)
            .map_err(client_err_to_broker_err)
    }

    fn read_timerfd(&self, handle: u64) -> Result<u64, BrokerOpError> {
        self.client
            .read_timerfd(handle)
            .map_err(client_err_to_broker_err)
    }
}

struct CallbackBridge {
    inner: Arc<dyn BrokerEventCallback>,
}

impl NotificationCallback for CallbackBridge {
    fn on_events(&self, events: u32) {
        self.inner.on_events(events);
    }
}

fn client_err_to_broker_err(err: ClientError) -> BrokerOpError {
    match err {
        ClientError::WouldBlock => BrokerOpError::WouldBlock,
        ClientError::InvalidValue { .. } => BrokerOpError::InvalidValue,
        ClientError::UnknownHandle { .. } => BrokerOpError::UnknownHandle,
        ClientError::PermissionDenied => BrokerOpError::PermissionDenied,
        ClientError::ProtocolNotSupported => BrokerOpError::ProtocolNotSupported,
        ClientError::Io(_)
        | ClientError::Protocol(_)
        | ClientError::UnexpectedOpcode { .. }
        | ClientError::BrokerRejectedProtocol
        | ClientError::DuplicateSubscription(_)
        | ClientError::UnknownSubscription(_)
        | ClientError::SubsystemMismatch
        | ClientError::NoNotificationRing
        | ClientError::BrokerInternal { .. }
        | ClientError::OtherStatus { .. }
        | ClientError::UnexpectedFdAttachment { .. }
        | ClientError::MissingFdAttachment { .. }
        | ClientError::ShortRead { .. }
        | ClientError::CmsgTruncated
        | ClientError::OperationIo { .. } => BrokerOpError::Io,
    }
}
