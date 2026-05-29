// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerSignalfdProvider`].

use litebox_common_linux::broker_eventfd::NotificationDispatcher;
use litebox_common_linux::broker_signalfd_provider::{
    BrokerEventCallback, BrokerOpError, BrokerSignalfdProvider,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

/// Runner-side concrete impl of [`BrokerSignalfdProvider`].
pub struct RunnerBrokerSignalfdProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerSignalfdProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable
    for RunnerBrokerSignalfdProvider
{
    fn subscribe(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        let bridge: Arc<dyn litebox_common_linux::broker_eventfd::NotificationCallback> =
            Arc::new(CallbackBridge { inner: callback });
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
            tracing::warn!(handle, subscription_id, error = %e, "signalfd unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "signalfd release failed; broker handle may leak");
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

impl BrokerSignalfdProvider for RunnerBrokerSignalfdProvider {
    fn create_signalfd(&self, sigmask_lo: u64, sigmask_hi: u64) -> Result<u64, BrokerOpError> {
        self.client
            .create_signalfd(sigmask_lo, sigmask_hi)
            .map_err(client_err_to_broker_err)
    }

    fn read_siginfo(&self, handle: u64) -> Result<Option<Vec<u8>>, BrokerOpError> {
        self.client
            .read_siginfo(handle)
            .map_err(client_err_to_broker_err)
    }

    fn push_siginfo(&self, handle: u64, payload: &[u8]) -> Result<(), BrokerOpError> {
        self.client
            .push_siginfo(handle, payload)
            .map_err(client_err_to_broker_err)
    }
}

struct CallbackBridge {
    inner: Arc<dyn BrokerEventCallback>,
}

impl litebox_common_linux::broker_eventfd::NotificationCallback for CallbackBridge {
    fn on_events(&self, events: u32) {
        self.inner.on_events(events);
    }
}

fn client_err_to_broker_err(err: ClientError) -> BrokerOpError {
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
        | ClientError::CmsgTruncated => BrokerOpError::Io,
    }
}
