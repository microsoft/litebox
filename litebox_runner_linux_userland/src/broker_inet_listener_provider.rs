// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerInetListenerProvider`].

use litebox_common_linux::broker_eventfd::NotificationDispatcher;
use litebox_common_linux::broker_inet_listener_provider::{
    BrokerEventCallback, BrokerInetListenerProvider, BrokerOpError,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

/// Runner-side concrete impl of [`BrokerInetListenerProvider`].
pub struct RunnerBrokerInetListenerProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerInetListenerProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable
    for RunnerBrokerInetListenerProvider
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
        match self.client.subscribe(handle, subscription_id, events_mask) {
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
            tracing::warn!(handle, subscription_id, error = %e, "inet listener unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "inet listener release failed; broker handle may leak");
        }
    }

    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
        self.client
            .dup_handle(handle)
            .map_err(client_err_to_broker_err)
    }

    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
        self.client
            .inet_listener_query_events(handle)
            .map_err(client_err_to_broker_err)
    }
}

impl BrokerInetListenerProvider for RunnerBrokerInetListenerProvider {
    fn create(&self, family: u8) -> Result<u64, BrokerOpError> {
        self.client
            .inet_listener_create(family)
            .map_err(client_err_to_broker_err)
    }

    fn bind(&self, handle: u64, sockaddr: &[u8]) -> Result<[u8; 28], BrokerOpError> {
        self.client
            .inet_listener_bind(handle, sockaddr)
            .map_err(client_err_to_broker_err)
    }

    fn listen(&self, handle: u64, backlog: u32) -> Result<(), BrokerOpError> {
        self.client
            .inet_listener_listen(handle, backlog)
            .map_err(client_err_to_broker_err)
    }

    fn accept(&self, handle: u64) -> Result<(u64, [u8; 28]), BrokerOpError> {
        self.client
            .inet_listener_accept(handle)
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
