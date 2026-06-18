// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerUnixStreamProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::cwfd::{
    broker_subscribable::BrokerSubscribable,
    broker_unix_stream_provider::{BrokerEventCallback, BrokerOpError, BrokerUnixStreamProvider},
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerUnixStreamProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerUnixStreamProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl BrokerSubscribable for RunnerBrokerUnixStreamProvider {
    fn subscribe(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        let bridge: Arc<dyn NotificationCallback> = Arc::new(CallbackBridge { inner: callback });
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
            tracing::warn!(handle, subscription_id, error = %e, "unix stream unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "unix stream release failed; broker handle may leak");
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

impl BrokerUnixStreamProvider for RunnerBrokerUnixStreamProvider {
    fn create(&self) -> Result<u64, BrokerOpError> {
        self.client
            .unix_stream_create()
            .map_err(client_err_to_broker_err)
    }

    fn bind(&self, handle: u64, addr: &[u8]) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .unix_stream_bind(handle, addr)
            .map_err(client_err_to_broker_err)
    }

    fn listen(&self, handle: u64, backlog: u32) -> Result<(), BrokerOpError> {
        self.client
            .unix_stream_listen(handle, backlog)
            .map_err(client_err_to_broker_err)
    }

    fn accept(&self, handle: u64) -> Result<u64, BrokerOpError> {
        self.client
            .unix_stream_accept(handle)
            .map_err(client_err_to_broker_err)
    }

    fn connect(&self, handle: u64, addr: &[u8]) -> Result<(), BrokerOpError> {
        self.client
            .unix_stream_connect(handle, addr)
            .map_err(client_err_to_broker_err)
    }

    fn send(&self, handle: u64, payload: &[u8]) -> Result<usize, BrokerOpError> {
        self.client
            .unix_stream_send(handle, payload)
            .map_err(client_err_to_broker_err)
    }

    fn recv(&self, handle: u64, max_len: u32) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .unix_stream_recv(handle, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn shutdown(&self, handle: u64, how: u8) -> Result<(), BrokerOpError> {
        self.client
            .unix_stream_shutdown(handle, how)
            .map_err(client_err_to_broker_err)
    }

    fn getsockname(&self, handle: u64) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .unix_stream_getsockname(handle)
            .map_err(client_err_to_broker_err)
    }

    fn getpeername(&self, handle: u64) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .unix_stream_getpeername(handle)
            .map_err(client_err_to_broker_err)
    }

    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
        self.client
            .query_events(handle)
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

fn client_err_to_broker_err(e: ClientError) -> BrokerOpError {
    match e {
        ClientError::UnknownHandle { .. } => BrokerOpError::UnknownHandle,
        ClientError::WouldBlock => BrokerOpError::WouldBlock,
        ClientError::InvalidValue { .. } | ClientError::Protocol(_) => BrokerOpError::InvalidValue,
        ClientError::PermissionDenied => BrokerOpError::PermissionDenied,
        ClientError::ProtocolNotSupported => BrokerOpError::ProtocolNotSupported,
        ClientError::Io(_)
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
