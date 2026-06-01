// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerInetDgramProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::cwfd::{
    broker_inet_dgram_provider::{BrokerEventCallback, BrokerInetDgramProvider, BrokerOpError},
    broker_subscribable::BrokerSubscribable,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerInetDgramProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerInetDgramProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl BrokerSubscribable for RunnerBrokerInetDgramProvider {
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
            tracing::warn!(handle, subscription_id, error = %e, "inet dgram unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "inet dgram release failed; broker handle may leak");
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

impl BrokerInetDgramProvider for RunnerBrokerInetDgramProvider {
    fn create(&self, family: u8) -> Result<u64, BrokerOpError> {
        self.client
            .inet_dgram_create(family)
            .map_err(client_err_to_broker_err)
    }

    fn bind(&self, handle: u64, sockaddr: &[u8]) -> Result<[u8; 28], BrokerOpError> {
        self.client
            .inet_dgram_bind(handle, sockaddr)
            .map_err(client_err_to_broker_err)
    }

    fn connect(&self, handle: u64, sockaddr: &[u8]) -> Result<(), BrokerOpError> {
        self.client
            .inet_dgram_connect(handle, sockaddr)
            .map_err(client_err_to_broker_err)
    }

    fn sendto(&self, handle: u64, sockaddr: &[u8], payload: &[u8]) -> Result<usize, BrokerOpError> {
        self.client
            .inet_dgram_sendto(handle, sockaddr, payload)
            .map_err(client_err_to_broker_err)
    }

    fn recvfrom(
        &self,
        handle: u64,
        max_len: u32,
    ) -> Result<([u8; 28], Vec<u8>, u32), BrokerOpError> {
        self.client
            .inet_dgram_recvfrom(handle, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn shutdown(&self, handle: u64, how: u8) -> Result<(), BrokerOpError> {
        self.client
            .inet_dgram_shutdown(handle, how)
            .map_err(client_err_to_broker_err)
    }

    fn getsockname(&self, handle: u64) -> Result<[u8; 28], BrokerOpError> {
        self.client
            .inet_dgram_getsockname(handle)
            .map_err(client_err_to_broker_err)
    }

    fn getpeername(&self, handle: u64) -> Result<[u8; 28], BrokerOpError> {
        self.client
            .inet_dgram_getpeername(handle)
            .map_err(client_err_to_broker_err)
    }

    fn setsockopt(
        &self,
        handle: u64,
        level: i32,
        name: i32,
        value: &[u8],
    ) -> Result<(), BrokerOpError> {
        self.client
            .inet_dgram_setsockopt(handle, level, name, value)
            .map_err(client_err_to_broker_err)
    }

    fn getsockopt(
        &self,
        handle: u64,
        level: i32,
        name: i32,
        max_len: u32,
    ) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .inet_dgram_getsockopt(handle, level, name, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
        self.client
            .inet_dgram_query_events(handle)
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
        ClientError::InvalidValue { .. } => BrokerOpError::InvalidValue,
        ClientError::Protocol(_) => BrokerOpError::InvalidValue,
        ClientError::PermissionDenied | ClientError::ProtocolNotSupported => BrokerOpError::Io,
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
