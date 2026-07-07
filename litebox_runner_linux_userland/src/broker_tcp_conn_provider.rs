// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerTcpConnProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::broker_tcp_conn_provider::{
    BrokerEventCallback, BrokerOpError, BrokerTcpConnProvider,
};
use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerTcpConnProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerTcpConnProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl BrokerSubscribable for RunnerBrokerTcpConnProvider {
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
            tracing::warn!(handle, subscription_id, error = %e, "tcp conn unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "tcp conn release failed; broker handle may leak");
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

impl BrokerTcpConnProvider for RunnerBrokerTcpConnProvider {
    fn create(&self, family: u8) -> Result<u64, BrokerOpError> {
        self.client
            .tcp_conn_create(family)
            .map_err(client_err_to_broker_err)
    }

    fn connect(&self, handle: u64, sockaddr: &[u8], timeout_ms: u32) -> Result<(), BrokerOpError> {
        self.client
            .tcp_conn_connect(handle, sockaddr, timeout_ms)
            .map_err(client_err_to_broker_err)
    }

    fn getsockname(&self, handle: u64) -> Result<[u8; 28], BrokerOpError> {
        self.client
            .tcp_conn_getsockname(handle)
            .map_err(client_err_to_broker_err)
    }

    fn getpeername(&self, handle: u64) -> Result<[u8; 28], BrokerOpError> {
        self.client
            .tcp_conn_getpeername(handle)
            .map_err(client_err_to_broker_err)
    }

    fn read_tcp_conn(&self, handle: u64, max_len: u64) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .read_tcp_conn(handle, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn write_tcp_conn(&self, handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError> {
        self.client
            .write_tcp_conn(handle, bytes)
            .map_err(client_err_to_broker_err)
    }

    fn shutdown_tcp_conn(&self, handle: u64, read: bool, write: bool) -> Result<(), BrokerOpError> {
        self.client
            .shutdown_tcp_conn(handle, read, write)
            .map_err(client_err_to_broker_err)
    }

    fn setsockopt(
        &self,
        handle: u64,
        level: u32,
        optname: u32,
        optval: &[u8],
    ) -> Result<(), BrokerOpError> {
        self.client
            .tcp_conn_setsockopt(handle, level, optname, optval)
            .map_err(client_err_to_broker_err)
    }

    fn getsockopt(
        &self,
        handle: u64,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .tcp_conn_getsockopt(handle, level, optname, optlen)
            .map_err(client_err_to_broker_err)
    }

    fn poll_tcp_conn_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
        self.client
            .poll_tcp_conn_events(handle)
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
        ClientError::PermissionDenied => BrokerOpError::PermissionDenied,
        ClientError::Io(_)
        | ClientError::UnexpectedOpcode { .. }
        | ClientError::BrokerRejectedProtocol
        | ClientError::DuplicateSubscription(_)
        | ClientError::UnknownSubscription(_)
        | ClientError::SubsystemMismatch
        | ClientError::NoNotificationRing
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
