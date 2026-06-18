// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerSocketSeqPacketProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::cwfd::{
    broker_socket_seqpacket_provider::{
        BrokerEventCallback, BrokerOpError, BrokerSocketSeqPacketProvider,
    },
    broker_subscribable::BrokerSubscribable,
    fd_transfer_frame::PassedToken,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerSocketSeqPacketProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerSocketSeqPacketProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl BrokerSubscribable for RunnerBrokerSocketSeqPacketProvider {
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
            tracing::warn!(handle, subscription_id, error = %e, "socket seqpacket unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "socket seqpacket release failed; broker handle may leak");
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

impl BrokerSocketSeqPacketProvider for RunnerBrokerSocketSeqPacketProvider {
    fn create(&self) -> Result<u64, BrokerOpError> {
        self.client
            .socket_seqpacket_create()
            .map_err(client_err_to_broker_err)
    }

    fn bind(&self, handle: u64, addr: &[u8]) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .socket_seqpacket_bind(handle, addr)
            .map_err(client_err_to_broker_err)
    }

    fn create_socketpair(&self) -> Result<(u64, u64), BrokerOpError> {
        self.client
            .socket_seqpacket_create_socketpair()
            .map_err(client_err_to_broker_err)
    }

    fn listen(&self, handle: u64, backlog: u32) -> Result<(), BrokerOpError> {
        self.client
            .socket_seqpacket_listen(handle, backlog)
            .map_err(client_err_to_broker_err)
    }

    fn accept(&self, handle: u64) -> Result<u64, BrokerOpError> {
        self.client
            .socket_seqpacket_accept(handle)
            .map_err(client_err_to_broker_err)
    }

    fn connect(&self, handle: u64, addr: &[u8]) -> Result<(), BrokerOpError> {
        self.client
            .socket_seqpacket_connect(handle, addr)
            .map_err(client_err_to_broker_err)
    }

    fn send(
        &self,
        handle: u64,
        payload: &[u8],
        tokens: &[PassedToken],
    ) -> Result<usize, BrokerOpError> {
        self.client
            .socket_seqpacket_send(handle, payload, tokens)
            .map_err(client_err_to_broker_err)
    }

    fn recv(
        &self,
        handle: u64,
        max_len: u32,
    ) -> Result<(Vec<u8>, u32, Vec<PassedToken>), BrokerOpError> {
        self.client
            .socket_seqpacket_recv(handle, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn shutdown(&self, handle: u64, how: u8) -> Result<(), BrokerOpError> {
        self.client
            .socket_seqpacket_shutdown(handle, how)
            .map_err(client_err_to_broker_err)
    }

    fn getsockname(&self, handle: u64) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .socket_seqpacket_getsockname(handle)
            .map_err(client_err_to_broker_err)
    }

    fn getpeername(&self, handle: u64) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .socket_seqpacket_getpeername(handle)
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
