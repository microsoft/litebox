// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of `BrokerPtyProvider`.

use litebox_common_linux::broker_eventfd::NotificationDispatcher;
use litebox_common_linux::broker_pty_provider::{
    BrokerEventCallback, BrokerOpError, BrokerPtyPair, BrokerPtyProvider,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use litebox_common_linux::fd_token_protocol::PtyIoctlOp;
use std::sync::Arc;

pub struct RunnerBrokerPtyProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerPtyProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable
    for RunnerBrokerPtyProvider
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
            .subscribe_pty(handle, subscription_id, events_mask)
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
            tracing::warn!(handle, subscription_id, error = %e, "pty unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "pty release failed; broker handle may leak");
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

impl BrokerPtyProvider for RunnerBrokerPtyProvider {
    fn create_pty(&self) -> Result<BrokerPtyPair, BrokerOpError> {
        let (master_handle, slave_handle, pty_id) =
            self.client.create_pty().map_err(client_err_to_broker_err)?;
        Ok(BrokerPtyPair {
            master_handle,
            slave_handle,
            pty_id,
        })
    }

    fn open_pty_slave(&self, pty_id: u32) -> Result<u64, BrokerOpError> {
        self.client
            .open_pty_slave(pty_id)
            .map_err(client_err_to_broker_err)
    }

    fn read_pty(&self, handle: u64, max_len: u32) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .pty_read(handle, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn write_pty(&self, handle: u64, data: &[u8]) -> Result<u32, BrokerOpError> {
        self.client
            .pty_write(handle, data)
            .map_err(client_err_to_broker_err)
    }

    fn ioctl_pty(
        &self,
        handle: u64,
        op: PtyIoctlOp,
        payload: &[u8],
    ) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .pty_ioctl(handle, op, payload)
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
        ClientError::PermissionDenied => BrokerOpError::PermissionDenied,
        ClientError::ProtocolNotSupported => BrokerOpError::ProtocolNotSupported,
        ClientError::OperationIo { .. } => BrokerOpError::Io,
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
        | ClientError::CmsgTruncated => BrokerOpError::Io,
    }
}
