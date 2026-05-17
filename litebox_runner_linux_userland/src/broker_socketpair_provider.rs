// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerSocketPairProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::broker_socketpair_provider::{
    BrokerEventCallback, BrokerOpError, BrokerSocketPairProvider,
};
use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerSocketPairProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerSocketPairProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl BrokerSubscribable for RunnerBrokerSocketPairProvider {
    /// Subscribes to broker events for the socketpair endpoint
    /// identified by `handle`. Each endpoint has its own broker
    /// state-registry entry, so the handle uniquely identifies the
    /// end; no endpoint byte is needed.
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
            tracing::warn!(handle, subscription_id, error = %e, "socketpair unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "socketpair release failed; broker handle may leak");
        }
    }

    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
        self.client
            .dup_handle(handle)
            .map_err(client_err_to_broker_err)
    }
}

impl BrokerSocketPairProvider for RunnerBrokerSocketPairProvider {
    fn create_socketpair(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<(u64, u64), BrokerOpError> {
        self.client
            .create_socketpair(capacity, atomic_write_size)
            .map_err(client_err_to_broker_err)
    }

    fn read_socketpair(&self, handle: u64, max_len: u64) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .read_socketpair(handle, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn write_socketpair(&self, handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError> {
        self.client
            .write_socketpair(handle, bytes)
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
        ClientError::Protocol(_) => BrokerOpError::InvalidValue,
        _ => BrokerOpError::Io,
    }
}
