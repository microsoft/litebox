// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerPipeProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::broker_pipe_provider::{
    BrokerEventCallback, BrokerOpError, BrokerPipeEnd, BrokerPipeProvider,
};
use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;

pub struct RunnerBrokerPipeProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerBrokerPipeProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl BrokerSubscribable for RunnerBrokerPipeProvider {
    /// Generic subscribe — required by `BrokerSubscribable`. This routes
    /// to the broker as a Read-end subscription, which is **only correct
    /// for read-end fds**. The shim's `BrokerPipeFd` MUST go through
    /// `BrokerPipeProvider::subscribe_pipe_end` (which carries the
    /// direction) instead. Kept here to satisfy the trait for callers
    /// that don't need per-end direction.
    fn subscribe(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        self.subscribe_pipe_end(handle, BrokerPipeEnd::Read, events_mask, callback)
    }

    fn unsubscribe(&self, handle: u64, subscription_id: u64) {
        self.dispatcher.unregister_callback(subscription_id);
        if let Err(e) = self.client.unsubscribe(handle, subscription_id) {
            tracing::warn!(handle, subscription_id, error = %e, "pipe unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "pipe release failed; broker handle may leak");
        }
    }

    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
        self.client
            .dup_handle(handle)
            .map_err(client_err_to_broker_err)
    }
}

impl BrokerPipeProvider for RunnerBrokerPipeProvider {
    fn create_pipe(&self, capacity: u64, atomic_write_size: u64) -> Result<u64, BrokerOpError> {
        self.client
            .create_pipe(capacity, atomic_write_size)
            .map_err(client_err_to_broker_err)
    }

    fn read_pipe(&self, handle: u64, max_len: u64) -> Result<Vec<u8>, BrokerOpError> {
        self.client
            .read_pipe(handle, max_len)
            .map_err(client_err_to_broker_err)
    }

    fn write_pipe(&self, handle: u64, bytes: &[u8]) -> Result<usize, BrokerOpError> {
        self.client
            .write_pipe(handle, bytes)
            .map_err(client_err_to_broker_err)
    }

    fn incref_pipe_end(&self, handle: u64, end: BrokerPipeEnd) -> Result<(), BrokerOpError> {
        self.client
            .incref_pipe_end(handle, end.as_u8())
            .map_err(client_err_to_broker_err)
    }

    fn close_pipe_end(&self, handle: u64, end: BrokerPipeEnd) {
        if let Err(e) = self.client.close_pipe_end(handle, end.as_u8()) {
            tracing::warn!(handle, ?end, error = %e, "pipe close-end failed");
        }
    }

    fn subscribe_pipe_end(
        &self,
        handle: u64,
        end: BrokerPipeEnd,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        let bridge: Arc<dyn NotificationCallback> = Arc::new(CallbackBridge { inner: callback });
        self.dispatcher.register_callback(subscription_id, bridge);
        match self
            .client
            .subscribe_pipe(handle, subscription_id, events_mask, end.as_u8())
        {
            Ok(()) => Ok(subscription_id),
            Err(e) => {
                self.dispatcher.unregister_callback(subscription_id);
                Err(client_err_to_broker_err(e))
            }
        }
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
        _ => BrokerOpError::Io,
    }
}
