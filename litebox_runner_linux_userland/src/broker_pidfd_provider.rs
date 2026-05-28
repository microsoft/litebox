// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerPidfdProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::broker_eventfd_provider::{BrokerEventCallback, BrokerOpError};
use litebox_common_linux::broker_pidfd_provider::BrokerPidfdProvider;
use litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable;
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Runner-side concrete impl of [`BrokerPidfdProvider`].
pub struct RunnerBrokerPidfdProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
    /// Counts subscribe failures; tests / telemetry can read it.
    failed_subscribes: AtomicU64,
}

impl RunnerBrokerPidfdProvider {
    /// Constructs the provider. The caller must have already registered
    /// the notification ring and started the dispatcher's reader thread.
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self {
            client,
            dispatcher,
            failed_subscribes: AtomicU64::new(0),
        }
    }
}

impl BrokerSubscribable for RunnerBrokerPidfdProvider {
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
                self.failed_subscribes.fetch_add(1, Ordering::Relaxed);
                Err(client_err_to_broker_err(e))
            }
        }
    }

    fn unsubscribe(&self, handle: u64, subscription_id: u64) {
        self.dispatcher.unregister_callback(subscription_id);
        if let Err(e) = self.client.unsubscribe(handle, subscription_id) {
            tracing::warn!(handle, subscription_id, error = %e, "pidfd unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "pidfd release failed; broker handle may leak");
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

impl BrokerPidfdProvider for RunnerBrokerPidfdProvider {
    fn create_pidfd(&self, target_host_pid: u32) -> Result<u64, BrokerOpError> {
        self.client
            .create_pidfd(target_host_pid)
            .map_err(client_err_to_broker_err)
    }

    fn pidfd_exited(&self, handle: u64) -> Result<bool, BrokerOpError> {
        self.client
            .pidfd_exited(handle)
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
