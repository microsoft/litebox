// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerEventfdProvider`].
//!
//! Wraps:
//! - [`FdTokenClient`] for control-channel RPCs (create / read / write
//!   / release / subscribe / unsubscribe), and
//! - [`NotificationDispatcher`] for routing async state-change events
//!   from the broker's push-only notification ring to the right local
//!   callback.
//!
//! The shim's `EventFile::BrokerBacked` variant calls into this trait
//! via the static accessor `litebox_shim_linux::syscalls::eventfd::
//! broker_eventfd_provider()`. The runner sets that accessor exactly
//! once at startup with an instance of this struct.
//!
//! # Subscribe / unsubscribe (Phase B-Step7d scope)
//!
//! Implemented for completeness: `subscribe_eventfd` allocates a
//! subscription id, registers the callback in the dispatcher,
//! and sends `SubscribeEventfd` to the broker. `unsubscribe_eventfd`
//! reverses both halves. The trait's `BrokerEventCallback` is invoked
//! by the dispatcher's reader thread; concrete usage (waking a
//! shim-side Pollee) is part of Phase B-Step7e — for now, callbacks
//! supplied by the shim are simply invoked when notifications fire.

use litebox_common_linux::broker_eventfd::NotificationDispatcher;
use litebox_common_linux::broker_eventfd_provider::{
    BrokerEventCallback, BrokerEventfdProvider, BrokerOpError,
};
use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Runner-side concrete impl of [`BrokerEventfdProvider`]. Stores the
/// client and dispatcher; methods route to either as appropriate.
pub struct RunnerBrokerEventfdProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
    /// Counts subscribe failures; tests / telemetry can read it.
    failed_subscribes: AtomicU32,
}

impl RunnerBrokerEventfdProvider {
    /// Constructs the provider. The caller must have already
    /// `register_notification_ring`'d on the client and started the
    /// dispatcher's reader thread.
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self {
            client,
            dispatcher,
            failed_subscribes: AtomicU32::new(0),
        }
    }
}

impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable
    for RunnerBrokerEventfdProvider
{
    fn subscribe(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        // Bridge BrokerEventCallback → NotificationCallback for the
        // dispatcher's reader thread.
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
                self.failed_subscribes.fetch_add(1, Ordering::Relaxed);
                Err(client_err_to_broker_err(e))
            }
        }
    }

    fn unsubscribe(&self, handle: u64, subscription_id: u64) {
        self.dispatcher.unregister_callback(subscription_id);
        if let Err(e) = self.client.unsubscribe(handle, subscription_id) {
            tracing::warn!(handle, subscription_id, error = %e, "unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            tracing::warn!(handle, error = %e, "release failed; broker handle may leak");
        }
    }

    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
        self.client
            .dup_handle(handle)
            .map_err(client_err_to_broker_err)
    }
}

impl BrokerEventfdProvider for RunnerBrokerEventfdProvider {
    fn create_eventfd(&self, initial: u64, semaphore: bool) -> Result<u64, BrokerOpError> {
        self.client
            .create_eventfd(initial, semaphore)
            .map_err(client_err_to_broker_err)
    }

    fn read_eventfd(&self, handle: u64) -> Result<u64, BrokerOpError> {
        self.client
            .read_eventfd(handle)
            .map_err(client_err_to_broker_err)
    }

    fn write_eventfd(&self, handle: u64, value: u64) -> Result<(), BrokerOpError> {
        self.client
            .write_eventfd(handle, value)
            .map_err(client_err_to_broker_err)
    }
}

/// Adapter so the dispatcher (no_std-friendly NotificationCallback)
/// can invoke a shim-supplied BrokerEventCallback.
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
        _ => BrokerOpError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker::fd_token_socket::spawn_control_listener;
    use litebox_broker::fd_tokens::BrokerFdTokenRegistry;
    use litebox_broker::state_registry::BrokerStateRegistry;
    use litebox_common_linux::broker_eventfd::NotificationDispatcher;
    use litebox_common_linux::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
    use litebox_common_linux::notification_ring::NotificationReceiver;
    use litebox_common_linux::shmem_ring::ShmemRingPair;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Standalone fixture: spawn a broker listener in this process,
    /// connect a client, register the notification ring, build a
    /// dispatcher, and return the provider plus the state registry
    /// (for assertions).
    fn spawn_provider() -> (
        RunnerBrokerEventfdProvider,
        Arc<BrokerStateRegistry>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("fd-token.sock");
        let fd_registry = Arc::new(BrokerFdTokenRegistry::new());
        let state_registry = Arc::new(BrokerStateRegistry::new());
        let process_registry = Arc::new(BrokerStateRegistry::new());
        let _ = spawn_control_listener(
            &path,
            Arc::clone(&fd_registry),
            Arc::clone(&state_registry),
            Arc::clone(&process_registry),
        )
        .expect("spawn listener");

        for _ in 0..100 {
            if path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let client = Arc::new(FdTokenClient::connect(&path).expect("connect"));

        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        let (_worker_writer_unused, worker_reader) = pair.into_parts();
        client
            .register_notification_ring(tx_fd, rx_fd)
            .expect("register_notification_ring");

        let dispatcher = NotificationDispatcher::start(NotificationReceiver::new(worker_reader));
        let provider = RunnerBrokerEventfdProvider::new(client, dispatcher);
        (provider, state_registry, dir)
    }

    #[test]
    fn create_read_write_release_round_trip() {
        let (provider, state_registry, _dir) = spawn_provider();

        let handle = provider.create_eventfd(0, false).expect("create");
        assert!(handle > 0);
        assert_eq!(state_registry.live_handle_count(), 1);

        provider.write_eventfd(handle, 7).expect("write");

        let value = provider.read_eventfd(handle).expect("read");
        assert_eq!(value, 7);

        // Empty: WouldBlock.
        match provider.read_eventfd(handle) {
            Err(BrokerOpError::WouldBlock) => {}
            other => panic!("expected WouldBlock, got {other:?}"),
        }

        // u64::MAX: InvalidValue.
        match provider.write_eventfd(handle, u64::MAX) {
            Err(BrokerOpError::InvalidValue) => {}
            other => panic!("expected InvalidValue, got {other:?}"),
        }

        provider.release_eventfd(handle);
        assert_eq!(state_registry.live_handle_count(), 0);
    }

    #[test]
    fn unknown_handle_maps_to_unknown_handle_error() {
        let (provider, _state, _dir) = spawn_provider();
        match provider.read_eventfd(999_999) {
            Err(BrokerOpError::UnknownHandle) => {}
            other => panic!("expected UnknownHandle, got {other:?}"),
        }
    }

    #[test]
    fn subscribe_delivers_notifications_to_callback() {
        struct AccumCb {
            events: Mutex<u32>,
            count: Mutex<u32>,
        }
        impl BrokerEventCallback for AccumCb {
            fn on_events(&self, events: u32) {
                *self.events.lock().unwrap() |= events;
                *self.count.lock().unwrap() += 1;
            }
        }

        let (provider, _state, _dir) = spawn_provider();
        let handle = provider.create_eventfd(0, false).expect("create");

        let cb = Arc::new(AccumCb {
            events: Mutex::new(0),
            count: Mutex::new(0),
        });
        let sub_id = provider
            .subscribe_eventfd(
                handle,
                NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT,
                Arc::clone(&cb) as Arc<dyn BrokerEventCallback>,
            )
            .expect("subscribe");

        // Write 1 → expect IN+OUT eventually.
        provider.write_eventfd(handle, 1).expect("write");
        // Wait up to ~1s for IN bit to appear (priming + write).
        for _ in 0..100 {
            if *cb.events.lock().unwrap() & NOTIFY_EVENT_IN != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let observed = *cb.events.lock().unwrap();
        assert!(
            observed & NOTIFY_EVENT_IN != 0,
            "expected IN, got 0x{observed:x}"
        );
        assert!(
            observed & NOTIFY_EVENT_OUT != 0,
            "expected OUT, got 0x{observed:x}"
        );

        provider.unsubscribe_eventfd(handle, sub_id);
        provider.release_eventfd(handle);
    }

    #[test]
    fn dup_handle_increments_refcount() {
        let (provider, state_registry, _dir) = spawn_provider();

        let handle = provider.create_eventfd(0, false).expect("create");
        assert_eq!(state_registry.live_handle_count(), 1);

        provider.dup_handle(handle).expect("dup");

        provider.release_eventfd(handle);
        assert_eq!(state_registry.live_handle_count(), 1);

        provider.release_eventfd(handle);
        assert_eq!(state_registry.live_handle_count(), 0);
    }

    #[test]
    fn dup_unknown_handle_errors() {
        let (provider, _state, _dir) = spawn_provider();
        match provider.dup_handle(999_999) {
            Err(BrokerOpError::UnknownHandle) => {}
            other => panic!("expected UnknownHandle, got {other:?}"),
        }
    }
}
