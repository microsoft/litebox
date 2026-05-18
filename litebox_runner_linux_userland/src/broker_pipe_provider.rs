// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`BrokerPipeProvider`].

use litebox_common_linux::broker_eventfd::{NotificationCallback, NotificationDispatcher};
use litebox_common_linux::broker_pipe_provider::{
    BrokerEventCallback, BrokerOpError, BrokerPipeProvider,
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
    /// Subscribes to broker events for the pipe end identified by
    /// `handle`. Each end of a pipe has its own broker state-registry
    /// entry, so the handle uniquely identifies the end; no direction
    /// byte is needed.
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
            tracing::warn!(handle, subscription_id, error = %e, "pipe unsubscribe failed");
        }
    }

    fn release(&self, handle: u64) {
        if let Err(e) = self.client.release(handle) {
            // PE.13 fix follow-up: surface release failures loudly to
            // /tmp/rst-diag.log. The most diagnostic case is when the
            // broker side hits PROTOCOL VIOLATION and closes the conn
            // — subsequent provider operations then see BrokenPipe. A
            // tracing::warn alone wasn't visible during PE.13
            // investigation because the runner doesn't init a tracing
            // subscriber. File logging is always-on (cheap; only fires
            // on the error path) and was essential to root-causing
            // the fork-snapshot restore bug.
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
            {
                let _ = writeln!(
                    f,
                    "[PE.13-diag] BrokerPipeProvider::release(handle={handle}) failed: {e}"
                );
            }
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
    fn create_pipe(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<(u64, u64), BrokerOpError> {
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
        other => {
            // PE.14 diag: log the underlying ClientError + a backtrace
            // + a snapshot of /proc/self/fd when we fall through to
            // the generic Io variant. This is a soft-breakpoint-style
            // snapshot: it captures everything we'd want to inspect
            // with gdb at the moment the dead-conn condition surfaces.
            use std::io::Write;
            let bt = std::backtrace::Backtrace::force_capture();
            let pid = std::process::id();
            let mut fd_snapshot = String::new();
            if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
                for e in entries.flatten() {
                    let name = e.file_name();
                    let target = std::fs::read_link(e.path())
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|err| format!("(read_link err: {err})"));
                    fd_snapshot
                        .push_str(&format!("  fd {} -> {}\n", name.to_string_lossy(), target));
                }
            }
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
            {
                let _ = writeln!(
                    f,
                    "[PE.14-diag] BrokerPipeProvider Io fallthrough pid={pid}: {other:?}\n\
                     /proc/self/fd:\n{fd_snapshot}\
                     backtrace:\n{bt}"
                );
            }
            BrokerOpError::Io
        }
    }
}
