// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`GuestPidProvider`].
//!
//! Wraps [`FdTokenClient`] for RegisterProcess / Release and the
//! Phase-G process-exit RPCs against the broker's process registry.

use litebox_common_linux::broker_eventfd::NotificationDispatcher;
use litebox_common_linux::cwfd::notification_frame::{NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN};
use litebox_common_linux::fd_token_client::FdTokenClient;
use litebox_common_linux::guest_pid_provider::{
    GuestPidProvider, GuestPidProviderError, ProcessExitSubscription,
};
use std::sync::Arc;

/// Runner-side concrete impl of [`GuestPidProvider`]. Stores the
/// shared broker control-channel client and notification dispatcher.
pub struct RunnerGuestPidProvider {
    client: Arc<FdTokenClient>,
    dispatcher: Arc<NotificationDispatcher>,
}

impl RunnerGuestPidProvider {
    pub fn new(client: Arc<FdTokenClient>, dispatcher: Arc<NotificationDispatcher>) -> Self {
        Self { client, dispatcher }
    }
}

impl GuestPidProvider for RunnerGuestPidProvider {
    fn register_process(&self) -> Result<u32, GuestPidProviderError> {
        match self.client.register_process() {
            Ok(handle_id) => {
                debug_assert!(
                    handle_id <= u64::from(u32::MAX),
                    "broker handed back a process handle id {handle_id} that doesn't fit u32"
                );
                Ok(handle_id as u32)
            }
            Err(e) => {
                tracing::warn!(error = %e, "register_process RPC failed");
                Err(GuestPidProviderError::Io)
            }
        }
    }

    fn release_process(&self, pid: u32) {
        if let Err(e) = self.client.release(u64::from(pid)) {
            tracing::warn!(pid, error = %e, "release_process RPC failed; pid may leak in broker");
        }
    }

    fn mark_process_exited(&self, pid: u32, exit_code: i32) -> Result<(), GuestPidProviderError> {
        self.client
            .mark_process_exited(pid, exit_code)
            .map_err(|e| map_client_error(pid, e))
    }

    fn set_pgid(
        &self,
        caller_pid: u32,
        target_pid: u32,
        new_pgid: u32,
    ) -> Result<(), GuestPidProviderError> {
        self.client
            .set_pgid(caller_pid, target_pid, new_pgid)
            .map_err(|e| map_client_error(target_pid, e))
    }

    fn set_sid(&self, caller_pid: u32) -> Result<u32, GuestPidProviderError> {
        self.client
            .set_sid(caller_pid)
            .map_err(|e| map_client_error(caller_pid, e))
    }

    fn subscribe_process_exit(
        &self,
        pid: u32,
        events_mask: u32,
        callback: Arc<dyn litebox_common_linux::cwfd::broker_subscribable::BrokerEventCallback>,
    ) -> Result<ProcessExitSubscription, GuestPidProviderError> {
        let subscription_id = self.dispatcher.alloc_subscription_id();
        let bridge: Arc<dyn litebox_common_linux::broker_eventfd::NotificationCallback> =
            Arc::new(CallbackBridge { inner: callback });
        self.dispatcher.register_callback(subscription_id, bridge);
        match self
            .client
            .subscribe_process_exit(pid, subscription_id, events_mask)
        {
            Ok(already_exited) => Ok(ProcessExitSubscription {
                subscription_id,
                already_exited,
            }),
            Err(e) => {
                self.dispatcher.unregister_callback(subscription_id);
                Err(map_client_error(pid, e))
            }
        }
    }

    fn unsubscribe_process_exit(&self, pid: u32, subscription_id: u64) {
        self.dispatcher.unregister_callback(subscription_id);
        if let Err(e) = self.client.unsubscribe(u64::from(pid), subscription_id) {
            tracing::warn!(pid, subscription_id, error = %e, "process-exit unsubscribe failed");
        }
    }

    fn release_all_for_pid(&self, pid: u32) -> Result<u32, GuestPidProviderError> {
        self.client
            .release_all_for_pid(pid)
            .map_err(|e| map_client_error(pid, e))
    }
}

struct CallbackBridge {
    inner: Arc<dyn litebox_common_linux::cwfd::broker_subscribable::BrokerEventCallback>,
}

impl litebox_common_linux::broker_eventfd::NotificationCallback for CallbackBridge {
    fn on_events(&self, events: u32) {
        self.inner.on_events(events);
    }
}

fn map_client_error(
    pid: u32,
    err: litebox_common_linux::fd_token_client::ClientError,
) -> GuestPidProviderError {
    // reason: unsupported variants intentionally share this fallback path.
    #[allow(clippy::wildcard_enum_match_arm)]
    match err {
        litebox_common_linux::fd_token_client::ClientError::UnknownHandle { .. } => {
            tracing::warn!(pid, "process-exit RPC returned UnknownHandle");
            GuestPidProviderError::UnknownHandle
        }
        litebox_common_linux::fd_token_client::ClientError::InvalidValue { .. } => {
            tracing::warn!(pid, "process-group RPC returned EPERM-like rejection");
            GuestPidProviderError::NotPermitted
        }
        other => {
            tracing::warn!(pid, error = %other, "process-exit RPC failed (mapped to Io)");
            // Mirror to /tmp/rst-diag.log so failures surface inside
            // the test container (tracing output may not reach the
            // log dir during fast failures).
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
            {
                let _ = writeln!(
                    f,
                    "[DBG-SUBSCRIBE] pid={} RPC error mapped to Io: {}",
                    pid, other
                );
            }
            GuestPidProviderError::Io
        }
    }
}

#[allow(dead_code)]
const PROCESS_EXIT_EVENTS: u32 = NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP;
