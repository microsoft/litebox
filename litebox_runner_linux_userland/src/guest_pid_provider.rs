// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-side implementation of [`GuestPidProvider`].
//!
//! Wraps [`FdTokenClient`] for the RegisterProcess / Release control-
//! channel RPCs against the broker's process registry. The shim's
//! `register_guest_pid` / `release_guest_pid` accessors call into
//! this trait via a `OnceBox` set at runner bootstrap.

use litebox_common_linux::fd_token_client::FdTokenClient;
use litebox_common_linux::guest_pid_provider::{GuestPidProvider, GuestPidProviderError};
use std::sync::Arc;

/// Runner-side concrete impl of [`GuestPidProvider`]. Stores the
/// shared broker control-channel client.
pub struct RunnerGuestPidProvider {
    client: Arc<FdTokenClient>,
}

impl RunnerGuestPidProvider {
    pub fn new(client: Arc<FdTokenClient>) -> Self {
        Self { client }
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
}
