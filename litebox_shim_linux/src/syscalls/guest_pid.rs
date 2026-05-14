// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shim-side accessor for the broker-hosted guest-pid provider.
//!
//! Mirrors the [`super::eventfd::broker_eventfd_provider`] pattern: a
//! process-global `OnceBox` holds an `Arc<dyn GuestPidProvider>`,
//! installed by the runner at bootstrap when an fd-token broker is
//! available. Shim call sites consult [`broker_guest_pid_provider`]
//! and fall back to per-shim allocation when the provider is unset.

use alloc::sync::Arc;

use litebox_common_linux::guest_pid_provider::{GuestPidProvider, GuestPidProviderError};

/// Process-global broker guest-pid provider. Set once at runner
/// bootstrap (in `litebox_runner_linux_userland`). `do_fork`
/// consults this; if `Some`, the broker allocates the child's pid;
/// if `None`, falls back to the local per-shim `ProcessRegistry`
/// counter — preserves existing single-worker behaviour when
/// fd-token transport is not configured.
static BROKER_GUEST_PID_PROVIDER: once_cell::race::OnceBox<Arc<dyn GuestPidProvider>> =
    once_cell::race::OnceBox::new();

/// Sets the process-global broker guest-pid provider. Called by the
/// runner exactly once during bootstrap. Returns `Err(provider)` if
/// a provider was already set; callers can decide whether to log +
/// drop or panic on that case (in practice it indicates a bootstrap
/// bug).
#[allow(dead_code)] // wired in by the runner bootstrap, not the shim itself
pub fn set_broker_guest_pid_provider(
    provider: Arc<dyn GuestPidProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn GuestPidProvider>>> {
    BROKER_GUEST_PID_PROVIDER.set(alloc::boxed::Box::new(provider))
}

/// Returns the broker guest-pid provider if one has been set.
pub fn broker_guest_pid_provider() -> Option<Arc<dyn GuestPidProvider>> {
    BROKER_GUEST_PID_PROVIDER.get().cloned()
}

/// Convenience: allocate a fresh globally-unique guest pid from the
/// broker if a provider is installed. Returns `None` if there's no
/// provider (caller falls back to the per-shim counter) or if the
/// broker RPC failed.
pub fn try_register_broker_guest_pid() -> Option<u32> {
    let provider = broker_guest_pid_provider()?;
    match provider.register_process() {
        Ok(pid) => Some(pid),
        Err(GuestPidProviderError::UnknownHandle | GuestPidProviderError::Io) => None,
    }
}

/// Convenience: release a broker-allocated guest pid. No-op if no
/// provider is installed.
pub fn try_release_broker_guest_pid(pid: u32) {
    if let Some(provider) = broker_guest_pid_provider() {
        provider.release_process(pid);
    }
}
