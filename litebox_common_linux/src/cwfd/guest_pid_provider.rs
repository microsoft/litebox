// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted guest pid allocation.
//!
//! Phase 1 of the broker-hosted process registry: the
//! `litebox_shim_linux` shim is `no_std` and therefore cannot
//! directly call the `std`-only broker client. This module exposes
//! a small trait that the shim depends on; the runner
//! (`litebox_runner_linux_userland`) supplies a concrete impl that
//! wraps [`crate::cwfd::fd_token_client::FdTokenClient`].
//!
//! The trait is intentionally minimal — just the two ops needed to
//! decouple guest pid allocation from the per-shim `ProcessRegistry`:
//! allocate a globally-unique pid, and release it when the process
//! is fully reaped.
//!
//! # Object safety
//!
//! Both methods are object-safe. The shim stores the provider as
//! `Arc<dyn GuestPidProvider>` in a process-global `OnceBox`.
//!
//! # Allocator semantics
//!
//! - [`GuestPidProvider::register_process`] returns a freshly
//!   allocated pid. The broker also retains a refcount = 1 entry in
//!   its `process_registry`; the caller's worker now holds one ref.
//! - [`GuestPidProvider::release_process`] decrements the broker's
//!   refcount. When the broker's refcount reaches 0 the entry is
//!   freed and the pid is released.
//! - Pids are monotonically allocated and never reused while the
//!   broker (and therefore the sandbox) is alive — same guarantee
//!   the existing [`crate::cwfd::fd_transfer_frame::SubsystemTag`]-
//!   tagged `StateHandle` ids give.

use alloc::sync::Arc;

use crate::cwfd::broker_subscribable::BrokerEventCallback;

/// Errors a guest-pid provider op may return to the shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestPidProviderError {
    /// The handle id was unknown to the broker (stale or never
    /// registered). Maps to no-op for release; for diagnostics only.
    UnknownHandle,
    /// Operation was rejected with EPERM-like process-group/session semantics.
    NotPermitted,
    /// Generic communications or broker-side failure.
    Io,
}

/// Result of subscribing to broker-owned process-exit notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessExitSubscription {
    /// Worker-allocated subscription id registered with the broker.
    pub subscription_id: u64,
    /// Cached exit code returned by the broker for late subscribers.
    pub already_exited: Option<i32>,
}

/// Trait abstraction over the broker's guest-pid allocator and process-exit state.
///
/// The shim sees this trait; the runner provides a concrete impl
/// that talks to the broker over the existing control plane.
pub trait GuestPidProvider: Send + Sync {
    /// Allocate a fresh globally-unique guest pid and register a
    /// process entry in the broker's `process_registry` with
    /// refcount = 1.
    fn register_process(&self) -> Result<u32, GuestPidProviderError>;

    /// Decrement the broker's refcount on `pid`. Logged-on-failure;
    /// there is no useful action a shim can take on release failure.
    fn release_process(&self, pid: u32);

    /// Mark the process exited in the broker-owned process state and
    /// wake any process-exit subscribers. Exit paths log failures but
    /// must not fail process teardown.
    fn mark_process_exited(&self, pid: u32, exit_code: i32) -> Result<(), GuestPidProviderError>;

    /// Eagerly stamp a successful `setpgid` in the broker.
    fn set_pgid(
        &self,
        caller_pid: u32,
        target_pid: u32,
        new_pgid: u32,
    ) -> Result<(), GuestPidProviderError>;

    /// Eagerly stamp a successful `setsid` in the broker and return the new pgid.
    fn set_sid(&self, caller_pid: u32) -> Result<u32, GuestPidProviderError>;

    /// Subscribe to process-exit readiness for `pid`, using the same
    /// broker notification ring as other broker-backed wait sources.
    fn subscribe_process_exit(
        &self,
        pid: u32,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<ProcessExitSubscription, GuestPidProviderError>;

    /// Remove a process-exit subscription. Best-effort during drop.
    fn unsubscribe_process_exit(&self, pid: u32, subscription_id: u64);

    /// Synchronously asks the broker for the current event bits on
    /// `pid`'s process-exit state. Returns a `NOTIFY_EVENT_*` bitmask:
    /// `IN | HUP` once the process is exited, `0` while it's still
    /// running. Issued by readiness-query paths (poll/select/epoll
    /// with timeout=0) so the broker — the single source of truth —
    /// is consulted directly rather than reading the shim's cached
    /// `BrokerProcessExitWake::exited` AtomicBool. Same property as
    /// [`BrokerSubscribable::query_events`] but on the process_registry
    /// side of the broker.
    fn query_process_exit(&self, pid: u32) -> Result<u32, GuestPidProviderError>;

    /// Phase F.5+ PE.1 Step D: release every (pid, *) entry the broker
    /// is tracking on this connection. Used during shim
    /// `prepare_for_exit` to release non-fd broker state and serve as
    /// a crash-safety belt-and-braces against ref leaks. Default-
    /// implemented as a no-op so existing in-process test impls that
    /// don't need per-pid release do not have to implement it.
    fn release_all_for_pid(&self, _pid: u32) -> Result<u32, GuestPidProviderError> {
        Ok(0)
    }

    /// Block this thread until the broker reports a process-exit event
    /// for `pid` and return the broker-cached exit code.
    ///
    /// Used by the fork-restore parent to wait on the runner-stamped
    /// install-complete signal (an auxiliary broker process handle
    /// whose `mark_exited` payload carries 0 on install success or an
    /// errno on install failure). Returns `None` if the broker
    /// subscription fails, if the timeout elapses, or if the trait
    /// impl does not support blocking waits (the default).
    ///
    /// `timeout` caps the wait so a crashed runner that never stamps
    /// is observable: callers treat `None` as install failure and
    /// reap the host process via the normal `wait_worker_host` path.
    /// Default-implemented as `None` so test impls do not have to
    /// provide blocking semantics.
    fn wait_process_exit_blocking(&self, _pid: u32, _timeout: core::time::Duration) -> Option<i32> {
        None
    }
}

/// Convenience: the `Arc<dyn GuestPidProvider>` shape the shim
/// stores in its `OnceBox`. Centralised here so trait-bound changes
/// (e.g. adding `+ core::fmt::Debug`) flow to all call sites.
pub type SharedGuestPidProvider = Arc<dyn GuestPidProvider>;
