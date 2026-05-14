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

/// Errors a guest-pid provider op may return to the shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestPidProviderError {
    /// The handle id was unknown to the broker (stale or never
    /// registered). Maps to no-op for release; for diagnostics only.
    UnknownHandle,
    /// Generic communications or broker-side failure.
    Io,
}

/// Trait abstraction over the broker's guest-pid allocator.
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
}

/// Convenience: the `Arc<dyn GuestPidProvider>` shape the shim
/// stores in its `OnceBox`. Centralised here so trait-bound changes
/// (e.g. adding `+ core::fmt::Debug`) flow to all call sites.
pub type SharedGuestPidProvider = Arc<dyn GuestPidProvider>;
