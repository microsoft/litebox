// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted eventfd operations.
//!
//! Phase B-Step7b: the `litebox_shim_linux` shim is `no_std` and
//! therefore cannot directly call the `std`-only
//! [`crate::broker_eventfd::BrokerEventfd`] facade. This module
//! exposes a small trait that the shim depends on; the runner
//! (`litebox_runner_linux_userland`) supplies a concrete impl that
//! wraps `BrokerEventfd` + `NotificationDispatcher`.
//!
//! The trait is intentionally minimal — just the ops a shim
//! `EventFile::BrokerBacked` variant needs.
//!
//! # Object safety
//!
//! All methods are object-safe. The shim stores
//! `Arc<dyn BrokerEventfdProvider>` per backed eventfd.

use alloc::sync::Arc;

/// Errors a broker eventfd op may return to the shim. Maps to a
/// `Errno` at the shim's syscall boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerOpError {
    /// Linux eventfd would block (counter is 0 on read, or saturated
    /// on write). Maps to `Errno::EAGAIN` in non-blocking mode.
    WouldBlock,
    /// `write(u64::MAX)` — invalid sentinel. Maps to `Errno::EINVAL`.
    InvalidValue,
    /// The handle id was unknown to the broker. Maps to `Errno::EBADF`.
    UnknownHandle,
    /// Generic communications or broker-side failure. Maps to
    /// `Errno::EIO`.
    Io,
}

/// A callback invoked from the broker's notification path when
/// subscribed events occur. Implementations typically wake a local
/// `Pollee` so `epoll_wait` / `poll` callers in the shim return.
pub trait BrokerEventCallback: Send + Sync {
    fn on_events(&self, events: u32);
}

/// Trait abstraction over broker-hosted eventfd state.
///
/// The shim sees this trait; the runner provides a concrete impl
/// (wrapping `BrokerEventfd` and `NotificationDispatcher`).
pub trait BrokerEventfdProvider: Send + Sync {
    /// Creates a broker-hosted eventfd with `initial` counter and
    /// optional semaphore mode. Returns the broker handle id, or an
    /// error.
    fn create_eventfd(&self, initial: u64, semaphore: bool) -> Result<u64, BrokerOpError>;

    /// Reads the counter (Linux eventfd `read(2)` semantics).
    fn read_eventfd(&self, handle: u64) -> Result<u64, BrokerOpError>;

    /// Writes (adds) to the counter (Linux eventfd `write(2)` semantics).
    fn write_eventfd(&self, handle: u64, value: u64) -> Result<(), BrokerOpError>;

    /// Releases the broker handle (decrement refcount). Invoked from
    /// shim cleanup; failures are logged and dropped — there's no
    /// useful action a shim can take on a release failure.
    fn release_eventfd(&self, handle: u64);

    /// Subscribes to events on the handle. The provider invokes
    /// `callback.on_events(events)` whenever matching events fire.
    /// Returns a subscription id for later `unsubscribe_eventfd`.
    fn subscribe_eventfd(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError>;

    /// Removes a subscription.
    fn unsubscribe_eventfd(&self, handle: u64, subscription_id: u64);

    /// Asks the broker to increment the refcount of an existing
    /// handle. Used when the worker is about to ship the handle to a
    /// peer (e.g. cross-worker SCM_RIGHTS) — the peer's eventual
    /// release balances this dup.
    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError>;
}
