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
//! `EventFile::BrokerBacked` variant needs. Lifecycle and
//! subscription operations (subscribe / unsubscribe / release /
//! dup_handle) live on the base [`BrokerSubscribable`] supertrait so
//! they can be shared across every broker-managed fd kind.
//!
//! # Object safety
//!
//! All methods are object-safe. The shim stores
//! `Arc<dyn BrokerEventfdProvider>` per backed eventfd. It can also
//! be coerced to `Arc<dyn BrokerSubscribable>` for the cross-kind
//! poll-wake-up scaffolding.

use crate::cwfd::broker_subscribable::BrokerSubscribable;

#[doc(inline)]
pub use crate::cwfd::broker_subscribable::{BrokerEventCallback, BrokerOpError};

/// Trait abstraction over broker-hosted eventfd state.
///
/// Extends [`BrokerSubscribable`] (lifecycle + subscription) with
/// the eventfd-specific RPCs `create` / `read` / `write`.
///
/// The shim sees this trait; the runner provides a concrete impl
/// (wrapping `BrokerEventfd` and `NotificationDispatcher`).
pub trait BrokerEventfdProvider: BrokerSubscribable {
    /// Creates a broker-hosted eventfd with `initial` counter and
    /// optional semaphore mode. Returns the broker handle id, or an
    /// error.
    fn create_eventfd(&self, initial: u64, semaphore: bool) -> Result<u64, BrokerOpError>;

    /// Reads the counter (Linux eventfd `read(2)` semantics).
    fn read_eventfd(&self, handle: u64) -> Result<u64, BrokerOpError>;

    /// Writes (adds) to the counter (Linux eventfd `write(2)` semantics).
    fn write_eventfd(&self, handle: u64, value: u64) -> Result<(), BrokerOpError>;

    // ---------------------------------------------------------------
    // Compatibility shims for pre-P2.0 call sites.
    //
    // The eventfd-flavoured names predate the BrokerSubscribable
    // factoring; these defaults forward to the generic methods so
    // shim code that still says `provider.release_eventfd(h)` keeps
    // working without an immediate sweep. New code should call the
    // BrokerSubscribable methods directly.
    // ---------------------------------------------------------------

    /// Compatibility alias for [`BrokerSubscribable::release`].
    fn release_eventfd(&self, handle: u64) {
        self.release(handle);
    }

    /// Compatibility alias for [`BrokerSubscribable::subscribe`].
    fn subscribe_eventfd(
        &self,
        handle: u64,
        events_mask: u32,
        callback: alloc::sync::Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError> {
        self.subscribe(handle, events_mask, callback)
    }

    /// Compatibility alias for [`BrokerSubscribable::unsubscribe`].
    fn unsubscribe_eventfd(&self, handle: u64, subscription_id: u64) {
        self.unsubscribe(handle, subscription_id);
    }
}
