// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trait abstraction for broker-hosted pidfd operations.
//!
//! Companion to [`crate::cwfd::broker_eventfd_provider`] but for the
//! pidfd kind (P2.B). Lifecycle and subscription operations live on
//! the [`BrokerSubscribable`] supertrait; this trait adds the
//! pidfd-specific RPCs:
//!
//! * [`create_pidfd`] — opens a broker-hosted pidfd watching a given
//!   target host PID and returns its broker handle id.
//! * [`pidfd_exited`] — synchronous query for the cached "target
//!   process has exited" flag, primarily used by the shim's
//!   `check_io_events` path before any subscription is active.
//!
//! The shim sees this trait via `Arc<dyn BrokerPidfdProvider>`; the
//! runner supplies a concrete implementation that wraps the existing
//! fd-token control client + notification dispatcher.
//!
//! [`create_pidfd`]: BrokerPidfdProvider::create_pidfd
//! [`pidfd_exited`]: BrokerPidfdProvider::pidfd_exited

use crate::cwfd::broker_subscribable::{BrokerOpError, BrokerSubscribable};

/// Worker-side trait for a broker-hosted pidfd kind.
///
/// Extends [`BrokerSubscribable`] with the pidfd-specific
/// `create_pidfd` and `pidfd_exited` RPCs. The shim's
/// `PidfdState::BrokerBacked` variant holds an
/// `Arc<dyn BrokerPidfdProvider>`.
pub trait BrokerPidfdProvider: BrokerSubscribable {
    /// Asks the broker to open a pidfd watching `target_host_pid`.
    /// On success the broker returns a handle id that names the
    /// canonical broker-side pidfd state; the worker is now
    /// responsible for one matching `release()` call (via the
    /// [`BrokerSubscribable`] supertrait) when its reference
    /// drops.
    ///
    /// Errors:
    /// * [`BrokerOpError::Io`] if `pidfd_open` fails or the broker
    ///   RPC fails. The shim translates this to `Errno::EIO` (or
    ///   `ESRCH` for "no such process" — the broker preserves the
    ///   distinction in its `Io` payload semantics on a future
    ///   refinement).
    fn create_pidfd(&self, target_host_pid: u32) -> Result<u64, BrokerOpError>;

    /// Returns whether the target process has exited, as observed
    /// by the broker. Used by `check_io_events` to report
    /// `Events::IN | Events::HUP` synchronously before any
    /// `subscribe()` has primed the local readable cache.
    ///
    /// Implementations should return cheaply (this is on the poll
    /// hot path); the broker stores the cached flag as an
    /// `AtomicBool` set by its watcher thread.
    fn pidfd_exited(&self, handle: u64) -> Result<bool, BrokerOpError>;
}
