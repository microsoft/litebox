// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Base trait for broker-hosted, subscribable kernel-object handles.
//!
//! Every broker-managed fd kind (eventfd, unix socket, pidfd,
//! signalfd, timerfd, inotify, …) needs the same four operations on
//! its handle id, independent of the kind:
//!
//! * `subscribe` — register a callback invoked from the broker's
//!   notification path. Returns a subscription id.
//! * `unsubscribe` — remove a registered subscription.
//! * `release` — decrement broker-side refcount; broker frees the
//!   underlying state when count reaches zero.
//! * `dup_handle` — increment refcount in preparation for shipping
//!   the handle to a peer worker via SCM_RIGHTS.
//!
//! Splitting this set out from the kind-specific RPCs lets the shim's
//! cross-worker poll-wake-up scaffolding (see
//! `litebox_shim_linux::syscalls::broker_backed::BrokerBackedCommon`)
//! talk to any broker-managed kind through one trait, instead of
//! parametrising over each kind-specific provider trait individually.
//!
//! Each kind's own provider trait (`BrokerEventfdProvider`,
//! `BrokerUnixSocketProvider`, …) is a **supertrait extension**:
//! `pub trait BrokerEventfdProvider: BrokerSubscribable { … }`, so
//! a single `Arc<dyn BrokerEventfdProvider>` can be downcast to
//! `Arc<dyn BrokerSubscribable>` for the common scaffolding.

use alloc::sync::Arc;

/// Errors a broker op may return to the shim. Maps to a `Errno` at
/// the shim's syscall boundary.
///
/// Re-exported from this module so that kind-specific provider
/// traits don't each have to redeclare it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerOpError {
    /// Operation would block (counter is 0 on read, queue is full on
    /// send, etc.). Maps to `Errno::EAGAIN` in non-blocking mode.
    WouldBlock,
    /// Invalid argument (e.g. `eventfd_write(u64::MAX)`). Maps to
    /// `Errno::EINVAL`.
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

/// Lifecycle + subscription operations common to every broker-managed
/// kernel-object kind.
///
/// Every kind-specific provider trait (`BrokerEventfdProvider`,
/// `BrokerUnixSocketProvider`, `BrokerPidfdProvider`,
/// `BrokerSignalfdProvider`, …) declares `BrokerSubscribable` as a
/// supertrait so the cross-kind shim scaffolding can hold an
/// `Arc<dyn BrokerSubscribable>` without knowing the concrete kind.
pub trait BrokerSubscribable: Send + Sync {
    /// Subscribes to events on the handle. The provider invokes
    /// `callback.on_events(events)` whenever matching events fire.
    /// Returns a subscription id for later [`unsubscribe`].
    ///
    /// [`unsubscribe`]: BrokerSubscribable::unsubscribe
    fn subscribe(
        &self,
        handle: u64,
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    ) -> Result<u64, BrokerOpError>;

    /// Removes a subscription previously installed via [`subscribe`].
    /// Failures are logged and dropped — there's no useful action a
    /// shim can take on an unsubscribe failure.
    ///
    /// [`subscribe`]: BrokerSubscribable::subscribe
    fn unsubscribe(&self, handle: u64, subscription_id: u64);

    /// Releases the broker handle (decrement refcount). Invoked from
    /// shim cleanup; failures are logged and dropped.
    fn release(&self, handle: u64);

    /// Asks the broker to increment the refcount of an existing
    /// handle. Used when the worker is about to ship the handle to a
    /// peer (e.g. cross-worker SCM_RIGHTS) — the peer's eventual
    /// release balances this dup.
    fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError>;
}
