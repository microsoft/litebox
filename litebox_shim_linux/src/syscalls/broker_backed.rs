// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared scaffolding for broker-backed file objects in the shim.
//!
//! Every broker-managed fd kind (eventfd, unix socket, pidfd,
//! signalfd, timerfd, inotify, …) needs the same plumbing to make
//! cross-worker `poll`/`epoll_wait` wake-ups work:
//!
//! 1. An `Arc<Pollee>` whose observers fire from the runner's
//!    notification-dispatcher thread when a peer worker pushes events.
//! 2. Lazy `subscribe` on first observer registration and
//!    `unsubscribe` on drop, talking to the broker through the
//!    kind-agnostic [`BrokerSubscribable`] trait.
//! 3. `release` on drop to balance the initial broker handle.
//!
//! Kind-specific code (read / write / sendmsg / etc.) lives outside
//! this struct on the embedding variant; this module owns just the
//! cross-worker wake-up plumbing.
//!
//! **No readiness cache.** The broker is the single source of truth
//! for broker-held resources, so [`BrokerBackedCommon::check_io_events`]
//! always issues a synchronous `QueryEvents` RPC. Notifications still
//! serve to *wake* blocked pollees, but they no longer write any local
//! state that polls read — eliminating the "stale mirror" race in
//! which a worker queries readiness *between* a broker-side event and
//! the dispatcher thread processing the corresponding frame.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};

use litebox::event::{Events, polling::Pollee};
use litebox::platform::TimeProvider;
use litebox::sync::RawSyncPrimitivesProvider;
use litebox_common_linux::cwfd::broker_subscribable::{
    BrokerEventCallback, BrokerOpError, BrokerSubscribable,
};
use litebox_common_linux::cwfd::notification_frame::{
    NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::errno::Errno;

/// Active broker subscription bookkeeping. Held inside a `Mutex`
/// inside [`BrokerBackedCommon`] so `ensure_subscribed` is
/// idempotent and `Drop` can unsubscribe.
struct BrokerSubscription {
    provider: Arc<dyn BrokerSubscribable>,
    handle: u64,
    subscription_id: u64,
}

/// Callback the runner's NotificationDispatcher invokes when a
/// broker NotificationFrame arrives for this subscription.
///
/// Pure wake-up signal: translates broker event bits to shim
/// `Events` and fires local `Pollee` observers so any blocked
/// `epoll_wait` / `poll` / `select` re-runs `scan_once`, which
/// queries the broker via `check_io_events`. No local cache is
/// touched — the broker is authoritative.
///
/// Holds a **`Weak`** reference to the owner's pollee so a delayed
/// callback after the owner has dropped is a no-op rather than a
/// dangling reference.
struct BrokerSubscriptionWaker<P: RawSyncPrimitivesProvider + TimeProvider> {
    pollee: Weak<Pollee<P>>,
}

impl<P> BrokerEventCallback for BrokerSubscriptionWaker<P>
where
    P: RawSyncPrimitivesProvider + TimeProvider + Send + Sync + 'static,
{
    fn on_events(&self, events: u32) {
        let Some(pollee) = self.pollee.upgrade() else {
            return;
        };
        let shim_events = broker_events_to_shim_events(events);
        if !shim_events.is_empty() {
            pollee.notify_observers(shim_events);
        }
    }
}

/// Translates a broker-side `NOTIFY_EVENT_*` bitmask to the shim's
/// `Events` enum.
#[inline]
fn broker_events_to_shim_events(events: u32) -> Events {
    let mut shim_events = Events::empty();
    if events & NOTIFY_EVENT_IN != 0 {
        shim_events |= Events::IN;
    }
    if events & NOTIFY_EVENT_OUT != 0 {
        shim_events |= Events::OUT;
    }
    if events & NOTIFY_EVENT_HUP != 0 {
        shim_events |= Events::HUP;
    }
    if events & NOTIFY_EVENT_ERR != 0 {
        shim_events |= Events::ERR;
    }
    shim_events
}

/// Scaffolding shared by every shim-side broker-backed file variant.
///
/// Does **not** own the `Arc<Pollee>` — the embedding type passes
/// its pollee to [`ensure_subscribed`] so that callers which share
/// one pollee across multiple variants (e.g. `EventFile` whose
/// `Eventfd` / `Timerfd` / `BrokerBacked` arms share one top-level
/// pollee) can do so without surfacing two competing pollees.
///
/// Generic over the same `Platform` bounds the embedding type
/// carries; in practice this is `litebox_platform_multiplex::Platform`.
///
/// [`ensure_subscribed`]: BrokerBackedCommon::ensure_subscribed
pub(crate) struct BrokerBackedCommon<P: RawSyncPrimitivesProvider + TimeProvider> {
    provider: Arc<dyn BrokerSubscribable>,
    handle: u64,
    sub: litebox::sync::Mutex<P, Option<BrokerSubscription>>,
    events_mask: u32,
    /// If `false`, `Drop` skips calling `provider.release(handle)`.
    /// Used by subsystems that manage the registry refcount per
    /// fd-table-slot (via `on_dup`/`on_close`), where Drop would
    /// double-release. The unsubscribe step in Drop still runs.
    release_on_drop: AtomicBool,
}

impl<P> BrokerBackedCommon<P>
where
    P: RawSyncPrimitivesProvider + TimeProvider,
{
    pub(crate) fn new(
        provider: Arc<dyn BrokerSubscribable>,
        handle: u64,
        events_mask: u32,
    ) -> Self {
        Self {
            provider,
            handle,
            sub: litebox::sync::Mutex::new(None),
            events_mask,
            release_on_drop: AtomicBool::new(true),
        }
    }

    /// Suppresses the automatic `release(handle)` in `Drop`. Used by
    /// subsystems that manage the registry refcount per fd-table-slot
    /// via `FdEnabledSubsystemEntry::{on_dup, on_close}`.
    pub(crate) fn disable_release_on_drop(&self) {
        self.release_on_drop.store(false, Ordering::Release);
    }

    /// Eagerly tears down the broker subscription, if any. Idempotent.
    /// Used by per-slot `on_close` paths whose last release decrements
    /// the broker StateObject refcount to 0; sending Unsubscribe BEFORE
    /// that final Release ensures the StateObject's SubscriptionList is
    /// empty by the time it drops (strict-assertion subsystems like
    /// PTY/pidfd/process require this — without it, the
    /// "dropped with N live subscription(s)" invariant fires).
    pub(crate) fn force_unsubscribe(&self) {
        if let Some(sub) = self.sub.lock().take() {
            sub.provider.unsubscribe(sub.handle, sub.subscription_id);
        }
    }

    /// Returns the canonical broker handle id.
    #[inline]
    pub(crate) fn handle(&self) -> u64 {
        self.handle
    }

    /// Synchronously asks the broker for the current `Events` bitmask
    /// on this handle. Replaces the previous local-cache mirror; the
    /// broker is the single source of truth for broker-held resources,
    /// so every readiness query goes to it. On RPC failure returns
    /// `Events::empty()` (treat as "no events ready" — the caller will
    /// retry, and a hard failure surfaces on the next read/write).
    #[inline]
    pub(crate) fn check_io_events(&self) -> Events {
        match self.provider.query_events(self.handle) {
            Ok(events) => broker_events_to_shim_events(events),
            Err(_) => Events::empty(),
        }
    }
}

impl<P> BrokerBackedCommon<P>
where
    P: RawSyncPrimitivesProvider + TimeProvider + Send + Sync + 'static,
{
    /// Lazily installs a broker subscription on the first call.
    /// Subsequent calls are no-ops. The caller supplies the pollee
    /// that should be woken from the dispatcher thread when a
    /// matching NotificationFrame arrives.
    ///
    /// Failures are soft — the embedding variant still registers
    /// the local pollee observer, and in-worker writes still wake
    /// via `pollee.notify_observers`. Cross-worker wake-up is the
    /// only thing missed on subscription failure.
    pub(crate) fn ensure_subscribed(&self, pollee: &Arc<Pollee<P>>) {
        let mut guard = self.sub.lock();
        if guard.is_some() {
            return;
        }
        let waker: Arc<BrokerSubscriptionWaker<P>> = Arc::new(BrokerSubscriptionWaker {
            pollee: Arc::downgrade(pollee),
        });
        let callback: Arc<dyn BrokerEventCallback> = waker;
        match self
            .provider
            .subscribe(self.handle, self.events_mask, callback)
        {
            Ok(subscription_id) => {
                *guard = Some(BrokerSubscription {
                    provider: Arc::clone(&self.provider),
                    handle: self.handle,
                    subscription_id,
                });
            }
            Err(_e) => {
                // Soft failure: in-worker writes still wake via the
                // local pollee. Cross-worker wake-up is missed for
                // this object, but that's not a correctness issue
                // for the local case.
            }
        }
    }
}

impl<P> Drop for BrokerBackedCommon<P>
where
    P: RawSyncPrimitivesProvider + TimeProvider,
{
    fn drop(&mut self) {
        // Unsubscribe first so the dispatcher stops dispatching to a
        // callback whose Weak refs are about to be invalidated.
        if let Some(sub) = self.sub.lock().take() {
            sub.provider.unsubscribe(sub.handle, sub.subscription_id);
        }
        if self.release_on_drop.load(Ordering::Acquire) {
            // Release balances the initial broker handle refcount.
            self.provider.release(self.handle);
        }
    }
}

/// Maps a `BrokerOpError` (kind-agnostic) to the shim `Errno`.
#[must_use]
pub(crate) fn broker_err_to_errno(err: BrokerOpError) -> Errno {
    match err {
        BrokerOpError::WouldBlock => Errno::EAGAIN,
        BrokerOpError::InvalidValue => Errno::EINVAL,
        BrokerOpError::UnknownHandle => Errno::EBADF,
        BrokerOpError::Io => Errno::EIO,
    }
}
