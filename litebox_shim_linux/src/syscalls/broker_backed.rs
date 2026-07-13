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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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
    edge_reset: Option<Weak<BrokerEdgeResetState>>,
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
        if let Some(edge_reset) = self.edge_reset.as_ref().and_then(Weak::upgrade) {
            edge_reset.note_broker_events(events);
        }
        if !shim_events.is_empty() {
            pollee.notify_observers(shim_events);
        }
    }
}

pub(crate) struct BrokerEdgeResetState {
    read_generation: AtomicU64,
    write_generation: AtomicU64,
    write_blocked: AtomicBool,
}

impl BrokerEdgeResetState {
    pub(crate) fn new() -> Self {
        Self {
            read_generation: AtomicU64::new(0),
            write_generation: AtomicU64::new(0),
            write_blocked: AtomicBool::new(false),
        }
    }

    pub(crate) fn read_generation(&self) -> u64 {
        self.read_generation.load(Ordering::Acquire)
    }

    pub(crate) fn write_generation(&self) -> u64 {
        self.write_generation.load(Ordering::Acquire)
    }

    pub(crate) fn note_write_would_block(&self) {
        self.write_blocked.store(true, Ordering::Release);
    }

    pub(crate) fn note_read_edge(&self) {
        self.read_generation.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn note_write_edge_if_armed(&self) {
        if self.write_blocked.swap(false, Ordering::AcqRel) {
            self.write_generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn note_broker_events(&self, events: u32) {
        if events & (NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP) != 0 {
            self.note_read_edge();
        }
        if events & NOTIFY_EVENT_OUT != 0 {
            self.note_write_edge_if_armed();
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
    edge_reset: Option<Arc<BrokerEdgeResetState>>,
    /// If `false`, `Drop` skips calling `provider.release(handle)`.
    /// Used by subsystems that manage the registry refcount per
    /// fd-table-slot (via `on_dup`/`on_close`), where Drop would
    /// double-release. The unsubscribe step in Drop still runs.
    release_on_drop: AtomicBool,
    /// Number of fd-table slots referencing this (shared) broker-backed
    /// fd object. Starts at 1 for the slot the object is created in;
    /// [`note_slot_dup`](Self::note_slot_dup) increments it on every
    /// additional slot (`dup`/`dup2`/fork-clone of the fd table), and
    /// [`force_unsubscribe_if_last_slot`](Self::force_unsubscribe_if_last_slot)
    /// decrements it on slot close. The broker subscription is shared by
    /// every slot, so it must only be torn down when the LAST slot
    /// closes — otherwise a forked child closing its inherited copy
    /// (e.g. CLOEXEC on `exec`) would unsubscribe a subscription the
    /// parent still relies on (e.g. a parent blocked in `accept()` on a
    /// named-unix listener). Subsystems with their own slot accounting
    /// (PTY) don't use this; subsystems that never eagerly unsubscribe
    /// in `on_close` (socketpair) leave it at its initial value.
    slot_refs: AtomicUsize,
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
            edge_reset: None,
            release_on_drop: AtomicBool::new(true),
            slot_refs: AtomicUsize::new(1),
        }
    }

    pub(crate) fn new_edge_tracked(
        provider: Arc<dyn BrokerSubscribable>,
        handle: u64,
        events_mask: u32,
        edge_reset: Arc<BrokerEdgeResetState>,
    ) -> Self {
        Self {
            provider,
            handle,
            sub: litebox::sync::Mutex::new(None),
            events_mask,
            edge_reset: Some(edge_reset),
            release_on_drop: AtomicBool::new(true),
            slot_refs: AtomicUsize::new(1),
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

    /// Records that this fd object has been installed into an additional
    /// fd-table slot (`dup`/`dup2`/fork-clone). Must be called from the
    /// embedding subsystem's `on_dup` alongside `provider.dup_handle`,
    /// and balances a later [`force_unsubscribe_if_last_slot`] in
    /// `on_close`. See [`slot_refs`](Self::slot_refs).
    pub(crate) fn note_slot_dup(&self) {
        self.slot_refs.fetch_add(1, Ordering::SeqCst);
    }

    /// Per-slot `on_close` teardown of the broker subscription that only
    /// actually unsubscribes when the **last** fd-table slot referencing
    /// this shared object closes.
    ///
    /// The fd object (and its single broker subscription) is shared by
    /// `Arc` across every slot it was duped/forked into. A non-final
    /// slot close must NOT unsubscribe, or it would kill a subscription
    /// the surviving slots still rely on — the concrete failure is a
    /// forked child's CLOEXEC close of an inherited named-unix listener
    /// fd tearing down the parent accept loop's subscription so the
    /// parent never wakes. On the final slot the unsubscribe still
    /// precedes the caller's `release`, preserving the eager-before-
    /// release ordering strict-assertion broker StateObjects require.
    pub(crate) fn force_unsubscribe_if_last_slot(&self) {
        let prev = self.slot_refs.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(
            prev > 0,
            "BrokerBackedCommon slot underflow: on_close called with slot_refs=0"
        );
        if prev == 1 {
            self.force_unsubscribe();
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
            edge_reset: self.edge_reset.as_ref().map(Arc::downgrade),
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
        BrokerOpError::PermissionDenied => Errno::EPERM,
        BrokerOpError::ProtocolNotSupported => Errno::EPROTONOSUPPORT,
        BrokerOpError::Io => Errno::EIO,
    }
}
