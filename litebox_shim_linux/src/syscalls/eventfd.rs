// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification, pid-backed polling, and timer-backed polling.

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::Duration,
};

use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        observer::Subject,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::{Instant as _, SystemTime as _, TimeProvider},
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    ClockId, EfdFlags, ItimerSpec, TimerfdFlags, TimerfdTimerFlags,
    broker_eventfd_provider::{BrokerEventfdProvider, BrokerOpError},
    broker_pgrp_signal_provider::BrokerPgrpSignalProvider,
    broker_pty_provider::BrokerPtyProvider,
    cwfd::broker_timerfd_provider::{BrokerTimerfdProvider, BrokerTimerfdSpec},
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

use super::guest_pid::BrokerProcessExitWake;

pub(crate) struct EventfdSubsystem;
impl FdEnabledSubsystem for EventfdSubsystem {
    const KIND: litebox::fd::SubsystemKind = litebox::fd::SubsystemKind::Eventfd;

    type Entry = EventFile<Platform>;
}
impl FdEnabledSubsystemEntry for EventFile<Platform> {}

/// Process-global broker eventfd provider. Set once at runner
/// bootstrap (in litebox_runner_linux_userland). `sys_eventfd2`
/// requires this to be set — new eventfds are broker-backed
/// eagerly at creation time. If unset, `sys_eventfd2` returns
/// ENODEV.
static BROKER_EVENTFD_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerEventfdProvider>> =
    once_cell::race::OnceBox::new();
static BROKER_PGRP_SIGNAL_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerPgrpSignalProvider>> =
    once_cell::race::OnceBox::new();
static BROKER_PTY_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerPtyProvider>> =
    once_cell::race::OnceBox::new();
static BROKER_TIMERFD_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerTimerfdProvider>> =
    once_cell::race::OnceBox::new();

/// Sets the process-global broker eventfd provider. Called by the
/// runner exactly once during bootstrap.
///
/// Returns `Err(provider)` if a provider was already set; callers
/// can decide whether to log + drop or panic on that case (in
/// practice it indicates a bootstrap bug).
#[allow(dead_code)] // wired in by the runner bootstrap, not the shim itself
pub fn set_broker_eventfd_provider(
    provider: Arc<dyn BrokerEventfdProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerEventfdProvider>>> {
    BROKER_EVENTFD_PROVIDER.set(alloc::boxed::Box::new(provider))
}

/// Returns the broker eventfd provider if one has been set.
pub fn broker_eventfd_provider() -> Option<Arc<dyn BrokerEventfdProvider>> {
    BROKER_EVENTFD_PROVIDER.get().cloned()
}

/// Sets the process-global broker pgrp signal provider.
#[allow(dead_code)]
pub fn set_broker_pgrp_signal_provider(
    provider: Arc<dyn BrokerPgrpSignalProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerPgrpSignalProvider>>> {
    BROKER_PGRP_SIGNAL_PROVIDER.set(alloc::boxed::Box::new(provider))
}

/// Returns the broker pgrp signal provider if one has been set.
pub fn broker_pgrp_signal_provider() -> Option<Arc<dyn BrokerPgrpSignalProvider>> {
    BROKER_PGRP_SIGNAL_PROVIDER.get().cloned()
}

/// Sets the process-global broker PTY provider.
#[allow(dead_code)]
pub fn set_broker_pty_provider(
    provider: Arc<dyn BrokerPtyProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerPtyProvider>>> {
    BROKER_PTY_PROVIDER.set(alloc::boxed::Box::new(provider))
}

/// Returns the broker PTY provider if one has been set.
pub fn broker_pty_provider() -> Option<Arc<dyn BrokerPtyProvider>> {
    BROKER_PTY_PROVIDER.get().cloned()
}

/// Sets the process-global broker timerfd provider.
#[allow(dead_code)]
pub fn set_broker_timerfd_provider(
    provider: Arc<dyn BrokerTimerfdProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerTimerfdProvider>>> {
    BROKER_TIMERFD_PROVIDER.set(alloc::boxed::Box::new(provider))
}

/// Returns the broker timerfd provider if one has been set.
pub fn broker_timerfd_provider() -> Option<Arc<dyn BrokerTimerfdProvider>> {
    BROKER_TIMERFD_PROVIDER.get().cloned()
}

enum EventFileInner<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Pidfd {
        target_pid: litebox::process::ProcessId,
        exited: Arc<AtomicBool>,
        subject: Arc<Subject<Events, Events, Platform>>,
        /// Broker process-exit subscription. Phase B.2 pidfds created by
        /// pidfd_open carry this from birth, so fork-snapshot can export
        /// the target ProcessId token instead of minting a host-pid-backed
        /// pidfd handle. Drop unsubscribes from the broker.
        broker_subscription: Option<BrokerProcessExitWake>,
        /// Host pid of the target process, if known. Captured at
        /// `sys_pidfd_open` time from `fork_child_host_pids`. Kept for
        /// process-control fallback paths; fork-snapshot no longer depends
        /// on it because Phase B.2 exports the broker process token instead.
        host_pid: Option<u32>,
    },
    /// Broker-hosted eventfd (Phase B-Step7b + P2.0 refactor). State
    /// lives in the broker; this worker holds only the canonical
    /// handle id + provider for kind-specific RPCs, alongside a
    /// [`BrokerBackedCommon`] scaffold that owns the cross-worker
    /// poll wake-up plumbing (cached readable flag, lazy subscribe,
    /// Drop-time unsubscribe + release).
    ///
    /// `semaphore` is recorded for diagnostics / future use; the
    /// broker is the source of truth for that flag.
    #[allow(dead_code)]
    BrokerBacked {
        provider: Arc<dyn BrokerEventfdProvider>,
        common: super::broker_backed::BrokerBackedCommon<Platform>,
        semaphore: bool,
    },
    TimerfdBrokerBacked {
        provider: Arc<dyn BrokerTimerfdProvider>,
        common: super::broker_backed::BrokerBackedCommon<Platform>,
    },
}

pub(crate) struct EventFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    inner: litebox::sync::Mutex<Platform, EventFileInner<Platform>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    /// Local pollee, wrapped in Arc so the cross-worker
    /// `BrokerSubscriptionWaker` (running on the runner's
    /// notification-dispatcher thread) can hold a Weak reference
    /// and fire local observer wake-ups when a broker→worker
    /// notification arrives.
    ///
    /// Shared by all variants: Timerfd uses it directly for
    /// in-worker observer registration; BrokerBacked uses it AND
    /// passes it to `BrokerBackedCommon::ensure_subscribed` so the
    /// broker subscription's callback wakes the same pollee.
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    /// Creates a broker-backed eventfd. The caller (`sys_eventfd2`) has
    /// already obtained `handle` from `provider.create_eventfd(...)`.
    /// All subsequent read/write ops route through the provider.
    ///
    /// Phase B-Step7b + P2.0 refactor: broker-backed variant. The
    /// cross-worker poll wake-up scaffolding is delegated to
    /// [`BrokerBackedCommon`] which is stashed inside the
    /// `BrokerBacked` enum arm.
    pub(crate) fn new_broker_backed(
        provider: Arc<dyn BrokerEventfdProvider>,
        handle: u64,
        flags: EfdFlags,
    ) -> Self {
        use litebox_common_linux::cwfd::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));
        // Coerce the kind-specific provider trait object to the base
        // `BrokerSubscribable` for the shared scaffold. The same
        // `Arc` is held in two trait-object forms (kind-specific for
        // RPCs in this file, base for subscribe/unsubscribe/release
        // inside `BrokerBackedCommon`).
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let common = super::broker_backed::BrokerBackedCommon::new(
            subscribable,
            handle,
            NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT,
        );
        Self {
            inner: litebox::sync::Mutex::new(EventFileInner::BrokerBacked {
                provider,
                common,
                semaphore: flags.contains(EfdFlags::SEMAPHORE),
            }),
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn new_timer_broker_backed(
        provider: Arc<dyn BrokerTimerfdProvider>,
        handle: u64,
        flags: TimerfdFlags,
    ) -> Self {
        use litebox_common_linux::cwfd::notification_frame::NOTIFY_EVENT_IN;
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(TimerfdFlags::NONBLOCK));
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let common =
            super::broker_backed::BrokerBackedCommon::new(subscribable, handle, NOTIFY_EVENT_IN);
        Self {
            inner: litebox::sync::Mutex::new(EventFileInner::TimerfdBrokerBacked {
                provider,
                common,
            }),
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn new_pidfd(
        target_pid: litebox::process::ProcessId,
        exited: Arc<AtomicBool>,
        subject: Arc<Subject<Events, Events, Platform>>,
        nonblock: bool,
        host_pid: Option<u32>,
        broker_subscription: Option<BrokerProcessExitWake>,
    ) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, nonblock);
        Self {
            inner: litebox::sync::Mutex::new(EventFileInner::Pidfd {
                target_pid,
                exited,
                subject,
                broker_subscription,
                host_pid,
            }),
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn is_timerfd(&self) -> bool {
        matches!(
            *self.inner.lock(),
            EventFileInner::TimerfdBrokerBacked { .. }
        )
    }

    /// Returns the broker handle id if this is a broker-backed
    /// eventfd, else `None`. Used by the cross-worker SCM_RIGHTS
    /// path to extract the handle for transport in an LBFD frame
    /// (Phase B-Step8e).
    pub(crate) fn broker_backed_handle(&self) -> Option<u64> {
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match &*self.inner.lock() {
            EventFileInner::BrokerBacked { common, .. }
            | EventFileInner::TimerfdBrokerBacked { common, .. } => Some(common.handle()),
            _ => None,
        }
    }

    /// Returns the broker provider if this is a broker-backed
    /// eventfd. Used by the cross-worker SCM_RIGHTS sender to call
    /// `dup_handle` on the same provider that owns this eventfd.
    pub(crate) fn broker_backed_provider(&self) -> Option<Arc<dyn BrokerEventfdProvider>> {
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match &*self.inner.lock() {
            EventFileInner::BrokerBacked { provider, .. } => Some(Arc::clone(provider)),
            _ => None,
        }
    }

    pub(crate) fn pidfd_target(&self) -> Option<(litebox::process::ProcessId, Option<u32>)> {
        // reason: non-pidfd event files intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match &*self.inner.lock() {
            EventFileInner::Pidfd {
                target_pid,
                host_pid,
                ..
            } => Some((*target_pid, *host_pid)),
            _ => None,
        }
    }

    /// Phase 2.F fork-snapshot bridge: extract the broker handle so
    /// the child worker can reattach to the same shared state across
    /// the cross-binary-type fork boundary.
    ///
    /// Behavior by variant:
    /// - `BrokerBacked` / `TimerfdBrokerBacked`: returns the existing handle.
    /// - `Pidfd { broker_subscription: Some(_), .. }`: Phase B.2 pidfds are
    ///   already broker-backed by process-exit subscription, so this is a
    ///   no-op that exports the target ProcessId as the child restore token.
    /// For handle-backed kinds, the caller MUST `dup_handle` the returned
    /// handle and arrange rollback `release`. For Phase B.2 pidfds, the
    /// returned value is a broker process token and needs no fd-handle dup.
    pub(crate) fn ensure_broker_backed_for_fork(
        &self,
        _eventfd_provider: Option<&Arc<dyn BrokerEventfdProvider>>,
        _pidfd_provider: Option<
            &Arc<dyn litebox_common_linux::broker_pidfd_provider::BrokerPidfdProvider>,
        >,
    ) -> Result<Option<super::fork_snapshot::FdKind>, BrokerOpError> {
        use super::fork_snapshot::FdKind;
        let guard = self.inner.lock();
        match &*guard {
            EventFileInner::BrokerBacked { common, .. } => Ok(Some(FdKind::Eventfd {
                handle_id: common.handle(),
            })),
            EventFileInner::TimerfdBrokerBacked { common, .. } => Ok(Some(FdKind::Timerfd {
                handle_id: common.handle(),
            })),
            EventFileInner::Pidfd {
                target_pid,
                broker_subscription,
                ..
            } => {
                let Some(_) = broker_subscription else {
                    unreachable!("pidfd without broker subscription cannot be fork-bridged")
                };
                Ok(Some(FdKind::Pidfd {
                    handle_id: u64::from(target_pid.0),
                }))
            }
        }
    }

    #[cfg(feature = "trace_syscalls")]
    pub(crate) fn kind_name(&self) -> &'static str {
        match &*self.inner.lock() {
            EventFileInner::Pidfd { .. } => "pidfd",
            EventFileInner::BrokerBacked { .. } => "broker_eventfd",
            EventFileInner::TimerfdBrokerBacked { .. } => "broker_timerfd",
        }
    }

    pub(crate) fn needs_host_poll(&self) -> bool {
        matches!(
            *self.inner.lock(),
            EventFileInner::TimerfdBrokerBacked { .. }
        )
    }

    fn try_read_eventfd(&self) -> Result<u64, TryOpError<Errno>> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            EventFileInner::BrokerBacked {
                provider,
                common,
                semaphore,
            } => {
                let provider = Arc::clone(provider);
                let handle = common.handle();
                let _ = semaphore;
                drop(inner);
                // reason: unsupported variants intentionally share this fallback path.
                #[allow(clippy::wildcard_enum_match_arm)]
                match provider.read_eventfd(handle) {
                    Ok(v) => {
                        // Wake in-process pollee observers; readiness
                        // is then re-derived synchronously via
                        // `check_io_events` -> broker. No local cache.
                        self.pollee.notify_observers(Events::OUT);
                        Ok(v)
                    }
                    Err(BrokerOpError::WouldBlock) => Err(TryOpError::TryAgain),
                    Err(BrokerOpError::UnknownHandle) => Err(TryOpError::Other(Errno::EBADF)),
                    Err(BrokerOpError::InvalidValue) => Err(TryOpError::Other(Errno::EINVAL)),
                    Err(BrokerOpError::PermissionDenied) => Err(TryOpError::Other(Errno::EPERM)),
                    Err(BrokerOpError::ProtocolNotSupported) => {
                        Err(TryOpError::Other(Errno::EPROTONOSUPPORT))
                    }
                    Err(BrokerOpError::Io) => Err(TryOpError::Other(Errno::EIO)),
                }
            }
            EventFileInner::Pidfd { .. } | EventFileInner::TimerfdBrokerBacked { .. } => {
                Err(TryOpError::Other(Errno::EINVAL))
            }
        }
    }

    fn try_read_timerfd(&self) -> Result<u64, Errno> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            EventFileInner::TimerfdBrokerBacked { provider, common } => {
                let provider = Arc::clone(provider);
                let handle = common.handle();
                drop(inner);
                provider
                    .read_timerfd(handle)
                    .map_err(super::broker_backed::broker_err_to_errno)
            }
            EventFileInner::Pidfd { .. } | EventFileInner::BrokerBacked { .. } => {
                Err(Errno::EINVAL)
            }
        }
    }

    fn try_read(&self) -> Result<u64, TryOpError<Errno>> {
        let inner = self.inner.lock();
        match &*inner {
            EventFileInner::BrokerBacked { .. } => {
                drop(inner);
                self.try_read_eventfd()
            }
            EventFileInner::TimerfdBrokerBacked { .. } => {
                drop(inner);
                self.try_read_timerfd().map_err(|err| {
                    if err == Errno::EAGAIN {
                        TryOpError::TryAgain
                    } else {
                        TryOpError::Other(err)
                    }
                })
            }
            EventFileInner::Pidfd { .. } => Err(TryOpError::Other(Errno::EINVAL)),
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::IN,
                || self.try_read(),
            )
            .map_err(Errno::from)
    }

    fn try_write_eventfd(&self, value: u64) -> Result<usize, TryOpError<Errno>> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            EventFileInner::BrokerBacked {
                provider, common, ..
            } => {
                let provider = Arc::clone(provider);
                let handle = common.handle();
                drop(inner);
                // reason: unsupported variants intentionally share this fallback path.
                #[allow(clippy::wildcard_enum_match_arm)]
                match provider.write_eventfd(handle, value) {
                    Ok(()) => {
                        // In-process observers still need a wake-up
                        // for this same-process write (the broker
                        // notification path covers cross-process
                        // wakes). Readiness is then queried back via
                        // `check_io_events` -> broker.
                        self.pollee.notify_observers(Events::IN);
                        Ok(8)
                    }
                    Err(BrokerOpError::WouldBlock) => Err(TryOpError::TryAgain),
                    Err(BrokerOpError::UnknownHandle) => Err(TryOpError::Other(Errno::EBADF)),
                    Err(BrokerOpError::InvalidValue) => Err(TryOpError::Other(Errno::EINVAL)),
                    Err(BrokerOpError::PermissionDenied) => Err(TryOpError::Other(Errno::EPERM)),
                    Err(BrokerOpError::ProtocolNotSupported) => {
                        Err(TryOpError::Other(Errno::EPROTONOSUPPORT))
                    }
                    Err(BrokerOpError::Io) => Err(TryOpError::Other(Errno::EIO)),
                }
            }
            EventFileInner::Pidfd { .. } | EventFileInner::TimerfdBrokerBacked { .. } => {
                Err(TryOpError::Other(Errno::EINVAL))
            }
        }
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        let writable = matches!(*self.inner.lock(), EventFileInner::BrokerBacked { .. });
        if !writable {
            let _ = (cx, value);
            return Err(Errno::EINVAL);
        }
        self.pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::OUT,
                || self.try_write_eventfd(value),
            )
            .map_err(Errno::from)
    }

    pub(crate) fn set_timer(
        &self,
        flags: TimerfdTimerFlags,
        new_value: ItimerSpec,
    ) -> Result<ItimerSpec, Errno> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            EventFileInner::TimerfdBrokerBacked { provider, common } => {
                let provider = Arc::clone(provider);
                let handle = common.handle();
                drop(inner);
                let old_value = broker_spec_to_itimer(
                    provider
                        .gettime_timerfd(handle)
                        .map_err(super::broker_backed::broker_err_to_errno)?,
                )?;
                provider
                    .settime_timerfd(handle, itimer_spec_to_broker(new_value)?, flags.bits())
                    .map_err(super::broker_backed::broker_err_to_errno)?;
                Ok(old_value)
            }
            EventFileInner::Pidfd { .. } | EventFileInner::BrokerBacked { .. } => {
                Err(Errno::EINVAL)
            }
        }
    }

    pub(crate) fn get_timer(&self) -> Result<ItimerSpec, Errno> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            EventFileInner::TimerfdBrokerBacked { provider, common } => {
                let provider = Arc::clone(provider);
                let handle = common.handle();
                drop(inner);
                broker_spec_to_itimer(
                    provider
                        .gettime_timerfd(handle)
                        .map_err(super::broker_backed::broker_err_to_errno)?,
                )
            }
            EventFileInner::Pidfd { .. } | EventFileInner::BrokerBacked { .. } => {
                Err(Errno::EINVAL)
            }
        }
    }

    super::common_functions_for_file_status!();
}

// EventFile no longer needs an explicit Drop impl for broker-backed
// state: the BrokerBackedCommon stashed inside the BrokerBacked
// variant performs both unsubscribe and release in its own Drop.

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + Send + Sync + 'static> IOPollable
    for EventFile<Platform>
{
    fn check_io_events(&self) -> Events {
        let mut inner = self.inner.lock();
        let mut events = Events::empty();
        match &mut *inner {
            EventFileInner::TimerfdBrokerBacked { common, .. } => {
                events |= common.check_io_events();
            }
            EventFileInner::Pidfd {
                target_pid,
                exited,
                broker_subscription,
                ..
            } => {
                // Local exit (set by the in-process registry's
                // prepare_for_exit) is in-process truth; no broker
                // round-trip needed.
                if exited.load(Ordering::Acquire) {
                    events |= Events::IN | Events::HUP;
                } else if let Some(sub) = broker_subscription.as_ref() {
                    // Cross-worker target. Two correct sources:
                    //
                    //   (a) the broker, via a synchronous QueryEvents
                    //       RPC on the process_registry handle —
                    //       authoritative *now*. This is the Phase H
                    //       invariant: never let the shim's mirror
                    //       lead the broker.
                    //   (b) the subscription's `exited` flag, set by
                    //       the broker dispatcher callback. Monotone:
                    //       only the broker can flip it to true, so
                    //       `is_exited()==true` proves the broker
                    //       already reported exit at some earlier
                    //       moment. It can lag the broker becoming-
                    //       true, never lead it.
                    //
                    // OR-combine. Phase H gain: when the cache lags
                    // (race window between MarkProcessExited and
                    // dispatcher catch-up), the broker query catches
                    // it. Inherited-pidfd-in-non-PIE-child gain: when
                    // the local broker provider has gone away or
                    // can't resolve the pid in process_registry from
                    // this connection, the cache's already-true bit
                    // still surfaces exit readiness.
                    let cache_says_exited = sub.is_exited();
                    let broker_says_exited = super::guest_pid::broker_guest_pid_provider()
                        .and_then(|p| p.query_process_exit(target_pid.0).ok())
                        .is_some_and(|bits| {
                            use litebox_common_linux::cwfd::notification_frame::{
                                NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN,
                            };
                            bits & (NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP) != 0
                        });
                    if cache_says_exited || broker_says_exited {
                        events |= Events::IN | Events::HUP;
                    }
                }
            }
            EventFileInner::BrokerBacked { common, .. } => {
                // Broker is the single source of truth for broker-held
                // resources. `check_io_events` issues a synchronous
                // `QueryEvents` RPC so we never report stale state.
                events |= common.check_io_events();
            }
        }

        events
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        let inner = self.inner.lock();
        match &*inner {
            EventFileInner::Pidfd {
                subject,
                broker_subscription,
                ..
            } => {
                let observer_mask = mask | Events::ALWAYS_POLLED;
                subject.register_observer(alloc::sync::Weak::clone(&observer), observer_mask);
                if let Some(subscription) = broker_subscription {
                    subscription
                        .subject
                        .register_observer(observer, observer_mask);
                }
            }
            EventFileInner::TimerfdBrokerBacked { common, .. } => {
                common.ensure_subscribed(&self.pollee);
                drop(inner);
                self.pollee.register_observer(observer, mask);
            }
            EventFileInner::BrokerBacked { common, .. } => {
                // Ensure we have an active broker subscription so that
                // cross-worker writes get pushed to our pollee via the
                // notification dispatcher. Idempotent on the inner
                // mutex inside BrokerBackedCommon.
                common.ensure_subscribed(&self.pollee);
                drop(inner);
                self.pollee.register_observer(observer, mask);
            }
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider + Send + Sync + 'static>
    EventFile<Platform>
{
    /// Pre-subscribe a broker-backed EventFile so the dispatcher
    /// thread can wake `self.pollee` even before any
    /// `register_observer` call (i.e. for guests that do a blocking
    /// `read()` without first poll/epoll). Idempotent. No-op for
    /// non-broker variants.
    ///
    /// Required for Phase 2.F follow-up `install_broker_eventfd_fd`:
    /// the cross-binary-type exec'd child binary may read the
    /// inherited eventfd directly, which would otherwise hang
    /// waiting on a pollee that never fires because the broker
    /// subscription is only set up lazily by the epoll path.
    pub(crate) fn pre_subscribe_for_broker_blocking_read(&self) {
        let inner = self.inner.lock();
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match &*inner {
            EventFileInner::BrokerBacked { common, .. }
            | EventFileInner::TimerfdBrokerBacked { common, .. } => {
                common.ensure_subscribed(&self.pollee);
            }
            EventFileInner::Pidfd { .. } => {}
        }
    }
}

pub(crate) fn timerfd_clockid_raw(clockid: ClockId) -> Result<i32, Errno> {
    // reason: unsupported clock ids intentionally share the EINVAL path.
    #[allow(clippy::wildcard_enum_match_arm)]
    match clockid {
        ClockId::RealTime => Ok(0),
        ClockId::Monotonic => Ok(1),
        ClockId::ProcessCputimeId => Ok(2),
        ClockId::ThreadCputimeId => Ok(3),
        ClockId::MonotonicRaw => Ok(4),
        ClockId::RealtimeCoarse => Ok(5),
        ClockId::MonotonicCoarse => Ok(6),
        ClockId::Boottime => Ok(7),
        _ => Err(Errno::EINVAL),
    }
}

fn itimer_spec_to_broker(spec: ItimerSpec) -> Result<BrokerTimerfdSpec, Errno> {
    let _ = Duration::try_from(spec.interval)?;
    let _ = Duration::try_from(spec.value)?;
    Ok(BrokerTimerfdSpec {
        interval_sec: u64::try_from(spec.interval.tv_sec).map_err(|_| Errno::EINVAL)?,
        interval_nsec: spec.interval.tv_nsec,
        value_sec: u64::try_from(spec.value.tv_sec).map_err(|_| Errno::EINVAL)?,
        value_nsec: spec.value.tv_nsec,
    })
}

fn broker_spec_to_itimer(spec: BrokerTimerfdSpec) -> Result<ItimerSpec, Errno> {
    let itimer = ItimerSpec {
        interval: litebox_common_linux::Timespec {
            tv_sec: i64::try_from(spec.interval_sec).map_err(|_| Errno::EINVAL)?,
            tv_nsec: spec.interval_nsec,
        },
        value: litebox_common_linux::Timespec {
            tv_sec: i64::try_from(spec.value_sec).map_err(|_| Errno::EINVAL)?,
            tv_nsec: spec.value_nsec,
        },
    };
    let _ = Duration::try_from(itimer.interval)?;
    let _ = Duration::try_from(itimer.value)?;
    Ok(itimer)
}

impl EventFile<Platform> {
    pub(crate) fn new_broker_process_pidfd(
        target_pid: litebox::process::ProcessId,
        subscription: BrokerProcessExitWake,
        nonblock: bool,
        host_pid: Option<u32>,
    ) -> Self {
        let exited = Arc::new(AtomicBool::new(subscription.is_exited()));
        let subject = Arc::clone(&subscription.subject);
        Self::new_pidfd(
            target_pid,
            exited,
            subject,
            nonblock,
            host_pid,
            Some(subscription),
        )
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    extern crate std;

    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::{collections::BTreeMap, sync::Mutex};

    use litebox_common_linux::{
        EfdFlags, TimerfdFlags,
        broker_eventfd_provider::{BrokerEventCallback, BrokerEventfdProvider, BrokerOpError},
        cwfd::{
            broker_subscribable::BrokerSubscribable,
            broker_timerfd_provider::{
                BrokerTimerfdProvider, test_util::TestBrokerTimerfdProvider,
            },
            notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT},
        },
    };

    use super::EventFile;

    #[derive(Default)]
    struct EventfdState {
        counter: u64,
        semaphore: bool,
        subscriptions: BTreeMap<u64, Subscription>,
    }

    struct Subscription {
        events_mask: u32,
        callback: Arc<dyn BrokerEventCallback>,
    }

    #[derive(Default)]
    struct ProviderState {
        next_handle: u64,
        next_subscription: u64,
        eventfds: BTreeMap<u64, EventfdState>,
    }

    pub(crate) struct TestBrokerEventfdProvider {
        state: Mutex<ProviderState>,
        reads: AtomicU64,
        writes: AtomicU64,
        releases: AtomicU64,
    }

    impl TestBrokerEventfdProvider {
        pub(crate) fn new() -> Self {
            Self {
                state: Mutex::new(ProviderState {
                    next_handle: 1,
                    next_subscription: 1,
                    eventfds: BTreeMap::new(),
                }),
                reads: AtomicU64::new(0),
                writes: AtomicU64::new(0),
                releases: AtomicU64::new(0),
            }
        }

        pub(crate) fn counter(&self, handle: u64) -> Option<u64> {
            self.state
                .lock()
                .unwrap()
                .eventfds
                .get(&handle)
                .map(|eventfd| eventfd.counter)
        }

        pub(crate) fn reads(&self) -> u64 {
            self.reads.load(Ordering::SeqCst)
        }

        pub(crate) fn writes(&self) -> u64 {
            self.writes.load(Ordering::SeqCst)
        }

        pub(crate) fn releases(&self) -> u64 {
            self.releases.load(Ordering::SeqCst)
        }
    }

    impl BrokerSubscribable for TestBrokerEventfdProvider {
        fn subscribe(
            &self,
            handle: u64,
            events_mask: u32,
            callback: Arc<dyn BrokerEventCallback>,
        ) -> Result<u64, BrokerOpError> {
            let mut state = self.state.lock().unwrap();
            let subscription_id = state.next_subscription;
            state.next_subscription += 1;
            let eventfd = state
                .eventfds
                .get_mut(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            eventfd.subscriptions.insert(
                subscription_id,
                Subscription {
                    events_mask,
                    callback,
                },
            );
            Ok(subscription_id)
        }

        fn unsubscribe(&self, handle: u64, subscription_id: u64) {
            if let Some(eventfd) = self.state.lock().unwrap().eventfds.get_mut(&handle) {
                eventfd.subscriptions.remove(&subscription_id);
            }
        }

        fn release(&self, _handle: u64) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }

        fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
            if self.state.lock().unwrap().eventfds.contains_key(&handle) {
                Ok(())
            } else {
                Err(BrokerOpError::UnknownHandle)
            }
        }

        fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
            let state = self.state.lock().unwrap();
            let eventfd = state
                .eventfds
                .get(&handle)
                .ok_or(BrokerOpError::UnknownHandle)?;
            Ok(readiness_bits(eventfd.counter))
        }
    }

    impl BrokerEventfdProvider for TestBrokerEventfdProvider {
        fn create_eventfd(&self, initial: u64, semaphore: bool) -> Result<u64, BrokerOpError> {
            if initial == u64::MAX {
                return Err(BrokerOpError::InvalidValue);
            }
            let mut state = self.state.lock().unwrap();
            let handle = state.next_handle;
            state.next_handle += 1;
            state.eventfds.insert(
                handle,
                EventfdState {
                    counter: initial,
                    semaphore,
                    subscriptions: BTreeMap::new(),
                },
            );
            Ok(handle)
        }

        fn read_eventfd(&self, handle: u64) -> Result<u64, BrokerOpError> {
            let callbacks = {
                let mut state = self.state.lock().unwrap();
                let eventfd = state
                    .eventfds
                    .get_mut(&handle)
                    .ok_or(BrokerOpError::UnknownHandle)?;
                if eventfd.counter == 0 {
                    return Err(BrokerOpError::WouldBlock);
                }
                self.reads.fetch_add(1, Ordering::SeqCst);
                let value = if eventfd.semaphore {
                    eventfd.counter -= 1;
                    1
                } else {
                    core::mem::take(&mut eventfd.counter)
                };
                let callbacks = matching_callbacks(eventfd, NOTIFY_EVENT_OUT);
                (value, callbacks)
            };
            notify(callbacks.1, NOTIFY_EVENT_OUT);
            Ok(callbacks.0)
        }

        fn write_eventfd(&self, handle: u64, value: u64) -> Result<(), BrokerOpError> {
            if value == u64::MAX {
                return Err(BrokerOpError::InvalidValue);
            }
            let callbacks = {
                let mut state = self.state.lock().unwrap();
                let eventfd = state
                    .eventfds
                    .get_mut(&handle)
                    .ok_or(BrokerOpError::UnknownHandle)?;
                let Some(new_value) = eventfd.counter.checked_add(value) else {
                    return Err(BrokerOpError::WouldBlock);
                };
                if new_value == u64::MAX {
                    return Err(BrokerOpError::WouldBlock);
                }
                eventfd.counter = new_value;
                self.writes.fetch_add(1, Ordering::SeqCst);
                matching_callbacks(eventfd, NOTIFY_EVENT_IN)
            };
            notify(callbacks, NOTIFY_EVENT_IN);
            Ok(())
        }
    }

    fn readiness_bits(counter: u64) -> u32 {
        let mut events = 0;
        if counter != 0 {
            events |= NOTIFY_EVENT_IN;
        }
        if counter < u64::MAX - 1 {
            events |= NOTIFY_EVENT_OUT;
        }
        events
    }

    fn matching_callbacks(
        eventfd: &EventfdState,
        events: u32,
    ) -> Vec<Arc<dyn BrokerEventCallback>> {
        eventfd
            .subscriptions
            .values()
            .filter(|subscription| subscription.events_mask & events != 0)
            .map(|subscription| Arc::clone(&subscription.callback))
            .collect()
    }

    fn notify(callbacks: Vec<Arc<dyn BrokerEventCallback>>, events: u32) {
        for callback in callbacks {
            callback.on_events(events);
        }
    }

    pub(crate) fn new_mock_broker_eventfd(
        count: u64,
        flags: EfdFlags,
    ) -> (
        Arc<TestBrokerEventfdProvider>,
        u64,
        EventFile<litebox_platform_multiplex::Platform>,
    ) {
        let provider = Arc::new(TestBrokerEventfdProvider::new());
        let handle = provider
            .create_eventfd(count, flags.contains(EfdFlags::SEMAPHORE))
            .expect("mock eventfd creation failed");
        let provider_dyn: Arc<dyn BrokerEventfdProvider> = provider.clone();
        let eventfd = EventFile::new_broker_backed(provider_dyn, handle, flags);
        (provider, handle, eventfd)
    }

    pub(crate) fn new_mock_broker_timerfd(
        flags: TimerfdFlags,
    ) -> (
        Arc<TestBrokerTimerfdProvider>,
        u64,
        EventFile<litebox_platform_multiplex::Platform>,
    ) {
        let provider = Arc::new(TestBrokerTimerfdProvider::new());
        let handle = provider
            .create_timerfd(1, flags.bits())
            .expect("mock timerfd creation failed");
        let provider_dyn: Arc<dyn BrokerTimerfdProvider> = provider.clone();
        let timerfd = EventFile::new_timer_broker_backed(provider_dyn, handle, flags);
        (provider, handle, timerfd)
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use litebox::event::wait::WaitState;
    use litebox::platform::TimeProvider as _;
    use litebox_common_linux::{
        ClockId, EfdFlags, ItimerSpec, TimerfdFlags, TimerfdTimerFlags, errno::Errno,
    };
    use litebox_platform_multiplex::platform;

    extern crate std;

    #[test]
    fn test_semaphore_eventfd() {
        let _task = crate::syscalls::tests::init_platform(None);

        let (_, _, eventfd) = super::test_support::new_mock_broker_eventfd(0, EfdFlags::SEMAPHORE);
        let eventfd = alloc::sync::Arc::new(eventfd);
        let total = 8;
        for _ in 0..total {
            let copied_eventfd = eventfd.clone();
            std::thread::spawn(move || {
                copied_eventfd
                    .read(&WaitState::new(platform()).context())
                    .unwrap();
            });
        }

        std::thread::sleep(core::time::Duration::from_millis(500));
        eventfd
            .write(&WaitState::new(platform()).context(), total)
            .unwrap();
    }

    #[test]
    fn test_blocking_eventfd() {
        let _task = crate::syscalls::tests::init_platform(None);

        let (_, _, eventfd) = super::test_support::new_mock_broker_eventfd(0, EfdFlags::empty());
        let eventfd = alloc::sync::Arc::new(eventfd);
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            copied_eventfd
                .write(&WaitState::new(platform()).context(), 1)
                .unwrap();
            // block until the first read finishes
            copied_eventfd
                .write(&WaitState::new(platform()).context(), u64::MAX - 1)
                .unwrap();
        });

        // block until the first write
        let ret = eventfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(ret, 1);

        // block until the second write
        let ret = eventfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(ret, u64::MAX - 1);
    }

    #[test]
    fn test_blocking_eventfd_no_race_on_massive_readwrite() {
        let _task = crate::syscalls::tests::init_platform(None);

        let (_, _, eventfd) = super::test_support::new_mock_broker_eventfd(0, EfdFlags::empty());
        let eventfd = alloc::sync::Arc::new(eventfd);
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            for _ in 0..10000 {
                copied_eventfd
                    .write(&WaitState::new(platform()).context(), u64::MAX - 1)
                    .unwrap();
            }
        });

        for _ in 0..10000 {
            let ret = eventfd.read(&WaitState::new(platform()).context()).unwrap();
            assert_eq!(ret, u64::MAX - 1);
        }
    }

    #[test]
    fn test_nonblocking_eventfd() {
        let _task = crate::syscalls::tests::init_platform(None);

        let (_, _, eventfd) = super::test_support::new_mock_broker_eventfd(0, EfdFlags::NONBLOCK);
        let eventfd = alloc::sync::Arc::new(eventfd);
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            // first write should succeed immediately
            copied_eventfd
                .write(&WaitState::new(platform()).context(), 1)
                .unwrap();
            // block until the first read finishes
            while let Err(e) =
                copied_eventfd.write(&WaitState::new(platform()).context(), u64::MAX - 1)
            {
                assert_eq!(e, Errno::EAGAIN, "Unexpected error: {e:?}");
                core::hint::spin_loop();
            }
        });

        let read = |eventfd: &super::EventFile<litebox_platform_multiplex::Platform>,
                    expected_value: u64| {
            loop {
                match eventfd.read(&WaitState::new(platform()).context()) {
                    Ok(ret) => {
                        assert_eq!(ret, expected_value);
                        break;
                    }
                    Err(Errno::EAGAIN) => {
                        // busy wait
                        // TODO: use poll rather than busy wait
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
                core::hint::spin_loop();
            }
        };

        // block until the first write
        read(&eventfd, 1);
        // block until the second write
        read(&eventfd, u64::MAX - 1);
    }

    #[test]
    fn test_timerfd_one_shot() {
        let _task = crate::syscalls::tests::init_platform(None);

        let (provider, handle, timerfd) =
            super::test_support::new_mock_broker_timerfd(TimerfdFlags::empty());
        let old = timerfd
            .set_timer(
                TimerfdTimerFlags::empty(),
                ItimerSpec {
                    interval: Duration::ZERO.into(),
                    value: Duration::from_millis(1).into(),
                },
            )
            .unwrap();
        assert_eq!(Duration::try_from(old.value).unwrap(), Duration::ZERO);

        provider
            .fire_timerfd(handle, 1)
            .expect("mock timerfd fire failed");
        let expirations = timerfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(expirations, 1);
        assert_eq!(
            Duration::try_from(timerfd.get_timer().unwrap().value).unwrap(),
            Duration::from_millis(1)
        );
    }

    /// Phase B-Step7b: verifies an `EventFile::new_broker_backed`
    /// instance routes read/write through a mock provider.
    /// Functional surface: the same `read`/`write` calls that work
    /// against a local `EventFile::new` work against a broker-backed
    /// one without the caller knowing the difference.
    #[test]
    fn test_broker_backed_eventfd_routes_read_write() {
        use alloc::sync::Arc;

        let _task = crate::syscalls::tests::init_platform(None);

        let (provider, handle, eventfd) =
            super::test_support::new_mock_broker_eventfd(0, EfdFlags::NONBLOCK);
        let eventfd = Arc::new(eventfd);

        let n = eventfd
            .write(&WaitState::new(platform()).context(), 5)
            .unwrap();
        assert_eq!(n, 8);
        assert_eq!(provider.counter(handle), Some(5));
        assert_eq!(provider.writes(), 1);

        let v = eventfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(v, 5);
        assert_eq!(provider.counter(handle), Some(0));
        assert_eq!(provider.reads(), 1);

        // Second read → WouldBlock, surfaces as EAGAIN because NONBLOCK is set.
        match eventfd.read(&WaitState::new(platform()).context()) {
            Err(Errno::EAGAIN) => {}
            other => panic!("expected EAGAIN, got {other:?}"),
        }

        // Write u64::MAX → InvalidValue → EINVAL.
        match eventfd.write(&WaitState::new(platform()).context(), u64::MAX) {
            Err(Errno::EINVAL) => {}
            other => panic!("expected EINVAL on u64::MAX write, got {other:?}"),
        }
    }

    /// Phase B-Step8: verifies that dropping a BrokerBacked EventFile
    /// calls provider.release_eventfd, balancing the broker-side
    /// refcount that sys_eventfd2 set up at create.
    #[test]
    fn test_broker_backed_eventfd_drop_releases_handle() {
        let _task = crate::syscalls::tests::init_platform(None);

        let (provider, _, eventfd) =
            super::test_support::new_mock_broker_eventfd(0, EfdFlags::empty());
        {
            let _ef = eventfd;
        }

        assert_eq!(
            provider.releases(),
            1,
            "EventFile::drop must call release_eventfd exactly once for the BrokerBacked variant",
        );
    }

    /// Phase B-Step12 focused test: does a broker-backed eventfd created
    /// via `sys_eventfd2` (the guest-visible syscall path) behave
    /// indistinguishably from a local eventfd for the basic
    /// write → read → counter-zero cycle, when the provider is a REAL
    /// `FdTokenClient` against a REAL in-process broker?
    ///
    /// **Coverage limitation**: this test exercises a SINGLE eventfd
    /// in a SINGLE task in a SINGLE thread. It does NOT exercise
    /// fork (delayed/snapshot/restore), cross-process eventfd
    /// inheritance, SCM_RIGHTS transfer of eventfds, multi-thread
    /// blocking-read wake-up, or concurrent operations across many
    /// eventfds. The docker integration regression triggers under
    /// fork-based test patterns the harness uses, so this test
    /// passing does NOT prove broker-backed eventfds work for that
    /// path. It DOES prove they work for the basic non-fork case —
    /// useful as a regression pin, and as evidence that the bug
    /// is fork-path-specific.
    #[test]
    fn sys_eventfd2_via_real_broker_basic_write_read() {
        use crate::syscalls::eventfd::set_broker_eventfd_provider;
        use alloc::sync::Arc;
        use litebox_broker::fd_token_socket::spawn_control_listener;
        use litebox_broker::fd_tokens::BrokerFdTokenRegistry;
        use litebox_broker::inotify_dispatcher::InotifyDispatcher;
        use litebox_broker::state_registry::BrokerStateRegistry;
        use litebox_common_linux::EfdFlags;
        use litebox_common_linux::broker_eventfd_provider::{
            BrokerEventCallback, BrokerEventfdProvider, BrokerOpError,
        };
        use litebox_common_linux::fd_token_client::FdTokenClient;
        use std::sync::Mutex as StdMutex;
        use tempfile::tempdir;

        /// Minimal provider wrapping a real FdTokenClient — same shape
        /// as RunnerBrokerEventfdProvider but stripped to what this
        /// test exercises (no dispatcher / no subscriptions). Real
        /// RPC over the real Unix socket.
        struct RealProviderForTest {
            client: StdMutex<FdTokenClient>,
        }
        impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable for RealProviderForTest {
            fn subscribe(
                &self,
                _: u64,
                _: u32,
                _: Arc<dyn BrokerEventCallback>,
            ) -> Result<u64, BrokerOpError> {
                Err(BrokerOpError::Io)
            }
            fn unsubscribe(&self, _: u64, _: u64) {}
            fn release(&self, handle: u64) {
                let _ = self.client.lock().unwrap().release(handle);
            }
            fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .dup_handle(handle)
                    .map_err(client_err_to_broker_err)
            }
            fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .query_events(handle)
                    .map_err(client_err_to_broker_err)
            }
        }

        impl BrokerEventfdProvider for RealProviderForTest {
            fn create_eventfd(&self, initial: u64, semaphore: bool) -> Result<u64, BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .create_eventfd(initial, semaphore)
                    .map_err(client_err_to_broker_err)
            }
            fn read_eventfd(&self, handle: u64) -> Result<u64, BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .read_eventfd(handle)
                    .map_err(client_err_to_broker_err)
            }
            fn write_eventfd(&self, handle: u64, value: u64) -> Result<(), BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .write_eventfd(handle, value)
                    .map_err(client_err_to_broker_err)
            }
        }
        fn client_err_to_broker_err(
            e: litebox_common_linux::fd_token_client::ClientError,
        ) -> BrokerOpError {
            use litebox_common_linux::fd_token_client::ClientError;
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            match e {
                ClientError::WouldBlock => BrokerOpError::WouldBlock,
                ClientError::UnknownHandle { .. } => BrokerOpError::UnknownHandle,
                ClientError::InvalidValue { .. } => BrokerOpError::InvalidValue,
                _ => BrokerOpError::Io,
            }
        }

        // Spawn an in-process broker on a unique socket path.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("fd-token.sock");
        let fd_registry = std::sync::Arc::new(BrokerFdTokenRegistry::new());
        let state_registry = std::sync::Arc::new(BrokerStateRegistry::new());
        let process_registry = std::sync::Arc::new(BrokerStateRegistry::new());
        let inotify_dispatcher = std::sync::Arc::new(InotifyDispatcher::new());
        let _listener_handle = spawn_control_listener(
            &path,
            std::sync::Arc::clone(&fd_registry),
            std::sync::Arc::clone(&state_registry),
            std::sync::Arc::clone(&process_registry),
            std::sync::Arc::clone(&inotify_dispatcher),
        )
        .expect("spawn listener");
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(path.exists(), "broker control socket never appeared");

        // Wire up a real provider against the listener.
        let client = FdTokenClient::connect(&path).expect("connect");
        let provider: Arc<dyn BrokerEventfdProvider> = Arc::new(RealProviderForTest {
            client: StdMutex::new(client),
        });

        // Install via the OnceBox global. If already set by another
        // test in this binary, we still get to verify behaviour via
        // direct EventFile::new_broker_backed — but install-set is the
        // path sys_eventfd2 takes.
        let install_result = set_broker_eventfd_provider(Arc::clone(&provider));
        let _ = install_result; // first-run installs; later runs are OK

        // Drive a real `Task` through `sys_eventfd2`.
        let task = crate::syscalls::tests::init_platform(None);
        let efd_u32 = task
            .sys_eventfd2(0, EfdFlags::NONBLOCK | EfdFlags::CLOEXEC)
            .expect("sys_eventfd2 should succeed with real broker installed");
        let efd = i32::try_from(efd_u32).expect("eventfd fd fits in i32");

        // sys_write(eventfd, 7u64) — guest-visible semantics.
        let val: u64 = 7;
        let buf = val.to_le_bytes();
        // We need a guest buf pointer; for tests, the harness has
        // helpers — use the simplest one available. The simplest
        // surface is task.sys_write(fd, &[u8], offset).
        let n = task
            .sys_write(efd, &buf, None)
            .expect("sys_write to broker-backed eventfd must succeed");
        assert_eq!(n, 8, "eventfd write should report 8 bytes");

        // sys_read(eventfd) — should return 7.
        let mut readbuf = [0u8; 8];
        let n = task
            .sys_read(efd, &mut readbuf, None)
            .expect("sys_read from broker-backed eventfd must succeed");
        assert_eq!(n, 8, "eventfd read should report 8 bytes");
        let got = u64::from_le_bytes(readbuf);
        assert_eq!(
            got, 7,
            "eventfd read should return the previously-written value"
        );

        // Subsequent non-blocking read returns EAGAIN.
        let mut readbuf2 = [0u8; 8];
        let err = task.sys_read(efd, &mut readbuf2, None).unwrap_err();
        assert_eq!(
            err,
            Errno::EAGAIN,
            "non-blocking read on empty broker-backed eventfd should return EAGAIN"
        );

        // Close cleanly.
        task.sys_close(efd).expect("close eventfd");
    }

    /// Phase B-Step12 focused test #2: SEMAPHORE-mode eventfd via real broker.
    /// Semaphore mode is used by some IPC patterns (each read returns 1
    /// and decrements; like a counting semaphore acquire). Verifying
    /// this works through the broker matters because some harness or
    /// guest user-space might use it.
    #[test]
    fn sys_eventfd2_via_real_broker_semaphore_mode() {
        use crate::syscalls::eventfd::set_broker_eventfd_provider;
        use alloc::sync::Arc;
        use litebox_broker::fd_token_socket::spawn_control_listener;
        use litebox_broker::fd_tokens::BrokerFdTokenRegistry;
        use litebox_broker::inotify_dispatcher::InotifyDispatcher;
        use litebox_broker::state_registry::BrokerStateRegistry;
        use litebox_common_linux::EfdFlags;
        use litebox_common_linux::broker_eventfd_provider::{
            BrokerEventCallback, BrokerEventfdProvider, BrokerOpError,
        };
        use litebox_common_linux::fd_token_client::FdTokenClient;
        use std::sync::Mutex as StdMutex;
        use tempfile::tempdir;

        struct RealProviderForTest {
            client: StdMutex<FdTokenClient>,
        }
        impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable for RealProviderForTest {
            fn subscribe(
                &self,
                _: u64,
                _: u32,
                _: Arc<dyn BrokerEventCallback>,
            ) -> Result<u64, BrokerOpError> {
                Err(BrokerOpError::Io)
            }
            fn unsubscribe(&self, _: u64, _: u64) {}
            fn release(&self, handle: u64) {
                let _ = self.client.lock().unwrap().release(handle);
            }
            fn dup_handle(&self, handle: u64) -> Result<(), BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .dup_handle(handle)
                    .map_err(|_| BrokerOpError::Io)
            }
            fn query_events(&self, handle: u64) -> Result<u32, BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .query_events(handle)
                    .map_err(|_| BrokerOpError::Io)
            }
        }
        impl BrokerEventfdProvider for RealProviderForTest {
            fn create_eventfd(&self, initial: u64, semaphore: bool) -> Result<u64, BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .create_eventfd(initial, semaphore)
                    .map_err(|_| BrokerOpError::Io)
            }
            fn read_eventfd(&self, handle: u64) -> Result<u64, BrokerOpError> {
                use litebox_common_linux::fd_token_client::ClientError;
                self.client
                    .lock()
                    .unwrap()
                    .read_eventfd(handle)
                    .map_err(|e| {
                        // reason: unsupported variants intentionally share this fallback path.
                        #[allow(clippy::wildcard_enum_match_arm)]
                        match e {
                            ClientError::WouldBlock => BrokerOpError::WouldBlock,
                            _ => BrokerOpError::Io,
                        }
                    })
            }
            fn write_eventfd(&self, handle: u64, value: u64) -> Result<(), BrokerOpError> {
                self.client
                    .lock()
                    .unwrap()
                    .write_eventfd(handle, value)
                    .map_err(|_| BrokerOpError::Io)
            }
        }

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("fd-token.sock");
        let fd_registry = std::sync::Arc::new(BrokerFdTokenRegistry::new());
        let state_registry = std::sync::Arc::new(BrokerStateRegistry::new());
        let process_registry = std::sync::Arc::new(BrokerStateRegistry::new());
        let inotify_dispatcher = std::sync::Arc::new(InotifyDispatcher::new());
        let _listener_handle = spawn_control_listener(
            &path,
            std::sync::Arc::clone(&fd_registry),
            std::sync::Arc::clone(&state_registry),
            std::sync::Arc::clone(&process_registry),
            std::sync::Arc::clone(&inotify_dispatcher),
        )
        .expect("spawn listener");
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let client = FdTokenClient::connect(&path).expect("connect");
        let provider: Arc<dyn BrokerEventfdProvider> = Arc::new(RealProviderForTest {
            client: StdMutex::new(client),
        });
        let _ = set_broker_eventfd_provider(Arc::clone(&provider));

        let task = crate::syscalls::tests::init_platform(None);
        let efd_u32 = task
            .sys_eventfd2(
                0,
                EfdFlags::NONBLOCK | EfdFlags::CLOEXEC | EfdFlags::SEMAPHORE,
            )
            .expect("sys_eventfd2 SEMAPHORE mode with real broker");
        let efd = i32::try_from(efd_u32).unwrap();

        // Write 3 → semaphore counter = 3.
        let val: u64 = 3;
        let n = task
            .sys_write(efd, &val.to_le_bytes(), None)
            .expect("write");
        assert_eq!(n, 8);

        // Read three times in semaphore mode: each returns 1, counter
        // decrements. After 3 reads, counter is 0 → EAGAIN.
        for i in 0..3 {
            let mut buf = [0u8; 8];
            let n = task
                .sys_read(efd, &mut buf, None)
                .unwrap_or_else(|e| panic!("semaphore read #{i} failed: {e:?}"));
            assert_eq!(n, 8, "semaphore read should return 8 bytes");
            let got = u64::from_le_bytes(buf);
            assert_eq!(got, 1, "semaphore read should return 1, got {got}");
        }
        // 4th read: counter is 0, NONBLOCK → EAGAIN.
        let mut buf = [0u8; 8];
        let err = task.sys_read(efd, &mut buf, None).unwrap_err();
        assert_eq!(err, Errno::EAGAIN);

        task.sys_close(efd).expect("close eventfd");
    }
}
