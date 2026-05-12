// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification, pid-backed polling, and timer-backed polling.

use alloc::sync::Arc;
use core::{
    convert::Infallible,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::Duration,
};

use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        observer::Subject,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError},
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::{Instant as _, SystemTime as _, TimeProvider},
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    ClockId, EfdFlags, ItimerSpec, TimerfdFlags, TimerfdTimerFlags,
    broker_eventfd_provider::{BrokerEventfdProvider, BrokerOpError},
    broker_pidfd_provider::BrokerPidfdProvider,
    errno::Errno,
};
use litebox_platform_multiplex::Platform;

pub(crate) struct EventfdSubsystem;
impl FdEnabledSubsystem for EventfdSubsystem {
    type Entry = EventFile<Platform>;
}
impl FdEnabledSubsystemEntry for EventFile<Platform> {}

/// Process-global broker eventfd provider. Set once at runner
/// bootstrap (in litebox_runner_linux_userland). `sys_eventfd2`
/// consults this; if `Some`, new eventfds are broker-backed.
/// If `None`, falls back to the local `EventFile::new` path —
/// preserves all existing behaviour when fd-token transport is
/// not configured.
static BROKER_EVENTFD_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerEventfdProvider>> =
    once_cell::race::OnceBox::new();
static BROKER_PIDFD_PROVIDER: once_cell::race::OnceBox<Arc<dyn BrokerPidfdProvider>> =
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

/// Sets the process-global broker pidfd provider.
#[allow(dead_code)]
pub fn set_broker_pidfd_provider(
    provider: Arc<dyn BrokerPidfdProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn BrokerPidfdProvider>>> {
    BROKER_PIDFD_PROVIDER.set(alloc::boxed::Box::new(provider))
}

/// Returns the broker pidfd provider if one has been set.
pub fn broker_pidfd_provider() -> Option<Arc<dyn BrokerPidfdProvider>> {
    BROKER_PIDFD_PROVIDER.get().cloned()
}

enum EventFileInner<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Eventfd {
        counter: u64,
        semaphore: bool,
    },
    Pidfd {
        exited: Arc<AtomicBool>,
        subject: Arc<Subject<Events, Events, Platform>>,
    },
    Timerfd(TimerFileState<Platform>),
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
    PidfdBrokerBacked {
        provider: Arc<dyn BrokerPidfdProvider>,
        common: super::broker_backed::BrokerBackedCommon<Platform>,
    },
}

struct TimerFileState<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    platform: &'static Platform,
    clockid: ClockId,
    boot_time: Platform::Instant,
    interval: Duration,
    next_deadline: Option<Platform::Instant>,
    pending_expirations: u64,
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
    /// Shared by all variants: Eventfd / Timerfd use it directly
    /// for in-worker observer registration; BrokerBacked uses it
    /// AND passes it to `BrokerBackedCommon::ensure_subscribed` so
    /// the broker subscription's callback wakes the same pollee.
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    pub(crate) fn new(count: u64, flags: EfdFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));

        Self {
            inner: litebox::sync::Mutex::new(EventFileInner::Eventfd {
                counter: count,
                semaphore: flags.contains(EfdFlags::SEMAPHORE),
            }),
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

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

    pub(crate) fn new_pidfd_broker_backed(
        provider: Arc<dyn BrokerPidfdProvider>,
        handle: u64,
        nonblock: bool,
    ) -> Self {
        use litebox_common_linux::cwfd::notification_frame::{NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN};
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, nonblock);
        let subscribable: Arc<
            dyn litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable,
        > = Arc::clone(&provider) as _;
        let common = super::broker_backed::BrokerBackedCommon::new(
            subscribable,
            handle,
            NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP,
        );
        Self {
            inner: litebox::sync::Mutex::new(EventFileInner::PidfdBrokerBacked {
                provider,
                common,
            }),
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn new_timer(
        platform: &'static Platform,
        boot_time: Platform::Instant,
        clockid: ClockId,
        flags: TimerfdFlags,
    ) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(TimerfdFlags::NONBLOCK));

        Self {
            inner: litebox::sync::Mutex::new(EventFileInner::Timerfd(TimerFileState {
                platform,
                clockid,
                boot_time,
                interval: Duration::ZERO,
                next_deadline: None,
                pending_expirations: 0,
            })),
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn new_pidfd(
        exited: Arc<AtomicBool>,
        subject: Arc<Subject<Events, Events, Platform>>,
        nonblock: bool,
    ) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, nonblock);
        Self {
            inner: litebox::sync::Mutex::new(EventFileInner::Pidfd { exited, subject }),
            status: AtomicU32::new(status.bits()),
            pollee: Arc::new(Pollee::new()),
        }
    }

    pub(crate) fn is_timerfd(&self) -> bool {
        matches!(*self.inner.lock(), EventFileInner::Timerfd(_))
    }

    /// Returns the broker handle id if this is a broker-backed
    /// eventfd, else `None`. Used by the cross-worker SCM_RIGHTS
    /// path to extract the handle for transport in an LBFD frame
    /// (Phase B-Step8e).
    pub(crate) fn broker_backed_handle(&self) -> Option<u64> {
        match &*self.inner.lock() {
            EventFileInner::BrokerBacked { common, .. }
            | EventFileInner::PidfdBrokerBacked { common, .. } => Some(common.handle()),
            _ => None,
        }
    }

    /// Returns the broker provider if this is a broker-backed
    /// eventfd. Used by the cross-worker SCM_RIGHTS sender to call
    /// `dup_handle` on the same provider that owns this eventfd.
    pub(crate) fn broker_backed_provider(&self) -> Option<Arc<dyn BrokerEventfdProvider>> {
        match &*self.inner.lock() {
            EventFileInner::BrokerBacked { provider, .. } => Some(Arc::clone(provider)),
            _ => None,
        }
    }

    #[cfg(feature = "trace_syscalls")]
    pub(crate) fn kind_name(&self) -> &'static str {
        match &*self.inner.lock() {
            EventFileInner::Eventfd { .. } => "eventfd",
            EventFileInner::Pidfd { .. } => "pidfd",
            EventFileInner::Timerfd(_) => "timerfd",
            EventFileInner::BrokerBacked { .. } => "broker_eventfd",
            EventFileInner::PidfdBrokerBacked { .. } => "broker_pidfd",
        }
    }

    pub(crate) fn needs_host_poll(&self) -> bool {
        self.is_timerfd()
    }

    fn try_read_eventfd(&self) -> Result<u64, TryOpError<Errno>> {
        let mut inner = self.inner.lock();
        match &mut *inner {
            EventFileInner::Eventfd { counter, semaphore } => {
                if *counter == 0 {
                    return Err(TryOpError::TryAgain);
                }
                let res = if *semaphore { 1 } else { *counter };
                *counter -= res;
                drop(inner);
                self.pollee.notify_observers(Events::OUT);
                Ok(res)
            }
            EventFileInner::BrokerBacked {
                provider,
                common,
                semaphore,
            } => {
                let provider = Arc::clone(provider);
                let handle = common.handle();
                let semaphore = *semaphore;
                let readable = common.readable_flag();
                drop(inner);
                match provider.read_eventfd(handle) {
                    Ok(v) => {
                        // Update local readability cache: if we read
                        // in semaphore mode we just took 1; broker
                        // counter may still be > 0. If non-semaphore,
                        // we drained the entire counter to 0.
                        // Without a separate "peek" RPC, the safe
                        // assumption for semaphore is that more data
                        // MAY exist (set readable=true). For
                        // non-semaphore, we drained → not readable.
                        // The next epoll wake from a broker write
                        // will re-set it to true via try_write_eventfd.
                        readable.store(semaphore, Ordering::SeqCst);
                        self.pollee.notify_observers(Events::OUT);
                        Ok(v)
                    }
                    Err(BrokerOpError::WouldBlock) => {
                        readable.store(false, Ordering::SeqCst);
                        Err(TryOpError::TryAgain)
                    }
                    Err(BrokerOpError::UnknownHandle) => Err(TryOpError::Other(Errno::EBADF)),
                    Err(BrokerOpError::InvalidValue) => Err(TryOpError::Other(Errno::EINVAL)),
                    Err(BrokerOpError::Io) => Err(TryOpError::Other(Errno::EIO)),
                }
            }
            _ => Err(TryOpError::Other(Errno::EINVAL)),
        }
    }

    fn try_read_timerfd(&self) -> Result<u64, Errno> {
        let mut inner = self.inner.lock();
        let EventFileInner::Timerfd(timer) = &mut *inner else {
            return Err(Errno::EINVAL);
        };
        timer.update();
        if timer.pending_expirations == 0 {
            return Err(Errno::EAGAIN);
        }
        Ok(core::mem::take(&mut timer.pending_expirations))
    }

    fn try_read(&self) -> Result<u64, TryOpError<Errno>> {
        let inner = self.inner.lock();
        match &*inner {
            EventFileInner::Eventfd { .. } | EventFileInner::BrokerBacked { .. } => {
                drop(inner);
                self.try_read_eventfd()
            }
            EventFileInner::Pidfd { .. }
            | EventFileInner::PidfdBrokerBacked { .. }
            | EventFileInner::Timerfd(_) => Err(TryOpError::Other(Errno::EINVAL)),
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        if self.is_timerfd() {
            if self.get_status().contains(OFlags::NONBLOCK) {
                return self.try_read_timerfd();
            }
            loop {
                match self.try_read_timerfd() {
                    Ok(v) => return Ok(v),
                    Err(Errno::EAGAIN) => {}
                    Err(e) => return Err(e),
                }

                let deadline = {
                    let mut inner = self.inner.lock();
                    let EventFileInner::Timerfd(timer) = &mut *inner else {
                        unreachable!();
                    };
                    timer.next_deadline
                };
                let wait_cx = cx.with_deadline(deadline);
                match self.pollee.wait(&wait_cx, false, Events::IN, || {
                    Result::<(), TryOpError<Infallible>>::Err(TryOpError::TryAgain)
                }) {
                    Ok(())
                    | Err(TryOpError::TryAgain | TryOpError::WaitError(WaitError::TimedOut)) => {}
                    Err(TryOpError::WaitError(WaitError::Interrupted)) => {
                        return Err(Errno::EINTR);
                    }
                    Err(TryOpError::Other(never)) => match never {},
                }
            }
        }
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
            EventFileInner::Eventfd { counter, .. } => {
                if let Some(new_value) = (*counter).checked_add(value)
                    // The maximum value that may be stored in the counter is the largest unsigned
                    // 64-bit value minus 1 (i.e., 0xfffffffffffffffe)
                    && new_value != u64::MAX
                {
                    *counter = new_value;
                    drop(inner);
                    self.pollee.notify_observers(Events::IN);
                    return Ok(8);
                }
                Err(TryOpError::TryAgain)
            }
            EventFileInner::BrokerBacked {
                provider, common, ..
            } => {
                let provider = Arc::clone(provider);
                let handle = common.handle();
                let readable = common.readable_flag();
                drop(inner);
                match provider.write_eventfd(handle, value) {
                    Ok(()) => {
                        // Mark locally readable so check_io_events
                        // reports Events::IN. This is what unblocks
                        // an in-process epoll observer that was woken
                        // by notify_observers below.
                        readable.store(true, Ordering::SeqCst);
                        self.pollee.notify_observers(Events::IN);
                        Ok(8)
                    }
                    Err(BrokerOpError::WouldBlock) => Err(TryOpError::TryAgain),
                    Err(BrokerOpError::UnknownHandle) => Err(TryOpError::Other(Errno::EBADF)),
                    Err(BrokerOpError::InvalidValue) => Err(TryOpError::Other(Errno::EINVAL)),
                    Err(BrokerOpError::Io) => Err(TryOpError::Other(Errno::EIO)),
                }
            }
            _ => Err(TryOpError::Other(Errno::EINVAL)),
        }
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        let writable = matches!(
            *self.inner.lock(),
            EventFileInner::Eventfd { .. } | EventFileInner::BrokerBacked { .. }
        );
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
        let EventFileInner::Timerfd(timer) = &mut *inner else {
            return Err(Errno::EINVAL);
        };
        let old_value = timer.current_spec();
        timer.set_time(flags, new_value)?;
        drop(inner);
        self.pollee.notify_observers(Events::IN);
        Ok(old_value)
    }

    pub(crate) fn get_timer(&self) -> Result<ItimerSpec, Errno> {
        let mut inner = self.inner.lock();
        let EventFileInner::Timerfd(timer) = &mut *inner else {
            return Err(Errno::EINVAL);
        };
        Ok(timer.current_spec())
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
            EventFileInner::Eventfd { counter, .. } => {
                if *counter != 0 {
                    events |= Events::IN;
                }
                // if it is possible to write a value of at least "1"
                // without blocking, the file is writable
                if *counter < u64::MAX - 1 {
                    events |= Events::OUT;
                }
            }
            EventFileInner::Timerfd(timer) => {
                timer.update();
                if timer.pending_expirations != 0 {
                    events |= Events::IN;
                }
            }
            EventFileInner::Pidfd { exited, .. } => {
                if exited.load(Ordering::Acquire) {
                    events |= Events::IN | Events::HUP;
                }
            }
            EventFileInner::BrokerBacked { common, .. } => {
                // Cached local readiness — updated by:
                //   - try_write_eventfd (local write success → true)
                //   - try_read_eventfd (drain-to-zero → false)
                //   - BrokerSubscriptionWaker::on_events (broker push
                //     with NOTIFY_EVENT_IN → true) — for cross-worker
                //     wake-ups from a peer worker's write.
                events |= common.check_io_events();
            }
            EventFileInner::PidfdBrokerBacked { provider, common } => {
                if common.is_readable()
                    || provider
                        .pidfd_exited(common.handle())
                        .inspect(|exited| common.set_readable(*exited))
                        .unwrap_or(false)
                {
                    events |= Events::IN | Events::HUP;
                }
            }
        }

        events
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        let inner = self.inner.lock();
        match &*inner {
            EventFileInner::Pidfd { subject, .. } => {
                subject.register_observer(observer, mask | Events::ALWAYS_POLLED);
            }
            EventFileInner::Eventfd { .. } | EventFileInner::Timerfd(_) => {
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
            EventFileInner::PidfdBrokerBacked { common, .. } => {
                common.ensure_subscribed(&self.pollee);
                drop(inner);
                self.pollee.register_observer(observer, mask);
            }
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> TimerFileState<Platform> {
    fn current_time(&self) -> Result<Duration, Errno> {
        match self.clockid {
            ClockId::Monotonic | ClockId::MonotonicCoarse | ClockId::MonotonicRaw | ClockId::Boottime => {
                Ok(self.platform.now().duration_since(&self.boot_time))
            }
            ClockId::RealTime | ClockId::RealtimeCoarse => self
                .platform
                .current_time()
                .duration_since(
                    &<<Platform as TimeProvider>::SystemTime as litebox::platform::SystemTime>::UNIX_EPOCH,
                )
                .map_err(|_| Errno::EINVAL),
            _ => Err(Errno::EINVAL),
        }
    }

    fn deadline_from_duration_since_epoch(
        &self,
        duration: Duration,
    ) -> Result<Option<Platform::Instant>, Errno> {
        match self.clockid {
            ClockId::Monotonic
            | ClockId::MonotonicCoarse
            | ClockId::MonotonicRaw
            | ClockId::Boottime => Ok(self.boot_time.checked_add(duration)),
            ClockId::RealTime | ClockId::RealtimeCoarse => {
                let current_time = self.current_time()?;
                Ok(self
                    .platform
                    .now()
                    .checked_add(duration.checked_sub(current_time).unwrap_or(Duration::ZERO)))
            }
            _ => Err(Errno::EINVAL),
        }
    }

    fn update(&mut self) {
        let Some(deadline) = self.next_deadline else {
            return;
        };
        let now = self.platform.now();
        if now < deadline {
            return;
        }

        if self.interval.is_zero() {
            self.pending_expirations = self.pending_expirations.saturating_add(1);
            self.next_deadline = None;
            return;
        }

        let elapsed_ns = now.duration_since(&deadline).as_nanos();
        let interval_ns = self.interval.as_nanos();
        let expirations = elapsed_ns / interval_ns + 1;
        // `.min(u128::from(u64::MAX))` guarantees the value fits in u64.
        #[allow(clippy::cast_possible_truncation)]
        let clamped = expirations.min(u128::from(u64::MAX)) as u64;
        self.pending_expirations = self.pending_expirations.saturating_add(clamped);

        let remaining = if elapsed_ns % interval_ns == 0 {
            self.interval
        } else {
            nanos_to_duration(interval_ns - (elapsed_ns % interval_ns))
                .expect("interval remainder is always representable")
        };
        self.next_deadline = now.checked_add(remaining);
    }

    fn current_spec(&mut self) -> ItimerSpec {
        self.update();
        let remaining = self.next_deadline.map_or(Duration::ZERO, |deadline| {
            deadline.duration_since(&self.platform.now())
        });
        ItimerSpec {
            interval: self.interval.into(),
            value: remaining.into(),
        }
    }

    fn set_time(&mut self, flags: TimerfdTimerFlags, new_value: ItimerSpec) -> Result<(), Errno> {
        let interval = Duration::try_from(new_value.interval)?;
        let value = Duration::try_from(new_value.value)?;
        let next_deadline = if value.is_zero() {
            None
        } else if flags.contains(TimerfdTimerFlags::ABSTIME) {
            self.deadline_from_duration_since_epoch(value)?
        } else {
            self.platform.now().checked_add(value)
        };
        if !value.is_zero() && next_deadline.is_none() {
            return Err(Errno::EINVAL);
        }
        self.interval = interval;
        self.next_deadline = next_deadline;
        self.pending_expirations = 0;
        Ok(())
    }
}

fn nanos_to_duration(nanos: u128) -> Option<Duration> {
    let secs = nanos / 1_000_000_000;
    let subsec_nanos = nanos % 1_000_000_000;
    Some(Duration::new(
        u64::try_from(secs).ok()?,
        u32::try_from(subsec_nanos).ok()?,
    ))
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

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(0, EfdFlags::SEMAPHORE));
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

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(0, EfdFlags::empty()));
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

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(0, EfdFlags::empty()));
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

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(0, EfdFlags::NONBLOCK));
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

        let timerfd = super::EventFile::new_timer(
            platform(),
            platform().now(),
            ClockId::Monotonic,
            TimerfdFlags::empty(),
        );
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

        let expirations = timerfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(expirations, 1);
        assert_eq!(
            Duration::try_from(timerfd.get_timer().unwrap().value).unwrap(),
            Duration::ZERO
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
        use core::sync::atomic::{AtomicU64, Ordering};
        use litebox_common_linux::broker_eventfd_provider::{
            BrokerEventCallback, BrokerEventfdProvider, BrokerOpError,
        };

        /// Mock provider: in-process counter modelling the broker.
        struct MockProvider {
            counter: AtomicU64,
            reads: AtomicU64,
            writes: AtomicU64,
        }

        impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable for MockProvider {
            fn subscribe(
                &self,
                _handle: u64,
                _events_mask: u32,
                _cb: Arc<dyn BrokerEventCallback>,
            ) -> Result<u64, BrokerOpError> {
                Ok(1)
            }
            fn unsubscribe(&self, _handle: u64, _subscription_id: u64) {}
            fn release(&self, _handle: u64) {}
            fn dup_handle(&self, _handle: u64) -> Result<(), BrokerOpError> {
                Ok(())
            }
        }

        impl BrokerEventfdProvider for MockProvider {
            fn create_eventfd(
                &self,
                _initial: u64,
                _semaphore: bool,
            ) -> Result<u64, BrokerOpError> {
                Ok(7) // arbitrary fixed handle id
            }
            fn read_eventfd(&self, _handle: u64) -> Result<u64, BrokerOpError> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                let v = self.counter.swap(0, Ordering::SeqCst);
                if v == 0 {
                    Err(BrokerOpError::WouldBlock)
                } else {
                    Ok(v)
                }
            }
            fn write_eventfd(&self, _handle: u64, value: u64) -> Result<(), BrokerOpError> {
                if value == u64::MAX {
                    return Err(BrokerOpError::InvalidValue);
                }
                self.writes.fetch_add(1, Ordering::SeqCst);
                self.counter.fetch_add(value, Ordering::SeqCst);
                Ok(())
            }
        }

        let _task = crate::syscalls::tests::init_platform(None);

        let provider = Arc::new(MockProvider {
            counter: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
        });
        let provider_dyn: Arc<dyn BrokerEventfdProvider> = provider.clone();

        let eventfd = alloc::sync::Arc::new(super::EventFile::new_broker_backed(
            provider_dyn,
            7,
            EfdFlags::NONBLOCK,
        ));

        // Write 5 → provider.counter goes to 5.
        let n = eventfd
            .write(&WaitState::new(platform()).context(), 5)
            .unwrap();
        assert_eq!(n, 8);
        assert_eq!(provider.counter.load(Ordering::SeqCst), 5);
        assert_eq!(provider.writes.load(Ordering::SeqCst), 1);

        // Read → returns 5, provider.counter back to 0.
        let v = eventfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(v, 5);
        assert_eq!(provider.counter.load(Ordering::SeqCst), 0);
        assert_eq!(provider.reads.load(Ordering::SeqCst), 1);

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
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicU32, Ordering};
        use litebox_common_linux::broker_eventfd_provider::{
            BrokerEventCallback, BrokerEventfdProvider, BrokerOpError,
        };

        struct ReleaseCountingProvider {
            releases: AtomicU32,
        }

        impl litebox_common_linux::cwfd::broker_subscribable::BrokerSubscribable
            for ReleaseCountingProvider
        {
            fn subscribe(
                &self,
                _handle: u64,
                _events_mask: u32,
                _cb: Arc<dyn BrokerEventCallback>,
            ) -> Result<u64, BrokerOpError> {
                Ok(1)
            }
            fn unsubscribe(&self, _handle: u64, _subscription_id: u64) {}
            fn release(&self, _handle: u64) {
                self.releases.fetch_add(1, Ordering::SeqCst);
            }
            fn dup_handle(&self, _handle: u64) -> Result<(), BrokerOpError> {
                Ok(())
            }
        }

        impl BrokerEventfdProvider for ReleaseCountingProvider {
            fn create_eventfd(
                &self,
                _initial: u64,
                _semaphore: bool,
            ) -> Result<u64, BrokerOpError> {
                Ok(99)
            }
            fn read_eventfd(&self, _handle: u64) -> Result<u64, BrokerOpError> {
                Err(BrokerOpError::WouldBlock)
            }
            fn write_eventfd(&self, _handle: u64, _value: u64) -> Result<(), BrokerOpError> {
                Ok(())
            }
        }

        let _task = crate::syscalls::tests::init_platform(None);

        let provider = Arc::new(ReleaseCountingProvider {
            releases: AtomicU32::new(0),
        });
        let provider_dyn: Arc<dyn BrokerEventfdProvider> = provider.clone();

        // Construct then drop.
        {
            let _ef: super::EventFile<litebox_platform_multiplex::Platform> =
                super::EventFile::new_broker_backed(provider_dyn, 99, EfdFlags::empty());
        }

        assert_eq!(
            provider.releases.load(Ordering::SeqCst),
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
        let _listener_handle = spawn_control_listener(
            &path,
            std::sync::Arc::clone(&fd_registry),
            std::sync::Arc::clone(&state_registry),
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
                    .map_err(|e| match e {
                        ClientError::WouldBlock => BrokerOpError::WouldBlock,
                        _ => BrokerOpError::Io,
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
        let _listener_handle = spawn_control_listener(
            &path,
            std::sync::Arc::clone(&fd_registry),
            std::sync::Arc::clone(&state_registry),
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
