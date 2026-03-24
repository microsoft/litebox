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
    ClockId, EfdFlags, ItimerSpec, TimerfdFlags, TimerfdTimerFlags, errno::Errno,
};
use litebox_platform_multiplex::Platform;

pub(crate) struct EventfdSubsystem;
impl FdEnabledSubsystem for EventfdSubsystem {
    type Entry = EventFile<Platform>;
}
impl FdEnabledSubsystemEntry for EventFile<Platform> {}

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
    pollee: Pollee<Platform>,
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
            pollee: Pollee::new(),
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
            pollee: Pollee::new(),
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
            pollee: Pollee::new(),
        }
    }

    pub(crate) fn is_timerfd(&self) -> bool {
        matches!(*self.inner.lock(), EventFileInner::Timerfd(_))
    }

    pub(crate) fn needs_host_poll(&self) -> bool {
        self.is_timerfd()
    }

    fn try_read_eventfd(&self) -> Result<u64, TryOpError<Errno>> {
        let mut inner = self.inner.lock();
        let EventFileInner::Eventfd { counter, semaphore } = &mut *inner else {
            return Err(TryOpError::Other(Errno::EINVAL));
        };
        if *counter == 0 {
            return Err(TryOpError::TryAgain);
        }

        let res = if *semaphore { 1 } else { *counter };
        *counter -= res;

        drop(inner);
        self.pollee.notify_observers(Events::OUT);
        Ok(res)
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
            EventFileInner::Eventfd { .. } => {
                drop(inner);
                self.try_read_eventfd()
            }
            EventFileInner::Pidfd { .. } | EventFileInner::Timerfd(_) => {
                Err(TryOpError::Other(Errno::EINVAL))
            }
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
        let EventFileInner::Eventfd { counter, .. } = &mut *inner else {
            return Err(TryOpError::Other(Errno::EINVAL));
        };
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

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        let is_eventfd = matches!(*self.inner.lock(), EventFileInner::Eventfd { .. });
        if !is_eventfd {
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventFile<Platform> {
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
}
