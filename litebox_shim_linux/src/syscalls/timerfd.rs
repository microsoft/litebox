// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Timer files (`timerfd_create(2)`) backed by broker timers.

use core::sync::atomic::AtomicU32;
use core::time::Duration;

use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        timer::{Timer, TimerSpec},
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_REALTIME, FileDescriptorFlags, Itimerspec, OFlags,
    TfdFlags, TfdTimerFlags, errno::Errno,
};
use litebox_platform::time::{Instant as _, TimeProvider};

use super::file::AnyTypedFd;
use crate::{ShimPlatform, Task, UserPtr, UserPtrMut};

pub(crate) struct TimerfdSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for TimerfdSubsystem<Platform> {
    type Entry = TimerFile<Platform>;
}
impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for TimerFile<Platform> {}

/// Clock against which absolute expiration times are measured.
///
/// The clock is only a shim concern: absolute times are converted to relative
/// ones when the timer is armed, and the broker timer counts them on its own
/// monotonic clock. Unlike Linux, an armed `CLOCK_REALTIME` timer therefore
/// does not follow later wall-clock changes.
#[derive(Clone, Copy)]
enum TimerClock {
    RealTime,
    Monotonic,
}

pub(crate) struct TimerFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    timer: Timer<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    clock: TimerClock,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> TimerFile<Platform> {
    /// Returns the number of expirations since the last read.
    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.timer
            .read(cx, self.get_status().contains(OFlags::NONBLOCK))
            .map_err(Errno::from)
    }

    super::common_functions_for_file_status!();
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for TimerFile<Platform> {
    fn check_io_events(&self) -> Events {
        self.timer.check_io_events()
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.timer.register_observer(observer, mask);
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `timerfd_create`.
    pub(crate) fn sys_timerfd_create(&self, clockid: i32, flags: TfdFlags) -> Result<u32, Errno> {
        if flags.intersects((TfdFlags::CLOEXEC | TfdFlags::NONBLOCK).complement()) {
            return Err(Errno::EINVAL);
        }
        let clock = match clockid {
            CLOCK_REALTIME => TimerClock::RealTime,
            // The guest never suspends, so its boot time is its monotonic time.
            CLOCK_MONOTONIC | CLOCK_BOOTTIME => TimerClock::Monotonic,
            _ => return Err(Errno::EINVAL),
        };
        let timer = Timer::new(&self.global.litebox).map_err(Errno::from)?;
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(TfdFlags::NONBLOCK));
        let file = TimerFile {
            timer,
            status: AtomicU32::new(status.bits()),
            clock,
        };

        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<TimerfdSubsystem<Platform>>(file);
        if flags.contains(TfdFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let files = self.files.borrow();
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            self.remove_and_drop_descriptor(&typed);
            Errno::EMFILE
        })?;
        Ok(raw_fd.try_into().unwrap())
    }

    /// Handle syscall `timerfd_settime`.
    pub(crate) fn sys_timerfd_settime(
        &self,
        fd: i32,
        flags: TfdTimerFlags,
        new_value: UserPtr<Itimerspec>,
        old_value: Option<UserPtrMut<Itimerspec>>,
    ) -> Result<(), Errno> {
        let new_value = new_value
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        // Wall-clock changes are not observable, so `TFD_TIMER_CANCEL_ON_SET`
        // cannot be honored.
        if flags.intersects(TfdTimerFlags::ABSTIME.complement()) {
            return Err(Errno::EINVAL);
        }
        let interval = Duration::try_from(new_value.it_interval)?;
        let value = Duration::try_from(new_value.it_value)?;
        let previous = self.with_timer_file(fd, |file| {
            let value = if flags.contains(TfdTimerFlags::ABSTIME) && !value.is_zero() {
                // An expiration time that already passed expires immediately.
                // Unlike Linux, a periodic timer then counts one expiration and
                // restarts its period from now rather than from `value`.
                value
                    .saturating_sub(self.timer_clock_now(file.clock))
                    .max(Duration::from_nanos(1))
            } else {
                value
            };
            file.timer
                .set(TimerSpec {
                    value_ns: saturating_nanos(value),
                    interval_ns: saturating_nanos(interval),
                })
                .map_err(Errno::from)
        })?;
        if let Some(old_value) = old_value {
            old_value
                .write_at_offset::<Platform>(0, itimerspec(previous))
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Handle syscall `timerfd_gettime`.
    pub(crate) fn sys_timerfd_gettime(
        &self,
        fd: i32,
        curr_value: UserPtrMut<Itimerspec>,
    ) -> Result<(), Errno> {
        let current = self.with_timer_file(fd, |file| file.timer.get().map_err(Errno::from))?;
        curr_value
            .write_at_offset::<Platform>(0, itimerspec(current))
            .ok_or(Errno::EFAULT)
    }

    fn with_timer_file<R>(
        &self,
        fd: i32,
        f: impl FnOnce(&TimerFile<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let AnyTypedFd::Timerfd(fd) = self.typed_fd(fd)? else {
            return Err(Errno::EINVAL);
        };
        let handle = self
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    fn timer_clock_now(&self, clock: TimerClock) -> Duration {
        match clock {
            TimerClock::RealTime => self.real_time_as_duration_since_epoch(),
            TimerClock::Monotonic => self
                .global
                .platform
                .now()
                .duration_since(&self.global.boot_time),
        }
    }
}

fn saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn itimerspec(spec: TimerSpec) -> Itimerspec {
    Itimerspec {
        it_interval: Duration::from_nanos(spec.interval_ns).into(),
        it_value: Duration::from_nanos(spec.value_ns).into(),
    }
}
