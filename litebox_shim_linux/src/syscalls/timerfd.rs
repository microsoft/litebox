// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Timer files (`timerfd_create(2)`) backed by broker timers.

use alloc::sync::Arc;
use core::time::Duration;

use litebox::{
    event::{Events, IOPollable, observer::Observer, timer::Timer, wait::WaitContext},
    process::ProcessError,
    sync::RawSyncPrimitivesProvider,
};
use litebox_broker_protocol::{
    ObjectHandle,
    fs::FileOpenFlags,
    timer::{TimerClock, TimerSetting, TimerSpec},
};
use litebox_common_linux::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_REALTIME, Itimerspec, OFlags, TfdFlags, TfdTimerFlags,
    errno::Errno,
};
use litebox_platform::time::{Instant as _, TimeProvider};

use super::file::{AnyTypedFd, linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform, Task, UserPtr, UserPtrMut};

pub(crate) type TimerfdFd<Platform> = TimerFile<Platform>;

/// A timerfd, whose clock, schedule, expirations, and status flags the broker owns.
pub(crate) struct TimerFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    timer: Arc<Timer<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> TimerFile<Platform> {
    /// Returns the number of expirations since the last read.
    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.timer.read(cx).map_err(Errno::from)
    }

    /// Returns the `F_GETFL` flags of the timerfd.
    pub(crate) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.timer.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the timerfd to their values in
    /// `flags`, ignoring flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(crate) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.timer.set_status_flags(mask, flags)?;
        Ok(())
    }

    pub(crate) fn timer(&self) -> &Arc<Timer<Platform>> {
        &self.timer
    }
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
        use litebox_broker_protocol::{fd::FdCreate, timer::CreateTimerRequest};
        if flags.intersects((TfdFlags::CLOEXEC | TfdFlags::NONBLOCK).complement()) {
            return Err(Errno::EINVAL);
        }
        let clock = match clockid {
            CLOCK_REALTIME => TimerClock::RealTime,
            // The guest never suspends, so its boot time is its monotonic time.
            CLOCK_MONOTONIC | CLOCK_BOOTTIME => TimerClock::Monotonic,
            _ => return Err(Errno::EINVAL),
        };
        let status = if flags.contains(TfdFlags::NONBLOCK) {
            FileOpenFlags::NONBLOCKING
        } else {
            FileOpenFlags::NONE
        };
        Ok(self
            .create_fds(
                FdCreate::Timer(CreateTimerRequest {
                    flags: status,
                    clock,
                }),
                flags.contains(TfdFlags::CLOEXEC),
            )?
            .0
            .number)
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
        // XXX: Track wall-clock changes to support `TFD_TIMER_CANCEL_ON_SET`.
        if flags.intersects(TfdTimerFlags::ABSTIME.complement()) {
            return Err(Errno::EINVAL);
        }
        let interval = Duration::try_from(new_value.it_interval)?;
        let value = Duration::try_from(new_value.it_value)?;
        let previous = self.with_timer_file(fd, |file| {
            let interval_ns = saturating_nanos(interval);
            let setting = if flags.contains(TfdTimerFlags::ABSTIME) && !value.is_zero() {
                TimerSetting::Absolute {
                    deadline: value,
                    interval_ns,
                    realtime_now: self.real_time_as_duration_since_epoch(),
                    monotonic_now: self
                        .global
                        .platform
                        .now()
                        .duration_since(&self.global.boot_time),
                }
            } else {
                TimerSetting::Relative(TimerSpec {
                    value_ns: saturating_nanos(value),
                    interval_ns,
                })
            };
            file.timer.set(setting).map_err(Errno::from)
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
        self.global.with_timerfd(&fd, f)
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Runs `f` on the timerfd at `fd`, without holding the descriptor table.
    pub(crate) fn with_timerfd<R>(
        &self,
        fd: &TimerfdFd<Platform>,
        f: impl FnOnce(&TimerFile<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        f(fd)
    }

    pub(crate) fn borrow_timerfd(
        &self,
        handle: ObjectHandle,
    ) -> Result<TimerfdFd<Platform>, ProcessError> {
        Ok(TimerFile {
            timer: Arc::new(self.litebox.borrow_fd_timer(handle)?),
        })
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
