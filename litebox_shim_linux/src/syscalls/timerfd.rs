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
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&fd)
            .ok_or(Errno::EBADF)?
            .with_entry(f)
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

#[cfg(test)]
mod tests {
    extern crate std;

    use core::time::Duration;

    use litebox_common_linux::{
        CLOCK_MONOTONIC, CLOCK_REALTIME, EfdFlags, Itimerspec, TfdFlags, TfdTimerFlags, Timespec,
        errno::Errno,
    };

    use crate::syscalls::{test_broker::timer_provider, tests::TestPlatform};
    use crate::{Task, UserPtr, UserPtrMut};

    const MS: Duration = Duration::from_millis(1);

    fn spec(value: Duration, interval: Duration) -> Itimerspec {
        Itimerspec {
            it_interval: interval.into(),
            it_value: value.into(),
        }
    }

    fn create(task: &Task<TestPlatform>, flags: TfdFlags) -> i32 {
        task.sys_timerfd_create(CLOCK_MONOTONIC, flags)
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn settime(
        task: &Task<TestPlatform>,
        fd: i32,
        flags: TfdTimerFlags,
        new_value: Itimerspec,
    ) -> Result<Itimerspec, Errno> {
        let mut old_value = Itimerspec::default();
        task.sys_timerfd_settime(
            fd,
            flags,
            UserPtr::from_usize(&raw const new_value as usize),
            Some(UserPtrMut::from_usize(&raw mut old_value as usize)),
        )?;
        Ok(old_value)
    }

    fn gettime(task: &Task<TestPlatform>, fd: i32) -> Itimerspec {
        let mut value = Itimerspec::default();
        task.sys_timerfd_gettime(fd, UserPtrMut::from_usize(&raw mut value as usize))
            .unwrap();
        value
    }

    fn read(task: &Task<TestPlatform>, fd: i32) -> Result<u64, Errno> {
        let mut buf = [0; 8];
        assert_eq!(task.sys_read(fd, &mut buf, None)?, buf.len());
        Ok(u64::from_ne_bytes(buf))
    }

    #[test]
    fn one_shot_timer_expires_once() {
        let task = crate::syscalls::tests::init_platform();
        let fd = create(&task, TfdFlags::NONBLOCK);
        assert_eq!(read(&task, fd), Err(Errno::EAGAIN));

        let old = settime(
            &task,
            fd,
            TfdTimerFlags::empty(),
            spec(10 * MS, Duration::ZERO),
        );
        assert_eq!(old, Ok(Itimerspec::default()));
        assert_eq!(gettime(&task, fd), spec(10 * MS, Duration::ZERO));

        timer_provider().advance(9 * MS);
        assert_eq!(read(&task, fd), Err(Errno::EAGAIN));
        timer_provider().advance(MS);
        assert_eq!(read(&task, fd), Ok(1));
        assert_eq!(read(&task, fd), Err(Errno::EAGAIN));
        assert_eq!(gettime(&task, fd), Itimerspec::default());
    }

    #[test]
    fn periodic_timer_counts_every_expiration() {
        let task = crate::syscalls::tests::init_platform();
        let fd = create(&task, TfdFlags::NONBLOCK);
        settime(&task, fd, TfdTimerFlags::empty(), spec(10 * MS, 5 * MS)).unwrap();

        timer_provider().advance(22 * MS);
        assert_eq!(read(&task, fd), Ok(3));
        assert_eq!(gettime(&task, fd), spec(3 * MS, 5 * MS));

        let old = settime(&task, fd, TfdTimerFlags::empty(), Itimerspec::default());
        assert_eq!(old, Ok(spec(3 * MS, 5 * MS)));
        timer_provider().advance(10 * MS);
        assert_eq!(read(&task, fd), Err(Errno::EAGAIN));
    }

    #[test]
    fn blocking_read_waits_for_expiration() {
        let task = crate::syscalls::tests::init_platform();
        let fd = create(&task, TfdFlags::empty());
        settime(&task, fd, TfdTimerFlags::empty(), spec(MS, Duration::ZERO)).unwrap();
        let advance = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(50));
            timer_provider().advance(MS);
        });
        assert_eq!(read(&task, fd), Ok(1));
        advance.join().unwrap();
    }

    #[test]
    fn absolute_time_is_measured_against_the_guest_clock() {
        let task = crate::syscalls::tests::init_platform();
        let fd = create(&task, TfdFlags::NONBLOCK);

        // A time that already passed expires as soon as the timer's clock ticks.
        let past = spec(Duration::from_nanos(1), Duration::ZERO);
        settime(&task, fd, TfdTimerFlags::ABSTIME, past).unwrap();
        timer_provider().advance(Duration::from_nanos(1));
        assert_eq!(read(&task, fd), Ok(1));

        let minute = Duration::from_secs(60);
        let hour = 60 * minute;
        let now = task.timer_clock_now(super::TimerClock::Monotonic);
        settime(
            &task,
            fd,
            TfdTimerFlags::ABSTIME,
            spec(now + hour, Duration::ZERO),
        )
        .unwrap();
        let remaining = Duration::try_from(gettime(&task, fd).it_value).unwrap();
        assert!(remaining <= hour && remaining > 59 * minute);
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        let task = crate::syscalls::tests::init_platform();
        assert_eq!(
            task.sys_timerfd_create(2, TfdFlags::empty()),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            task.sys_timerfd_create(CLOCK_REALTIME, TfdFlags::from_bits_retain(1)),
            Err(Errno::EINVAL)
        );

        let fd = create(&task, TfdFlags::NONBLOCK);
        let armed = spec(MS, Duration::ZERO);
        assert_eq!(
            settime(&task, fd, TfdTimerFlags::CANCEL_ON_SET, armed),
            Err(Errno::EINVAL)
        );
        let invalid = Itimerspec {
            it_value: Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            },
            ..Itimerspec::default()
        };
        assert_eq!(
            settime(&task, fd, TfdTimerFlags::empty(), invalid),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            settime(&task, 1000, TfdTimerFlags::empty(), armed),
            Err(Errno::EBADF)
        );
        let eventfd = task.sys_eventfd2(0, EfdFlags::empty()).unwrap();
        assert_eq!(
            settime(
                &task,
                eventfd.try_into().unwrap(),
                TfdTimerFlags::empty(),
                armed
            ),
            Err(Errno::EINVAL)
        );

        let mut short = [0; 7];
        assert_eq!(task.sys_read(fd, &mut short, None), Err(Errno::EINVAL));
        assert_eq!(task.sys_write(fd, &[0; 8], None), Err(Errno::EINVAL));
    }
}
