// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Timer file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    event::{Events, IOPollable, observer::Observer, timer::Timer, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{TfdFlags, errno::Errno};

use crate::{GlobalState, ShimFS, ShimPlatform};

pub(crate) struct TimerfdSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for TimerfdSubsystem<Platform> {
    type Entry = TimerFile<Platform>;
}
impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for TimerFile<Platform> {}

pub(crate) struct TimerFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    timer: Timer<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> TimerFile<Platform> {
    fn new(timer: Timer<Platform>, flags: TfdFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(TfdFlags::NONBLOCK));
        Self {
            timer,
            status: AtomicU32::new(status.bits()),
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.timer
            .read(cx, self.is_nonblocking())
            .map_err(Errno::from)
    }

    pub(crate) fn settime(
        &self,
        spec: litebox::event::timer::TimerSpec,
        flags: u32,
    ) -> Result<litebox::event::timer::TimerSpec, Errno> {
        self.timer.set_time(spec, flags).map_err(Errno::from)
    }

    pub(crate) fn gettime(&self) -> Result<litebox::event::timer::TimerSpec, Errno> {
        self.timer.get_time().map_err(Errno::from)
    }

    super::common_functions_for_file_status!();

    fn is_nonblocking(&self) -> bool {
        self.get_status().contains(OFlags::NONBLOCK)
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

impl<Platform: ShimPlatform, FS: ShimFS> GlobalState<Platform, FS> {
    pub(crate) fn create_linux_timerfd(
        &self,
        clockid: i32,
        flags: TfdFlags,
    ) -> Result<TimerFile<Platform>, Errno> {
        if clockid != litebox_common_linux::CLOCK_REALTIME
            && clockid != litebox_common_linux::CLOCK_MONOTONIC
        {
            return Err(Errno::EINVAL);
        }
        if flags.intersects((TfdFlags::CLOEXEC | TfdFlags::NONBLOCK).complement()) {
            return Err(Errno::EINVAL);
        }

        let timer = Timer::new(&self.litebox, clockid).map_err(Errno::from)?;
        Ok(TimerFile::new(timer, flags))
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::{TfdFlags, errno::Errno};

    #[test]
    fn test_timerfd_requires_broker_control() {
        let task = crate::syscalls::tests::init_platform();

        assert!(matches!(
            task.global.create_linux_timerfd(1, TfdFlags::empty()),
            Err(Errno::EIO)
        ));
    }
}
