// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    event::{
        Events, IOPollable,
        counter::{EventCounter, EventCounterReadMode},
        observer::Observer,
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{EfdFlags, errno::Errno};

use crate::{GlobalState, Platform, ShimFS};

pub(crate) struct EventfdSubsystem;
impl FdEnabledSubsystem for EventfdSubsystem {
    type Entry = EventFile<Platform>;
}
impl FdEnabledSubsystemEntry for EventFile<Platform> {}

pub(crate) struct EventFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    counter: EventCounter<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    semaphore: bool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    fn new(counter: EventCounter<Platform>, flags: EfdFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));
        Self {
            counter,
            status: AtomicU32::new(status.bits()),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.counter
            .read(
                cx,
                self.is_nonblocking(),
                if self.semaphore {
                    EventCounterReadMode::One
                } else {
                    EventCounterReadMode::All
                },
            )
            .map_err(Errno::from)
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        self.counter
            .write(cx, self.is_nonblocking(), value)
            .map_err(Errno::from)
    }

    super::common_functions_for_file_status!();

    fn is_nonblocking(&self) -> bool {
        self.get_status().contains(OFlags::NONBLOCK)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventFile<Platform> {
    fn check_io_events(&self) -> Events {
        self.counter.check_io_events()
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.counter.register_observer(observer, mask);
    }
}

impl<FS: ShimFS> GlobalState<FS> {
    pub(crate) fn create_linux_eventfd(
        &self,
        initval: u32,
        flags: EfdFlags,
    ) -> Result<EventFile<Platform>, Errno> {
        if flags
            .intersects((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let count = u64::from(initval);
        let counter = EventCounter::new(&self.litebox, count).map_err(Errno::from)?;
        Ok(EventFile::new(counter, flags))
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::{EfdFlags, errno::Errno};

    #[test]
    fn test_eventfd_requires_broker_control() {
        let task = crate::syscalls::tests::init_platform(None);

        assert!(matches!(
            task.global.create_linux_eventfd(0, EfdFlags::NONBLOCK),
            Err(Errno::EIO)
        ));
    }
}
