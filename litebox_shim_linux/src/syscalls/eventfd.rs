// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    LiteBox,
    event::{
        EventCounter, EventCounterConsumeMode, Events, IOPollable, observer::Observer,
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{EfdFlags, errno::Errno};
use litebox_platform_multiplex::Platform;

pub(crate) struct EventfdSubsystem;
impl FdEnabledSubsystem for EventfdSubsystem {
    type Entry = EventFile<Platform>;
}
impl FdEnabledSubsystemEntry for EventFile<Platform> {}

pub(crate) struct EventFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    event: EventCounter<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    semaphore: bool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    pub(crate) fn new(
        litebox: &LiteBox<Platform>,
        count: u64,
        flags: EfdFlags,
    ) -> Result<Self, Errno> {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));
        let event = litebox
            .create_event_counter(count, !flags.contains(EfdFlags::NONBLOCK))
            .map_err(Errno::from)?;

        Ok(Self {
            event,
            status: AtomicU32::new(status.bits()),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        })
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        let mode = if self.semaphore {
            EventCounterConsumeMode::One
        } else {
            EventCounterConsumeMode::All
        };
        self.event
            .read(cx, self.get_status().contains(OFlags::NONBLOCK), mode)
            .map_err(Errno::from)
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        self.event
            .write(cx, self.get_status().contains(OFlags::NONBLOCK), value)
            .map_err(Errno::from)
    }

    super::common_functions_for_file_status!();

    pub(crate) fn set_status_flags(&self, requested: OFlags, mask: OFlags) -> Result<(), Errno> {
        let new_status = (self.get_status() & mask.complement()) | (requested & mask);
        if !new_status.contains(OFlags::NONBLOCK) && !self.event.supports_blocking_operations() {
            return Err(Errno::EINVAL);
        }
        self.set_status(requested & mask, true);
        self.set_status(requested.complement() & mask, false);
        Ok(())
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventFile<Platform> {
    fn check_io_events(&self) -> Events {
        self.event.check_io_events()
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.event.register_observer(observer, mask);
    }
}

#[cfg(test)]
mod tests {
    use litebox::event::wait::WaitState;
    use litebox_common_linux::{EfdFlags, errno::Errno};
    use litebox_platform_multiplex::platform;

    extern crate std;

    #[test]
    fn test_semaphore_eventfd() {
        let task = crate::syscalls::tests::init_platform(None);

        let eventfd = alloc::sync::Arc::new(
            super::EventFile::new(&task.global.litebox, 0, EfdFlags::SEMAPHORE).unwrap(),
        );
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
        let task = crate::syscalls::tests::init_platform(None);

        let eventfd = alloc::sync::Arc::new(
            super::EventFile::new(&task.global.litebox, 0, EfdFlags::empty()).unwrap(),
        );
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
        let task = crate::syscalls::tests::init_platform(None);

        let eventfd = alloc::sync::Arc::new(
            super::EventFile::new(&task.global.litebox, 0, EfdFlags::empty()).unwrap(),
        );
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
        let task = crate::syscalls::tests::init_platform(None);

        let eventfd = alloc::sync::Arc::new(
            super::EventFile::new(&task.global.litebox, 0, EfdFlags::NONBLOCK).unwrap(),
        );
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
                    Err(e) => panic!("Unexpected error: {e:?}"),
                }
                core::hint::spin_loop();
            }
        };

        // block until the first write
        read(&eventfd, 1);
        // block until the second write
        read(&eventfd, u64::MAX - 1);
    }
}
