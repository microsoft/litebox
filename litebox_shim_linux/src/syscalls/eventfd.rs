// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    event::{
        Events, IOPollable,
        counter::{EventCounter, EventCounterReadMode},
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_linux::{EfdFlags, errno::Errno};

use crate::{GlobalState, Platform, ShimFS};

pub(crate) struct EventfdSubsystem;
impl FdEnabledSubsystem for EventfdSubsystem {
    type Entry = EventFile<Platform>;
}
impl FdEnabledSubsystemEntry for EventFile<Platform> {}

/// Backing counter for a Linux eventfd file description.
///
/// Blocking eventfd still uses the shim-local implementation because the
/// local-core event counter does not support blocking operations yet. Once it
/// does, this split can collapse to the local-core counter.
enum EventFileCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    ShimLocal {
        count: Mutex<Platform, u64>,
        pollee: Pollee<Platform>,
    },
    LocalCore(EventCounter<Platform>),
}

pub(crate) struct EventFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    counter: EventFileCounter<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    semaphore: bool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFileCounter<Platform> {
    fn shim_local(count: u64) -> Self {
        Self::ShimLocal {
            count: Mutex::new(count),
            pollee: Pollee::new(),
        }
    }

    fn local_core(counter: EventCounter<Platform>) -> Self {
        Self::LocalCore(counter)
    }

    fn supports_blocking_operations(&self) -> bool {
        match self {
            Self::ShimLocal { .. } => true,
            Self::LocalCore(counter) => counter.supports_blocking_operations(),
        }
    }

    fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        semaphore: bool,
    ) -> Result<u64, Errno> {
        match self {
            Self::ShimLocal { count, pollee } => pollee
                .wait(cx, nonblock, Events::IN, || {
                    Self::try_read_local(count, pollee, semaphore)
                })
                .map_err(Errno::from),
            Self::LocalCore(counter) => counter
                .read(cx, nonblock, consume_mode(semaphore))
                .map_err(Errno::from),
        }
    }

    fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        value: u64,
    ) -> Result<usize, Errno> {
        match self {
            Self::ShimLocal { count, pollee } => pollee
                .wait(cx, nonblock, Events::OUT, || {
                    Self::try_write_local(count, pollee, value)
                })
                .map_err(Errno::from),
            Self::LocalCore(counter) => counter.write(cx, nonblock, value).map_err(Errno::from),
        }
    }

    fn try_read_local(
        count: &Mutex<Platform, u64>,
        pollee: &Pollee<Platform>,
        semaphore: bool,
    ) -> Result<u64, TryOpError<Errno>> {
        let mut count = count.lock();
        if *count == 0 {
            return Err(TryOpError::TryAgain);
        }

        let res = if semaphore { 1 } else { *count };
        *count -= res;

        drop(count);
        pollee.notify_observers(Events::OUT);
        Ok(res)
    }

    fn try_write_local(
        count: &Mutex<Platform, u64>,
        pollee: &Pollee<Platform>,
        value: u64,
    ) -> Result<usize, TryOpError<Errno>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(Errno::EINVAL));
        }

        let mut count = count.lock();
        if let Some(new_value) = (*count).checked_add(value)
            && new_value != u64::MAX
        {
            *count = new_value;
            drop(count);
            pollee.notify_observers(Events::IN);
            return Ok(core::mem::size_of::<u64>());
        }

        Err(TryOpError::TryAgain)
    }

    fn check_io_events(&self) -> Events {
        match self {
            Self::ShimLocal { count, .. } => {
                let count = count.lock();
                let mut events = Events::empty();
                if *count != 0 {
                    events |= Events::IN;
                }
                if *count < u64::MAX - 1 {
                    events |= Events::OUT;
                }
                events
            }
            Self::LocalCore(counter) => counter.check_io_events(),
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        match self {
            Self::ShimLocal { pollee, .. } => pollee.register_observer(observer, mask),
            Self::LocalCore(counter) => counter.register_observer(observer, mask),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    fn new(counter: EventFileCounter<Platform>, flags: EfdFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));
        Self {
            counter,
            status: AtomicU32::new(status.bits()),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.counter.read(cx, self.is_nonblocking(), self.semaphore)
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        self.counter.write(cx, self.is_nonblocking(), value)
    }

    super::common_functions_for_file_status!();

    pub(crate) fn set_status_flags(&self, requested: OFlags, mask: OFlags) -> Result<(), Errno> {
        let new_status = (self.get_status() & mask.complement()) | (requested & mask);
        if !new_status.contains(OFlags::NONBLOCK) && !self.counter.supports_blocking_operations() {
            return Err(Errno::EINVAL);
        }
        self.set_status(requested & mask, true);
        self.set_status(requested.complement() & mask, false);
        Ok(())
    }

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
        let counter = if flags.contains(EfdFlags::NONBLOCK) {
            EventFileCounter::local_core(
                EventCounter::new(&self.litebox, count).map_err(Errno::from)?,
            )
        } else {
            EventFileCounter::shim_local(count)
        };
        Ok(EventFile::new(counter, flags))
    }
}

fn consume_mode(semaphore: bool) -> EventCounterReadMode {
    if semaphore {
        EventCounterReadMode::One
    } else {
        EventCounterReadMode::All
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
            task.global
                .create_linux_eventfd(0, EfdFlags::SEMAPHORE)
                .unwrap(),
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
            task.global
                .create_linux_eventfd(0, EfdFlags::empty())
                .unwrap(),
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
            task.global
                .create_linux_eventfd(0, EfdFlags::empty())
                .unwrap(),
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
    fn test_nonblocking_eventfd_requires_broker_control() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(
            task.global
                .create_linux_eventfd(0, EfdFlags::NONBLOCK)
                .map(|_| ()),
            Err(Errno::EIO)
        );
    }
}
