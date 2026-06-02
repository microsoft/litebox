// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    broker::{BrokerEvent, BrokerEventConsumeMode, BrokerObjectError},
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
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
    backend: EventBackend<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    semaphore: bool,
    pollee: Pollee<Platform>,
}

enum EventBackend<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Local {
        counter: litebox::sync::Mutex<Platform, u64>,
    },
    Broker {
        /// Broker-backed eventfds are currently created only for `EFD_NONBLOCK`;
        /// blocking broker wait/notification plumbing is not implemented yet.
        event: BrokerEvent,
    },
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    pub(crate) fn new(count: u64, flags: EfdFlags) -> Self {
        Self::new_with_backend(
            EventBackend::Local {
                counter: litebox::sync::Mutex::new(count),
            },
            flags,
        )
    }

    pub(crate) fn new_broker(event: BrokerEvent, flags: EfdFlags) -> Result<Self, Errno> {
        if !flags.contains(EfdFlags::NONBLOCK) {
            return Err(Errno::EINVAL);
        }
        Ok(Self::new_with_backend(
            EventBackend::Broker { event },
            flags,
        ))
    }

    fn new_with_backend(backend: EventBackend<Platform>, flags: EfdFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));

        Self {
            backend,
            status: AtomicU32::new(status.bits()),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
            pollee: Pollee::new(),
        }
    }

    fn try_read(&self) -> Result<u64, TryOpError<Errno>> {
        match &self.backend {
            EventBackend::Local { counter } => {
                let mut counter = counter.lock();
                if *counter == 0 {
                    return Err(TryOpError::TryAgain);
                }

                let res = if self.semaphore { 1 } else { *counter };
                *counter -= res;

                drop(counter);
                self.pollee.notify_observers(Events::OUT);
                Ok(res)
            }
            EventBackend::Broker { event } => {
                let mode = if self.semaphore {
                    BrokerEventConsumeMode::One
                } else {
                    BrokerEventConsumeMode::All
                };
                match event.consume(mode) {
                    Ok(value) => {
                        self.pollee.notify_observers(Events::OUT);
                        Ok(value)
                    }
                    Err(BrokerObjectError::WouldBlock) => Err(TryOpError::TryAgain),
                    Err(error) => Err(TryOpError::Other(broker_object_error_to_errno(error))),
                }
            }
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        if matches!(&self.backend, EventBackend::Broker { .. }) {
            return self.try_read().map_err(Errno::from);
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

    fn try_write(&self, value: u64) -> Result<usize, TryOpError<Errno>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(Errno::EINVAL));
        }

        match &self.backend {
            EventBackend::Local { counter } => {
                let mut counter = counter.lock();
                if let Some(new_value) = (*counter).checked_add(value) {
                    // The maximum value that may be stored in the counter is the largest unsigned
                    // 64-bit value minus 1 (i.e., 0xfffffffffffffffe)
                    if new_value != u64::MAX {
                        *counter = new_value;
                        drop(counter);
                        self.pollee.notify_observers(Events::IN);
                        return Ok(8);
                    }
                }

                Err(TryOpError::TryAgain)
            }
            EventBackend::Broker { event } => match event.add(value) {
                Ok(()) => {
                    self.pollee.notify_observers(Events::IN);
                    Ok(8)
                }
                Err(BrokerObjectError::WouldBlock | BrokerObjectError::ResourceExhausted) => {
                    Err(TryOpError::TryAgain)
                }
                Err(error) => Err(TryOpError::Other(broker_object_error_to_errno(error))),
            },
        }
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        if matches!(&self.backend, EventBackend::Broker { .. }) {
            return self.try_write(value).map_err(Errno::from);
        }
        self.pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::OUT,
                || self.try_write(value),
            )
            .map_err(Errno::from)
    }

    super::common_functions_for_file_status!();

    pub(crate) fn set_status_flags(&self, requested: OFlags, mask: OFlags) -> Result<(), Errno> {
        let new_status = (self.get_status() & mask.complement()) | (requested & mask);
        if matches!(&self.backend, EventBackend::Broker { .. })
            && !new_status.contains(OFlags::NONBLOCK)
        {
            return Err(Errno::EINVAL);
        }
        self.set_status(requested & mask, true);
        self.set_status(requested.complement() & mask, false);
        Ok(())
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventFile<Platform> {
    fn check_io_events(&self) -> Events {
        match &self.backend {
            EventBackend::Local { counter } => {
                let counter = counter.lock();
                let mut events = Events::empty();
                if *counter != 0 {
                    events |= Events::IN;
                }
                // if it is possible to write a value of at least "1"
                // without blocking, the file is writable
                let is_writable = *counter < u64::MAX - 1;
                if is_writable {
                    events |= Events::OUT;
                }

                events
            }
            EventBackend::Broker { event } => {
                // The broker protocol currently exposes read readiness only. Keep
                // write readiness optimistic and surface counter-limit failures
                // from write as EAGAIN until broker write-readiness plumbing exists.
                let mut events = Events::OUT;
                if event.is_read_ready().unwrap_or(false) {
                    events |= Events::IN;
                }
                events
            }
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }
}

pub(crate) fn broker_object_error_to_errno(error: BrokerObjectError) -> Errno {
    match error {
        BrokerObjectError::InvalidObject => Errno::EINVAL,
        BrokerObjectError::WouldBlock | BrokerObjectError::ResourceExhausted => Errno::EAGAIN,
        _ => Errno::EIO,
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
