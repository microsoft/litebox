//! Event file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    fs::OFlags,
    sync::{RawSyncPrimitivesProvider, Synchronization},
};
use litebox_common_linux::{EfdFlags, errno::Errno};

pub(crate) struct EventFile<'platform, Platform: RawSyncPrimitivesProvider> {
    counter: litebox::sync::Mutex<'platform, Platform, u64>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    semaphore: bool,
}

impl<'platform, Platform: RawSyncPrimitivesProvider> EventFile<'platform, Platform> {
    pub(crate) fn new(count: u64, flags: EfdFlags, platform: &'platform Platform) -> Self {
        Self {
            counter: Synchronization::new(platform).new_mutex(count),
            status: AtomicU32::new(if flags.contains(EfdFlags::NONBLOCK) {
                litebox::fs::OFlags::NONBLOCK.bits()
            } else {
                0
            }),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        }
    }

    pub(crate) fn get_status(&self) -> OFlags {
        OFlags::from_bits(self.status.load(core::sync::atomic::Ordering::Relaxed)).unwrap()
    }

    pub(crate) fn set_status(&self, flag: OFlags, on: bool) {
        if on {
            self.status
                .fetch_or(flag.bits(), core::sync::atomic::Ordering::Relaxed);
        } else {
            self.status.fetch_and(
                flag.complement().bits(),
                core::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    fn try_read(&self) -> Result<u64, Errno> {
        let mut counter = self.counter.lock();
        if *counter == 0 {
            return Err(Errno::EAGAIN);
        }

        let res = if self.semaphore { 1 } else { *counter };
        *counter -= res;
        Ok(res)
    }

    pub(crate) fn read(&self, is_nonblocking: bool) -> Result<u64, Errno> {
        if is_nonblocking {
            self.try_read()
        } else {
            // TODO: use poll rather than busy wait
            loop {
                match self.try_read() {
                    Err(Errno::EAGAIN) => {}
                    ret => return ret,
                }
            }
        }
    }

    fn try_write(&self, value: u64) -> Result<usize, Errno> {
        let mut counter = self.counter.lock();
        if let Some(new_value) = (*counter).checked_add(value) {
            // The maximum value that may be stored in the counter is the largest unsigned
            // 64-bit value minus 1 (i.e., 0xfffffffffffffffe)
            if new_value != u64::MAX {
                *counter = new_value;
                return Ok(8);
            }
        }

        Err(Errno::EAGAIN)
    }

    pub(crate) fn write(&self, value: u64, is_nonblocking: bool) -> Result<usize, Errno> {
        if is_nonblocking {
            self.try_write(value)
        } else {
            // TODO: use poll rather than busy wait
            loop {
                match self.try_write(value) {
                    Err(Errno::EAGAIN) => {}
                    ret => return ret,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use litebox::platform::trivial_providers::ImpossiblePunchthroughProvider;
    use litebox_common_linux::{EfdFlags, errno::Errno};
    use litebox_platform_multiplex::{Platform, set_platform};

    extern crate std;

    fn init_platform() {
        let platform = alloc::boxed::Box::leak(alloc::boxed::Box::new(Platform::new(
            None,
            ImpossiblePunchthroughProvider {},
        )));
        set_platform(&*platform);
    }

    #[test]
    fn test_semaphore_eventfd() {
        init_platform();

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(
            0,
            EfdFlags::SEMAPHORE,
            litebox_platform_multiplex::platform(),
        ));
        let total = 8;
        for _ in 0..total {
            let copied_eventfd = eventfd.clone();
            std::thread::spawn(move || {
                copied_eventfd.read(false).unwrap();
            });
        }

        std::thread::sleep(core::time::Duration::from_millis(500));
        eventfd.write(total, false).unwrap();
    }

    #[test]
    fn test_blocking_eventfd() {
        init_platform();

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(
            0,
            EfdFlags::empty(),
            litebox_platform_multiplex::platform(),
        ));
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            copied_eventfd.write(1, false).unwrap();
            // block until the first read finishes
            copied_eventfd.write(u64::MAX - 1, false).unwrap();
        });

        // block until the first write
        let ret = eventfd.read(false).unwrap();
        assert_eq!(ret, 1);

        // block until the second write
        let ret = eventfd.read(false).unwrap();
        assert_eq!(ret, u64::MAX - 1);
    }

    #[test]
    fn test_nonblocking_eventfd() {
        init_platform();

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(
            0,
            EfdFlags::NONBLOCK,
            litebox_platform_multiplex::platform(),
        ));
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            // first write should succeed immediately
            copied_eventfd.write(1, true).unwrap();
            // block until the first read finishes
            while let Err(e) = copied_eventfd.write(u64::MAX - 1, true) {
                assert_eq!(e, Errno::EAGAIN, "Unexpected error: {e:?}");
                core::hint::spin_loop();
            }
        });

        let read = |eventfd: &super::EventFile<litebox_platform_multiplex::Platform>,
                    expected_value: u64| {
            loop {
                match eventfd.read(true) {
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
        // std::thread::sleep(core::time::Duration::from_millis(100));
        // block until the second write
        read(&eventfd, u64::MAX - 1);
    }
}
