use core::sync::atomic::AtomicU32;

use litebox::{
    fs::OFlags,
    sync::{RawSyncPrimitivesProvider, Synchronization},
};
use litebox_common_linux::{EfdFlags, errno::Errno};

pub(crate) struct EventFile<'platform, Platform: RawSyncPrimitivesProvider> {
    counter: litebox::sync::Mutex<'platform, Platform, u64>,
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
        let cur_value = *counter;
        if *counter == 0 {
            return Err(Errno::EAGAIN);
        }

        let res = if self.semaphore { 1 } else { cur_value };
        *counter = cur_value - res;
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
