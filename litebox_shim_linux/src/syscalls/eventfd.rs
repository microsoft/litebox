use litebox::{platform::RawMutexProvider, sync::Synchronization};
use litebox_common_linux::{EfdFlags, errno::Errno};

pub(crate) struct EventFile<'platform, Platform: RawMutexProvider> {
    count: litebox::sync::Mutex<'platform, Platform, u64>,
    semaphore: bool,
}

impl<'platform, Platform: RawMutexProvider> EventFile<'platform, Platform> {
    pub(crate) fn new(count: u64, flags: EfdFlags, platform: &'platform Platform) -> Self {
        Self {
            count: Synchronization::new(platform).new_mutex(count),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        }
    }

    fn try_read(&self) -> Result<u64, Errno> {
        let mut counter = self.count.lock();
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
                    Err(Errno::EAGAIN) => continue,
                    ret => return ret,
                }
            }
        }
    }

    fn try_write(&self, value: u64) -> Result<usize, Errno> {
        let mut counter = self.count.lock();
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
                    Err(Errno::EAGAIN) => continue,
                    ret => return ret,
                }
            }
        }
    }
}
