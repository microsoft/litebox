// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland broker synchronization primitives.

use core::sync::atomic::AtomicU32;

use litebox_broker_core::sync::{ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider};
use rustix::thread::futex;

/// Blocking synchronization primitives for a Linux-userland broker.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxSyncPrimitivesProvider;

impl RawMutexProvider for LinuxSyncPrimitivesProvider {
    type RawMutex = LinuxRawMutex;
}

/// Raw blocking mutex used by the Linux-userland broker.
pub struct LinuxRawMutex {
    state: AtomicU32,
}

impl LinuxRawMutex {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }
}

impl RawMutexTrait for LinuxRawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.state
    }

    fn wake_many(&self, count: usize) -> usize {
        assert!(count > 0, "wake count must be nonzero");
        let count = u32::try_from(count.min(i32::MAX as usize)).unwrap();
        futex::wake(&self.state, futex::Flags::PRIVATE, count)
            .expect("failed to wake broker mutex waiters")
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        match futex::wait(&self.state, futex::Flags::PRIVATE, expected, None) {
            Ok(()) | Err(rustix::io::Errno::INTR) => Ok(()),
            Err(rustix::io::Errno::AGAIN) => Err(ImmediatelyWokenUp),
            Err(error) => panic!("failed to block on broker mutex: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use litebox_broker_core::sync::{Mutex, RwLock};

    use super::LinuxSyncPrimitivesProvider;

    type LinuxMutex<T> = Mutex<LinuxSyncPrimitivesProvider, T>;
    type LinuxRwLock<T> = RwLock<LinuxSyncPrimitivesProvider, T>;

    #[test]
    fn mutex_serializes_mutation() {
        let value = Arc::new(LinuxMutex::new(0));
        let threads = (0..4)
            .map(|_| {
                let value = Arc::clone(&value);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        *value.lock() += 1;
                    }
                })
            })
            .collect::<Vec<_>>();

        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(*value.lock(), 4_000);
    }

    #[test]
    fn rwlock_supports_shared_reads_and_exclusive_writes() {
        let value = LinuxRwLock::new(1);
        let first = value.read();
        let second = value.read();
        assert_eq!(*first, 1);
        assert_eq!(*second, 1);
        drop((first, second));

        *value.write() = 2;
        assert_eq!(*value.read(), 2);
    }

    #[test]
    fn rwlock_serializes_concurrent_writers() {
        let value = Arc::new(LinuxRwLock::new(0));
        let threads = (0..4)
            .map(|_| {
                let value = Arc::clone(&value);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        *value.write() += 1;
                    }
                })
            })
            .collect::<Vec<_>>();

        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(*value.read(), 4_000);
    }
}
