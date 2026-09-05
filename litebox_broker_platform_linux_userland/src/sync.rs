// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland broker synchronization primitives.

use core::sync::atomic::AtomicU32;
use core::time::Duration;

use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
};
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

    fn block_or_maybe_timeout(
        &self,
        expected: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let timeout = timeout.map(|timeout| {
            futex::Timespec::try_from(timeout).expect("broker mutex timeout exceeds timespec")
        });
        match futex::wait(
            &self.state,
            futex::Flags::PRIVATE,
            expected,
            timeout.as_ref(),
        ) {
            Ok(()) | Err(rustix::io::Errno::INTR) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(rustix::io::Errno::AGAIN) => Err(ImmediatelyWokenUp),
            Err(rustix::io::Errno::TIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            Err(error) => panic!("failed to block on broker mutex: {error}"),
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
        match self.block_or_maybe_timeout(expected, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        expected: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(expected, Some(timeout))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use core::sync::atomic::Ordering;
    use core::time::Duration;

    use litebox_broker_core::sync::{Mutex, RwLock};
    use litebox_platform::sync::{ImmediatelyWokenUp, RawMutex as _, UnblockedOrTimedOut};

    use super::{LinuxRawMutex, LinuxSyncPrimitivesProvider};

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
    fn rwlock_supports_shared_reads_and_serializes_writers() {
        let value = Arc::new(LinuxRwLock::new(0));
        let first = value.read();
        let second = value.read();
        assert_eq!(*first, 0);
        assert_eq!(*second, 0);
        drop((first, second));

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

    #[test]
    fn raw_mutex_timed_wait_distinguishes_timeout_and_changed_value() {
        let raw = LinuxRawMutex::INIT;
        assert_eq!(
            raw.block_or_timeout(0, Duration::ZERO),
            Ok(UnblockedOrTimedOut::TimedOut)
        );

        raw.underlying_atomic().store(1, Ordering::Release);
        assert_eq!(
            raw.block_or_timeout(0, Duration::ZERO),
            Err(ImmediatelyWokenUp)
        );
    }
}
