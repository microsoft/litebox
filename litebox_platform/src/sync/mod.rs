// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform synchronization contracts and portable lock implementations.
//!
//! The [`Mutex`] and [`RwLock`] implementations are derived from related
//! source files in Rust's `std`. See `./cgmanifest.json` for the specific
//! upstream commits. They are modified to operate through [`RawMutex`] rather
//! than system interfaces and to support the optional lock-tracing feature.

use core::sync::atomic::AtomicU32;
use core::task::Waker;
use core::time::Duration;

mod mutex;
mod rwlock;

#[cfg(feature = "lock_tracing")]
mod lock_tracing;

#[cfg(feature = "lock_tracing")]
pub use lock_tracing::{
    RecordingSummary, flush_to_jsonl, init_lock_tracing, start_recording, stop_recording,
};
pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

/// A raw mutex/lock API expected to roughly match a Linux futex.
pub trait RawMutex: Send + Sync + 'static {
    /// The initial value for a raw mutex, with an underlying atomic value of zero.
    const INIT: Self;

    /// Returns the underlying atomic value.
    fn underlying_atomic(&self) -> &AtomicU32;

    /// Wakes up to `count` execution contexts blocked on this raw mutex.
    ///
    /// Implementations that cannot observe the number woken may return zero.
    fn wake_many(&self, count: usize) -> usize;

    /// Wakes one execution context blocked on this raw mutex.
    fn wake_one(&self) -> bool {
        self.wake_many(1) > 0
    }

    /// Wakes every execution context blocked on this raw mutex.
    fn wake_all(&self) -> usize {
        self.wake_many(i32::MAX as usize)
    }

    /// Blocks while the underlying atomic value equals `expected`.
    ///
    /// A wakeup does not imply that the atomic value changed. If the value
    /// changed before the caller blocked, this returns [`ImmediatelyWokenUp`].
    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp>;

    /// Blocks while the underlying atomic value equals `expected`, or until
    /// `timeout` elapses.
    ///
    /// If the value changed before the caller blocked, this returns
    /// [`ImmediatelyWokenUp`].
    fn block_or_timeout(
        &self,
        expected: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp>;
}

/// Platform capability that selects a raw mutex implementation.
pub trait RawMutexProvider {
    /// Raw mutex used by portable synchronization primitives.
    type RawMutex: RawMutex;
}

/// Platform capabilities required by the portable synchronization primitives.
pub trait RawSyncPrimitivesProvider: RawMutexProvider + Sync + 'static {}

impl<Platform> RawSyncPrimitivesProvider for Platform where
    Platform: RawMutexProvider + Sync + 'static
{
}

/// Platform capability for publishing the current interruptible-wait waker.
pub trait WaitWakerProvider {
    /// Updates the waker for the current execution context's interruptible wait.
    ///
    /// Platforms that can interrupt a blocked execution context should retain
    /// the waker while it is registered and invoke it when an interrupt occurs.
    #[expect(unused_variables)]
    fn update_waker(&self, waker: Option<Waker>) {}
}

/// Indicates that a raw mutex value changed before the caller could block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImmediatelyWokenUp;

/// Outcome of a raw mutex wait with a timeout.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnblockedOrTimedOut {
    /// Unblocked by a wake call.
    Unblocked,
    /// Sufficient time elapsed without a wake call.
    TimedOut,
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use core::time::Duration;

    use super::{
        ImmediatelyWokenUp, Mutex, RawMutex, RawMutexProvider, RwLock, UnblockedOrTimedOut,
    };

    static RAW_MUTEX_DROPS: AtomicUsize = AtomicUsize::new(0);

    struct DroppingRawMutex {
        state: AtomicU32,
    }

    impl Drop for DroppingRawMutex {
        fn drop(&mut self) {
            RAW_MUTEX_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl RawMutex for DroppingRawMutex {
        const INIT: Self = Self {
            state: AtomicU32::new(0),
        };

        fn underlying_atomic(&self) -> &AtomicU32 {
            &self.state
        }

        fn wake_many(&self, _count: usize) -> usize {
            0
        }

        fn block(&self, _expected: u32) -> Result<(), ImmediatelyWokenUp> {
            unreachable!("the test never contends on a lock")
        }

        fn block_or_timeout(
            &self,
            _expected: u32,
            _timeout: Duration,
        ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
            unreachable!("the test never contends on a lock")
        }
    }

    struct DroppingRawMutexProvider;

    impl RawMutexProvider for DroppingRawMutexProvider {
        type RawMutex = DroppingRawMutex;
    }

    #[test]
    fn into_inner_drops_raw_mutexes() {
        RAW_MUTEX_DROPS.store(0, Ordering::Relaxed);

        assert_eq!(Mutex::<DroppingRawMutexProvider, _>::new(1).into_inner(), 1);
        assert_eq!(RAW_MUTEX_DROPS.load(Ordering::Relaxed), 1);

        assert_eq!(
            RwLock::<DroppingRawMutexProvider, _>::new(2).into_inner(),
            2
        );
        assert_eq!(RAW_MUTEX_DROPS.load(Ordering::Relaxed), 3);
    }
}
