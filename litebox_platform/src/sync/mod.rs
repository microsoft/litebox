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

/// Holds, until the returned guard is dropped, the process-wide
/// synchronization state that no other thread may be changing while the
/// process is cloned: with lock tracing, its own locks, which every tracked
/// lock operation takes; without it, nothing.
///
/// A clone contains only the calling thread, so a lock another thread held at
/// that moment would stay held in the clone forever. Call this immediately
/// before cloning the process and drop the guard immediately afterwards, in
/// both the original process and the clone. Nothing in between may take a
/// tracked lock.
#[must_use = "the state is held only until the guard is dropped"]
pub fn hold_for_fork() -> impl Sized {
    #[cfg(feature = "lock_tracing")]
    return lock_tracing::hold_for_fork();
}
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

    /// Called first by every acquisition that may block, for platforms that
    /// check where blocking is allowed.
    #[inline(always)]
    fn might_block() {}
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
