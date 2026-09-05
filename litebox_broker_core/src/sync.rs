// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker synchronization primitives supplied by the deployment platform.

use core::sync::atomic::AtomicU32;

mod mutex;
mod rwlock;

pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

/// A raw blocking mutex primitive supplied by a broker platform.
pub trait RawMutex: Send + Sync + 'static {
    /// Initial unlocked mutex value.
    const INIT: Self;

    /// Returns the atomic word used by the portable lock algorithms.
    fn underlying_atomic(&self) -> &AtomicU32;

    /// Wakes up to `count` execution contexts blocked on this mutex.
    ///
    /// Implementations that cannot observe the number woken may return zero.
    fn wake_many(&self, count: usize) -> usize;

    /// Wakes one execution context blocked on this mutex.
    fn wake_one(&self) -> bool {
        self.wake_many(1) > 0
    }

    /// Wakes every execution context blocked on this mutex.
    fn wake_all(&self) -> usize {
        self.wake_many(i32::MAX as usize)
    }

    /// Blocks while the underlying atomic word equals `expected`.
    ///
    /// A wakeup does not imply that the atomic word changed. If the value
    /// changed before the caller blocked, this returns [`ImmediatelyWokenUp`].
    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp>;
}

/// Broker platform capability that selects its raw mutex implementation.
pub trait RawMutexProvider {
    /// Raw mutex used by the portable synchronization primitives.
    type RawMutex: RawMutex;
}

/// Convenience bound for broker platforms that provide synchronization.
pub trait RawSyncPrimitivesProvider: RawMutexProvider + Sync + 'static {}

impl<Provider> RawSyncPrimitivesProvider for Provider where
    Provider: RawMutexProvider + Sync + 'static
{
}

/// Indicates that a raw mutex value changed before the caller could block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImmediatelyWokenUp;
