// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker synchronization primitives supplied by the deployment platform.

use core::ops::{Deref, DerefMut};

/// Platform-provided blocking synchronization primitives.
///
/// Broker subsystems use the portable [`Mutex`] and [`RwLock`] wrappers while
/// the deployment supplies the underlying lock and guard types. Implementations
/// must block the current execution context under contention rather than spin.
pub trait RawSyncPrimitivesProvider: Send + Sync + 'static {
    /// Platform mutex storing `T`.
    type RawMutex<T: Send>: Send + Sync;

    /// Guard returned while a platform mutex is locked.
    type MutexGuard<'a, T: Send + 'a>: Deref<Target = T> + DerefMut
    where
        Self: 'a;

    /// Platform reader-writer lock storing `T`.
    type RawRwLock<T: Send + Sync>: Send + Sync;

    /// Guard returned while a platform reader-writer lock is read-locked.
    type RwLockReadGuard<'a, T: Send + Sync + 'a>: Deref<Target = T>
    where
        Self: 'a;

    /// Guard returned while a platform reader-writer lock is write-locked.
    type RwLockWriteGuard<'a, T: Send + Sync + 'a>: Deref<Target = T> + DerefMut
    where
        Self: 'a;

    /// Creates a platform mutex containing `value`.
    fn new_mutex<T: Send>(value: T) -> Self::RawMutex<T>;

    /// Locks a platform mutex, blocking until it is available.
    fn lock_mutex<T: Send>(mutex: &Self::RawMutex<T>) -> Self::MutexGuard<'_, T>;

    /// Creates a platform reader-writer lock containing `value`.
    fn new_rwlock<T: Send + Sync>(value: T) -> Self::RawRwLock<T>;

    /// Read-locks a platform reader-writer lock, blocking until it is available.
    fn read_rwlock<T: Send + Sync>(rwlock: &Self::RawRwLock<T>) -> Self::RwLockReadGuard<'_, T>;

    /// Write-locks a platform reader-writer lock, blocking until it is available.
    fn write_rwlock<T: Send + Sync>(rwlock: &Self::RawRwLock<T>) -> Self::RwLockWriteGuard<'_, T>;
}

/// A platform-backed mutual-exclusion lock.
pub struct Mutex<Provider: RawSyncPrimitivesProvider, T: Send> {
    raw: Provider::RawMutex<T>,
}

impl<Provider: RawSyncPrimitivesProvider, T: Send> Mutex<Provider, T> {
    /// Creates a mutex containing `value`.
    pub fn new(value: T) -> Self {
        Self {
            raw: Provider::new_mutex(value),
        }
    }

    /// Locks the mutex, blocking until it is available.
    pub fn lock(&self) -> Provider::MutexGuard<'_, T> {
        Provider::lock_mutex(&self.raw)
    }
}

/// A platform-backed reader-writer lock.
pub struct RwLock<Provider: RawSyncPrimitivesProvider, T: Send + Sync> {
    raw: Provider::RawRwLock<T>,
}

impl<Provider: RawSyncPrimitivesProvider, T: Send + Sync> RwLock<Provider, T> {
    /// Creates a reader-writer lock containing `value`.
    pub fn new(value: T) -> Self {
        Self {
            raw: Provider::new_rwlock(value),
        }
    }

    /// Read-locks the value, blocking until it is available.
    pub fn read(&self) -> Provider::RwLockReadGuard<'_, T> {
        Provider::read_rwlock(&self.raw)
    }

    /// Write-locks the value, blocking until it is available.
    pub fn write(&self) -> Provider::RwLockWriteGuard<'_, T> {
        Provider::write_rwlock(&self.raw)
    }
}
