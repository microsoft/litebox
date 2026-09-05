// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland broker synchronization primitives.

use litebox_broker_core::sync::RawSyncPrimitivesProvider;

/// Blocking synchronization primitives for a Linux-userland broker.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxSyncPrimitivesProvider;

impl RawSyncPrimitivesProvider for LinuxSyncPrimitivesProvider {
    type RawMutex<T: Send> = std::sync::Mutex<T>;
    type MutexGuard<'a, T: Send + 'a> = std::sync::MutexGuard<'a, T>;
    type RawRwLock<T: Send + Sync> = std::sync::RwLock<T>;
    type RwLockReadGuard<'a, T: Send + Sync + 'a> = std::sync::RwLockReadGuard<'a, T>;
    type RwLockWriteGuard<'a, T: Send + Sync + 'a> = std::sync::RwLockWriteGuard<'a, T>;

    fn new_mutex<T: Send>(value: T) -> Self::RawMutex<T> {
        std::sync::Mutex::new(value)
    }

    fn lock_mutex<T: Send>(mutex: &Self::RawMutex<T>) -> Self::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn new_rwlock<T: Send + Sync>(value: T) -> Self::RawRwLock<T> {
        std::sync::RwLock::new(value)
    }

    fn read_rwlock<T: Send + Sync>(rwlock: &Self::RawRwLock<T>) -> Self::RwLockReadGuard<'_, T> {
        rwlock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_rwlock<T: Send + Sync>(rwlock: &Self::RawRwLock<T>) -> Self::RwLockWriteGuard<'_, T> {
        rwlock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        assert_eq!(*value.read(), 1);
        *value.write() = 2;
        assert_eq!(*value.read(), 2);
    }
}
