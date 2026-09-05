// Copyright (c) The Rust Project Contributors & Microsoft Corporation.
// Licensed under the MIT license.

//! Mutual exclusion.

use core::cell::UnsafeCell;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use litebox_platform::sync::RawMutex as _;

use super::RawSyncPrimitivesProvider;

struct SpinEnabledRawMutex<Platform: RawSyncPrimitivesProvider> {
    /// 0: unlocked
    /// 1: locked, no other execution context waiting
    /// 2: locked, with another execution context waiting
    raw: Platform::RawMutex,
}

impl<Platform: RawSyncPrimitivesProvider> SpinEnabledRawMutex<Platform> {
    const fn new() -> Self {
        Self {
            raw: Platform::RawMutex::INIT,
        }
    }

    fn try_lock(&self) -> bool {
        self.raw
            .underlying_atomic()
            .compare_exchange(0, 1, Acquire, Relaxed)
            .is_ok()
    }

    fn lock(&self) {
        if !self.try_lock() {
            self.lock_contended();
        }
    }

    #[cold]
    fn lock_contended(&self) {
        let mut state = self.spin();
        if state == 0 {
            match self
                .raw
                .underlying_atomic()
                .compare_exchange(0, 1, Acquire, Relaxed)
            {
                Ok(_) => return,
                Err(observed) => state = observed,
            }
        }

        loop {
            if state != 2 && self.raw.underlying_atomic().swap(2, Acquire) == 0 {
                return;
            }
            let _ = self.raw.block(2);
            state = self.spin();
        }
    }

    fn spin(&self) -> u32 {
        let mut remaining = 100;
        loop {
            let state = self.raw.underlying_atomic().load(Relaxed);
            if state != 1 || remaining == 0 {
                return state;
            }
            core::hint::spin_loop();
            remaining -= 1;
        }
    }

    /// # Safety
    ///
    /// The caller must hold this mutex.
    unsafe fn unlock(&self) {
        if self.raw.underlying_atomic().swap(0, Release) == 2 {
            self.raw.wake_one();
        }
    }
}

/// A platform-backed mutual-exclusion lock.
pub struct Mutex<Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    raw: SpinEnabledRawMutex<Platform>,
    data: UnsafeCell<T>,
}

impl<Platform: RawSyncPrimitivesProvider, T> Mutex<Platform, T> {
    /// Creates a mutex containing `value`.
    pub const fn new(value: T) -> Self {
        Self {
            raw: SpinEnabledRawMutex::new(),
            data: UnsafeCell::new(value),
        }
    }

    /// Consumes the mutex and returns its value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }

    /// Returns mutable access without locking.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> Mutex<Platform, T> {
    /// Attempts to acquire the mutex without blocking.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, Platform, T>> {
        self.raw.try_lock().then_some(MutexGuard { mutex: self })
    }

    /// Acquires the mutex, blocking until it is available.
    pub fn lock(&self) -> MutexGuard<'_, Platform, T> {
        self.raw.lock();
        MutexGuard { mutex: self }
    }
}

// SAFETY: The mutex transfers ownership of its protected value only when `T`
// itself can be sent between execution contexts.
unsafe impl<Platform: RawSyncPrimitivesProvider, T: Send + ?Sized> Send for Mutex<Platform, T> {}

// SAFETY: The mutex provides exclusive access to `T`, so sharing the mutex is
// sound whenever `T` can be sent between execution contexts.
unsafe impl<Platform: RawSyncPrimitivesProvider, T: Send + ?Sized> Sync for Mutex<Platform, T> {}

/// Exclusive access guard returned by [`Mutex::lock`].
pub struct MutexGuard<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    mutex: &'a Mutex<Platform, T>,
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::Deref
    for MutexGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: Holding the guard guarantees shared access is synchronized.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::DerefMut
    for MutexGuard<'_, Platform, T>
{
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Holding the exclusive guard guarantees unique access.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> Drop for MutexGuard<'_, Platform, T> {
    fn drop(&mut self) {
        // SAFETY: A MutexGuard exists only while its mutex is locked.
        unsafe {
            self.mutex.raw.unlock();
        }
    }
}
