//! Mutual exclusion

use core::cell::UnsafeCell;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use crate::platform::RawMutex as _;

#[cfg(feature = "lock_tracing")]
use crate::sync::lock_tracing::{LockTracker, LockType, LockedWitness};

use super::RawSyncPrimitivesProvider;

/// A spin-enabled wrapper around [`platform::RawMutex`](crate::platform::RawMutex) to reduce the
/// number of unnecessary calls out to platform.
struct SpinEnabledRawMutex<Platform: RawSyncPrimitivesProvider> {
    /// 0: unlocked
    /// 1: locked, no other threads waiting
    /// 2: locked, and other threads waiting (contended)
    raw: Platform::RawMutex,
}

impl<Platform: RawSyncPrimitivesProvider> SpinEnabledRawMutex<Platform> {
    /// Create a new [`SpinEnabledRawMutex`] from a [`RawMutex`](crate::platform::RawMutex).
    #[inline]
    fn new(raw: Platform::RawMutex) -> Self {
        Self { raw }
    }

    /// Attempts to acquire this mutex without blocking. Returns `true` if the lock was successfully
    /// acquired and `false` otherwise.
    #[inline]
    #[must_use]
    fn try_lock(&self) -> bool {
        self.raw
            .underlying_atomic()
            .compare_exchange(0, 1, Acquire, Relaxed)
            .is_ok()
    }

    /// Acquires this mutex, blocking the current thread until it is able to do so.
    #[inline]
    fn lock(&self) {
        if self.try_lock() {
            // Acquired immediately, nice!
        } else {
            self.lock_contended();
        }
    }

    /// Could not _immediately_ acquire the mutex, there might be some contention to account for.
    #[cold]
    fn lock_contended(&self) {
        // Spin first to speed things up if the lock is released quickly.
        let mut state = self.spin();

        // If it's unlocked now, attempt to take the lock without marking it as contended.
        if state == 0 {
            match self
                .raw
                .underlying_atomic()
                .compare_exchange(0, 1, Acquire, Relaxed)
            {
                Ok(_) => return, // Locked!
                Err(s) => state = s,
            }
        }

        loop {
            // Put the lock in contended state.
            // We avoid an unnecessary write if it as already set to 2,
            // to be friendlier for the caches.
            if state != 2 && self.raw.underlying_atomic().swap(2, Acquire) == 0 {
                // We changed it from 0 to 2, so we just successfully locked it.
                return;
            }

            // Wait for change in state, assuming it is still 2.
            // ignore the error code as it is non-interruptible
            let _ = self.raw.block(2);

            // Spin again after waking up
            state = self.spin();
        }
    }

    /// Spin for a little while to see if quick release is possible.
    ///
    /// Returns the state of the raw lock as soon as it is in unlocked (0) or contended (2), or when
    /// it has spun for long enough.
    fn spin(&self) -> u32 {
        let mut spin = 100;
        loop {
            // We only use `load` (and not `swap` or `compare_exchange`)
            // while spinning, to be easier on the caches.
            let state = self.raw.underlying_atomic().load(Relaxed);

            // We stop spinning when the mutex is unlocked (0),
            // but also when it's contended (2)
            //
            // Or if we run out of fuel to spin.
            if state != 1 || spin == 0 {
                return state;
            }

            core::hint::spin_loop();
            spin -= 1;
        }
    }

    /// Unlocks this mutex.
    ///
    /// # Safety
    ///
    /// This method may only be called if the mutex is held in the current context, i.e. it must be
    /// paired with a successful call to `lock`, `try_lock`, ...
    #[inline]
    unsafe fn unlock(&self) {
        if self.raw.underlying_atomic().swap(0, Release) == 2 {
            // We only wake up one thread. When that thread locks the mutex, it
            // will mark the mutex as contended (2) (see lock_contended above),
            // which makes sure that any other waiting threads will also be
            // woken up eventually.
            self.raw.wake_one();
        }
    }
}

/// An RAII implementation of a "scoped lock" of a mutex. When this structure is dropped (falls out
/// of scope), the lock will be unlocked.
///
/// The data protected by the mutex can be accessed through this guard via its `Deref` and
/// `DerefMut` implementations.
///
/// This structure is created by [`Mutex::lock`].
pub struct MutexGuard<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized + 'a> {
    mutex: &'a Mutex<Platform, T>,
    #[cfg(feature = "lock_tracing")]
    locked_witness: LockedWitness<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::Deref
    for MutexGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: Access to the guard means that the current thread is the only thread with access
        unsafe { &*self.mutex.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::DerefMut
    for MutexGuard<'_, Platform, T>
{
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Access to the guard means that the current thread is the only thread with access
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> Drop for MutexGuard<'_, Platform, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lock_tracing")]
        self.locked_witness.mark_unlock();

        // SAFETY: Access to the guard means that the current thread is the only thread with access
        unsafe {
            self.mutex.raw.unlock();
        }
    }
}

/// A mutual exclusion primitive useful for protecting shared data, roughly analogous to Rust's
/// [`std::sync::Mutex`](https://doc.rust-lang.org/std/sync/struct.Mutex.html).
///
/// A notable difference from Rust's `std` is that this `Mutex` does not maintain any poisoning
/// information, thus its [`lock`](Self::lock) functionality directly returns a locked guard.
pub struct Mutex<Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    raw: SpinEnabledRawMutex<Platform>,

    #[cfg(feature = "lock_tracing")]
    tracker: LockTracker<Platform>,

    data: UnsafeCell<T>,
}

impl<Platform: RawSyncPrimitivesProvider, T> Mutex<Platform, T> {
    #[inline]
    pub(super) fn new_from_synchronization(
        sync: &super::Synchronization<Platform>,
        val: T,
    ) -> Self {
        Self {
            raw: SpinEnabledRawMutex::new(sync.platform.new_raw_mutex()),
            data: UnsafeCell::new(val),
            #[cfg(feature = "lock_tracing")]
            tracker: sync.tracker.clone(),
        }
    }
}

// SAFETY: `Mutex<T>` inherits `Send` from `T`.
unsafe impl<Platform: RawSyncPrimitivesProvider, T: Send> Send for Mutex<Platform, T> {}
// SAFETY: `Mutex` provides mutually exclusive access to `T`, so it's OK to
// share a reference to it between threads as long as `T` can be _sent_ between
// threads.
unsafe impl<Platform: RawSyncPrimitivesProvider, T: Send> Sync for Mutex<Platform, T> {}

impl<Platform: RawSyncPrimitivesProvider, T> Mutex<Platform, T> {
    #[inline]
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, Platform, T> {
        #[cfg(feature = "lock_tracing")]
        let attempt = self
            .tracker
            .begin_lock_attempt(LockType::Mutex, self.raw.raw.underlying_atomic());

        self.raw.lock();

        MutexGuard {
            mutex: self,
            #[cfg(feature = "lock_tracing")]
            locked_witness: self.tracker.mark_lock(attempt),
        }
    }
}
