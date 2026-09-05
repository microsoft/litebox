// Copyright (c) The Rust Project Contributors & Microsoft Corporation.
// Licensed under the MIT license.

//! Reader-writer locking.

use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use super::{RawMutex as _, RawSyncPrimitivesProvider};

const READ_LOCKED: u32 = 1;
const MASK: u32 = (1 << 30) - 1;
const WRITE_LOCKED: u32 = MASK;
const MAX_READERS: u32 = MASK - 1;
const READERS_WAITING: u32 = 1 << 30;
const WRITERS_WAITING: u32 = 1 << 31;

fn is_unlocked(state: u32) -> bool {
    state & MASK == 0
}

fn is_write_locked(state: u32) -> bool {
    state & MASK == WRITE_LOCKED
}

fn has_readers_waiting(state: u32) -> bool {
    state & READERS_WAITING != 0
}

fn has_writers_waiting(state: u32) -> bool {
    state & WRITERS_WAITING != 0
}

fn is_read_lockable(state: u32) -> bool {
    state & MASK < MAX_READERS && !has_readers_waiting(state) && !has_writers_waiting(state)
}

struct RawRwLock<Platform: RawSyncPrimitivesProvider> {
    state: Platform::RawMutex,
    writer_notify: Platform::RawMutex,
}

impl<Platform: RawSyncPrimitivesProvider> RawRwLock<Platform> {
    const fn new() -> Self {
        Self {
            state: Platform::RawMutex::INIT,
            writer_notify: Platform::RawMutex::INIT,
        }
    }

    fn read(&self) {
        let state = self.state.underlying_atomic().load(Relaxed);
        if !is_read_lockable(state)
            || self
                .state
                .underlying_atomic()
                .compare_exchange_weak(state, state + READ_LOCKED, Acquire, Relaxed)
                .is_err()
        {
            self.read_contended();
        }
    }

    #[cold]
    fn read_contended(&self) {
        let mut state = self.spin_read();
        loop {
            if is_read_lockable(state) {
                match self.state.underlying_atomic().compare_exchange_weak(
                    state,
                    state + READ_LOCKED,
                    Acquire,
                    Relaxed,
                ) {
                    Ok(_) => return,
                    Err(observed) => {
                        state = observed;
                        continue;
                    }
                }
            }

            assert!(
                state & MASK != MAX_READERS,
                "too many active read locks on RwLock"
            );
            if !has_readers_waiting(state)
                && let Err(observed) = self.state.underlying_atomic().compare_exchange(
                    state,
                    state | READERS_WAITING,
                    Relaxed,
                    Relaxed,
                )
            {
                state = observed;
                continue;
            }
            let _ = self.state.block(state | READERS_WAITING);
            state = self.spin_read();
        }
    }

    /// # Safety
    ///
    /// The caller must hold a read lock.
    unsafe fn read_unlock(&self) {
        let state = self
            .state
            .underlying_atomic()
            .fetch_sub(READ_LOCKED, Release)
            - READ_LOCKED;
        debug_assert!(!has_readers_waiting(state) || has_writers_waiting(state));
        if is_unlocked(state) && has_writers_waiting(state) {
            self.wake_writer_or_readers(state);
        }
    }

    fn write(&self) {
        if self
            .state
            .underlying_atomic()
            .compare_exchange_weak(0, WRITE_LOCKED, Acquire, Relaxed)
            .is_err()
        {
            self.write_contended();
        }
    }

    #[cold]
    fn write_contended(&self) {
        let mut state = self.spin_write();
        let mut other_writers_waiting = 0;
        loop {
            if is_unlocked(state) {
                match self.state.underlying_atomic().compare_exchange_weak(
                    state,
                    state | WRITE_LOCKED | other_writers_waiting,
                    Acquire,
                    Relaxed,
                ) {
                    Ok(_) => return,
                    Err(observed) => {
                        state = observed;
                        continue;
                    }
                }
            }

            if !has_writers_waiting(state)
                && let Err(observed) = self.state.underlying_atomic().compare_exchange(
                    state,
                    state | WRITERS_WAITING,
                    Relaxed,
                    Relaxed,
                )
            {
                state = observed;
                continue;
            }
            other_writers_waiting = WRITERS_WAITING;

            let sequence = self.writer_notify.underlying_atomic().load(Acquire);
            state = self.state.underlying_atomic().load(Relaxed);
            if is_unlocked(state) || !has_writers_waiting(state) {
                continue;
            }
            let _ = self.writer_notify.block(sequence);
            state = self.spin_write();
        }
    }

    /// # Safety
    ///
    /// The caller must hold the write lock.
    unsafe fn write_unlock(&self) {
        let state = self
            .state
            .underlying_atomic()
            .fetch_sub(WRITE_LOCKED, Release)
            - WRITE_LOCKED;
        debug_assert!(is_unlocked(state));
        if has_writers_waiting(state) || has_readers_waiting(state) {
            self.wake_writer_or_readers(state);
        }
    }

    fn wake_writer_or_readers(&self, mut state: u32) {
        debug_assert!(is_unlocked(state));

        if state == WRITERS_WAITING {
            match self
                .state
                .underlying_atomic()
                .compare_exchange(state, 0, Relaxed, Relaxed)
            {
                Ok(_) => {
                    self.wake_writer();
                    return;
                }
                Err(observed) => state = observed,
            }
        }

        if state == READERS_WAITING + WRITERS_WAITING {
            if self
                .state
                .underlying_atomic()
                .compare_exchange(state, READERS_WAITING, Relaxed, Relaxed)
                .is_err()
            {
                return;
            }
            if self.wake_writer() {
                return;
            }
            state = READERS_WAITING;
        }

        if state == READERS_WAITING
            && self
                .state
                .underlying_atomic()
                .compare_exchange(state, 0, Relaxed, Relaxed)
                .is_ok()
        {
            self.state.wake_all();
        }
    }

    fn wake_writer(&self) -> bool {
        self.writer_notify.underlying_atomic().fetch_add(1, Release);
        self.writer_notify.wake_one()
    }

    fn spin_until(&self, stop: impl Fn(u32) -> bool) -> u32 {
        let mut remaining = 100;
        loop {
            let state = self.state.underlying_atomic().load(Relaxed);
            if stop(state) || remaining == 0 {
                return state;
            }
            core::hint::spin_loop();
            remaining -= 1;
        }
    }

    fn spin_write(&self) -> u32 {
        self.spin_until(|state| is_unlocked(state) || has_writers_waiting(state))
    }

    fn spin_read(&self) -> u32 {
        self.spin_until(|state| {
            !is_write_locked(state) || has_readers_waiting(state) || has_writers_waiting(state)
        })
    }
}

/// A platform-backed reader-writer lock.
pub struct RwLock<Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    raw: RawRwLock<Platform>,
    data: UnsafeCell<T>,
}

impl<Platform: RawSyncPrimitivesProvider, T> RwLock<Platform, T> {
    /// Creates a reader-writer lock containing `value`.
    pub const fn new(value: T) -> Self {
        Self {
            raw: RawRwLock::new(),
            data: UnsafeCell::new(value),
        }
    }

    /// Consumes the lock and returns its value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }

    /// Returns mutable access without locking.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> RwLock<Platform, T> {
    /// Acquires shared read access, blocking until it is available.
    pub fn read(&self) -> RwLockReadGuard<'_, Platform, T> {
        self.raw.read();
        RwLockReadGuard { rwlock: self }
    }

    /// Acquires exclusive write access, blocking until it is available.
    pub fn write(&self) -> RwLockWriteGuard<'_, Platform, T> {
        self.raw.write();
        RwLockWriteGuard { rwlock: self }
    }
}

// SAFETY: The lock transfers ownership of its protected value only when `T`
// itself can be sent between execution contexts.
unsafe impl<Platform: RawSyncPrimitivesProvider, T: Send + ?Sized> Send for RwLock<Platform, T> {}

// SAFETY: Readers may share references to `T`, while writers have exclusive
// access, so sharing the lock requires `T` to be both Send and Sync.
unsafe impl<Platform: RawSyncPrimitivesProvider, T: Send + Sync + ?Sized> Sync
    for RwLock<Platform, T>
{
}

/// Shared access guard returned by [`RwLock::read`].
pub struct RwLockReadGuard<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    rwlock: &'a RwLock<Platform, T>,
}

/// Exclusive access guard returned by [`RwLock::write`].
pub struct RwLockWriteGuard<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    rwlock: &'a RwLock<Platform, T>,
}

/// Shared access guard mapped to a component of the locked value.
pub struct MappedRwLockReadGuard<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    data: NonNull<T>,
    raw: &'a RawRwLock<Platform>,
}

/// Exclusive access guard mapped to a component of the locked value.
pub struct MappedRwLockWriteGuard<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    data: NonNull<T>,
    raw: &'a RawRwLock<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::Deref
    for RwLockReadGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: Holding a read guard permits shared access to the value.
        unsafe { &*self.rwlock.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> Drop for RwLockReadGuard<'_, Platform, T> {
    fn drop(&mut self) {
        // SAFETY: A read guard exists only while one read lock is held.
        unsafe {
            self.rwlock.raw.read_unlock();
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::Deref
    for RwLockWriteGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: Holding the write guard permits shared access to the value.
        unsafe { &*self.rwlock.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::DerefMut
    for RwLockWriteGuard<'_, Platform, T>
{
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Holding the write guard guarantees unique access.
        unsafe { &mut *self.rwlock.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> Drop for RwLockWriteGuard<'_, Platform, T> {
    fn drop(&mut self) {
        // SAFETY: A write guard exists only while the write lock is held.
        unsafe {
            self.rwlock.raw.write_unlock();
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::Deref
    for MappedRwLockReadGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: The mapped pointer remains protected by the retained read lock.
        unsafe { self.data.as_ref() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> Drop
    for MappedRwLockReadGuard<'_, Platform, T>
{
    fn drop(&mut self) {
        // SAFETY: This mapped guard owns the original read lock.
        unsafe {
            self.raw.read_unlock();
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::Deref
    for MappedRwLockWriteGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: The mapped pointer remains protected by the retained write lock.
        unsafe { self.data.as_ref() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> core::ops::DerefMut
    for MappedRwLockWriteGuard<'_, Platform, T>
{
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: The retained write lock guarantees unique access.
        unsafe { self.data.as_mut() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: ?Sized> Drop
    for MappedRwLockWriteGuard<'_, Platform, T>
{
    fn drop(&mut self) {
        // SAFETY: This mapped guard owns the original write lock.
        unsafe {
            self.raw.write_unlock();
        }
    }
}

impl<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized> RwLockReadGuard<'a, Platform, T> {
    /// Maps this guard to a component of the protected value.
    pub fn map<U: ?Sized>(
        original: Self,
        map: impl FnOnce(&T) -> &U,
    ) -> MappedRwLockReadGuard<'a, Platform, U> {
        let data = NonNull::from(map(&original));
        let original = core::mem::ManuallyDrop::new(original);
        MappedRwLockReadGuard {
            data,
            raw: &original.rwlock.raw,
        }
    }
}

impl<'a, Platform: RawSyncPrimitivesProvider, T: ?Sized> RwLockWriteGuard<'a, Platform, T> {
    /// Maps this guard to a component of the protected value.
    pub fn map<U: ?Sized>(
        mut original: Self,
        map: impl FnOnce(&mut T) -> &mut U,
    ) -> MappedRwLockWriteGuard<'a, Platform, U> {
        let data = NonNull::from(map(&mut original));
        let original = core::mem::ManuallyDrop::new(original);
        MappedRwLockWriteGuard {
            data,
            raw: &original.rwlock.raw,
        }
    }
}
