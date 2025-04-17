//! A reader-writer lock
//!
//! This type of lock allows a number of readers or at most one writer at any point in time. The
//! write portion of this lock typically allows modification of the underlying data (exclusive
//! access) and the read portion of this lock typically allows for read-only access (shared access).

use core::cell::UnsafeCell;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use crate::platform::RawMutex;

#[cfg(feature = "lock_tracing")]
use crate::sync::lock_tracing::{LockTracker, LockType, LockedWitness};

use super::RawSyncPrimitivesProvider;

struct RawRwLock<Platform: RawSyncPrimitivesProvider> {
    // The state consists of a 30-bit reader counter, a 'readers waiting' flag, and a 'writers waiting' flag.
    // Bits 0..30:
    //   0: Unlocked
    //   1..=0x3FFF_FFFE: Locked by N readers
    //   0x3FFF_FFFF: Write locked
    // Bit 30: Readers are waiting on this futex.
    // Bit 31: Writers are waiting on the writer_notify futex.
    state: Platform::RawMutex,
    // The 'condition variable' to notify writers through.
    // Incremented on every signal.
    writer_notify: Platform::RawMutex,
}

const READ_LOCKED: u32 = 1;
const MASK: u32 = (1 << 30) - 1;
const WRITE_LOCKED: u32 = MASK;
const MAX_READERS: u32 = MASK - 1;
const READERS_WAITING: u32 = 1 << 30;
const WRITERS_WAITING: u32 = 1 << 31;

#[inline]
fn is_unlocked(state: u32) -> bool {
    state & MASK == 0
}

#[inline]
fn is_write_locked(state: u32) -> bool {
    state & MASK == WRITE_LOCKED
}

#[inline]
fn has_readers_waiting(state: u32) -> bool {
    state & READERS_WAITING != 0
}

#[inline]
fn has_writers_waiting(state: u32) -> bool {
    state & WRITERS_WAITING != 0
}

#[inline]
fn is_read_lockable(state: u32) -> bool {
    // This also returns false if the counter could overflow if we tried to read lock it.
    //
    // We don't allow read-locking if there's readers waiting, even if the lock is unlocked
    // and there's no writers waiting. The only situation when this happens is after unlocking,
    // at which point the unlocking thread might be waking up writers, which have priority over readers.
    // The unlocking thread will clear the readers waiting bit and wake up readers, if necessary.
    state & MASK < MAX_READERS && !has_readers_waiting(state) && !has_writers_waiting(state)
}

#[inline]
fn has_reached_max_readers(state: u32) -> bool {
    state & MASK == MAX_READERS
}

impl<Platform: RawSyncPrimitivesProvider> RawRwLock<Platform> {
    #[inline]
    fn new(platform: &Platform) -> Self {
        Self {
            state: platform.new_raw_mutex(),
            writer_notify: platform.new_raw_mutex(),
        }
    }

    #[inline]
    fn try_read(&self) -> bool {
        self.state
            .underlying_atomic()
            .fetch_update(Acquire, Relaxed, |s| {
                is_read_lockable(s).then(|| s + READ_LOCKED)
            })
            .is_ok()
    }

    #[inline]
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

    #[inline]
    unsafe fn read_unlock(&self) {
        let state = self
            .state
            .underlying_atomic()
            .fetch_sub(READ_LOCKED, Release)
            - READ_LOCKED;

        // It's impossible for a reader to be waiting on a read-locked RwLock,
        // except if there is also a writer waiting.
        debug_assert!(!has_readers_waiting(state) || has_writers_waiting(state));

        // Wake up a writer if we were the last reader and there's a writer waiting.
        if is_unlocked(state) && has_writers_waiting(state) {
            self.wake_writer_or_readers(state);
        }
    }

    #[cold]
    fn read_contended(&self) {
        let mut state = self.spin_read();

        loop {
            // If we can lock it, lock it.
            if is_read_lockable(state) {
                match self.state.underlying_atomic().compare_exchange_weak(
                    state,
                    state + READ_LOCKED,
                    Acquire,
                    Relaxed,
                ) {
                    Ok(_) => return, // Locked!
                    Err(s) => {
                        state = s;
                        continue;
                    }
                }
            }

            // Check for overflow.
            assert!(
                !has_reached_max_readers(state),
                "too many active read locks on RwLock"
            );

            // Make sure the readers waiting bit is set before we go to sleep.
            if !has_readers_waiting(state) {
                if let Err(s) = self.state.underlying_atomic().compare_exchange(
                    state,
                    state | READERS_WAITING,
                    Relaxed,
                    Relaxed,
                ) {
                    state = s;
                    continue;
                }
            }

            // Wait for the state to change.
            // ignore the error code as it is non-interruptible
            let _ = self.state.block(state | READERS_WAITING);

            // Spin again after waking up.
            state = self.spin_read();
        }
    }

    #[inline]
    fn try_write(&self) -> bool {
        self.state
            .underlying_atomic()
            .fetch_update(Acquire, Relaxed, |s| {
                is_unlocked(s).then(|| s + WRITE_LOCKED)
            })
            .is_ok()
    }

    #[inline]
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

    #[inline]
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

    #[cold]
    fn write_contended(&self) {
        let mut state = self.spin_write();

        let mut other_writers_waiting = 0;

        loop {
            // If it's unlocked, we try to lock it.
            if is_unlocked(state) {
                match self.state.underlying_atomic().compare_exchange_weak(
                    state,
                    state | WRITE_LOCKED | other_writers_waiting,
                    Acquire,
                    Relaxed,
                ) {
                    Ok(_) => return, // Locked!
                    Err(s) => {
                        state = s;
                        continue;
                    }
                }
            }

            // Set the waiting bit indicating that we're waiting on it.
            if !has_writers_waiting(state) {
                if let Err(s) = self.state.underlying_atomic().compare_exchange(
                    state,
                    state | WRITERS_WAITING,
                    Relaxed,
                    Relaxed,
                ) {
                    state = s;
                    continue;
                }
            }

            // Other writers might be waiting now too, so we should make sure
            // we keep that bit on once we manage lock it.
            other_writers_waiting = WRITERS_WAITING;

            // Examine the notification counter before we check if `state` has changed,
            // to make sure we don't miss any notifications.
            let seq = self.writer_notify.underlying_atomic().load(Acquire);

            // Don't go to sleep if the lock has become available,
            // or if the writers waiting bit is no longer set.
            state = self.state.underlying_atomic().load(Relaxed);
            if is_unlocked(state) || !has_writers_waiting(state) {
                continue;
            }

            // Wait for the state to change.
            // ignore the error code as it is non-interruptible
            let _ = self.writer_notify.block(seq);

            // Spin again after waking up.
            state = self.spin_write();
        }
    }

    /// Wake up waiting threads after unlocking.
    ///
    /// If both are waiting, this will wake up only one writer, but will fall
    /// back to waking up readers if there was no writer to wake up.
    #[cold]
    fn wake_writer_or_readers(&self, mut state: u32) {
        assert!(is_unlocked(state));

        // The readers waiting bit might be turned on at any point now,
        // since readers will block when there's anything waiting.
        // Writers will just lock the lock though, regardless of the waiting bits,
        // so we don't have to worry about the writer waiting bit.
        //
        // If the lock gets locked in the meantime, we don't have to do
        // anything, because then the thread that locked the lock will take
        // care of waking up waiters when it unlocks.

        // If only writers are waiting, wake one of them up.
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
                Err(s) => {
                    // Maybe some readers are now waiting too. So, continue to the next `if`.
                    state = s;
                }
            }
        }

        // If both writers and readers are waiting, leave the readers waiting
        // and only wake up one writer.
        if state == READERS_WAITING + WRITERS_WAITING {
            if self
                .state
                .underlying_atomic()
                .compare_exchange(state, READERS_WAITING, Relaxed, Relaxed)
                .is_err()
            {
                // The lock got locked. Not our problem anymore.
                return;
            }
            if self.wake_writer() {
                return;
            }
            // No writers were actually blocked on futex_wait, so we continue
            // to wake up readers instead, since we can't be sure if we notified a writer.
            state = READERS_WAITING;
        }

        // If readers are waiting, wake them all up.
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

    /// This wakes one writer and returns true if we woke up a writer that was
    /// blocked on futex_wait.
    ///
    /// If this returns false, it might still be the case that we notified a
    /// writer that was about to go to sleep.
    fn wake_writer(&self) -> bool {
        self.writer_notify.underlying_atomic().fetch_add(1, Release);
        self.writer_notify.wake_one()
        // Note that FreeBSD and DragonFlyBSD don't tell us whether they woke
        // up any threads or not, and always return `false` here. That still
        // results in correct behaviour: it just means readers get woken up as
        // well in case both readers and writers were waiting.
    }

    /// Spin for a while, but stop directly at the given condition.
    #[inline]
    fn spin_until(&self, f: impl Fn(u32) -> bool) -> u32 {
        let mut spin = 100; // Chosen by fair dice roll.
        loop {
            let state = self.state.underlying_atomic().load(Relaxed);
            if f(state) || spin == 0 {
                return state;
            }
            core::hint::spin_loop();
            spin -= 1;
        }
    }

    #[inline]
    fn spin_write(&self) -> u32 {
        // Stop spinning when it's unlocked or when there's waiting writers, to keep things somewhat fair.
        self.spin_until(|state| is_unlocked(state) || has_writers_waiting(state))
    }

    #[inline]
    fn spin_read(&self) -> u32 {
        // Stop spinning when it's unlocked or read locked, or when there's waiting threads.
        self.spin_until(|state| {
            !is_write_locked(state) || has_readers_waiting(state) || has_writers_waiting(state)
        })
    }
}

/// A reader-writer lock useful for protecting shared data, roughly analogous to Rust's
/// [`std::sync::RwLock`](https://doc.rust-lang.org/std/sync/struct.RwLock.html).
///
/// A notable difference from Rust's `std` is that this `RwLock` does not maintain any poisoning
/// information.
pub struct RwLock<Platform: RawSyncPrimitivesProvider, T: ?Sized> {
    raw: RawRwLock<Platform>,

    #[cfg(feature = "lock_tracing")]
    tracker: LockTracker<Platform>,

    data: UnsafeCell<T>,
}

pub struct RwLockReadGuard<'a, Platform: RawSyncPrimitivesProvider, T> {
    rwlock: &'a RwLock<Platform, T>,
    #[cfg(feature = "lock_tracing")]
    locked_witness: LockedWitness<Platform>,
}

pub struct MappedRwLockReadGuard<'a, Platform: RawSyncPrimitivesProvider, T> {
    data: core::ptr::NonNull<T>,
    raw_lock: &'a RawRwLock<Platform>,
    #[cfg(feature = "lock_tracing")]
    locked_witness: LockedWitness<Platform>,
}

pub struct RwLockWriteGuard<'a, Platform: RawSyncPrimitivesProvider, T> {
    rwlock: &'a RwLock<Platform, T>,
    #[cfg(feature = "lock_tracing")]
    locked_witness: LockedWitness<Platform>,
}

pub struct MappedRwLockWriteGuard<'a, Platform: RawSyncPrimitivesProvider, T> {
    data: core::ptr::NonNull<T>,
    raw_lock: &'a RawRwLock<Platform>,
    #[cfg(feature = "lock_tracing")]
    locked_witness: LockedWitness<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider, T> core::ops::Deref for RwLockReadGuard<'_, Platform, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.rwlock.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> Drop for RwLockReadGuard<'_, Platform, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lock_tracing")]
        self.locked_witness.mark_unlock();

        unsafe {
            self.rwlock.raw.read_unlock();
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> core::ops::Deref
    for RwLockWriteGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.rwlock.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> core::ops::DerefMut
    for RwLockWriteGuard<'_, Platform, T>
{
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.rwlock.data.get() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> Drop for RwLockWriteGuard<'_, Platform, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lock_tracing")]
        self.locked_witness.mark_unlock();

        unsafe {
            self.rwlock.raw.write_unlock();
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> core::ops::Deref
    for MappedRwLockReadGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.data.as_ref() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> Drop for MappedRwLockReadGuard<'_, Platform, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lock_tracing")]
        self.locked_witness.mark_unlock();

        unsafe {
            self.raw_lock.read_unlock();
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> core::ops::Deref
    for MappedRwLockWriteGuard<'_, Platform, T>
{
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.data.as_ref() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> core::ops::DerefMut
    for MappedRwLockWriteGuard<'_, Platform, T>
{
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.data.as_mut() }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> Drop for MappedRwLockWriteGuard<'_, Platform, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lock_tracing")]
        self.locked_witness.mark_unlock();

        unsafe {
            self.raw_lock.write_unlock();
        }
    }
}

impl<'a, Platform: RawSyncPrimitivesProvider, T> RwLockReadGuard<'a, Platform, T> {
    /// Makes a `MappedRwLockReadGuard` for a component of the borrowed data, e.g. an enum variant.
    ///
    /// The `RwLock` is already locked for reading, so this cannot fail.
    ///
    /// This is an associated function that needs to be used as `RwLockReadGuard::map(...)`. A
    /// method would interfere with methods of the same name on the contents of the `RwLockReadGuard`
    /// used through `Deref`.
    pub fn map<U, F: FnOnce(&T) -> &U>(orig: Self, f: F) -> MappedRwLockReadGuard<'a, Platform, U> {
        let data_t: *mut T = orig.rwlock.data.get();
        let data_t: *const T = data_t;
        // SAFETY: We are holding a read-lock to the underlying T, thus it is safe to dereference
        // here. The reference to U has the same lifetime as that to T, and the lock will continue
        // to be held to the right duration.
        let data_u: &U = f(unsafe { &*data_t });
        let data = core::ptr::NonNull::from(data_u);
        let mut orig = core::mem::ManuallyDrop::new(orig);
        MappedRwLockReadGuard {
            data,
            raw_lock: &orig.rwlock.raw,
            #[cfg(feature = "lock_tracing")]
            locked_witness: unsafe { orig.locked_witness.reborrow_for_mapped_guard() },
        }
    }
}

impl<'a, Platform: RawSyncPrimitivesProvider, T> RwLockWriteGuard<'a, Platform, T> {
    /// Makes a `MappedRwLockWriteGuard` for a component of the borrowed data, e.g. an enum variant.
    ///
    /// The `RwLock` is already locked for writing, so this cannot fail.
    ///
    /// This is an associated function that needs to be used as `RwLockWriteGuard::map(...)`. A
    /// method would interfere with methods of the same name on the contents of the `RwLockWriteGuard`
    /// used through `Deref`/`DerefMut`.
    pub fn map<U, F: FnOnce(&mut T) -> &mut U>(
        orig: Self,
        f: F,
    ) -> MappedRwLockWriteGuard<'a, Platform, U> {
        let data_t: *mut T = orig.rwlock.data.get();
        // SAFETY: We are holding a write-lock to the underlying T, thus it is safe to dereference
        // here. The reference to U has the same lifetime as that to T, and the lock will continue
        // to be held to the right duration.
        let data_u: &mut U = f(unsafe { &mut *data_t });
        let data = core::ptr::NonNull::from(data_u);
        let mut orig = core::mem::ManuallyDrop::new(orig);
        MappedRwLockWriteGuard {
            data,
            raw_lock: &orig.rwlock.raw,
            #[cfg(feature = "lock_tracing")]
            locked_witness: unsafe { orig.locked_witness.reborrow_for_mapped_guard() },
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> RwLock<Platform, T> {
    #[inline]
    pub(super) fn new_from_synchronization(
        sync: &super::Synchronization<Platform>,
        val: T,
    ) -> Self {
        Self {
            raw: RawRwLock::new(sync.platform),
            data: UnsafeCell::new(val),
            #[cfg(feature = "lock_tracing")]
            tracker: sync.tracker.clone(),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider, T> RwLock<Platform, T> {
    #[inline]
    #[track_caller]
    pub fn read(&self) -> RwLockReadGuard<'_, Platform, T> {
        #[cfg(feature = "lock_tracing")]
        let attempt = self
            .tracker
            .begin_lock_attempt(LockType::RwLockRead, &self.raw.state);
        self.raw.read();
        RwLockReadGuard {
            rwlock: self,
            #[cfg(feature = "lock_tracing")]
            locked_witness: self.tracker.mark_lock(attempt),
        }
    }

    #[inline]
    #[track_caller]
    pub fn write(&self) -> RwLockWriteGuard<'_, Platform, T> {
        #[cfg(feature = "lock_tracing")]
        let attempt = self
            .tracker
            .begin_lock_attempt(LockType::RwLockWrite, &self.raw.state);
        self.raw.write();
        RwLockWriteGuard {
            rwlock: self,
            #[cfg(feature = "lock_tracing")]
            locked_witness: self.tracker.mark_lock(attempt),
        }
    }

    /// Consumes this `RwLock`, returning the underlying data.
    ///
    /// Since this function consumes `self`, it is guaranteed that no other thread has borrowed it
    /// or has unreleased locks.
    #[inline]
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this function borrows `self` mutably, it is guaranteed that no other thread has
    /// borrowed it, or has unreleased locks. Thus, no actual locking needs to take place---the
    /// mutable borrow statically guarantees exclusivity.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

unsafe impl<Platform: RawSyncPrimitivesProvider, T> Sync for RwLock<Platform, T> {}
unsafe impl<Platform: RawSyncPrimitivesProvider, T> Send for RwLock<Platform, T> {}
