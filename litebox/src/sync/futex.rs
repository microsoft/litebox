//! A Linux-y `futex`-like abstraction. Fast user-space mutexes.

// Implementation note: other submodules of `crate::sync` should NOT depend on this module directly,
// because this module itself depends on some of the other modules (specifically, this module
// depends on on `RwLock`). A refactoring could clean this up and prevent this dependency, but at
// the moment, it has been decided that this ordering of dependency is more fruitful.

use super::{RawSyncPrimitivesProvider, RwLock};
use crate::platform::{
    ImmediatelyWokenUp, Instant, RawConstPointer as _, RawMutex, TimeProvider, UnblockedOrTimedOut,
};
use crate::{LiteBox, platform::RawPointerProvider};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use core::{num::NonZeroU32, sync::atomic::AtomicU32, time::Duration};
use hashbrown::HashMap;
use thiserror::Error;

/// A manager of all available futexes.
///
/// Note: currently, this only supports "private" futexes, since it assumes only a single process.
/// In the future, this may be expanded to support multi-process futexes.
pub struct FutexManager<Platform: RawSyncPrimitivesProvider + RawPointerProvider + TimeProvider> {
    // A map from user-space addresses to raw mutexes.
    lockables: RwLock<Platform, HashMap<usize, Lockable<Platform>>>,
    litebox: LiteBox<Platform>,
}

/// (Private-only) storage for a specific futex.
struct Lockable<Platform: RawSyncPrimitivesProvider> {
    // TODO(jayb): Move the `num_waiters` to be part of the raw mutex underlying atomic itself.
    num_waiters: u32,
    raw_mutex: Arc<Platform::RawMutex>,
    latest_wake_bitset: Option<NonZeroU32>,
}

impl<Platform: RawSyncPrimitivesProvider> Lockable<Platform> {
    fn new(litebox: &LiteBox<Platform>) -> Self {
        let raw_mutex = Arc::new(litebox.x.platform.new_raw_mutex());
        raw_mutex.underlying_atomic().store(0, Ordering::SeqCst);
        Self {
            num_waiters: 0,
            raw_mutex,
            latest_wake_bitset: None,
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + RawPointerProvider + TimeProvider>
    FutexManager<Platform>
{
    /// A new futex manager.
    // TODO(jayb): Integrate this into the `litebox` object itself, to prevent the possibility of
    // double-creation.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let lockables = litebox.sync().new_rwlock(HashMap::new());
        Self {
            lockables,
            litebox: litebox.clone(),
        }
    }

    /// (Private-only) convert the `futex_addr` to an atomic u32. The lifetime created by this MUST
    /// NOT be used outside of its immediately-invoking function.
    fn futex_addr_as_atomic<'a>(
        futex_addr: Platform::RawMutPointer<u32>,
    ) -> Result<&'a AtomicU32, FutexError> {
        let addr: usize = futex_addr.as_usize();
        if !addr.is_multiple_of(align_of::<AtomicU32>()) {
            return Err(FutexError::NotAligned);
        }
        let ptr = addr as *mut u32;
        // SAFETY: we've ensured that it is aligned. The read/write lifetimes of `ptr` are going to
        // be valid as long as we don't actually expose the created `AtomicU32` lifetime outside
        // this module. And for the memory model, we are explicitly using it only on things that are
        // supposed to be for futex operations.
        Ok(unsafe { AtomicU32::from_ptr(ptr) })
    }

    /// (Private-only) decrement the number of waiters at `addr`, GCing if it hits zero.
    fn decrement_num_waiters_at(&self, addr: usize) {
        let mut lockables = self.lockables.write();
        let lockable = lockables.get_mut(&addr).unwrap();
        lockable.num_waiters -= 1;
        if lockable.num_waiters == 0 {
            lockables.remove(&addr).unwrap();
        }
    }

    /// Test if the futex word still contains the expected value. If it does not, return immediately
    /// with a [`FutexError::ImmediatelyWokenBecauseValueMismatch`]. If it does, wait till a `Wake`
    /// operation.
    ///
    /// If `timeout` is `None`, then this blocks indefinitely.
    ///
    /// If `bitset` is `Some`, then it specifies a mask that can be used by a `Wake` with a `bitset`,
    /// in which case, it provides the ability to select a subset of waiters to be awoken
    /// (specifically, ones whose mask intersection is non-zero). Specifying `None` is equivalent to
    /// setting all bits on the mask.
    ///
    /// Note: this function is similar to `FUTEX_WAIT` or `FUTEX_WAIT_BITSET`. However, independent
    /// of which of the two is in use, this always uses relative durations. If an absolute duration
    /// is needed, it is up to the caller to convert it to a relative duration.
    pub fn wait(
        &self,
        futex_addr: Platform::RawMutPointer<u32>,
        expected_value: u32,
        timeout: Option<Duration>,
        bitset: Option<NonZeroU32>,
    ) -> Result<(), FutexError> {
        let addr = futex_addr.as_usize();
        let futex_addr = Self::futex_addr_as_atomic(futex_addr)?;
        // We currently lock _before_ we check the value, just to simplify understanding. It may be
        // ok to do this after the check, but that would need more thinking to make sure that the
        // semantics are correct.
        let mut lockables = self.lockables.write();
        // Now we check whether the value is the expected or not. If it is the expected, we continue
        // on, otherwise, get out quickly!
        if futex_addr.load(Ordering::SeqCst) != expected_value {
            return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
        }
        // Now we actually can get into the waiting behavior.
        let lockable: &mut Lockable<Platform> = lockables
            .entry(addr)
            .or_insert_with(|| Lockable::new(&self.litebox));
        lockable.num_waiters += 1;
        let start = self.litebox.x.platform.now();
        // We grab the ability to get to the raw mutex, and then unlock the lockables, so that other
        // threads can then get access to the underlying raw-mutex too, to be able to wake us up.
        let raw_mutex = Arc::clone(&lockable.raw_mutex);
        drop(lockables);

        // Zzz, till we have a reason to wake up.
        loop {
            let remaining = timeout.map(|timeout| {
                self.litebox
                    .x
                    .platform
                    .now()
                    .duration_since(&start)
                    .saturating_sub(timeout)
            });

            // Check if we have timed out
            if remaining.is_some_and(|r| r.is_zero()) {
                self.decrement_num_waiters_at(addr);
                return Err(FutexError::TimedOut);
            }

            // We should block till we are woken up.
            if let Some(remaining) = remaining {
                match raw_mutex.block_or_timeout(0, remaining) {
                    Ok(UnblockedOrTimedOut::Unblocked) => {
                        // fallthrough
                    }
                    Ok(UnblockedOrTimedOut::TimedOut) => {
                        self.decrement_num_waiters_at(addr);
                        return Err(FutexError::TimedOut);
                    }
                    Err(ImmediatelyWokenUp) => unreachable!(),
                }
            } else {
                match raw_mutex.block(0) {
                    Ok(()) => {
                        // fallthrough
                    }
                    Err(ImmediatelyWokenUp) => unreachable!(),
                }
            }

            // We've just been woken up, we might need to go back to sleep if we are not in the
            // bitset to be woken up, but otherwise, we are free to exit!
            let Some(bitset) = bitset else {
                self.decrement_num_waiters_at(addr);
                return Ok(());
            };

            // We check the latest waker bitset; if we are part of what should be woken up, we do,
            // otherwise we go back to sleep.
            let latest_wake_bitset = {
                #[expect(clippy::missing_panics_doc, reason = "the lockable must still exist")]
                {
                    self.lockables
                        .read()
                        .get(&addr)
                        .unwrap()
                        .latest_wake_bitset
                        .map_or(0, NonZeroU32::get)
                }
            };
            if (latest_wake_bitset & bitset.get()) != 0 {
                self.decrement_num_waiters_at(addr);
                return Ok(());
            }

            // Green Day time? https://youtu.be/pGhwBFYtn1s
        }
    }

    /// This operation wakes at most `num_to_wake` of the waiters that are waiting on the futex
    /// word. Most commonly, `num_to_wake` is specified as either 1 (wake up a single waiter) or
    /// max value (to wake up all waiters). No guarantee is provided about which waiters are
    /// awoken.
    ///
    /// If `bitset` is `Some`, then it specifies a mask that specifies which waiters to wake up.
    /// Specifically, any waiters that have an intersection between their masks and the provided
    /// `bitset` are valid waiters to wake up.
    ///
    /// Returns the number of waiters that were woken up.
    pub fn wake(
        &self,
        futex_addr: Platform::RawMutPointer<u32>,
        num_to_wake_up: NonZeroU32,
        bitset: Option<NonZeroU32>,
    ) -> Result<u32, FutexError> {
        let addr = futex_addr.as_usize();
        // We will loop until there is no other waker in active play.
        let mut lockables = loop {
            let mut lockables = self.lockables.write();
            if let Some(lockable) = lockables.get_mut(&addr) {
                if lockable.latest_wake_bitset.is_none() {
                    // There is no other waiter in play, we take it by setting it up.
                    lockable.latest_wake_bitset = Some(bitset.unwrap_or(NonZeroU32::MAX));
                    break lockables;
                } else {
                    // There is another waker in play, we yield to them, and will come back later.
                    core::hint::spin_loop();
                }
            } else {
                // There are no waiters, so we can quit early. No one was woken up.
                return Ok(0);
            }
        };
        // Now, we are the sole waker in play.
        let Some(lockable): Option<&mut Lockable<Platform>> = lockables.get_mut(&addr) else {
            // There are no remaining waiters, so we can quit early. No one was woken up.
            return Ok(0);
        };
        debug_assert!(
            lockable.num_waiters > 0,
            "The `lockable` for the address should have been GC'd if there were no more waiters."
        );
        // We can only wake up the number of sleepers that actually exist. The number of sleepers
        // does not change while we are calculating these things because we are holding on to this
        // lock, thus no more waiters can actually enter sleep while we finish this up.
        let num_to_wake_up: u32 = lockable.num_waiters.min(num_to_wake_up.get());
        // Now we can actually trigger things to start waking up. We don't actually trust the
        // underlying primitive to tell us accurately how many woke up, although we do a quick
        // sanity check that it claims that at least one woke up.
        let num_claimed_woken_up: usize = lockable.raw_mutex.wake_many(
            #[expect(
                clippy::missing_panics_doc,
                reason = "this conversion should never fail"
            )]
            {
                num_to_wake_up.try_into().unwrap()
            },
        );
        debug_assert!(num_claimed_woken_up > 0);
        // Releasing the lock allows those woken threads to proceed with their wake-up sequence.
        drop(lockables);
        // Now, we spin until at least one of the waiters has woken up and finished letting us know
        // it has woken up. We know there must have been at least one before, so as long as the
        // value does not drop, we know that nothing has been woken up yet. If the `lockable` for it
        // has been GC'd out, that means all wakers got woken up, which is fine too to quit out.
        //
        // XXX(jayb): This check may not be ideal if there are no waiters that have any overlap in
        // terms of bitset masks, in which case this might spin forever until at least someone with
        // that mask goes to sleep.
        while let Some(lockable) = self.lockables.write().get_mut(&addr)
            && lockable.num_waiters >= num_to_wake_up
        {
            core::hint::spin_loop();
        }
        // We can now reset the mask out, and return the number that actually woke up.
        if let Some(lockable) = self.lockables.write().get_mut(&addr) {
            lockable.latest_wake_bitset = None;
            debug_assert!(num_to_wake_up > lockable.num_waiters);
            Ok(num_to_wake_up - lockable.num_waiters)
        } else {
            // The addr has been GC'd from the addressables. All waiters have been woken up.
            Ok(num_to_wake_up)
        }
    }
}

/// Potential errors that can be returned by [`FutexManager`]'s operations.
#[derive(Debug, Error)]
pub enum FutexError {
    #[error("address not correctly aligned to 4-bytes")]
    NotAligned,
    #[error("immediately woken: value did not match expected")]
    ImmediatelyWokenBecauseValueMismatch,
    #[error("timeout expired before operation completed")]
    TimedOut,
}
