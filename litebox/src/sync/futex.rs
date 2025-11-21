//! A Linux-y `futex`-like abstraction. Fast user-space mutexes.

// Implementation note: other submodules of `crate::sync` should NOT depend on
// this module directly, because this module itself depends on some of the other
// modules (specifically, this module depends on `LoanList`, which depends on
// `Mutex`). A refactoring could clean this up and prevent this dependency, but
// at the moment, it has been decided that this ordering of dependency is more
// fruitful.

use core::hash::BuildHasher as _;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::{num::NonZeroU32, sync::atomic::AtomicU32};

use super::RawSyncPrimitivesProvider;
use crate::event::wait::{WaitContext, WaitError, Waker};
use crate::platform::{RawConstPointer as _, TimeProvider};
use crate::utilities::loan_list::{LoanList, LoanListEntry};
use crate::utils::TruncateExt as _;
use crate::{LiteBox, platform::RawPointerProvider};
use thiserror::Error;

/// A manager of all available futexes.
///
/// Note: currently, this only supports "private" futexes, since it assumes only a single process.
/// In the future, this may be expanded to support multi-process futexes.
pub struct FutexManager<Platform: RawSyncPrimitivesProvider> {
    /// Chaining hash table to map from futex address to waiter lists.
    table: alloc::boxed::Box<[LoanList<Platform, FutexEntry<Platform>>; HASH_TABLE_ENTRIES]>,
    hash_builder: hashbrown::DefaultHashBuilder,
    platform: &'static Platform,
}

/// The number of buckets in the hash table.
///
/// FUTURE: consider making this scale with some property of the platform, such
/// as number of CPUs.
const HASH_TABLE_ENTRIES: usize = 256;

struct FutexEntry<Platform: RawSyncPrimitivesProvider> {
    addr: usize,
    waker: Waker<Platform>,
    bitset: u32,
    done: AtomicBool,
}

const ALL_BITS: NonZeroU32 = NonZeroU32::new(u32::MAX).unwrap();

impl<Platform: RawSyncPrimitivesProvider + RawPointerProvider + TimeProvider>
    FutexManager<Platform>
{
    /// A new futex manager.
    // TODO(jayb): Integrate this into the `litebox` object itself, to prevent the possibility of
    // double-creation.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            table: alloc::boxed::Box::new(core::array::from_fn(|_| LoanList::new(litebox))),
            hash_builder: hashbrown::DefaultHashBuilder::default(),
            platform: litebox.x.platform,
        }
    }

    /// Returns the hash table bucket for the given futex address.
    fn bucket(&self, addr: usize) -> &LoanList<Platform, FutexEntry<Platform>> {
        let hash: usize = self.hash_builder.hash_one(addr).truncate();
        &self.table[hash % HASH_TABLE_ENTRIES]
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

    /// Performs a futex wait.
    ///
    /// This function tests once if the futex word matches the expected value,
    /// returning immediately with
    /// [`FutexError::ImmediatelyWokenBecauseValueMismatch`] if it does not.
    /// Otherwise, it waits until woken by a corresponding until
    /// [`FutexManager::wake`] is called targeting the same futex word or until
    /// the wait times out or is interrupted.
    ///
    /// If `bitset` is `Some`, then the waiter is only woken if the wake call's
    /// `bitset` has a non-zero intersection with the waiter's mask. Specifying
    /// `None` is equivalent to setting all bits in the mask.
    pub fn wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        futex_addr: Platform::RawMutPointer<u32>,
        expected_value: u32,
        bitset: Option<NonZeroU32>,
    ) -> Result<(), FutexError> {
        let bitset = bitset.unwrap_or(ALL_BITS).get();
        let addr = futex_addr.as_usize();
        let futex_addr = Self::futex_addr_as_atomic(futex_addr)?;

        let bucket = self.bucket(addr);
        let mut entry = pin!(LoanListEntry::new(
            self.platform,
            FutexEntry {
                addr,
                waker: cx.waker().clone(),
                bitset,
                done: AtomicBool::new(false),
            },
        ));

        // Insert into the bucket's list. It will be removed when woken or the
        // entry goes out of scope.
        entry.as_mut().insert(bucket);

        // Check the value once. Do this only after inserting into the list so
        // that we don't miss a wakeup.
        if futex_addr.load(Ordering::Relaxed) != expected_value {
            return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
        }
        // Only return when woken--don't reevaluate the futex word. This
        // ensures that the rate control mechanisms provided by the futex
        // interface are effective.
        cx.wait_until(|| entry.get().done.load(Ordering::Acquire))
            .map_err(FutexError::WaitError)
    }

    /// Wakes waiters on the given futex word.
    ///
    /// This operation wakes at most `num_to_wake` of the waiters that are
    /// waiting on the futex word. Most commonly, `num_to_wake` is specified as
    /// either 1 (wake up a single waiter) or max value (to wake up all
    /// waiters). No guarantee is provided about which waiters are awoken.
    ///
    /// If `bitset` is `Some`, then it contains a mask that specifies which
    /// waiters to wake up. Specifically, any waiters that have a non-zero
    /// intersection between their masks and the provided `bitset` can be woken,
    /// (subject to the `num_to_wake` limit). If `bitset` is `None`, then all
    /// waiters are eligible to be woken.
    ///
    /// Returns the number of waiters that were woken up.
    pub fn wake(
        &self,
        futex_addr: Platform::RawMutPointer<u32>,
        num_to_wake_up: NonZeroU32,
        bitset: Option<NonZeroU32>,
    ) -> Result<u32, FutexError> {
        let addr = futex_addr.as_usize();
        if !addr.is_multiple_of(align_of::<AtomicU32>()) {
            return Err(FutexError::NotAligned);
        }
        let bitset = bitset.unwrap_or(ALL_BITS).get();
        let mut woken = 0;
        let bucket = self.bucket(addr);
        // Extract matching entries from the bucket until we've woken enough.
        let entries = bucket.extract_if(|entry| {
            if entry.addr != addr || entry.bitset & bitset == 0 {
                return core::ops::ControlFlow::Continue(false);
            }
            woken += 1;
            if woken >= num_to_wake_up.get() {
                core::ops::ControlFlow::Break(true)
            } else {
                core::ops::ControlFlow::Continue(true)
            }
        });
        // Wake the waiters outside the `extract_if` closure to minimize the list's lock hold
        // time.
        for entry in entries {
            entry.done.store(true, Ordering::Relaxed);
            entry.waker.wake();
        }
        Ok(woken)
    }
}

/// Potential errors that can be returned by [`FutexManager`]'s operations.
#[derive(Debug, Error)]
pub enum FutexError {
    #[error("address not correctly aligned to 4-bytes")]
    NotAligned,
    #[error("immediately woken: value did not match expected")]
    ImmediatelyWokenBecauseValueMismatch,
    #[error("wait error")]
    WaitError(WaitError),
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::LiteBox;
    use crate::event::wait::WaitState;
    use crate::platform::mock::MockPlatform;
    use alloc::sync::Arc;
    use core::num::NonZeroU32;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_futex_wait_wake_single_thread() {
        let platform = MockPlatform::new();
        let litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new(&litebox));

        let futex_word = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let futex_manager_clone = Arc::clone(&futex_manager);
        let futex_word_clone = Arc::clone(&futex_word);
        let barrier_clone = Arc::clone(&barrier);

        // Spawn waiter thread
        let waiter = thread::spawn(move || {
            let futex_addr =
                <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                    futex_word_clone.as_ptr() as usize,
                );

            barrier_clone.wait(); // Sync with main thread

            // Wait for value 0
            futex_manager_clone.wait(&WaitState::new(platform).context(), futex_addr, 0, None)
        });

        barrier.wait(); // Wait for waiter to be ready
        thread::sleep(Duration::from_millis(10)); // Give waiter time to block

        // Change the value and wake
        futex_word.store(1, Ordering::SeqCst);
        let futex_addr =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex_word.as_ptr() as usize,
            );
        let woken = futex_manager
            .wake(futex_addr, NonZeroU32::new(1).unwrap(), None)
            .unwrap();

        // Wait for waiter thread to complete
        let result = waiter.join().unwrap();
        assert!(result.is_ok());
        assert_eq!(woken, 1);
    }

    #[test]
    fn test_futex_wait_wake_single_thread_with_timeout() {
        let platform = MockPlatform::new();
        let litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new(&litebox));

        let futex_word = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let futex_manager_clone = Arc::clone(&futex_manager);
        let futex_word_clone = Arc::clone(&futex_word);
        let barrier_clone = Arc::clone(&barrier);

        // Spawn waiter thread with timeout
        let waiter_thread = thread::spawn(move || {
            let futex_addr =
                <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                    futex_word_clone.as_ptr() as usize,
                );

            barrier_clone.wait(); // Sync with main thread

            // Wait for value 0 with some timeout
            futex_manager_clone.wait(
                &WaitState::new(platform)
                    .context()
                    .with_timeout(Duration::from_millis(300)),
                futex_addr,
                0,
                None,
            )
        });

        barrier.wait(); // Wait for waiter to be ready
        thread::sleep(Duration::from_millis(30)); // Give waiter time to block

        // Change the value and wake
        futex_word.store(1, Ordering::SeqCst);
        let futex_addr =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex_word.as_ptr() as usize,
            );
        let woken = futex_manager
            .wake(futex_addr, NonZeroU32::new(1).unwrap(), None)
            .unwrap();

        // Wait for waiter thread to complete
        let result = waiter_thread.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(woken, 1);
    }

    #[test]
    fn test_futex_multiple_waiters_with_timeout() {
        let platform = MockPlatform::new();
        let litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new(&litebox));

        let futex_word = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(4)); // 3 waiters + 1 waker

        let mut waiters = std::vec::Vec::new();

        // Spawn 3 waiter threads with timeout
        for _ in 0..3 {
            let futex_manager_clone = Arc::clone(&futex_manager);
            let futex_word_clone = Arc::clone(&futex_word);
            let barrier_clone = Arc::clone(&barrier);

            let waiter = thread::spawn(move || {
                let futex_addr = <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                    futex_word_clone.as_ptr() as usize
                );

                barrier_clone.wait(); // Sync with other threads

                // Wait for value 0 with some timeout
                futex_manager_clone.wait(
                    &WaitState::new(platform)
                        .context()
                        .with_timeout(Duration::from_millis(300)),
                    futex_addr,
                    0,
                    None,
                )
            });
            waiters.push(waiter);
        }

        barrier.wait(); // Wait for all waiters to be ready
        thread::sleep(Duration::from_millis(10)); // Give waiters time to block

        // Change the value and wake all
        futex_word.store(1, Ordering::SeqCst);
        let futex_addr =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex_word.as_ptr() as usize,
            );
        let woken = futex_manager
            .wake(futex_addr, NonZeroU32::new(u32::MAX).unwrap(), None)
            .unwrap();

        // Wait for all waiter threads to complete
        for waiter in waiters {
            let result = waiter.join().unwrap();
            match result {
                Ok(()) | Err(FutexError::WaitError(_)) => {}
                Err(FutexError::ImmediatelyWokenBecauseValueMismatch | FutexError::NotAligned) => {
                    unreachable!()
                }
            }
        }

        assert!((1..=3).contains(&woken));
    }
}
