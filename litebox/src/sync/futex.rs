//! A Linux-y `futex`-like abstraction. Fast user-space mutexes.

// Implementation note: other submodules of `crate::sync` should NOT depend on this module directly,
// because this module itself depends on some of the other modules (specifically, this module
// depends on on `RwLock`). A refactoring could clean this up and prevent this dependency, but at
// the moment, it has been decided that this ordering of dependency is more fruitful.

use super::RawSyncPrimitivesProvider;
use crate::platform::{RawConstPointer as _, TimeProvider};
use crate::sync::Mutex;
use crate::sync::waiter::Waiter;
use crate::utils::TruncateExt as _;
use crate::{LiteBox, platform::RawPointerProvider};
use alloc::vec::Vec;
use core::hash::BuildHasher;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use core::{num::NonZeroU32, sync::atomic::AtomicU32, time::Duration};
use thiserror::Error;

/// A manager of all available futexes.
///
/// Note: currently, this only supports "private" futexes, since it assumes only a single process.
/// In the future, this may be expanded to support multi-process futexes.
pub struct FutexManager<Platform: RawSyncPrimitivesProvider + RawPointerProvider + TimeProvider> {
    table: HashTable<Platform>,
}

const HASH_TABLE_ENTRIES: usize = 256;

struct HashTable<Platform: RawSyncPrimitivesProvider> {
    hash: hashbrown::DefaultHashBuilder,
    buckets: [Mutex<Platform, Bucket<Platform>>; HASH_TABLE_ENTRIES],
}

struct Bucket<Platform: RawSyncPrimitivesProvider> {
    // FUTURE: consider a linked list in `Entry` to avoid allocations.
    entries: Vec<*const Entry<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider> Bucket<Platform> {
    /// Wake up to `max` entries that satisfy the predicate `f`.
    fn wake(&mut self, max: u32, mut f: impl FnMut(&Entry<Platform>) -> bool) -> u32 {
        let mut woken = 0;
        let mut i = 0;
        while i < self.entries.len() && woken < max {
            let entry = unsafe { &*self.entries[i] };
            if f(entry) {
                entry.woken.store(true, Ordering::Relaxed);
                entry.waker.wake();
                woken += 1;
                self.entries.swap_remove(i);
            } else {
                i += 1;
            }
        }
        woken
    }
}

struct Entry<Platform: RawSyncPrimitivesProvider> {
    waker: super::waiter::Waker<Platform>,
    addr: usize,
    bitset: NonZeroU32,
    woken: AtomicBool,
}

struct Defer<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for Defer<F> {
    fn drop(&mut self) {
        (self.0.take().unwrap())();
    }
}

fn defer<F: FnOnce()>(f: F) -> Defer<F> {
    Defer(Some(f))
}

impl<Platform: RawSyncPrimitivesProvider> HashTable<Platform> {
    fn bucket(&self, addr: usize) -> &Mutex<Platform, Bucket<Platform>> {
        use core::hash::Hasher as _;
        let mut hash = self.hash.build_hasher();
        hash.write_usize(addr);
        let hash: usize = hash.finish().truncate();
        &self.buckets[hash % HASH_TABLE_ENTRIES]
    }

    fn with_entry<R>(&self, entry: &Entry<Platform>, f: impl FnOnce() -> R) -> R {
        let bucket = self.bucket(entry.addr);
        {
            let mut bucket = bucket.lock();
            bucket.entries.push(entry);
        }
        // Use a guard to automatically remove the entry from the bucket when it goes out of scope.
        // This ensures that even if `f` panics, we still clean up properly.
        let _defer = defer(|| {
            let mut bucket = bucket.lock();
            if entry.woken.load(Ordering::Relaxed) {
                // Already removed during wake.
                return;
            }
            if let Some(pos) = bucket.entries.iter().position(|&e| core::ptr::eq(e, entry)) {
                bucket.entries.swap_remove(pos);
            }
        });
        f()
    }
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
            table: HashTable {
                hash: hashbrown::DefaultHashBuilder::default(),
                buckets: core::array::from_fn(|_| {
                    litebox.sync().new_mutex(Bucket {
                        entries: Vec::new(),
                    })
                }),
            },
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
        waiter: Waiter<Platform>,
        futex_addr: Platform::RawMutPointer<u32>,
        expected_value: u32,
        timeout: Option<Duration>,
        bitset: Option<NonZeroU32>,
    ) -> Result<(), FutexError> {
        let bitset = bitset.unwrap_or(ALL_BITS);
        let addr = futex_addr.as_usize();
        let futex_addr = Self::futex_addr_as_atomic(futex_addr)?;

        let entry = Entry {
            waker: waiter.waker(),
            addr,
            bitset,
            woken: AtomicBool::new(false),
        };

        self.table.with_entry(&entry, || {
            if futex_addr.load(Ordering::SeqCst) != expected_value {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
            match waiter.wait_or_timeout(timeout, || {
                entry.woken.load(Ordering::Acquire).then_some(())
            }) {
                Ok(()) => Ok(()),
                Err(super::waiter::WaitError::TimedOut) => Err(FutexError::TimedOut),
                Err(super::waiter::WaitError::Interrupted) => {
                    todo!("Handle interrupted wait");
                }
            }
        })
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
        let bitset = bitset.unwrap_or(ALL_BITS);
        let bucket = self.table.bucket(addr);
        let woken = bucket.lock().wake(num_to_wake_up.get(), |entry| {
            entry.addr == addr && (entry.bitset.get() & bitset.get()) != 0
        });
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
    #[error("timeout expired before operation completed")]
    TimedOut,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::LiteBox;
    use crate::platform::mock::MockPlatform;
    use crate::sync::waiter::SimpleWaiter;
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
            futex_manager_clone.wait(&SimpleWaiter::new(platform), futex_addr, 0, None, None)
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
                &SimpleWaiter::new(platform),
                futex_addr,
                0,
                Some(Duration::from_millis(300)),
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
                    &SimpleWaiter::new(platform),
                    futex_addr,
                    0,
                    Some(Duration::from_millis(300)),
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
                Ok(()) | Err(FutexError::TimedOut) => {}
                Err(FutexError::ImmediatelyWokenBecauseValueMismatch | FutexError::NotAligned) => {
                    unreachable!()
                }
            }
        }

        assert!((1..=3).contains(&woken));
    }
}
