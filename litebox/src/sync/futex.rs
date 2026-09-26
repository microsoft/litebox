// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A Linux-y `futex`-like abstraction. Fast user-space mutexes.

// Implementation note: other submodules of `crate::sync` should NOT depend on
// this module directly, because this module itself depends on some of the other
// modules (specifically, this module depends on `LoanList`, which depends on
// `Mutex`). A refactoring could clean this up and prevent this dependency, but
// at the moment, it has been decided that this ordering of dependency is more
// fruitful.

use core::hash::BuildHasher as _;
use core::num::NonZeroU32;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{Mutex, RawSyncPrimitivesProvider};
use crate::event::wait::{WaitContext, WaitError, Waker};
use crate::platform::RawPointerProvider;
use crate::platform::{RawConstPointer as _, TimeProvider};
use crate::utilities::loan_list::{LoanList, LoanListEntry};
use crate::utils::TruncateExt as _;
use thiserror::Error;

/// A futex wait-queue identity within one [`FutexManager`].
///
/// `namespace` distinguishes process-private address spaces while `address` identifies the word
/// within that namespace. Callers use a common namespace for mappings backed by shared storage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FutexKey {
    shared: bool,
    namespace: usize,
    address: usize,
}

impl FutexKey {
    /// Creates a key in a process-private namespace.
    pub const fn new(namespace: usize, address: usize) -> Self {
        Self {
            shared: false,
            namespace,
            address,
        }
    }

    /// Creates a key from shared-backing identity and byte offset.
    pub const fn new_shared(backing: usize, offset: usize) -> Self {
        Self {
            shared: true,
            namespace: backing,
            address: offset,
        }
    }

    fn for_address(address: usize) -> Self {
        Self::new(0, address)
    }
}

/// A manager of one futex namespace family.
///
/// Each operation supplies a [`FutexKey`], allowing one manager to contain both process-private
/// keys and keys derived from shared backing storage. Keeping requeue source and destination in
/// the same manager preserves Linux's atomic cross-key requeue semantics.
pub struct FutexManager<Platform: RawSyncPrimitivesProvider> {
    /// Chaining hash table to map from futex keys to waiter lists.
    table: alloc::boxed::Box<[FutexBucket<Platform>; HASH_TABLE_ENTRIES]>,
    hash_builder: hashbrown::DefaultHashBuilder,
    /// Monotonic process-private namespace allocator. Zero is reserved for shared backing keys.
    next_namespace: AtomicUsize,
}

struct FutexBucket<Platform: RawSyncPrimitivesProvider> {
    /// Serializes wait registration, wake extraction, cancellation, and requeue transactions.
    transaction: Mutex<Platform, ()>,
    waiters: LoanList<Platform, FutexEntry<Platform>>,
}

/// The number of buckets in the hash table.
///
/// FUTURE: consider making this scale with some property of the platform, such
/// as number of CPUs.
const HASH_TABLE_ENTRIES: usize = 256;

struct FutexEntry<Platform: RawSyncPrimitivesProvider> {
    /// Sequence counter protecting the two-word key below. Even values are stable; odd values mean
    /// a requeue is publishing a new key. Readers retry if the sequence changes.
    key_sequence: AtomicUsize,
    key_shared: AtomicBool,
    key_namespace: AtomicUsize,
    key_address: AtomicUsize,
    waker: Waker<Platform>,
    bitset: u32,
    done: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider> FutexEntry<Platform> {
    fn key(&self) -> FutexKey {
        loop {
            let before = self.key_sequence.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let key = FutexKey {
                shared: self.key_shared.load(Ordering::Relaxed),
                namespace: self.key_namespace.load(Ordering::Relaxed),
                address: self.key_address.load(Ordering::Relaxed),
            };
            if self.key_sequence.load(Ordering::Acquire) == before {
                return key;
            }
        }
    }

    fn set_key(&self, key: FutexKey) {
        let previous = self.key_sequence.fetch_add(1, Ordering::AcqRel);
        debug_assert_eq!(previous & 1, 0);
        self.key_shared.store(key.shared, Ordering::Relaxed);
        self.key_namespace.store(key.namespace, Ordering::Relaxed);
        self.key_address.store(key.address, Ordering::Relaxed);
        self.key_sequence.fetch_add(1, Ordering::Release);
    }
}

const ALL_BITS: NonZeroU32 = NonZeroU32::new(u32::MAX).unwrap();

impl<Platform: RawSyncPrimitivesProvider + RawPointerProvider + TimeProvider>
    FutexManager<Platform>
{
    /// A new futex manager.
    // TODO(jayb): Integrate this into the `litebox` object itself, to prevent the possibility of
    // double-creation.
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            table: alloc::boxed::Box::new(core::array::from_fn(|_| FutexBucket {
                transaction: Mutex::new(()),
                waiters: LoanList::new(),
            })),
            hash_builder: hashbrown::DefaultHashBuilder::default(),
            next_namespace: AtomicUsize::new(1),
        }
    }

    /// Allocates a process-private key namespace. IDs are never reused within this manager.
    ///
    /// # Panics
    ///
    /// Panics if this manager has exhausted the `usize` namespace space (never happens in
    /// practice).
    pub fn new_private_namespace(&self) -> usize {
        self.next_namespace
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |namespace| {
                namespace.checked_add(1)
            })
            .expect("futex namespace ID space exhausted")
    }

    /// Returns the hash table index for the given futex key.
    fn bucket_index(&self, key: FutexKey) -> usize {
        let hash: usize = self.hash_builder.hash_one(key).trunc();
        hash % HASH_TABLE_ENTRIES
    }

    /// Returns the hash table bucket for the given futex key.
    fn bucket(&self, key: FutexKey) -> &FutexBucket<Platform> {
        &self.table[self.bucket_index(key)]
    }

    /// Performs a futex wait.
    ///
    /// This function validates that the futex word matches the expected value,
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
        self.wait_keyed(
            cx,
            FutexKey::for_address(futex_addr.as_usize()),
            futex_addr,
            expected_value,
            bitset,
            || {},
        )
    }

    /// Performs a futex wait using `key` as the wait-queue identity and `futex_addr` only for the
    /// atomic value check. `after_register` runs after the waiter is visible but before this method
    /// blocks, allowing a caller to release a mapping lock that made key derivation and insertion
    /// atomic with respect to unmap/remap.
    pub fn wait_keyed(
        &self,
        cx: &WaitContext<'_, Platform>,
        key: FutexKey,
        futex_addr: Platform::RawMutPointer<u32>,
        expected_value: u32,
        bitset: Option<NonZeroU32>,
        after_register: impl FnOnce(),
    ) -> Result<(), FutexError> {
        let bitset = bitset.unwrap_or(ALL_BITS).get();
        if !key.address.is_multiple_of(align_of::<u32>())
            || !futex_addr.as_usize().is_multiple_of(align_of::<u32>())
        {
            return Err(FutexError::NotAligned);
        }

        let bucket = self.bucket(key);
        let mut entry = pin!(LoanListEntry::new(FutexEntry {
            key_sequence: AtomicUsize::new(0),
            key_shared: AtomicBool::new(key.shared),
            key_namespace: AtomicUsize::new(key.namespace),
            key_address: AtomicUsize::new(key.address),
            waker: cx.waker().clone(),
            bitset,
            done: AtomicBool::new(false),
        },));

        // The bucket transaction makes the value check and queue insertion atomic with respect to
        // every wake or requeue targeting this bucket. If the check happens first, a later wake
        // must see the inserted waiter; if the wake happens first, this check must see the value
        // written before that wake.
        {
            let _transaction = bucket.transaction.lock();
            let value = futex_addr.read_at_offset(0).ok_or(FutexError::Fault)?;
            if value != expected_value {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
            entry.as_mut().insert(&bucket.waiters);
        }
        after_register();

        // A timeout or interruption can race a wake that has already extracted and counted this
        // waiter. Resolve that race under the entry's current bucket transaction. Requeue may
        // change both the key and the bucket while this thread is acquiring the lock, so retry
        // until the locked bucket still matches the current key.
        let wait_result = cx.wait_until(|| entry.get().done.load(Ordering::Acquire));
        loop {
            let key = entry.get().key();
            let bucket_index = self.bucket_index(key);
            let bucket = &self.table[bucket_index];
            let transaction = bucket.transaction.lock();
            if entry.get().key() != key {
                drop(transaction);
                continue;
            }

            let completed = entry.get().done.load(Ordering::Acquire);
            entry.as_mut().remove();
            drop(transaction);
            return if completed {
                Ok(())
            } else {
                wait_result.map_err(FutexError::WaitError)
            };
        }
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
        self.wake_keyed(
            FutexKey::for_address(futex_addr.as_usize()),
            num_to_wake_up,
            bitset,
        )
    }

    /// Wakes waiters identified by `key`.
    pub fn wake_keyed(
        &self,
        key: FutexKey,
        num_to_wake_up: NonZeroU32,
        bitset: Option<NonZeroU32>,
    ) -> Result<u32, FutexError> {
        if !key.address.is_multiple_of(align_of::<u32>()) {
            return Err(FutexError::NotAligned);
        }
        let bitset = bitset.unwrap_or(ALL_BITS).get();
        let mut woken = 0;
        let bucket = self.bucket(key);
        let _transaction = bucket.transaction.lock();
        // Extract matching entries from the bucket until we've woken enough. The transaction stays
        // held until every extracted entry has published completion and received a wake attempt, so
        // a racing timeout cannot return an error after this operation counted the waiter.
        let entries = bucket.waiters.extract_if(|entry| {
            if entry.key() != key || entry.bitset & bitset == 0 {
                return core::ops::ControlFlow::Continue(false);
            }
            woken += 1;
            if woken >= num_to_wake_up.get() {
                core::ops::ControlFlow::Break(true)
            } else {
                core::ops::ControlFlow::Continue(true)
            }
        });
        for entry in entries {
            entry.done.store(true, Ordering::Release);
            entry.waker.wake();
        }
        Ok(woken)
    }

    /// Implements `FUTEX_REQUEUE`: wakes up to `num_to_wake` waiters on `addr1`, then moves up
    /// to `num_to_requeue` of the *remaining* waiters on `addr1` onto `addr2`'s wait queue,
    /// without waking them -- they stay asleep until a later [`Self::wake`] (or another
    /// [`Self::requeue`]) targets `addr2`.
    ///
    /// Reuses the exact same `LoanList`-based wait-queue nodes `wait`/`wake` use (via
    /// `LoanedEntry::requeue_into`) rather than a parallel
    /// mechanism, so a requeued waiter is indistinguishable from one that called `wait(addr2,
    /// ...)` in the first place, from `wake`'s point of view.
    ///
    /// Returns the total number of waiters actually woken or requeued, matching Linux's
    /// `futex(2)` return value for `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE`.
    ///
    /// If `expected_value` is `Some`, this implements `FUTEX_CMP_REQUEUE` instead of plain
    /// `FUTEX_REQUEUE`: the futex word at `addr1` must still equal it, or this returns
    /// [`FutexError::ImmediatelyWokenBecauseValueMismatch`] without waking or requeuing anyone
    /// (closing the race where the word changed between userspace's check and this call).
    pub fn requeue(
        &self,
        addr1: Platform::RawMutPointer<u32>,
        addr2: Platform::RawMutPointer<u32>,
        num_to_wake: u32,
        num_to_requeue: u32,
        expected_value: Option<u32>,
    ) -> Result<u32, FutexError> {
        self.requeue_keyed(
            FutexKey::for_address(addr1.as_usize()),
            FutexKey::for_address(addr2.as_usize()),
            addr1,
            num_to_wake,
            num_to_requeue,
            expected_value,
        )
    }

    /// Implements requeue between two explicit wait-queue identities.
    pub fn requeue_keyed(
        &self,
        key1: FutexKey,
        key2: FutexKey,
        addr1: Platform::RawMutPointer<u32>,
        num_to_wake: u32,
        num_to_requeue: u32,
        expected_value: Option<u32>,
    ) -> Result<u32, FutexError> {
        if !key1.address.is_multiple_of(align_of::<u32>())
            || !key2.address.is_multiple_of(align_of::<u32>())
            || !addr1.as_usize().is_multiple_of(align_of::<u32>())
        {
            return Err(FutexError::NotAligned);
        }
        if key1 == key2 {
            return Err(FutexError::SameKey);
        }

        let source_index = self.bucket_index(key1);
        let target_index = self.bucket_index(key2);
        let first_index = core::cmp::min(source_index, target_index);
        let second_index = core::cmp::max(source_index, target_index);

        // Every two-bucket operation takes transaction gates in canonical table order. Hash aliases
        // take one gate, which is both necessary for progress and sufficient to protect the single
        // underlying wait list.
        let _first_transaction = self.table[first_index].transaction.lock();
        let _second_transaction = if first_index == second_index {
            None
        } else {
            Some(self.table[second_index].transaction.lock())
        };

        // Keep CMP_REQUEUE's comparison in the same transaction as source selection and target
        // insertion. A mismatched value therefore cannot leave a partially woken or moved queue.
        if let Some(expected_value) = expected_value {
            let value = addr1.read_at_offset(0).ok_or(FutexError::Fault)?;
            if value != expected_value {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
        }

        if num_to_wake == 0 && num_to_requeue == 0 {
            return Ok(0);
        }

        let source = &self.table[source_index].waiters;
        let target = &self.table[target_index].waiters;
        let total_to_take = num_to_wake.saturating_add(num_to_requeue);
        let mut taken = 0u32;
        let entries = source.extract_if(|entry| {
            if taken >= total_to_take || entry.key() != key1 {
                return core::ops::ControlFlow::Continue(false);
            }
            taken += 1;
            if taken >= total_to_take {
                core::ops::ControlFlow::Break(true)
            } else {
                core::ops::ControlFlow::Continue(true)
            }
        });

        // Complete every extracted entry before releasing either transaction gate. Wake entries
        // publish `done` and receive a wake attempt before their loan is finalized. Requeued
        // entries change address and become visible in the target list while both source and target
        // remain locked against all competing futex operations.
        let mut woken = 0u32;
        let mut requeued = 0u32;
        for entry in entries {
            if woken < num_to_wake {
                entry.done.store(true, Ordering::Release);
                entry.waker.wake();
                woken += 1;
            } else {
                entry.set_key(key2);
                entry.requeue_into(target);
                requeued += 1;
            }
        }
        debug_assert!(requeued <= num_to_requeue);
        Ok(woken + requeued)
    }
}

/// Potential errors that can be returned by [`FutexManager`]'s operations.
#[derive(Debug, Error)]
pub enum FutexError {
    #[error("address not correctly aligned to 4-bytes")]
    NotAligned,
    #[error("source and destination identify the same futex")]
    SameKey,
    #[error("immediately woken: value did not match expected")]
    ImmediatelyWokenBecauseValueMismatch,
    #[error("wait error")]
    WaitError(WaitError),
    #[error("fault reading futex word")]
    Fault,
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
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

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
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

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
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

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
                Ok(())
                | Err(
                    FutexError::WaitError(_) | FutexError::ImmediatelyWokenBecauseValueMismatch,
                ) => {}
                Err(FutexError::NotAligned | FutexError::Fault | FutexError::SameKey) => {
                    unreachable!()
                }
            }
        }

        assert!((1..=3).contains(&woken));
    }

    /// Real threads, real `FutexManager::requeue`: proves waiters that get requeued (rather than
    /// woken) genuinely stay asleep -- not just "eventually return", but specifically do NOT
    /// return before a later `wake` targeting the *new* address, and DO return once that `wake`
    /// happens. A buggy "requeue == wake everyone" implementation would pass a check that only
    /// waits for all threads to finish; this test would catch it via `woken_before_second_wake`.
    #[test]
    fn test_futex_requeue_moves_remaining_waiters_and_wakes_them_later() {
        const N: usize = 5;

        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

        let futex1 = Arc::new(AtomicU32::new(0));
        let futex2 = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(N + 1));
        // Incremented by each waiter immediately after its `wait()` call returns, so the main
        // thread can observe *when* (relative to `requeue`/the second `wake`) each waiter
        // actually unblocked, not just that it eventually did.
        let completed = Arc::new(core::sync::atomic::AtomicUsize::new(0));

        let mut waiters = std::vec::Vec::new();
        for _ in 0..N {
            let futex_manager = Arc::clone(&futex_manager);
            let futex1 = Arc::clone(&futex1);
            let barrier = Arc::clone(&barrier);
            let completed = Arc::clone(&completed);
            waiters.push(thread::spawn(move || {
                let futex_addr =
                    <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                        futex1.as_ptr() as usize,
                    );
                barrier.wait();
                let result = futex_manager.wait(
                    &WaitState::new(platform)
                        .context()
                        .with_timeout(Duration::from_secs(10)),
                    futex_addr,
                    0,
                    None,
                );
                completed.fetch_add(1, Ordering::SeqCst);
                result
            }));
        }

        barrier.wait(); // release all 5 waiters together
        thread::sleep(Duration::from_millis(50)); // give them time to genuinely block

        let addr1 =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex1.as_ptr() as usize,
            );
        let addr2 =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex2.as_ptr() as usize,
            );

        // Wake 2, requeue the remaining 3 onto `futex2`'s wait queue.
        let moved_by_requeue = futex_manager.requeue(addr1, addr2, 2, 3, None).unwrap();
        assert_eq!(
            moved_by_requeue, 5,
            "matches Linux: requeue's return value is the total woken-or-requeued count, not \
             just the wake count"
        );

        // Give the 2 directly-woken waiters ample time to actually return, and any
        // incorrectly-also-woken requeued waiters a real chance to (wrongly) return too.
        thread::sleep(Duration::from_millis(100));
        let woken_before_second_wake = completed.load(Ordering::SeqCst);
        assert_eq!(
            woken_before_second_wake, 2,
            "exactly the 2 directly-woken waiters should have returned by now -- the other 3 \
             must still be genuinely blocked, waiting on futex2, not woken early"
        );

        // Now wake the requeued waiters via their *new* address.
        let woken_on_addr2 = futex_manager
            .wake(addr2, NonZeroU32::new(u32::MAX).unwrap(), None)
            .unwrap();
        assert_eq!(
            woken_on_addr2, 3,
            "all 3 requeued waiters should be discoverable (and wakeable) via addr2"
        );

        for waiter in waiters {
            let result = waiter.join().unwrap();
            assert!(result.is_ok(), "{result:?}");
        }
        assert_eq!(completed.load(Ordering::SeqCst), N);
    }

    /// A single waiter requeued (never woken directly) must actually move to the target futex's
    /// wait queue and later be wakeable there -- exercising `num_to_wake == 0`.
    #[test]
    fn test_futex_requeue_with_zero_wake_moves_the_sole_waiter() {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

        let futex1 = Arc::new(AtomicU32::new(0));
        let futex2 = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let waiter = {
            let futex_manager = Arc::clone(&futex_manager);
            let futex1 = Arc::clone(&futex1);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let futex_addr =
                    <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                        futex1.as_ptr() as usize,
                    );
                barrier.wait();
                futex_manager.wait(
                    &WaitState::new(platform)
                        .context()
                        .with_timeout(Duration::from_secs(10)),
                    futex_addr,
                    0,
                    None,
                )
            })
        };

        barrier.wait();
        thread::sleep(Duration::from_millis(50));

        let addr1 =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex1.as_ptr() as usize,
            );
        let addr2 =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex2.as_ptr() as usize,
            );

        // Matches Linux: `FUTEX_REQUEUE`'s return value is the total number of waiters woken
        // *or* requeued, not just the directly-woken count -- so this is 1 (the sole waiter,
        // requeued) even though `num_to_wake` is 0.
        let moved = futex_manager.requeue(addr1, addr2, 0, 1, None).unwrap();
        assert_eq!(moved, 1);

        // A `wake` still targeting the *old* address must find nobody -- the waiter has
        // genuinely moved, not merely been duplicated/left behind.
        let woken_on_stale_addr = futex_manager
            .wake(addr1, NonZeroU32::new(1).unwrap(), None)
            .unwrap();
        assert_eq!(woken_on_stale_addr, 0);

        assert!(
            !waiter.is_finished(),
            "the sole waiter was requeued, not woken; it must still be blocked"
        );

        let woken_on_addr2 = futex_manager
            .wake(addr2, NonZeroU32::new(1).unwrap(), None)
            .unwrap();
        assert_eq!(woken_on_addr2, 1);

        assert!(waiter.join().unwrap().is_ok());
    }

    /// `FUTEX_CMP_REQUEUE`'s documented race-closing check: if the futex word no longer matches
    /// `expected_value` by the time this call runs (e.g. another thread already unlocked and
    /// re-locked it between userspace's read and this syscall), the call must fail with
    /// [`FutexError::ImmediatelyWokenBecauseValueMismatch`] and touch neither the woken-count nor
    /// any waiter -- never silently fall back to a plain `FUTEX_REQUEUE`.
    #[test]
    fn test_futex_cmp_requeue_rejects_stale_value_and_touches_nothing() {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let futex_manager = Arc::new(FutexManager::new());

        let futex1 = Arc::new(AtomicU32::new(5));
        let futex2 = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let waiter = {
            let futex_manager = Arc::clone(&futex_manager);
            let futex1 = Arc::clone(&futex1);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let futex_addr =
                    <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                        futex1.as_ptr() as usize,
                    );
                barrier.wait();
                futex_manager.wait(
                    &WaitState::new(platform)
                        .context()
                        .with_timeout(Duration::from_secs(10)),
                    futex_addr,
                    5,
                    None,
                )
            })
        };

        barrier.wait();
        thread::sleep(Duration::from_millis(50));

        let addr1 =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex1.as_ptr() as usize,
            );
        let addr2 =
            <MockPlatform as crate::platform::RawPointerProvider>::RawMutPointer::from_usize(
                futex2.as_ptr() as usize,
            );

        let result = futex_manager.requeue(addr1, addr2, 1, 1, Some(999));
        assert!(matches!(
            result,
            Err(FutexError::ImmediatelyWokenBecauseValueMismatch)
        ));

        assert!(
            !waiter.is_finished(),
            "a value-mismatched CMP_REQUEUE must not wake the waiter"
        );

        let woken = futex_manager
            .wake(addr1, NonZeroU32::new(1).unwrap(), None)
            .unwrap();
        assert_eq!(
            woken, 1,
            "the waiter must still be on addr1's own wait queue -- a mismatched CMP_REQUEUE \
             must not have requeued it onto addr2 either"
        );

        assert!(waiter.join().unwrap().is_ok());
    }
}
