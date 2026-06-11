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
use core::sync::atomic::Ordering;

#[cfg(not(feature = "loom"))]
use core::sync::atomic::AtomicBool;
#[cfg(feature = "loom")]
use loom::sync::atomic::AtomicBool;

use super::RawSyncPrimitivesProvider;
use crate::event::wait::{WaitContext, WaitError, Waker};
use crate::platform::RawPointerProvider;
use crate::platform::{RawConstPointer as _, TimeProvider};
use crate::utilities::loan_list::{LoanList, LoanListEntry};
use crate::utils::TruncateExt as _;
use thiserror::Error;

/// A manager of all available futexes.
///
/// Note: currently, this only supports "private" futexes, since it assumes only a single process.
/// In the future, this may be expanded to support multi-process futexes.
pub struct FutexManager<Platform: RawSyncPrimitivesProvider> {
    /// Chaining hash table to map from futex address to waiter lists.
    table: alloc::boxed::Box<[LoanList<Platform, FutexEntry<Platform>>; HASH_TABLE_ENTRIES]>,
    hash_builder: hashbrown::DefaultHashBuilder,
}

/// The number of buckets in the hash table.
///
/// FUTURE: consider making this scale with some property of the platform, such
/// as number of CPUs.
#[cfg(not(feature = "loom"))]
const HASH_TABLE_ENTRIES: usize = 256;
#[cfg(feature = "loom")]
const HASH_TABLE_ENTRIES: usize = 4;

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
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            table: alloc::boxed::Box::new(core::array::from_fn(|_| LoanList::new())),
            hash_builder: hashbrown::DefaultHashBuilder::default(),
        }
    }

    /// Returns the hash table bucket for the given futex address.
    fn bucket(&self, addr: usize) -> &LoanList<Platform, FutexEntry<Platform>> {
        let hash: usize = self.hash_builder.hash_one(addr).trunc();
        &self.table[hash % HASH_TABLE_ENTRIES]
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
        if !addr.is_multiple_of(align_of::<u32>()) {
            return Err(FutexError::NotAligned);
        }

        let bucket = self.bucket(addr);
        let mut entry = pin!(LoanListEntry::new(FutexEntry {
            addr,
            waker: cx.waker().clone(),
            bitset,
            done: AtomicBool::new(false),
        },));

        // Insert into the bucket's list. It will be removed when woken or the
        // entry goes out of scope.
        entry.as_mut().insert(bucket);

        // Check the value once. Do this only after inserting into the
        // list so that we don't miss a wakeup.
        let value = futex_addr.read_at_offset(0).ok_or(FutexError::Fault)?;
        if value != expected_value {
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
        if !addr.is_multiple_of(align_of::<u32>()) {
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
            entry.done.store(true, Ordering::SeqCst);
            #[cfg(feature = "loom")]
            loom::sync::atomic::fence(Ordering::SeqCst);
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
    #[error("fault reading futex word")]
    Fault,
}

#[cfg(all(test, not(feature = "loom")))]
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
                Err(FutexError::NotAligned | FutexError::Fault) => {
                    unreachable!()
                }
            }
        }

        assert!((1..=3).contains(&woken));
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use alloc::boxed::Box;
    use core::marker::PhantomData;
    use core::num::NonZeroU32;

    use super::{FutexError, FutexManager};
    use crate::event::wait::WaitState;
    use crate::platform::loom_model::{Arc, LoomPlatform, LoomRawMutex};
    use crate::platform::{RawConstPointer, RawMutPointer, RawMutexProvider, RawPointerProvider};
    use crate::platform::{TimeProvider, trivial_providers};
    use loom::sync::atomic::{AtomicU32, Ordering, fence};
    use zerocopy::{FromBytes, IntoBytes};

    fn model(f: impl Fn() + Send + Sync + 'static) {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(1);
        builder.check(f);
    }

    fn platform() -> &'static FutexTestPlatform {
        Box::leak(Box::new(FutexTestPlatform::new()))
    }

    fn futex_addr(
        word: &Arc<AtomicU32>,
    ) -> <FutexTestPlatform as RawPointerProvider>::RawMutPointer<u32> {
        FutexTestMutPtr::from_atomic_u32(Arc::as_ptr(word))
    }

    struct FutexTestPlatform {
        platform: LoomPlatform,
    }

    impl FutexTestPlatform {
        fn new() -> Self {
            Self {
                platform: LoomPlatform::new(),
            }
        }
    }

    impl RawMutexProvider for FutexTestPlatform {
        type RawMutex = LoomRawMutex;
    }

    impl RawPointerProvider for FutexTestPlatform {
        type RawConstPointer<T: FromBytes> = FutexTestConstPtr<T>;
        type RawMutPointer<T: FromBytes + IntoBytes> = FutexTestMutPtr<T>;
    }

    impl TimeProvider for FutexTestPlatform {
        type Instant = <LoomPlatform as TimeProvider>::Instant;
        type SystemTime = <LoomPlatform as TimeProvider>::SystemTime;

        fn now(&self) -> Self::Instant {
            self.platform.now()
        }

        fn current_time(&self) -> Self::SystemTime {
            self.platform.current_time()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(usize)]
    enum FutexTestPtrKind {
        Regular = 0,
        AtomicU32 = 1,
    }

    #[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
    #[repr(C)]
    struct FutexTestPtrRepr {
        kind: usize,
        addr: usize,
    }

    impl FutexTestPtrRepr {
        fn new(kind: FutexTestPtrKind, addr: usize) -> Self {
            Self {
                kind: kind as usize,
                addr,
            }
        }

        fn kind(&self) -> Option<FutexTestPtrKind> {
            match self.kind {
                kind if kind == FutexTestPtrKind::Regular as usize => {
                    Some(FutexTestPtrKind::Regular)
                }
                kind if kind == FutexTestPtrKind::AtomicU32 as usize => {
                    Some(FutexTestPtrKind::AtomicU32)
                }
                _ => None,
            }
        }
    }

    #[derive(FromBytes, IntoBytes)]
    #[repr(transparent)]
    struct FutexTestConstPtr<T: Sized> {
        inner: FutexTestPtrRepr,
        _phantom_ptr: PhantomData<*const T>,
    }

    impl<T> Clone for FutexTestConstPtr<T> {
        fn clone(&self) -> Self {
            *self
        }
    }

    impl<T> Copy for FutexTestConstPtr<T> {}

    impl<T> core::fmt::Debug for FutexTestConstPtr<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("FutexTestConstPtr")
                .field("kind", &self.inner.kind())
                .field("addr", &self.inner.addr)
                .finish()
        }
    }

    impl<T: FromBytes> RawConstPointer<T> for FutexTestConstPtr<T> {
        fn as_usize(&self) -> usize {
            self.inner.addr
        }

        fn from_usize(addr: usize) -> Self {
            Self {
                inner: FutexTestPtrRepr::new(FutexTestPtrKind::Regular, addr),
                _phantom_ptr: PhantomData,
            }
        }

        fn read_at_offset(self, count: isize) -> Option<T> {
            read_at_offset(self.inner, count)
        }

        fn to_owned_slice(self, len: usize) -> Option<Box<[T]>> {
            let ptr = transparent_const_ptr(self.inner)?;
            ptr.to_owned_slice(len)
        }
    }

    #[derive(FromBytes, IntoBytes)]
    #[repr(transparent)]
    struct FutexTestMutPtr<T: Sized> {
        inner: FutexTestPtrRepr,
        _phantom_ptr: PhantomData<*mut T>,
    }

    impl FutexTestMutPtr<u32> {
        fn from_atomic_u32(word: *const AtomicU32) -> Self {
            Self {
                inner: FutexTestPtrRepr::new(FutexTestPtrKind::AtomicU32, word as usize),
                _phantom_ptr: PhantomData,
            }
        }
    }

    impl<T> Clone for FutexTestMutPtr<T> {
        fn clone(&self) -> Self {
            *self
        }
    }

    impl<T> Copy for FutexTestMutPtr<T> {}

    impl<T> core::fmt::Debug for FutexTestMutPtr<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("FutexTestMutPtr")
                .field("kind", &self.inner.kind())
                .field("addr", &self.inner.addr)
                .finish()
        }
    }

    impl<T: FromBytes> RawConstPointer<T> for FutexTestMutPtr<T> {
        fn as_usize(&self) -> usize {
            self.inner.addr
        }

        fn from_usize(addr: usize) -> Self {
            Self {
                inner: FutexTestPtrRepr::new(FutexTestPtrKind::Regular, addr),
                _phantom_ptr: PhantomData,
            }
        }

        fn read_at_offset(self, count: isize) -> Option<T> {
            read_at_offset(self.inner, count)
        }

        fn to_owned_slice(self, len: usize) -> Option<Box<[T]>> {
            let ptr = transparent_const_ptr(self.inner)?;
            ptr.to_owned_slice(len)
        }
    }

    impl<T: FromBytes + IntoBytes> RawMutPointer<T> for FutexTestMutPtr<T> {
        fn write_at_offset(self, count: isize, value: T) -> Option<()> {
            if self.inner.kind()? == FutexTestPtrKind::AtomicU32 {
                if core::mem::size_of::<T>() != core::mem::size_of::<u32>() || count != 0 {
                    return None;
                }
                let ptr = self.inner.addr as *const AtomicU32;
                if ptr.is_null() || !ptr.is_aligned() {
                    return None;
                }
                let mut bytes = [0; core::mem::size_of::<u32>()];
                let value_ptr = core::ptr::from_ref(&value).cast::<u8>();
                // SAFETY: `value` is a valid initialized `T`, and `bytes` has exactly
                // the same size in this branch.
                unsafe {
                    core::ptr::copy_nonoverlapping(value_ptr, bytes.as_mut_ptr(), bytes.len());
                    (*ptr).store(u32::from_ne_bytes(bytes), Ordering::SeqCst);
                }
                Some(())
            } else {
                let ptr = transparent_mut_ptr(self.inner)?;
                ptr.write_at_offset(count, value)
            }
        }

        fn mutate_subslice_with<R>(
            self,
            range: impl core::ops::RangeBounds<isize>,
            f: impl FnOnce(&mut [T]) -> R,
        ) -> Option<R> {
            let ptr = transparent_mut_ptr(self.inner)?;
            #[allow(deprecated)]
            ptr.mutate_subslice_with(range, f)
        }
    }

    fn read_at_offset<T: FromBytes>(ptr_repr: FutexTestPtrRepr, count: isize) -> Option<T> {
        if ptr_repr.kind()? == FutexTestPtrKind::AtomicU32 {
            assert!(core::mem::size_of::<T>() == core::mem::size_of::<u32>() && count == 0);

            let ptr = ptr_repr.addr as *const AtomicU32;
            if ptr.is_null() || !ptr.is_aligned() {
                return None;
            }
            // SAFETY: futex test pointers are created from `Arc<AtomicU32>`, and the
            // alignment check above rejects invalid addresses for this model.
            let value = unsafe { (*ptr).load(Ordering::SeqCst) };
            let bytes = value.to_ne_bytes();
            T::read_from_bytes(&bytes).ok()
        } else {
            let ptr = transparent_const_ptr(ptr_repr)?;
            ptr.read_at_offset(count)
        }
    }

    fn transparent_const_ptr<T: FromBytes>(
        ptr_repr: FutexTestPtrRepr,
    ) -> Option<trivial_providers::TransparentConstPtr<T>> {
        if ptr_repr.kind()? == FutexTestPtrKind::Regular {
            Some(trivial_providers::TransparentConstPtr::<T>::from_usize(
                ptr_repr.addr,
            ))
        } else {
            None
        }
    }

    fn transparent_mut_ptr<T: FromBytes + IntoBytes>(
        ptr_repr: FutexTestPtrRepr,
    ) -> Option<trivial_providers::TransparentMutPtr<T>> {
        if ptr_repr.kind()? == FutexTestPtrKind::Regular {
            Some(trivial_providers::TransparentMutPtr::<T>::from_usize(
                ptr_repr.addr,
            ))
        } else {
            None
        }
    }

    fn assert_wait_result(result: Result<(), FutexError>) {
        match result {
            Ok(()) | Err(FutexError::ImmediatelyWokenBecauseValueMismatch) => {}
            Err(FutexError::NotAligned | FutexError::Fault | FutexError::WaitError(_)) => {
                panic!("unexpected futex wait result: {result:?}")
            }
        }
    }

    #[test]
    fn wait_returns_immediately_when_value_mismatches() {
        model(|| {
            let futex_manager = FutexManager::<FutexTestPlatform>::new();
            let futex_word = Arc::new(AtomicU32::new(1));
            let wait_state = WaitState::new(platform());

            let result =
                futex_manager.wait(&wait_state.context(), futex_addr(&futex_word), 0, None);

            assert!(matches!(
                result,
                Err(FutexError::ImmediatelyWokenBecauseValueMismatch)
            ));
        });
    }

    #[test]
    fn wake_without_waiters_returns_zero() {
        model(|| {
            let futex_manager = FutexManager::<FutexTestPlatform>::new();
            let futex_word = Arc::new(AtomicU32::new(0));

            let woken = futex_manager
                .wake(futex_addr(&futex_word), NonZeroU32::new(1).unwrap(), None)
                .unwrap();

            assert_eq!(woken, 0);
        });
    }

    #[test]
    fn wait_wake_does_not_miss_registered_waiter() {
        model(|| {
            let futex_manager = Arc::new(FutexManager::<FutexTestPlatform>::new());
            let futex_word = Arc::new(AtomicU32::new(0));

            let waiter = {
                let futex_manager = Arc::clone(&futex_manager);
                let futex_word = Arc::clone(&futex_word);
                loom::thread::spawn(move || {
                    let wait_state = WaitState::new(platform());
                    let result =
                        futex_manager.wait(&wait_state.context(), futex_addr(&futex_word), 0, None);
                    assert!(wait_state.is_running_in_host_for_test());
                    result
                })
            };

            let waker = loom::thread::spawn(move || {
                let addr = futex_addr(&futex_word);
                futex_word.store(1, Ordering::SeqCst);
                fence(Ordering::SeqCst);
                let woken = futex_manager
                    .wake(addr, NonZeroU32::new(1).unwrap(), None)
                    .unwrap();
                assert!(woken <= 1);
            });

            assert_wait_result(waiter.join().unwrap());
            waker.join().unwrap();
        });
    }

    #[test]
    fn wake_all_releases_multiple_waiters() {
        model(|| {
            let futex_manager = Arc::new(FutexManager::<FutexTestPlatform>::new());
            let futex_word = Arc::new(AtomicU32::new(0));

            let waiter = |futex_manager: Arc<FutexManager<FutexTestPlatform>>,
                          futex_word: Arc<AtomicU32>| {
                loom::thread::spawn(move || {
                    let wait_state = WaitState::new(platform());
                    futex_manager.wait(&wait_state.context(), futex_addr(&futex_word), 0, None)
                })
            };

            let waiter_a = waiter(Arc::clone(&futex_manager), Arc::clone(&futex_word));
            let waiter_b = waiter(Arc::clone(&futex_manager), Arc::clone(&futex_word));

            let addr = futex_addr(&futex_word);
            futex_word.store(1, Ordering::SeqCst);
            let woken = futex_manager
                .wake(addr, NonZeroU32::new(u32::MAX).unwrap(), None)
                .unwrap();
            assert!(woken <= 2);

            assert_wait_result(waiter_a.join().unwrap());
            assert_wait_result(waiter_b.join().unwrap());
        });
    }
}
