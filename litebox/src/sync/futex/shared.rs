// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futexes in memory that several processes share.
//!
//! Processes that share memory, such as a Linux `MAP_SHARED | MAP_ANONYMOUS` mapping that native
//! fork children inherit, name it by a [`SharedMemoryId`] that its creator draws from
//! [`SharedMemoryIdAllocator`], and a futex word in it by a [`SharedFutexKey`]. The broker keys futex wait
//! queues by that key, so [`LiteBox::wake_shared_futex`] in any process reaches the threads
//! waiting with [`SharedFutexWaiter::wait`] in every process.
//!
//! Each waiting thread owns a [`SharedFutexWaiter`]. A wait arms it in the broker, re-checks the
//! futex word, and sleeps until the broker publishes a wake for it or the wait times out or is
//! interrupted. A published wake that carries the generation of this arm proves the wake, so the
//! wait returns without another broker call. Otherwise it disarms the waiter, which reports
//! whether a wake selected it, so a wake racing with a timeout or interruption is reported rather
//! than lost.

use alloc::sync::Arc;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{FutexError, check_aligned, mask, word_matches};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_futex::{
    FUTEX_WAITER_GENERATIONS, FUTEX_WORD_SIZE, SharedFutexKey, SharedMemoryId,
    woken_futex_waiter_generation,
};
use litebox_platform::time::TimeProvider;
use thiserror::Error;

use crate::LiteBox;
use crate::broker::error::BrokerObjectError;
use crate::broker::{BrokerControl, BrokerPollableRegistry};
use crate::event::wait::WaitContext;
use crate::event::{
    Events,
    observer::Observer,
    polling::{Pollee, PolleeObserver},
};
use crate::platform::{RawConstPointer as _, RawPointerProvider};
use crate::sync::RawSyncPrimitivesProvider;

/// Errors from the broker behind futexes in shared memory.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedFutexError {
    /// The broker ran out of objects or memory.
    #[error("shared futex resource exhausted")]
    ResourceExhausted,
    /// Broker policy forbids the caller from using futexes in shared memory, or in the memory
    /// named.
    #[error("shared futex permission denied")]
    PermissionDenied,
    /// The broker failed, or its association with this process did.
    #[error("shared futex broker failed")]
    Io,
    /// This process has no broker, so no other process can share its memory.
    #[error("shared futex authority unavailable")]
    Unavailable,
}

/// Allocates the [`SharedMemoryId`]s of memory this process creates.
///
/// The IDs come from a block that the broker reserves on first use, and again after each
/// [`Self::retire_block`]. The broker lets a process name the blocks it reserved, and those its
/// creator had reserved when creating it. So a process must call [`Self::retire_block`] after
/// creating another, so that memory it creates later takes its IDs from a block reserved after
/// the new process was created, which the new process cannot name. A process that duplicates its
/// memory, as native fork does, must give the duplicate a new allocator.
pub struct SharedMemoryIdAllocator {
    state: spin::Mutex<AllocatorState>,
}

struct AllocatorState {
    /// The first ID of the current block, and how many of its IDs were allocated, once reserved.
    block: Option<(SharedMemoryId, u64)>,
    /// How many times the block was retired.
    retirements: u64,
}

impl Default for SharedMemoryIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedMemoryIdAllocator {
    /// Creates an allocator that reserves its block on first use.
    pub const fn new() -> Self {
        Self {
            state: spin::Mutex::new(AllocatorState {
                block: None,
                retirements: 0,
            }),
        }
    }

    /// Returns an ID that no other shared memory uses.
    ///
    /// Fails with [`SharedFutexError::Unavailable`] without a broker, as then no other process
    /// can share the memory either, and with [`SharedFutexError::ResourceExhausted`] once the
    /// block is used up.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn allocate<Platform: RawSyncPrimitivesProvider>(
        &self,
        litebox: &LiteBox<Platform>,
    ) -> Result<SharedMemoryId, SharedFutexError> {
        loop {
            let retirements = {
                let mut state = self.state.lock();
                if let Some(block) = state.block.as_mut() {
                    return Self::next_in_block(block);
                }
                state.retirements
            };
            let broker = litebox
                .broker_control()
                .ok_or(SharedFutexError::Unavailable)?;
            // Reserved without holding the lock, so concurrent first uses may each reserve a
            // block; one is kept.
            let reserved = broker
                .reserve_shared_memory_ids()
                .map_err(BrokerObjectError::from)?;
            let mut state = self.state.lock();
            // A block reserved while the block was retired may be one that a process created
            // meanwhile can name.
            if state.retirements == retirements {
                return Self::next_in_block(state.block.get_or_insert((reserved, 0)));
            }
        }
    }

    /// Makes later IDs come from a block reserved after this call, which the processes created
    /// before it cannot name.
    pub fn retire_block(&self) {
        let mut state = self.state.lock();
        state.block = None;
        state.retirements = state.retirements.wrapping_add(1);
    }

    /// Allocates the next ID of the block whose first ID and number of allocated IDs are
    /// `block`, failing with [`SharedFutexError::ResourceExhausted`] once it is used up.
    fn next_in_block(
        (first, allocated): &mut (SharedMemoryId, u64),
    ) -> Result<SharedMemoryId, SharedFutexError> {
        let next = allocated
            .checked_add(1)
            .ok_or(SharedFutexError::ResourceExhausted)?;
        Ok(first.nth_in_block(core::mem::replace(allocated, next)))
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Wakes up to `count` of the oldest waiters on the futex word `key` whose masks intersect
    /// `bitset`, or all masks if it is `None`, returning how many it woke.
    ///
    /// Fails with [`FutexError::NotAligned`] if the word's offset is not a multiple of
    /// [`FUTEX_WORD_SIZE`], and with [`SharedFutexError::Unavailable`] without a broker.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn wake_shared_futex(
        &self,
        key: SharedFutexKey,
        count: NonZeroU32,
        bitset: Option<NonZeroU32>,
    ) -> Result<u32, FutexError> {
        if !key.offset.is_multiple_of(FUTEX_WORD_SIZE) {
            return Err(FutexError::NotAligned);
        }
        let broker = self.broker_control().ok_or(SharedFutexError::Unavailable)?;
        Ok(broker
            .futex_wake(key, count.get(), mask(bitset))
            .map_err(BrokerObjectError::from)?)
    }
}

/// One thread's waiter for futexes in shared memory.
pub struct SharedFutexWaiter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    /// Kept alive for the pollable registry, which holds it weakly.
    pollee: Arc<Pollee<Platform>>,
    /// The raw readiness of the latest notification for the waiter, which the pollable registry
    /// stores before waking the pollee's observers.
    latest_readiness: Arc<AtomicU32>,
    /// Counts arms, whose generations it gives modulo [`FUTEX_WAITER_GENERATIONS`].
    arms: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> SharedFutexWaiter<Platform> {
    /// Creates a waiter, with which only one thread may wait at a time.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn new(litebox: &LiteBox<Platform>) -> Result<Self, SharedFutexError> {
        let broker = litebox
            .broker_control()
            .ok_or(SharedFutexError::Unavailable)?;
        let handle = broker
            .create_futex_waiter()
            .map_err(BrokerObjectError::from)?;
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        let latest_readiness = Arc::new(AtomicU32::new(0));
        pollable_registry.register_pollable_with_latest_readiness(
            handle,
            &pollee,
            &latest_readiness,
        );
        Ok(Self {
            broker,
            handle,
            pollable_registry,
            pollee,
            latest_readiness,
            arms: AtomicU32::new(0),
        })
    }

    /// Waits on the futex word at `futex_addr`, which `key` names, until a
    /// [`LiteBox::wake_shared_futex`] whose mask intersects `bitset`, or any mask if it is
    /// `None`, selects this waiter, or the wait times out or is interrupted.
    ///
    /// Returns [`FutexError::ImmediatelyWokenBecauseValueMismatch`] if the word does not hold
    /// `expected_value`, checked both before and after the waiter is armed so that no wake in
    /// between is missed. A wake that selects the waiter before it disarms is reported as
    /// success, even if it races with a value change, fault, timeout, or interruption.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn wait(
        &self,
        cx: &WaitContext<'_, Platform>,
        key: SharedFutexKey,
        futex_addr: <Platform as RawPointerProvider>::RawMutPointer<u32>,
        expected_value: u32,
        bitset: Option<NonZeroU32>,
    ) -> Result<(), FutexError>
    where
        Platform: RawPointerProvider,
    {
        // Shared memory is mapped page-aligned, so an aligned address has an aligned offset.
        check_aligned(futex_addr.as_usize())?;
        let bitset = mask(bitset);
        let matches = || word_matches::<Platform>(futex_addr, expected_value);
        if !matches()? {
            return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
        }
        // Records wake notifications, including those that arrive before the thread sleeps.
        let observer = Arc::new(PolleeObserver::new(cx.waker().clone()));
        self.pollee.register_observer(
            Arc::downgrade(&observer) as alloc::sync::Weak<dyn Observer<Events>>,
            Events::all(),
        );
        loop {
            // A notification from an earlier arm may still arrive and wake this one spuriously,
            // which its generation, or else disarming, detects.
            let generation = self.arms.fetch_add(1, Ordering::Relaxed) % FUTEX_WAITER_GENERATIONS;
            self.latest_readiness.store(0, Ordering::Release);
            observer.reset();
            self.broker
                .futex_arm(key, bitset, self.handle, generation)
                .map_err(BrokerObjectError::from)?;
            // A waker changes the word before waking, so either this sees the change or the
            // wake sees this waiter.
            match matches() {
                Ok(true) => {}
                mismatch_or_fault => {
                    if self.disarm_unless_woken(generation)? {
                        return Ok(());
                    }
                    mismatch_or_fault?;
                    return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
                }
            }
            let waited = cx.wait_until(|| observer.is_ready());
            if self.disarm_unless_woken(generation)? {
                return Ok(());
            }
            waited.map_err(FutexError::WaitError)?;
            if !matches()? {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
        }
    }

    /// Disarms the waiter unless readiness that carries `generation` proves that a wake selected
    /// it while it was armed with `generation`, returning whether a wake did.
    ///
    /// Either way the waiter is left disarmed or woken, either of which it may be armed again
    /// from. A proven wake needs no broker call, as the broker then still holds the waiter woken.
    fn disarm_unless_woken(&self, generation: u32) -> Result<bool, FutexError> {
        let readiness = ReadinessFlags(self.latest_readiness.load(Ordering::Acquire));
        if woken_futex_waiter_generation(readiness) == Some(generation) {
            return Ok(true);
        }
        Ok(self
            .broker
            .futex_disarm(self.handle)
            .map_err(BrokerObjectError::from)?)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for SharedFutexWaiter<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}
