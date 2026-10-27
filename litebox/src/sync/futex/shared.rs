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
//! interrupted. It then disarms the waiter, which reports whether a wake selected it, so a wake
//! racing with a timeout or interruption is reported rather than lost.

use alloc::sync::Arc;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU64, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::shared_futex::{SharedFutexKey, SharedMemoryId};
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
use crate::sync::futex::FutexError;

/// Errors returned when creating futex waiters or naming shared memory.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedFutexError {
    /// The broker ran out of objects or memory.
    #[error("shared futex resource exhausted")]
    ResourceExhausted,
    /// Broker policy forbids the caller from creating the object.
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
/// Each ID is a prefix that the broker reserves once per allocator, followed by a counter. A
/// process that duplicates its memory, as native fork does, must give the duplicate a new
/// allocator, so that the two use different prefixes.
pub struct SharedMemoryIdAllocator {
    /// The reserved prefix, plus one, or zero until it is reserved.
    prefix: AtomicU64,
    next: AtomicU64,
}

impl Default for SharedMemoryIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedMemoryIdAllocator {
    /// Creates an allocator that reserves its prefix on first use.
    pub const fn new() -> Self {
        Self {
            prefix: AtomicU64::new(0),
            next: AtomicU64::new(0),
        }
    }

    /// Returns an ID that no other shared memory uses.
    ///
    /// Fails with [`SharedFutexError::Unavailable`] without a broker, as then no other process
    /// can share the memory either.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn allocate<Platform: RawSyncPrimitivesProvider>(
        &self,
        litebox: &LiteBox<Platform>,
    ) -> Result<SharedMemoryId, SharedFutexError> {
        let mut stored = self.prefix.load(Ordering::Acquire);
        if stored == 0 {
            let broker = litebox
                .broker_control()
                .ok_or(SharedFutexError::Unavailable)?;
            let reserved = broker
                .reserve_shared_memory_ids()
                .map_err(BrokerObjectError::from)?;
            // Concurrent first uses may each reserve a prefix; one is kept.
            let candidate = reserved
                .checked_add(1)
                .ok_or(SharedFutexError::ResourceExhausted)?;
            stored = match self.prefix.compare_exchange(
                0,
                candidate,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => candidate,
                Err(raced) => raced,
            };
        }
        let prefix = stored - 1;
        let serial = self.next.fetch_add(1, Ordering::Relaxed);
        Ok(SharedMemoryId(
            u128::from(prefix) << 64 | u128::from(serial),
        ))
    }
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Wakes up to `count` of the oldest waiters on the futex word `key` whose masks intersect
    /// `bitset`, or all masks if it is `None`, returning how many it woke.
    ///
    /// Fails with [`FutexError::NotAligned`] if the word's offset is not a multiple of four.
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
        if !key.offset.is_multiple_of(align_of::<u32>() as u64) {
            return Err(FutexError::NotAligned);
        }
        let broker = self.broker_control().ok_or(FutexError::Io)?;
        Ok(broker
            .futex_wake(key, count.get(), bitset.map_or(u32::MAX, NonZeroU32::get))
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
        pollable_registry.register_pollable(handle, &pollee);
        Ok(Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        })
    }

    /// Waits on the futex word at `futex_addr`, which `key` names, until a
    /// [`LiteBox::wake_shared_futex`] whose mask intersects `bitset` selects this waiter, or the wait
    /// times out or is interrupted.
    ///
    /// Returns [`FutexError::ImmediatelyWokenBecauseValueMismatch`] if the word does not hold
    /// `expected_value`, checked both before and after the waiter is armed so that no wake in
    /// between is missed. A wake that races with a timeout or interruption is reported as a
    /// successful wake.
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
        if !futex_addr.as_usize().is_multiple_of(align_of::<u32>())
            || !key.offset.is_multiple_of(align_of::<u32>() as u64)
        {
            return Err(FutexError::NotAligned);
        }
        let bitset = bitset.map_or(u32::MAX, NonZeroU32::get);
        let matches = || -> Result<bool, FutexError> {
            Ok(futex_addr.read_at_offset(0).ok_or(FutexError::Fault)? == expected_value)
        };
        // Records wake notifications, including those that arrive before the thread sleeps.
        let observer = Arc::new(PolleeObserver::new(cx.waker().clone()));
        self.pollee.register_observer(
            Arc::downgrade(&observer) as alloc::sync::Weak<dyn Observer<Events>>,
            Events::all(),
        );
        loop {
            if !matches()? {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
            // A notification from an earlier wait may still arrive and wake this one
            // spuriously, which disarming detects.
            observer.reset();
            self.broker
                .futex_arm(key, bitset, self.handle)
                .map_err(BrokerObjectError::from)?;
            // A waker changes the word before waking, so either this sees the change or the
            // wake sees this waiter.
            match matches() {
                Ok(true) => {}
                mismatch_or_fault => {
                    if self.disarm_and_take_woken()? {
                        return Ok(());
                    }
                    mismatch_or_fault?;
                    return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
                }
            }
            let waited = cx.wait_until(|| observer.is_ready());
            if self.disarm_and_take_woken()? {
                return Ok(());
            }
            waited.map_err(FutexError::WaitError)?;
        }
    }

    /// Disarms the waiter, returning whether a wake selected it.
    fn disarm_and_take_woken(&self) -> Result<bool, FutexError> {
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
