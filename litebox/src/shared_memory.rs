// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared memory whose futexes span processes.
//!
//! A [`SharedMemory`] names memory that this process and others map, such as a Linux
//! `MAP_SHARED | MAP_ANONYMOUS` mapping a native fork child inherits. The broker keys futex wait
//! queues by the memory and a byte offset in it, so a [`SharedMemory::wake`] in any process
//! reaches the threads waiting with [`SharedFutexWaiter::wait`] in every process holding the
//! memory.
//!
//! Each waiting thread owns a [`SharedFutexWaiter`]. A wait arms it in the broker, re-checks the
//! futex word, and sleeps until the broker publishes a wake for it or the wait times out or is
//! interrupted. It then disarms the waiter, which reports whether a wake selected it, so a wake
//! racing with a timeout or interruption is reported rather than lost.

use alloc::sync::Arc;
use core::num::NonZeroU32;

use litebox_broker_protocol::ObjectHandle;
use litebox_platform::time::TimeProvider;
use thiserror::Error;

use crate::LiteBox;
use crate::broker::error::BrokerObjectError;
use crate::broker::{BrokerControl, BrokerPollableRegistry};
use crate::event::wait::{WaitContext, Waker};
use crate::event::{
    Events,
    observer::Observer,
    polling::{Pollee, PolleeObserver},
};
use crate::platform::{RawConstPointer as _, RawPointerProvider};
use crate::process::ProcessError;
use crate::sync::RawSyncPrimitivesProvider;
use crate::sync::futex::FutexError;

/// Errors returned when creating shared memory or futex waiters.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedMemoryError {
    /// The broker ran out of objects or memory.
    #[error("shared memory resource exhausted")]
    ResourceExhausted,
    /// Broker policy forbids the caller from creating the object.
    #[error("shared memory permission denied")]
    PermissionDenied,
    /// The broker failed, or its association with this process did.
    #[error("shared memory broker failed")]
    Io,
    /// This process has no broker, so no other process can share its memory.
    #[error("shared memory backing authority unavailable")]
    Unavailable,
}

/// Shared memory whose futexes span every process holding it.
///
/// Dropping it releases this process's reference; waiters already armed on it keep it alive in
/// the broker until they are disarmed.
pub struct SharedMemory<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    _platform: core::marker::PhantomData<fn() -> Platform>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> SharedMemory<Platform> {
    /// Creates shared memory of `length` bytes, which bounds futex offsets.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn new(litebox: &LiteBox<Platform>, length: u64) -> Result<Self, SharedMemoryError> {
        let broker = litebox
            .broker_control()
            .ok_or(SharedMemoryError::Unavailable)?;
        let handle = broker
            .create_shared_memory(length)
            .map_err(BrokerObjectError::from)?;
        Ok(Self::from_handle(broker, handle))
    }

    fn from_handle(broker: Arc<dyn BrokerControl>, handle: ObjectHandle) -> Self {
        Self {
            broker,
            handle,
            _platform: core::marker::PhantomData,
        }
    }

    /// The broker handle this memory owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Wakes up to `count` of the oldest waiters on the futex word at `offset` whose masks
    /// intersect `bitset`, or all masks if it is `None`, returning how many it woke.
    ///
    /// Fails with [`FutexError::NotAligned`] if `offset` is not a multiple of four.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn wake(
        &self,
        offset: u64,
        count: NonZeroU32,
        bitset: Option<NonZeroU32>,
    ) -> Result<u32, FutexError> {
        if !offset.is_multiple_of(align_of::<u32>() as u64) {
            return Err(FutexError::NotAligned);
        }
        Ok(self
            .broker
            .futex_wake(
                self.handle,
                offset,
                count.get(),
                bitset.map_or(u32::MAX, NonZeroU32::get),
            )
            .map_err(BrokerObjectError::from)?)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Returns the shared memory this process inherited from its parent as `handle` through
    /// [`PendingChild::inherit_shared_memory`](crate::process::PendingChild::inherit_shared_memory).
    ///
    /// The memory owns `handle`, so callers adopt each handle once.
    pub fn adopt_inherited_shared_memory(
        &self,
        handle: ObjectHandle,
    ) -> Result<SharedMemory<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(SharedMemory::from_handle(broker, handle))
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for SharedMemory<Platform> {
    fn drop(&mut self) {
        let _ = self.broker.close_object(self.handle);
    }
}

/// One thread's waiter for futexes in [`SharedMemory`].
pub struct SharedFutexWaiter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    /// Kept alive for the pollable registry, which holds it weakly.
    _pollee: Arc<Pollee<Platform>>,
    /// Records wake notifications, including those that arrive before the thread sleeps.
    latch: Arc<PolleeObserver<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> SharedFutexWaiter<Platform> {
    /// Creates a waiter for the thread that `waker` wakes, which must be the only thread that
    /// waits with it.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn new(
        litebox: &LiteBox<Platform>,
        waker: &Waker<Platform>,
    ) -> Result<Self, SharedMemoryError> {
        let broker = litebox
            .broker_control()
            .ok_or(SharedMemoryError::Unavailable)?;
        let handle = broker
            .create_futex_waiter()
            .map_err(BrokerObjectError::from)?;
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        let latch = Arc::new(PolleeObserver::new(waker.clone()));
        pollee.register_observer(
            Arc::downgrade(&latch) as alloc::sync::Weak<dyn Observer<Events>>,
            Events::all(),
        );
        pollable_registry.register_pollable(handle, &pollee);
        Ok(Self {
            broker,
            handle,
            pollable_registry,
            _pollee: pollee,
            latch,
        })
    }

    /// Waits on the futex word at `futex_addr`, which is at `offset` of `memory`, until a
    /// [`SharedMemory::wake`] whose mask intersects `bitset` selects this waiter, or the wait
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
        memory: &SharedMemory<Platform>,
        offset: u64,
        futex_addr: <Platform as RawPointerProvider>::RawMutPointer<u32>,
        expected_value: u32,
        bitset: Option<NonZeroU32>,
    ) -> Result<(), FutexError>
    where
        Platform: RawPointerProvider,
    {
        if !futex_addr.as_usize().is_multiple_of(align_of::<u32>())
            || !offset.is_multiple_of(align_of::<u32>() as u64)
        {
            return Err(FutexError::NotAligned);
        }
        let bitset = bitset.map_or(u32::MAX, NonZeroU32::get);
        let matches = || -> Result<bool, FutexError> {
            Ok(futex_addr.read_at_offset(0).ok_or(FutexError::Fault)? == expected_value)
        };
        loop {
            if !matches()? {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
            // A notification from an earlier wait may still arrive and wake this one
            // spuriously, which disarming detects.
            self.latch.reset();
            self.broker
                .futex_arm(memory.handle(), offset, bitset, self.handle)
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
            let waited = cx.wait_until(|| self.latch.is_ready());
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
