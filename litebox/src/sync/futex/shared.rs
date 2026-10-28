// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Futexes in memory that several processes share.

use alloc::sync::Arc;
use core::num::NonZeroU32;

use super::{FutexError, check_aligned, mask, word_matches};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::shared_futex::{FUTEX_WORD_SIZE, SharedFutexKey, SharedMemoryId};
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

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Returns a new ID for memory this process creates, which the broker signs, so that only
    /// processes given the ID, such as native fork children, can reach its futexes.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error.
    pub fn issue_shared_memory_id(&self) -> Result<SharedMemoryId, SharedFutexError> {
        let broker = self.broker_control().ok_or(SharedFutexError::Unavailable)?;
        Ok(broker
            .issue_shared_memory_id()
            .map_err(BrokerObjectError::from)?)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Wakes up to `count` of the oldest waiters on the futex word `key` whose masks intersect
    /// `bitset`, or all masks if it is `None`, returning how many it woke.
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
    /// [`LiteBox::wake_shared_futex`] whose mask intersects `bitset`, or any mask if it is
    /// `None`, selects this waiter, or the wait times out or is interrupted.
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
            // which disarming detects.
            observer.reset();
            self.broker
                .futex_arm(key, bitset, self.handle)
                .map_err(BrokerObjectError::from)?;
            // A waker changes the word before waking, so either this sees the change or the
            // wake sees this waiter.
            match matches() {
                Ok(true) => {}
                mismatch_or_fault => {
                    if self.disarm()? {
                        return Ok(());
                    }
                    mismatch_or_fault?;
                    return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
                }
            }
            let waited = cx.wait_until(|| observer.is_ready());
            // TODO(perf): A woken wait costs two broker calls, arm and disarm. The broker could
            // publish a per-arm generation in the waiter's readiness, which the pollable registry
            // would record for the waiter, so that readiness carrying this arm's generation
            // proves the wake without disarming, and the broker accepts arming a woken waiter.
            if self.disarm()? {
                return Ok(());
            }
            waited.map_err(FutexError::WaitError)?;
            if !matches()? {
                return Err(FutexError::ImmediatelyWokenBecauseValueMismatch);
            }
        }
    }

    /// Disarms the waiter, leaving it idle, and returns whether a wake selected it since it was
    /// armed.
    fn disarm(&self) -> Result<bool, FutexError> {
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
