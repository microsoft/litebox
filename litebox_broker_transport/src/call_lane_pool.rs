// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Portable call-lane admission over caller-supplied synchronization.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

/// A mutex usable by [`CallLanePool`].
pub trait CallLanePoolMutex<T> {
    /// Guard granting access to the protected value.
    type Guard<'a>: Deref<Target = T> + DerefMut
    where
        Self: 'a,
        T: 'a;

    /// Locks the mutex.
    fn lock(&self) -> Self::Guard<'_>;
}

/// A condition variable paired with a [`CallLanePoolMutex`].
pub trait CallLanePoolCondvar<T> {
    /// Mutex type whose guard this condition variable waits on.
    type Mutex: CallLanePoolMutex<T>;

    /// Atomically releases the guard and waits for a notification.
    fn wait<'a>(
        &self,
        guard: <Self::Mutex as CallLanePoolMutex<T>>::Guard<'a>,
    ) -> <Self::Mutex as CallLanePoolMutex<T>>::Guard<'a>
    where
        Self::Mutex: 'a,
        T: 'a;

    /// Wakes one waiter.
    fn notify_one(&self);

    /// Wakes all waiters.
    fn notify_all(&self);
}

/// Supplies synchronization primitives for [`CallLanePool`].
pub trait CallLanePoolSync {
    /// Mutex protecting a value of type `T`.
    type Mutex<T>: CallLanePoolMutex<T>;

    /// Condition variable paired with [`Self::Mutex`].
    type Condvar<T>: CallLanePoolCondvar<T, Mutex = Self::Mutex<T>>;

    /// Creates a mutex protecting `value`.
    fn mutex<T>(value: T) -> Self::Mutex<T>;

    /// Creates a condition variable.
    fn condvar<T>() -> Self::Condvar<T>;
}

/// Failure from call-lane coordination.
#[derive(Debug)]
pub enum CallLanePoolError<Error> {
    /// The association had already failed.
    AssociationFailed(Arc<Error>),
    /// The guarded operation failed.
    Operation(Error),
}

/// Admission of concurrent calls to a fixed set of call lanes.
///
/// A call holds a lane from writing its request until reading its response,
/// so calls on different lanes never wait for each other. Calls claim the
/// lowest free lane, so an association uses only as many lanes as it has
/// concurrent calls; callers beyond the lane count wait for a lane to free up.
/// Lane 0 is always demanded; before a call first claims any higher lane, the
/// claim raises the demand so the peer starts serving that lane.
pub struct CallLanePool<Sync: CallLanePoolSync, Lane, Error> {
    state: Sync::Mutex<CallLanePoolInner<Lane, Error>>,
    lane_freed: Sync::Condvar<CallLanePoolInner<Lane, Error>>,
}

struct CallLanePoolInner<Lane, Error> {
    /// Each lane, or `None` while a call holds it.
    lanes: Vec<Option<Lane>>,
    /// Number of lanes demanded so far.
    demanded_lane_count: usize,
    /// Number of claims waiting for a free lane. Freeing a lane notifies only
    /// if one waits, since a notification can cost a system call even with no
    /// waiters.
    waiting_claim_count: usize,
    failure: Option<Arc<Error>>,
}

/// A lane held by one call; releasing or dropping the claim frees the lane.
pub struct LaneClaim<'lanes, Sync: CallLanePoolSync, Lane, Error> {
    lanes: &'lanes CallLanePool<Sync, Lane, Error>,
    index: usize,
    /// The lane, or `None` once released.
    lane: Option<Lane>,
}

impl<Sync: CallLanePoolSync, Lane, Error> Deref for LaneClaim<'_, Sync, Lane, Error> {
    type Target = Lane;

    fn deref(&self) -> &Lane {
        self.lane
            .as_ref()
            .expect("claimed lane is present until released")
    }
}

impl<Sync: CallLanePoolSync, Lane, Error> DerefMut for LaneClaim<'_, Sync, Lane, Error> {
    fn deref_mut(&mut self) -> &mut Lane {
        self.lane
            .as_mut()
            .expect("claimed lane is present until released")
    }
}

impl<Sync: CallLanePoolSync, Lane, Error> Drop for LaneClaim<'_, Sync, Lane, Error> {
    fn drop(&mut self) {
        if self.lane.is_some() {
            let lanes = self.lanes;
            self.free(&mut lanes.state.lock());
        }
    }
}

impl<Sync: CallLanePoolSync, Lane, Error> LaneClaim<'_, Sync, Lane, Error> {
    /// Runs `operation` on the lane and frees the lane, both while excluding
    /// failure recording, so a call completes only while the association is
    /// live.
    ///
    /// If the association has failed or `operation` fails, the claim keeps
    /// the lane until dropped, so the caller can fail the association first.
    pub fn release_if_live<T>(
        &mut self,
        operation: impl FnOnce(&mut Lane) -> Result<T, Error>,
    ) -> Result<T, CallLanePoolError<Error>> {
        let lanes = self.lanes;
        let mut state = lanes.state.lock();
        if let Some(error) = state.failure.as_ref() {
            return Err(CallLanePoolError::AssociationFailed(Arc::clone(error)));
        }
        let value = operation(self).map_err(CallLanePoolError::Operation)?;
        self.free(&mut state);
        Ok(value)
    }

    /// Returns the lane to its slot, under the admission lock.
    fn free(&mut self, state: &mut CallLanePoolInner<Lane, Error>) {
        state.lanes[self.index] = self.lane.take();
        if state.waiting_claim_count > 0 {
            self.lanes.lane_freed.notify_one();
        }
    }
}

impl<Sync: CallLanePoolSync, Lane, Error> CallLanePool<Sync, Lane, Error> {
    /// Creates live admission over `lanes`, of which only lane 0 is demanded.
    ///
    /// # Panics
    ///
    /// Panics if `lanes` is empty.
    pub fn new(lanes: Vec<Lane>) -> Self {
        assert!(!lanes.is_empty(), "call lanes need at least one lane");
        Self {
            state: Sync::mutex(CallLanePoolInner {
                lanes: lanes.into_iter().map(Some).collect(),
                demanded_lane_count: 1,
                waiting_claim_count: 0,
                failure: None,
            }),
            lane_freed: Sync::condvar(),
        }
    }

    /// Claims the lowest free lane, blocking while every lane is held.
    ///
    /// When the claimed lane is the first beyond those demanded so far,
    /// `demand` is called with the new lane count, under the admission lock so
    /// demand only rises. If it fails, the lane stays free and undemanded.
    pub fn claim(
        &self,
        demand: impl FnOnce(usize) -> Result<(), Error>,
    ) -> Result<LaneClaim<'_, Sync, Lane, Error>, CallLanePoolError<Error>> {
        let mut state = self.state.lock();
        let index = loop {
            if let Some(error) = state.failure.as_ref() {
                return Err(CallLanePoolError::AssociationFailed(Arc::clone(error)));
            }
            if let Some(index) = state.lanes.iter().position(Option::is_some) {
                break index;
            }
            state.waiting_claim_count += 1;
            state = self.lane_freed.wait(state);
            state.waiting_claim_count -= 1;
        };
        if index >= state.demanded_lane_count {
            demand(index + 1).map_err(CallLanePoolError::Operation)?;
            state.demanded_lane_count = index + 1;
        }
        Ok(LaneClaim {
            lanes: self,
            index,
            lane: state.lanes[index].take(),
        })
    }

    /// Records the first terminal failure and wakes every waiting claim.
    ///
    /// Returns whether this call recorded the first failure.
    pub fn record_failure(&self, error: Arc<Error>) -> bool {
        let mut state = self.state.lock();
        if state.failure.is_some() {
            return false;
        }
        state.failure = Some(error);
        self.lane_freed.notify_all();
        true
    }

    /// Returns the association's terminal failure, if one was recorded.
    pub fn current_failure(&self) -> Option<Arc<Error>> {
        self.state.lock().failure.as_ref().map(Arc::clone)
    }

    /// Runs an operation while excluding failure recording.
    pub fn run_if_live<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, CallLanePoolError<Error>> {
        let state = self.state.lock();
        if let Some(error) = state.failure.as_ref() {
            return Err(CallLanePoolError::AssociationFailed(Arc::clone(error)));
        }
        operation().map_err(CallLanePoolError::Operation)
    }
}
