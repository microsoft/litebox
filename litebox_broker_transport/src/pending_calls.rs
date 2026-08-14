// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Portable pending-call coordination over caller-supplied synchronization.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};

use litebox_broker_protocol::RequestId;
use litebox_broker_protocol::message::BrokerResponse;

/// Maximum number of active calls waiting for broker responses.
pub const MAX_PENDING_CALLS: usize = 64;

/// A mutex usable by [`PendingCalls`].
pub trait PendingCallsMutex<T> {
    /// Guard granting access to the protected value.
    type Guard<'a>: Deref<Target = T> + DerefMut
    where
        Self: 'a,
        T: 'a;

    /// Locks the mutex.
    fn lock(&self) -> Self::Guard<'_>;
}

/// A condition variable paired with a [`PendingCallsMutex`].
pub trait PendingCallsCondvar<T> {
    /// Mutex type whose guard this condition variable waits on.
    type Mutex: PendingCallsMutex<T>;

    /// Atomically releases the guard and waits for a notification.
    fn wait<'a>(
        &self,
        guard: <Self::Mutex as PendingCallsMutex<T>>::Guard<'a>,
    ) -> <Self::Mutex as PendingCallsMutex<T>>::Guard<'a>
    where
        Self::Mutex: 'a,
        T: 'a;

    /// Wakes one waiter.
    fn notify_one(&self);

    /// Wakes all waiters.
    fn notify_all(&self);
}

/// Supplies synchronization primitives for [`PendingCalls`].
pub trait PendingCallsSync {
    /// Mutex protecting a value of type `T`.
    type Mutex<T>: PendingCallsMutex<T>;

    /// Condition variable paired with [`Self::Mutex`].
    type Condvar<T>: PendingCallsCondvar<T, Mutex = Self::Mutex<T>>;

    /// Creates a mutex protecting `value`.
    fn mutex<T>(value: T) -> Self::Mutex<T>;

    /// Creates a condition variable.
    fn condvar<T>() -> Self::Condvar<T>;
}

/// Failure from pending-call registry coordination.
#[derive(Debug)]
pub enum PendingCallsError<Error> {
    /// The association had already failed.
    AssociationFailed(Arc<Error>),
    /// The guarded operation failed.
    Operation(Error),
    /// A request reused an active request identifier.
    DuplicateRequestId,
    /// A response did not identify an active request.
    UnknownResponseId,
}

/// Concurrent registry of requests awaiting broker responses.
pub struct PendingCalls<Sync: PendingCallsSync, Error> {
    state: Sync::Mutex<PendingCallsState<Sync, Error>>,
    capacity_available: Sync::Condvar<PendingCallsState<Sync, Error>>,
}

struct PendingCallsState<Sync: PendingCallsSync, Error> {
    calls: BTreeMap<RequestId, Arc<PendingCall<Sync, Error>>>,
    failure: Option<Arc<Error>>,
}

/// Completion state for one request awaiting a broker response.
pub struct PendingCall<Sync: PendingCallsSync, Error> {
    result: Sync::Mutex<Option<Result<BrokerResponse, Arc<Error>>>>,
    result_ready: Sync::Condvar<Option<Result<BrokerResponse, Arc<Error>>>>,
}

impl<Sync: PendingCallsSync, Error> PendingCall<Sync, Error> {
    fn new() -> Self {
        Self {
            result: Sync::mutex(None),
            result_ready: Sync::condvar(),
        }
    }

    fn resolve(&self, result: Result<BrokerResponse, Arc<Error>>) {
        let mut stored = self.result.lock();
        assert!(stored.is_none(), "broker pending call already resolved");
        *stored = Some(result);
        self.result_ready.notify_one();
    }

    /// Blocks until the broker responds or the association fails.
    pub fn wait(&self) -> Result<BrokerResponse, Arc<Error>> {
        let mut result = self.result.lock();
        loop {
            if let Some(result) = result.take() {
                return result;
            }
            result = self.result_ready.wait(result);
        }
    }
}

impl<Sync: PendingCallsSync, Error> PendingCalls<Sync, Error> {
    /// Creates an empty live pending-call registry.
    pub fn new() -> Self {
        Self {
            state: Sync::mutex(PendingCallsState {
                calls: BTreeMap::new(),
                failure: None,
            }),
            capacity_available: Sync::condvar(),
        }
    }

    /// Registers a request, blocking while the pending-call limit is full.
    pub fn register(
        &self,
        request_id: RequestId,
    ) -> Result<Arc<PendingCall<Sync, Error>>, PendingCallsError<Error>> {
        let pending_call = Arc::new(PendingCall::new());
        let mut state = self.state.lock();
        while state.calls.len() == MAX_PENDING_CALLS && state.failure.is_none() {
            state = self.capacity_available.wait(state);
        }
        if let Some(error) = state.failure.as_ref() {
            return Err(PendingCallsError::AssociationFailed(Arc::clone(error)));
        }
        match state.calls.entry(request_id) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&pending_call));
            }
            Entry::Occupied(_) => return Err(PendingCallsError::DuplicateRequestId),
        }
        Ok(pending_call)
    }

    /// Completes the pending call identified by `response`.
    pub fn complete(&self, response: BrokerResponse) -> Result<(), PendingCallsError<Error>> {
        let pending_call = {
            let mut state = self.state.lock();
            if let Some(error) = state.failure.as_ref() {
                return Err(PendingCallsError::AssociationFailed(Arc::clone(error)));
            }
            let Some(pending_call) = state.calls.remove(&response.request_id) else {
                return Err(PendingCallsError::UnknownResponseId);
            };
            self.capacity_available.notify_one();
            pending_call
        };
        pending_call.resolve(Ok(response));
        Ok(())
    }

    /// Records the first terminal failure and resolves every pending call.
    ///
    /// Returns whether this call recorded the first failure.
    pub fn record_failure(&self, error: Arc<Error>) -> bool {
        let pending_calls = {
            let mut state = self.state.lock();
            if state.failure.is_some() {
                return false;
            }
            state.failure = Some(Arc::clone(&error));
            let pending_calls = core::mem::take(&mut state.calls);
            self.capacity_available.notify_all();
            pending_calls
        };
        for pending_call in pending_calls.into_values() {
            pending_call.resolve(Err(Arc::clone(&error)));
        }
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
    ) -> Result<T, PendingCallsError<Error>> {
        let state = self.state.lock();
        if let Some(error) = state.failure.as_ref() {
            return Err(PendingCallsError::AssociationFailed(Arc::clone(error)));
        }
        operation().map_err(PendingCallsError::Operation)
    }
}

impl<Sync: PendingCallsSync, Error> Default for PendingCalls<Sync, Error> {
    fn default() -> Self {
        Self::new()
    }
}
