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
///
/// Callers waiting for responses also read them: while any call is pending,
/// one waiting caller holds the reader role and completes responses for every
/// caller until its own arrives, then hands the role to another pending call.
/// A response therefore reaches a lone caller without a thread handoff.
pub struct PendingCalls<Sync: PendingCallsSync, Error> {
    state: Sync::Mutex<PendingCallsInner<Sync, Error>>,
    capacity_available: Sync::Condvar<PendingCallsInner<Sync, Error>>,
}

struct PendingCallsInner<Sync: PendingCallsSync, Error> {
    calls: BTreeMap<RequestId, Arc<CallSlot<Sync, Error>>>,
    failure: Option<Arc<Error>>,
    /// The call whose caller holds the reader role, if any call is pending.
    reader: Option<Arc<CallSlot<Sync, Error>>>,
}

/// Completion state shared between a pending call and its registry.
struct CallSlot<Sync: PendingCallsSync, Error> {
    state: Sync::Mutex<CallState<Error>>,
    changed: Sync::Condvar<CallState<Error>>,
}

struct CallState<Error> {
    result: Option<Result<BrokerResponse, Arc<Error>>>,
    /// Whether this call's caller holds the reader role.
    reads_responses: bool,
}

impl<Sync: PendingCallsSync, Error> CallSlot<Sync, Error> {
    fn new(reads_responses: bool) -> Self {
        Self {
            state: Sync::mutex(CallState {
                result: None,
                reads_responses,
            }),
            changed: Sync::condvar(),
        }
    }

    fn resolve(&self, result: Result<BrokerResponse, Arc<Error>>, notify: bool) {
        let mut state = self.state.lock();
        assert!(
            state.result.is_none(),
            "broker pending call already resolved"
        );
        state.result = Some(result);
        if notify {
            self.changed.notify_one();
        }
    }

    fn hand_reader_role(&self) {
        self.state.lock().reads_responses = true;
        self.changed.notify_one();
    }
}

/// One registered request awaiting its broker response.
///
/// Dropping the call withdraws it from its registry and hands off the reader
/// role if it holds it, so an abandoned call never strands other callers.
pub struct PendingCall<'calls, Sync: PendingCallsSync, Error> {
    pending_calls: &'calls PendingCalls<Sync, Error>,
    request_id: RequestId,
    slot: Arc<CallSlot<Sync, Error>>,
}

impl<Sync: PendingCallsSync, Error> PendingCall<'_, Sync, Error> {
    /// Blocks until the broker responds or the association fails.
    ///
    /// While this caller holds the reader role, it calls `read_responses`
    /// repeatedly. Each call must block until it reads at least one response
    /// and passes it to [`PendingCalls::complete`], or until the association
    /// fails and the failure is recorded with [`PendingCalls::record_failure`].
    /// Only the caller holding the reader role calls `read_responses`.
    pub fn wait(self, mut read_responses: impl FnMut()) -> Result<BrokerResponse, Arc<Error>> {
        loop {
            {
                let mut state = self.slot.state.lock();
                loop {
                    if let Some(result) = state.result.take() {
                        return result;
                    }
                    if state.reads_responses {
                        break;
                    }
                    state = self.slot.changed.wait(state);
                }
            }
            read_responses();
        }
    }
}

impl<Sync: PendingCallsSync, Error> Drop for PendingCall<'_, Sync, Error> {
    fn drop(&mut self) {
        self.pending_calls.withdraw(self.request_id, &self.slot);
    }
}

impl<Sync: PendingCallsSync, Error> PendingCalls<Sync, Error> {
    /// Creates an empty live pending-call registry.
    pub fn new() -> Self {
        Self {
            state: Sync::mutex(PendingCallsInner {
                calls: BTreeMap::new(),
                failure: None,
                reader: None,
            }),
            capacity_available: Sync::condvar(),
        }
    }

    /// Registers a request, blocking while the pending-call limit is full.
    ///
    /// The first call registered while no call is pending takes the reader
    /// role.
    pub fn register(
        &self,
        request_id: RequestId,
    ) -> Result<PendingCall<'_, Sync, Error>, PendingCallsError<Error>> {
        let mut state = self.state.lock();
        while state.calls.len() >= MAX_PENDING_CALLS && state.failure.is_none() {
            state = self.capacity_available.wait(state);
        }
        let state = &mut *state;
        if let Some(error) = state.failure.as_ref() {
            return Err(PendingCallsError::AssociationFailed(Arc::clone(error)));
        }
        let Entry::Vacant(entry) = state.calls.entry(request_id) else {
            return Err(PendingCallsError::DuplicateRequestId);
        };
        let slot = Arc::new(CallSlot::new(state.reader.is_none()));
        entry.insert(Arc::clone(&slot));
        if state.reader.is_none() {
            state.reader = Some(Arc::clone(&slot));
        }
        Ok(PendingCall {
            pending_calls: self,
            request_id,
            slot,
        })
    }

    /// Completes the pending call identified by `response`.
    pub fn complete(&self, response: BrokerResponse) -> Result<(), PendingCallsError<Error>> {
        let (slot, notify) = {
            let mut state = self.state.lock();
            if let Some(error) = state.failure.as_ref() {
                return Err(PendingCallsError::AssociationFailed(Arc::clone(error)));
            }
            let Some(slot) = state.calls.remove(&response.request_id) else {
                return Err(PendingCallsError::UnknownResponseId);
            };
            // Registrations wait only while the registry is full.
            if state.calls.len() + 1 == MAX_PENDING_CALLS {
                self.capacity_available.notify_all();
            }
            // The reader completes its own call while reading, not waiting.
            let notify = !state
                .reader
                .as_ref()
                .is_some_and(|reader| Arc::ptr_eq(reader, &slot));
            (slot, notify)
        };
        slot.resolve(Ok(response), notify);
        Ok(())
    }

    fn withdraw(&self, request_id: RequestId, slot: &Arc<CallSlot<Sync, Error>>) {
        let mut state = self.state.lock();
        if state
            .calls
            .get(&request_id)
            .is_some_and(|registered| Arc::ptr_eq(registered, slot))
        {
            state.calls.remove(&request_id);
            if state.calls.len() + 1 == MAX_PENDING_CALLS {
                self.capacity_available.notify_all();
            }
        }
        let holds_reader_role = state
            .reader
            .as_ref()
            .is_some_and(|reader| Arc::ptr_eq(reader, slot));
        if holds_reader_role && state.failure.is_none() {
            state.reader = state.calls.values().next().map(|next| {
                next.hand_reader_role();
                Arc::clone(next)
            });
        }
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
            pending_call.resolve(Err(Arc::clone(&error)), true);
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
