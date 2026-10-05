// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::Error;
use std::marker::PhantomData;
use std::sync::{Condvar, Mutex, MutexGuard};

use litebox_broker_transport::pending_calls::{
    PendingCalls as GenericPendingCalls, PendingCallsCondvar, PendingCallsError, PendingCallsMutex,
    PendingCallsSync,
};

use crate::setup::{copy_io_error, invalid_data};

pub(crate) type PendingCalls = GenericPendingCalls<StdPendingCallsSync, Error>;

pub(crate) struct StdPendingCallsSync;

pub(crate) struct StdPendingCallsMutex<T>(Mutex<T>);

pub(crate) struct StdPendingCallsCondvar<T>(Condvar, PhantomData<fn(T)>);

impl<T> PendingCallsMutex<T> for StdPendingCallsMutex<T> {
    type Guard<'a>
        = MutexGuard<'a, T>
    where
        T: 'a;

    fn lock(&self) -> Self::Guard<'_> {
        self.0.lock().expect("broker pending mutex poisoned")
    }
}

impl<T> PendingCallsCondvar<T> for StdPendingCallsCondvar<T> {
    type Mutex = StdPendingCallsMutex<T>;

    fn wait<'a>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T>
    where
        Self::Mutex: 'a,
        T: 'a,
    {
        self.0.wait(guard).expect("broker pending mutex poisoned")
    }

    fn notify_one(&self) {
        self.0.notify_one();
    }

    fn notify_all(&self) {
        self.0.notify_all();
    }
}

impl PendingCallsSync for StdPendingCallsSync {
    type Mutex<T> = StdPendingCallsMutex<T>;
    type Condvar<T> = StdPendingCallsCondvar<T>;

    fn mutex<T>(value: T) -> Self::Mutex<T> {
        StdPendingCallsMutex(Mutex::new(value))
    }

    fn condvar<T>() -> Self::Condvar<T> {
        StdPendingCallsCondvar(Condvar::new(), PhantomData)
    }
}

pub(crate) fn pending_calls_error(error: PendingCallsError<Error>) -> Error {
    match error {
        PendingCallsError::AssociationFailed(error) => copy_io_error(&error),
        PendingCallsError::Operation(error) => error,
        PendingCallsError::DuplicateRequestId => invalid_data("duplicate broker request ID"),
        PendingCallsError::UnknownResponseId => {
            invalid_data("broker returned an unknown response ID")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use litebox_broker_protocol::RequestId;
    use litebox_broker_protocol::message::{BrokerResponse, BrokerResult};
    use litebox_broker_transport::pending_calls::{MAX_PENDING_CALLS, PendingCallsError};

    use super::PendingCalls;

    fn response(id: u64) -> BrokerResponse {
        BrokerResponse {
            request_id: RequestId(id),
            result: BrokerResult::ObjectClosed,
        }
    }

    #[test]
    fn a_full_registry_wakes_registration_when_a_call_completes() {
        let pending_calls = PendingCalls::new();
        let mut calls: Vec<_> = (0..MAX_PENDING_CALLS as u64)
            .map(|id| pending_calls.register(RequestId(id)).unwrap())
            .collect();
        let (registered, registration) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let call = pending_calls.register(RequestId(MAX_PENDING_CALLS as u64));
                registered.send(call.is_ok()).unwrap();
            });
            assert!(
                registration
                    .recv_timeout(Duration::from_millis(50))
                    .is_err()
            );
            pending_calls.complete(response(0)).unwrap();
            assert!(registration.recv_timeout(Duration::from_secs(10)).unwrap());
        });
        assert!(calls.remove(0).wait(|| unreachable!()).is_ok());
    }

    #[test]
    fn the_first_caller_reads_responses_for_later_callers() {
        let pending_calls = PendingCalls::new();
        let reader = pending_calls.register(RequestId(1)).unwrap();
        let follower = pending_calls.register(RequestId(2)).unwrap();
        std::thread::scope(|scope| {
            let follower = scope.spawn(move || follower.wait(|| panic!("follower read")));
            let mut responses = [2, 1].into_iter();
            let result = reader.wait(|| {
                pending_calls
                    .complete(response(responses.next().unwrap()))
                    .unwrap();
            });
            assert_eq!(result.unwrap().request_id, RequestId(1));
            assert_eq!(follower.join().unwrap().unwrap().request_id, RequestId(2));
        });
    }

    #[test]
    fn a_finished_reader_hands_its_role_to_a_pending_call() {
        let pending_calls = PendingCalls::new();
        let reader = pending_calls.register(RequestId(1)).unwrap();
        let follower = pending_calls.register(RequestId(2)).unwrap();
        let follower_read = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let follower = scope.spawn(|| {
                follower.wait(|| {
                    follower_read.store(true, Ordering::Relaxed);
                    pending_calls.complete(response(2)).unwrap();
                })
            });
            let result = reader.wait(|| pending_calls.complete(response(1)).unwrap());
            assert_eq!(result.unwrap().request_id, RequestId(1));
            assert_eq!(follower.join().unwrap().unwrap().request_id, RequestId(2));
        });
        assert!(follower_read.load(Ordering::Relaxed));
    }

    #[test]
    fn an_abandoned_reader_hands_off_its_role() {
        let pending_calls = PendingCalls::new();
        let reader = pending_calls.register(RequestId(1)).unwrap();
        let follower = pending_calls.register(RequestId(2)).unwrap();
        drop(reader);
        let result = follower.wait(|| pending_calls.complete(response(2)).unwrap());
        assert_eq!(result.unwrap().request_id, RequestId(2));
        assert!(matches!(
            pending_calls.complete(response(1)),
            Err(PendingCallsError::UnknownResponseId)
        ));
    }

    #[test]
    fn a_call_registered_while_none_is_pending_reads_its_own_response() {
        let pending_calls = PendingCalls::new();
        for id in 1..=2 {
            let call = pending_calls.register(RequestId(id)).unwrap();
            let result = call.wait(|| pending_calls.complete(response(id)).unwrap());
            assert_eq!(result.unwrap().request_id, RequestId(id));
        }
    }

    #[test]
    fn a_reader_failure_resolves_every_pending_call() {
        let pending_calls = PendingCalls::new();
        let reader = pending_calls.register(RequestId(1)).unwrap();
        let follower = pending_calls.register(RequestId(2)).unwrap();
        std::thread::scope(|scope| {
            let follower = scope.spawn(move || follower.wait(|| panic!("follower read")));
            let result = reader.wait(|| {
                pending_calls.record_failure(Arc::new(Error::other("failed")));
            });
            assert!(result.is_err());
            assert!(follower.join().unwrap().is_err());
        });
    }
}
