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
