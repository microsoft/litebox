// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::Error;
use std::marker::PhantomData;
use std::sync::{Condvar, Mutex, MutexGuard};

use litebox_broker_transport::call_lane_pool::{
    CallLanePool as GenericCallLanePool, CallLanePoolCondvar, CallLanePoolError, CallLanePoolMutex,
    CallLanePoolSync, LaneClaim as GenericLaneClaim,
};

use crate::setup::copy_io_error;

pub(crate) type CallLanePool<Lane> = GenericCallLanePool<StdCallLanePoolSync, Lane, Error>;

pub(crate) type LaneClaim<'lanes, Lane> =
    GenericLaneClaim<'lanes, StdCallLanePoolSync, Lane, Error>;

pub(crate) struct StdCallLanePoolSync;

pub(crate) struct StdCallLanePoolMutex<T>(Mutex<T>);

pub(crate) struct StdCallLanePoolCondvar<T>(Condvar, PhantomData<fn(T)>);

impl<T> CallLanePoolMutex<T> for StdCallLanePoolMutex<T> {
    type Guard<'a>
        = MutexGuard<'a, T>
    where
        T: 'a;

    fn lock(&self) -> Self::Guard<'_> {
        self.0.lock().expect("broker call-lanes mutex poisoned")
    }
}

impl<T> CallLanePoolCondvar<T> for StdCallLanePoolCondvar<T> {
    type Mutex = StdCallLanePoolMutex<T>;

    fn wait<'a>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T>
    where
        Self::Mutex: 'a,
        T: 'a,
    {
        self.0
            .wait(guard)
            .expect("broker call-lanes mutex poisoned")
    }

    fn notify_one(&self) {
        self.0.notify_one();
    }

    fn notify_all(&self) {
        self.0.notify_all();
    }
}

impl CallLanePoolSync for StdCallLanePoolSync {
    type Mutex<T> = StdCallLanePoolMutex<T>;
    type Condvar<T> = StdCallLanePoolCondvar<T>;

    fn mutex<T>(value: T) -> Self::Mutex<T> {
        StdCallLanePoolMutex(Mutex::new(value))
    }

    fn condvar<T>() -> Self::Condvar<T> {
        StdCallLanePoolCondvar(Condvar::new(), PhantomData)
    }
}

pub(crate) fn call_lane_pool_error(error: CallLanePoolError<Error>) -> Error {
    match error {
        CallLanePoolError::AssociationFailed(error) => copy_io_error(&error),
        CallLanePoolError::Operation(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::Duration;

    use litebox_broker_transport::call_lane_pool::CallLanePoolError;

    use super::CallLanePool;

    fn no_demand(_: usize) -> Result<(), Error> {
        unreachable!("lane 0 needs no demand")
    }

    #[test]
    fn calls_claim_the_lowest_free_lane_and_demand_each_new_lane_once() {
        let lanes = CallLanePool::new(vec![0, 1, 2]);
        let mut demands = Vec::new();
        let first = lanes.claim(no_demand).unwrap();
        let second = lanes
            .claim(|count| {
                demands.push(count);
                Ok(())
            })
            .unwrap();
        assert_eq!((*first, *second), (0, 1));
        drop(first);
        let reused = lanes.claim(no_demand).unwrap();
        assert_eq!(*reused, 0);
        drop((reused, second));
        let again = lanes.claim(no_demand).unwrap();
        let next = lanes
            .claim(|_| panic!("lane 1 is already demanded"))
            .unwrap();
        assert_eq!((*again, *next), (0, 1));
        assert_eq!(demands, [2]);
    }

    #[test]
    fn a_failed_demand_leaves_the_lane_free_and_undemanded() {
        let lanes = CallLanePool::new(vec![0, 1]);
        let _first = lanes.claim(no_demand).unwrap();
        assert!(matches!(
            lanes.claim(|_| Err(Error::other("demand failed"))),
            Err(CallLanePoolError::Operation(_))
        ));
        let mut demanded = None;
        let second = lanes
            .claim(|count| {
                demanded = Some(count);
                Ok(())
            })
            .unwrap();
        assert_eq!((*second, demanded), (1, Some(2)));
    }

    #[test]
    fn claims_wait_while_every_lane_is_held() {
        let lanes = CallLanePool::new(vec![0]);
        let held = lanes.claim(no_demand).unwrap();
        let (claimed, claim) = mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let lane = lanes.claim(no_demand).map(|lane| *lane);
                claimed.send(lane.is_ok()).unwrap();
            });
            assert!(claim.recv_timeout(Duration::from_millis(50)).is_err());
            drop(held);
            assert!(claim.recv_timeout(Duration::from_secs(10)).unwrap());
        });
    }

    #[test]
    fn a_release_frees_the_lane_only_if_live_and_its_operation_succeeds() {
        let lanes = CallLanePool::new(vec![0, 1]);
        let mut released = lanes.claim(no_demand).unwrap();
        assert_eq!(released.release_if_live(|lane| Ok(*lane)).unwrap(), 0);
        // Dropping a released claim leaves its lane free.
        drop(released);
        let mut held = lanes.claim(no_demand).unwrap();
        assert_eq!(*held, 0);
        assert!(matches!(
            held.release_if_live(|_| Err::<(), _>(Error::other("release failed"))),
            Err(CallLanePoolError::Operation(_))
        ));
        assert_eq!(*lanes.claim(|_| Ok(())).unwrap(), 1);
        assert!(lanes.record_failure(Arc::new(Error::from(ErrorKind::BrokenPipe))));
        assert!(matches!(
            held.release_if_live(|_| -> Result<(), Error> { unreachable!() }),
            Err(CallLanePoolError::AssociationFailed(_))
        ));
        assert_eq!(*held, 0);
    }

    #[test]
    fn a_failure_wakes_waiting_claims_and_rejects_new_ones() {
        let lanes = CallLanePool::new(vec![0]);
        let _held = lanes.claim(no_demand).unwrap();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| lanes.claim(no_demand).map(|lane| *lane));
            std::thread::sleep(Duration::from_millis(10));
            assert!(lanes.record_failure(Arc::new(Error::from(ErrorKind::BrokenPipe))));
            assert!(matches!(
                waiter.join().unwrap(),
                Err(CallLanePoolError::AssociationFailed(_))
            ));
        });
        assert!(!lanes.record_failure(Arc::new(Error::from(ErrorKind::Other))));
        assert_eq!(
            lanes.current_failure().unwrap().kind(),
            ErrorKind::BrokenPipe
        );
        assert!(matches!(
            lanes.run_if_live(|| Ok(())),
            Err(CallLanePoolError::AssociationFailed(_))
        ));
    }
}
