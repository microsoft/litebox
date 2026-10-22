// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Local-side admission of concurrent calls to call lanes, for hosted peers.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use std::io::Error;
use std::sync::{Condvar, Mutex, MutexGuard};

/// Admission of concurrent calls to a fixed set of call lanes.
///
/// A call holds a lane from writing its request until reading its response,
/// so calls on different lanes never wait for each other. Calls claim the
/// lowest free lane, so an association uses only as many lanes as it has
/// concurrent calls; callers beyond the lane count wait for a lane to free up.
/// Lane 0 is always demanded; before a call first claims any higher lane, the
/// claim raises the demand so the broker starts serving that lane.
pub struct LocalCallLanePool<Lane> {
    state: Mutex<LocalCallLanePoolInner<Lane>>,
    lane_freed: Condvar,
}

struct LocalCallLanePoolInner<Lane> {
    /// Each lane, or `None` while a call holds it.
    lanes: Vec<Option<Lane>>,
    /// Number of lanes demanded so far.
    demanded_lane_count: usize,
    /// Number of claims waiting for a free lane. Freeing a lane notifies only
    /// if one waits, since a notification can cost a system call even with no
    /// waiters.
    waiting_claim_count: usize,
    failure: Option<Error>,
}

impl<Lane> LocalCallLanePoolInner<Lane> {
    /// Fails with a copy of the association's failure, if one was recorded.
    fn check_live(&self) -> Result<(), Error> {
        match &self.failure {
            Some(failure) => Err(copy_error(failure)),
            None => Ok(()),
        }
    }
}

/// A lane held by one call; releasing or dropping the claim frees the lane.
pub struct LaneClaim<'lanes, Lane> {
    lanes: &'lanes LocalCallLanePool<Lane>,
    index: usize,
    /// The lane, or `None` once released.
    lane: Option<Lane>,
}

impl<Lane> Deref for LaneClaim<'_, Lane> {
    type Target = Lane;

    fn deref(&self) -> &Lane {
        self.lane
            .as_ref()
            .expect("claimed lane is present until released")
    }
}

impl<Lane> DerefMut for LaneClaim<'_, Lane> {
    fn deref_mut(&mut self) -> &mut Lane {
        self.lane
            .as_mut()
            .expect("claimed lane is present until released")
    }
}

impl<Lane> Drop for LaneClaim<'_, Lane> {
    fn drop(&mut self) {
        if self.lane.is_some() {
            let lanes = self.lanes;
            self.free(&mut lanes.lock());
        }
    }
}

impl<Lane> LaneClaim<'_, Lane> {
    /// Runs `operation` on the lane and frees the lane, both while excluding
    /// failure recording, so a call completes only while the association is
    /// live.
    ///
    /// If the association has failed or `operation` fails, the claim keeps
    /// the lane until dropped, so the caller can fail the association first.
    pub fn release_if_live<T>(
        &mut self,
        operation: impl FnOnce(&mut Lane) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let lanes = self.lanes;
        let mut state = lanes.lock();
        state.check_live()?;
        let value = operation(self)?;
        self.free(&mut state);
        Ok(value)
    }

    /// Returns the lane to its slot, under the admission lock.
    fn free(&mut self, state: &mut LocalCallLanePoolInner<Lane>) {
        state.lanes[self.index] = self.lane.take();
        if state.waiting_claim_count > 0 {
            self.lanes.lane_freed.notify_one();
        }
    }
}

impl<Lane> LocalCallLanePool<Lane> {
    /// Creates live admission over `lanes`, of which only lane 0 is demanded.
    ///
    /// # Panics
    ///
    /// Panics if `lanes` is empty.
    pub fn new(lanes: Vec<Lane>) -> Self {
        assert!(!lanes.is_empty(), "call lanes need at least one lane");
        Self {
            state: Mutex::new(LocalCallLanePoolInner {
                lanes: lanes.into_iter().map(Some).collect(),
                demanded_lane_count: 1,
                waiting_claim_count: 0,
                failure: None,
            }),
            lane_freed: Condvar::new(),
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
    ) -> Result<LaneClaim<'_, Lane>, Error> {
        let mut state = self.lock();
        let index = loop {
            state.check_live()?;
            if let Some(index) = state.lanes.iter().position(Option::is_some) {
                break index;
            }
            state.waiting_claim_count += 1;
            state = self.wait_for_free_lane(state);
            state.waiting_claim_count -= 1;
        };
        if index >= state.demanded_lane_count {
            demand(index + 1)?;
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
    pub fn record_failure(&self, error: Error) -> bool {
        let mut state = self.lock();
        if state.failure.is_some() {
            return false;
        }
        state.failure = Some(error);
        self.lane_freed.notify_all();
        true
    }

    /// Returns a copy of the association's terminal failure, if one was
    /// recorded.
    pub fn current_failure(&self) -> Option<Error> {
        self.lock().failure.as_ref().map(copy_error)
    }

    /// Runs an operation while excluding failure recording.
    pub fn run_if_live<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let state = self.lock();
        state.check_live()?;
        operation()
    }

    fn lock(&self) -> MutexGuard<'_, LocalCallLanePoolInner<Lane>> {
        self.state.lock().expect("broker call-lanes mutex poisoned")
    }

    fn wait_for_free_lane<'a>(
        &self,
        state: MutexGuard<'a, LocalCallLanePoolInner<Lane>>,
    ) -> MutexGuard<'a, LocalCallLanePoolInner<Lane>> {
        self.lane_freed
            .wait(state)
            .expect("broker call-lanes mutex poisoned")
    }
}

/// Copies `error`, since [`Error`] is not `Clone`.
fn copy_error(error: &Error) -> Error {
    match error.raw_os_error() {
        Some(code) => Error::from_raw_os_error(code),
        None => Error::new(error.kind(), error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use std::io::{Error, ErrorKind};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{LocalCallLanePool, Vec};

    fn no_demand(_: usize) -> Result<(), Error> {
        unreachable!("lane 0 needs no demand")
    }

    #[test]
    fn calls_claim_the_lowest_free_lane_and_demand_each_new_lane_once() {
        let lanes = LocalCallLanePool::new(vec![0, 1, 2]);
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
        let lanes = LocalCallLanePool::new(vec![0, 1]);
        let _first = lanes.claim(no_demand).unwrap();
        assert!(matches!(
            lanes.claim(|_| Err(Error::from(ErrorKind::Other))),
            Err(error) if error.kind() == ErrorKind::Other
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
        let lanes = LocalCallLanePool::new(vec![0]);
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
        let lanes = LocalCallLanePool::new(vec![0, 1]);
        let mut released = lanes.claim(no_demand).unwrap();
        assert_eq!(released.release_if_live(|lane| Ok(*lane)).unwrap(), 0);
        // Dropping a released claim leaves its lane free.
        drop(released);
        let mut held = lanes.claim(no_demand).unwrap();
        assert_eq!(*held, 0);
        assert!(matches!(
            held.release_if_live(|_| Err::<(), _>(Error::from(ErrorKind::Other))),
            Err(error) if error.kind() == ErrorKind::Other
        ));
        assert_eq!(*lanes.claim(|_| Ok(())).unwrap(), 1);
        assert!(lanes.record_failure(Error::from(ErrorKind::BrokenPipe)));
        assert!(matches!(
            held.release_if_live(|_| -> Result<(), Error> { unreachable!() }),
            Err(error) if error.kind() == ErrorKind::BrokenPipe
        ));
        assert_eq!(*held, 0);
    }

    #[test]
    fn a_failure_wakes_waiting_claims_and_rejects_new_ones() {
        let lanes = LocalCallLanePool::new(vec![0]);
        let _held = lanes.claim(no_demand).unwrap();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| lanes.claim(no_demand).map(|lane| *lane));
            std::thread::sleep(Duration::from_millis(10));
            assert!(lanes.record_failure(Error::from(ErrorKind::BrokenPipe)));
            assert!(matches!(
                waiter.join().unwrap(),
                Err(error) if error.kind() == ErrorKind::BrokenPipe
            ));
        });
        assert!(!lanes.record_failure(Error::from(ErrorKind::Other)));
        assert_eq!(
            lanes.current_failure().unwrap().kind(),
            ErrorKind::BrokenPipe
        );
        assert!(matches!(
            lanes.run_if_live(|| Ok(())),
            Err(error) if error.kind() == ErrorKind::BrokenPipe
        ));
    }
}
