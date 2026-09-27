// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Explicit mutex policy for kernel backends without a scheduler. Uncontended atomic
//! locking is supported; actually parking a thread is not. This is not a futex
//! implementation and must be replaced when scheduler-backed waits are added.

use core::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use litebox::platform::{ImmediatelyWokenUp, RawMutex, UnblockedOrTimedOut};

pub struct NoSchedulerMutex(AtomicU32);

impl RawMutex for NoSchedulerMutex {
    const INIT: Self = Self(AtomicU32::new(0));
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.0
    }
    fn wake_many(&self, _n: usize) -> usize {
        0
    } // No thread can have parked here.
    fn block(&self, value: u32) -> Result<(), ImmediatelyWokenUp> {
        if self.0.load(Ordering::Relaxed) != value {
            return Err(ImmediatelyWokenUp);
        }
        panic!("blocking requires a scheduler");
    }
    fn block_or_timeout(
        &self,
        value: u32,
        _time: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block(value).map(|()| UnblockedOrTimedOut::Unblocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_value_does_not_need_a_scheduler() {
        let mutex = NoSchedulerMutex::INIT;
        assert!(mutex.block(1).is_err());
        assert!(mutex.block_or_timeout(1, Duration::ZERO).is_err());
        assert_eq!(mutex.wake_many(10), 0);
    }
    #[test]
    #[should_panic(expected = "blocking requires a scheduler")]
    fn parking_is_not_silently_emulated() {
        let mutex = NoSchedulerMutex::INIT;
        mutex.block(0).ok();
    }
}
