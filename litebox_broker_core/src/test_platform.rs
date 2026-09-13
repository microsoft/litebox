// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host synchronization for broker-core unit tests.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use litebox_platform::sync::{ImmediatelyWokenUp, RawMutex, RawMutexProvider, UnblockedOrTimedOut};
use std::sync::{Condvar, Mutex};

pub(crate) struct TestRawMutex {
    state: AtomicU32,
    waiters: Mutex<()>,
    wake: Condvar,
}

impl RawMutex for TestRawMutex {
    const INIT: Self = Self {
        state: AtomicU32::new(0),
        waiters: Mutex::new(()),
        wake: Condvar::new(),
    };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.state
    }

    fn wake_many(&self, count: usize) -> usize {
        let _waiters = self.waiters.lock().unwrap();
        if count == i32::MAX as usize {
            self.wake.notify_all();
        } else {
            for _ in 0..count {
                self.wake.notify_one();
            }
        }
        // The host condition variable does not report how many waiters were woken.
        0
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        let waiters = self.waiters.lock().unwrap();
        if self.state.load(Ordering::Acquire) != expected {
            return Err(ImmediatelyWokenUp);
        }
        let _waiters = self.wake.wait(waiters).unwrap();
        Ok(())
    }

    fn block_or_timeout(
        &self,
        expected: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let waiters = self.waiters.lock().unwrap();
        if self.state.load(Ordering::Acquire) != expected {
            return Err(ImmediatelyWokenUp);
        }
        let (_waiters, result) = self.wake.wait_timeout(waiters, timeout).unwrap();
        Ok(if result.timed_out() {
            UnblockedOrTimedOut::TimedOut
        } else {
            UnblockedOrTimedOut::Unblocked
        })
    }
}

pub(crate) struct TestPlatform;

impl RawMutexProvider for TestPlatform {
    type RawMutex = TestRawMutex;
}
