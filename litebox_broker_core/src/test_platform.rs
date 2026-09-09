// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Synchronization platform shared by broker-core unit tests.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use litebox_platform::sync::{ImmediatelyWokenUp, RawMutex, RawMutexProvider, UnblockedOrTimedOut};
use std::sync::{Condvar, Mutex};

/// A [`RawMutex`] built on the host's condition variables.
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
        self.wake.notify_all();
        count
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        let waiters = self.waiters.lock().unwrap();
        if self.state.load(Ordering::Acquire) != expected {
            return Err(ImmediatelyWokenUp);
        }
        let _waiters = self
            .wake
            .wait_while(waiters, |()| self.state.load(Ordering::Acquire) == expected)
            .unwrap();
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
        let (_waiters, result) = self
            .wake
            .wait_timeout_while(waiters, timeout, |()| {
                self.state.load(Ordering::Acquire) == expected
            })
            .unwrap();
        Ok(if result.timed_out() {
            UnblockedOrTimedOut::TimedOut
        } else {
            UnblockedOrTimedOut::Unblocked
        })
    }
}

/// The platform broker-core tests instantiate platform-generic types with.
pub(crate) struct TestPlatform;

impl RawMutexProvider for TestPlatform {
    type RawMutex = TestRawMutex;
}
