// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Synchronization for the trusted macOS broker, independent of guest platform
//! initialization and guest signal handlers.
#![cfg(target_os = "macos")]

use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
};
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicU32, Ordering},
};
use std::time::Duration;

/// Blocking synchronization for a macOS broker's file service.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacosSyncPrimitivesProvider;

impl RawMutexProvider for MacosSyncPrimitivesProvider {
    type RawMutex = MacosRawMutex;
}

/// Address-wait semantics implemented using a host mutex/condition variable.
/// The gate serializes comparison and waiter registration with wakeups.
pub struct MacosRawMutex {
    state: AtomicU32,
    gate: Mutex<()>,
    changed: Condvar,
}

impl RawMutexTrait for MacosRawMutex {
    const INIT: Self = Self {
        state: AtomicU32::new(0),
        gate: Mutex::new(()),
        changed: Condvar::new(),
    };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.state
    }

    fn wake_many(&self, count: usize) -> usize {
        assert!(count > 0);
        let _gate = self.gate.lock().unwrap();
        if count >= i32::MAX as usize {
            self.changed.notify_all();
        } else {
            for _ in 0..count {
                self.changed.notify_one();
            }
        }
        // Like Windows, the host API does not report an exact wake count.
        0
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        let gate = self.gate.lock().unwrap();
        if self.state.load(Ordering::Relaxed) != expected {
            return Err(ImmediatelyWokenUp);
        }
        drop(self.changed.wait(gate).unwrap());
        Ok(())
    }

    fn block_or_timeout(
        &self,
        expected: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let gate = self.gate.lock().unwrap();
        if self.state.load(Ordering::Relaxed) != expected {
            return Err(ImmediatelyWokenUp);
        }
        // Bound conversion to the host condvar's absolute deadline. A bounded
        // wait ending early is a permitted spurious wakeup, not a full timeout.
        let bounded = timeout.min(Duration::from_secs(86400));
        let (_gate, result) = self.changed.wait_timeout(gate, bounded).unwrap();
        Ok(if result.timed_out() && bounded == timeout {
            UnblockedOrTimedOut::TimedOut
        } else {
            UnblockedOrTimedOut::Unblocked
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        mpsc::{self, RecvTimeoutError},
    };
    use std::time::Instant;

    fn block_then_wake(timeout: Option<Duration>) {
        let mutex = Arc::new(MacosRawMutex::INIT);
        let waiter = Arc::clone(&mutex);
        let (started, ready) = mpsc::sync_channel(1);
        let (completed, completion) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            started.send(()).unwrap();
            let result = match timeout {
                Some(timeout) => waiter.block_or_timeout(0, timeout),
                None => waiter.block(0).map(|()| UnblockedOrTimedOut::Unblocked),
            };
            let _ = completed.send(result);
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        let result = loop {
            // Leave the value unchanged so block's immediate-return path cannot
            // pass this test. Repeat in case the first wake precedes registration.
            mutex.wake_many(1);
            match completion.recv_timeout(Duration::from_millis(2)) {
                Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                result => break result,
            }
        };
        // Release a stuck waiter even if wake_many regresses to a no-op. This
        // cleanup is deliberately outside the behavior being asserted.
        {
            let _gate = mutex.gate.lock().unwrap();
            mutex.state.store(1, Ordering::Relaxed);
            mutex.changed.notify_all();
        }
        thread.join().unwrap();
        assert_eq!(
            result.expect("wake did not unblock the waiter").unwrap(),
            UnblockedOrTimedOut::Unblocked
        );
    }

    #[test]
    fn contended_block_is_released_by_wake() {
        block_then_wake(None);
    }

    #[test]
    fn contended_timed_block_is_released_before_timeout() {
        block_then_wake(Some(Duration::from_secs(5)));
    }

    #[test]
    fn nonzero_timeout_expires_while_value_is_unchanged() {
        let mutex = MacosRawMutex::INIT;
        let timeout = Duration::from_millis(20);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let start = Instant::now();
            match mutex.block_or_timeout(0, timeout).unwrap() {
                UnblockedOrTimedOut::TimedOut => {
                    assert!(start.elapsed() >= timeout);
                    break;
                }
                UnblockedOrTimedOut::Unblocked => {
                    assert!(Instant::now() < deadline, "wait never reports timeout");
                }
            }
        }
    }

    #[test]
    fn changed_value_does_not_block_and_zero_timeout_expires() {
        let mutex = MacosRawMutex::INIT;
        assert_eq!(mutex.block(1), Err(ImmediatelyWokenUp));
        assert!(matches!(
            mutex.block_or_timeout(1, Duration::ZERO),
            Err(ImmediatelyWokenUp)
        ));
        assert!(matches!(
            mutex.block_or_timeout(0, Duration::ZERO),
            Ok(UnblockedOrTimedOut::TimedOut)
        ));
    }
}
