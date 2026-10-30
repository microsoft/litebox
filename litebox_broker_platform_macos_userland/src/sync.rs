// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland broker synchronization primitives.
//!
//! Waits use `os_sync_wait_on_address` (macOS 14.4+) with process-private
//! flags, the macOS analog of a private Linux futex.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
};

/// Blocking synchronization primitives for a macOS-userland broker.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacosSyncPrimitivesProvider;

impl RawMutexProvider for MacosSyncPrimitivesProvider {
    type RawMutex = MacosRawMutex;
}

/// Raw blocking mutex used by the macOS-userland broker.
pub struct MacosRawMutex {
    state: AtomicU32,
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .expect("os_sync failures set errno")
}

impl MacosRawMutex {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }

    fn address(&self) -> *mut c_void {
        self.state.as_ptr().cast()
    }

    fn block_or_maybe_timeout(
        &self,
        expected: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // `os_sync_wait_on_address` returns success rather than a distinct error
        // when the value already differs, so the mismatch is detected here to
        // match the futex `EAGAIN` contract.
        if self.state.load(Ordering::Relaxed) != expected {
            return Err(ImmediatelyWokenUp);
        }
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Ok(UnblockedOrTimedOut::TimedOut);
        }

        let result = if let Some(timeout) = timeout {
            let timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
            // SAFETY: The address is the aligned `AtomicU32` owned by `self`,
            // which outlives the call, and `size` matches its width.
            unsafe {
                libc::os_sync_wait_on_address_with_timeout(
                    self.address(),
                    u64::from(expected),
                    size_of::<u32>(),
                    libc::OS_SYNC_WAIT_ON_ADDRESS_NONE,
                    libc::OS_CLOCK_MACH_ABSOLUTE_TIME,
                    timeout_ns,
                )
            }
        } else {
            // SAFETY: The address is the aligned `AtomicU32` owned by `self`,
            // which outlives the call, and `size` matches its width.
            unsafe {
                libc::os_sync_wait_on_address(
                    self.address(),
                    u64::from(expected),
                    size_of::<u32>(),
                    libc::OS_SYNC_WAIT_ON_ADDRESS_NONE,
                )
            }
        };
        if result >= 0 {
            return Ok(UnblockedOrTimedOut::Unblocked);
        }
        match last_errno() {
            libc::ETIMEDOUT => Ok(UnblockedOrTimedOut::TimedOut),
            // Documented transient failures are equivalent to spurious wakeups.
            libc::EINTR | libc::EFAULT | libc::ENOMEM => Ok(UnblockedOrTimedOut::Unblocked),
            error => panic!("failed to block on broker mutex: errno {error}"),
        }
    }
}

impl RawMutexTrait for MacosRawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.state
    }

    fn wake_many(&self, count: usize) -> usize {
        assert!(count > 0, "wake count must be nonzero");
        if count >= i32::MAX as usize {
            // SAFETY: The address is the aligned `AtomicU32` used by matching waits.
            let result = unsafe {
                libc::os_sync_wake_by_address_all(
                    self.address(),
                    size_of::<u32>(),
                    libc::OS_SYNC_WAKE_BY_ADDRESS_NONE,
                )
            };
            if result != 0 {
                let error = last_errno();
                assert_eq!(
                    error,
                    libc::ENOENT,
                    "failed to wake broker mutex waiters: errno {error}"
                );
            }
            return 0;
        }

        let mut woken = 0;
        for _ in 0..count {
            // SAFETY: The address is the aligned `AtomicU32` used by matching waits.
            let result = unsafe {
                libc::os_sync_wake_by_address_any(
                    self.address(),
                    size_of::<u32>(),
                    libc::OS_SYNC_WAKE_BY_ADDRESS_NONE,
                )
            };
            if result != 0 {
                // `ENOENT` means no thread is waiting, so later wakes would also find none.
                let error = last_errno();
                assert_eq!(
                    error,
                    libc::ENOENT,
                    "failed to wake broker mutex waiter: errno {error}"
                );
                break;
            }
            woken += 1;
        }
        woken
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(expected, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        expected: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_or_maybe_timeout(expected, Some(timeout))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use core::sync::atomic::{AtomicBool, Ordering};
    use core::time::Duration;

    use litebox_platform::sync::{ImmediatelyWokenUp, Mutex, RawMutex as _, UnblockedOrTimedOut};

    use super::{MacosRawMutex, MacosSyncPrimitivesProvider};

    type MacosMutex<T> = Mutex<MacosSyncPrimitivesProvider, T>;

    #[test]
    fn mutex_serializes_mutation() {
        let value = Arc::new(MacosMutex::new(0));
        let threads = (0..4)
            .map(|_| {
                let value = Arc::clone(&value);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        *value.lock() += 1;
                    }
                })
            })
            .collect::<Vec<_>>();

        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(*value.lock(), 4_000);
    }

    #[test]
    fn raw_mutex_timed_wait_distinguishes_timeout_and_changed_value() {
        let raw = MacosRawMutex::INIT;
        assert_eq!(
            raw.block_or_timeout(0, Duration::ZERO),
            Ok(UnblockedOrTimedOut::TimedOut)
        );
        assert_eq!(
            raw.block_or_timeout(0, Duration::from_millis(10)),
            Ok(UnblockedOrTimedOut::TimedOut)
        );

        raw.underlying_atomic().store(1, Ordering::Release);
        assert_eq!(
            raw.block_or_timeout(0, Duration::ZERO),
            Err(ImmediatelyWokenUp)
        );
    }

    #[test]
    fn raw_mutex_wake_tolerates_no_waiters_and_releases_a_waiter() {
        let raw = Arc::new(MacosRawMutex::INIT);
        assert_eq!(raw.wake_many(1), 0, "no waiter is blocked yet");

        // `block` may return spuriously, so the waiter blocks again until the
        // parent releases it, and the parent bounds both of its loops.
        let released = Arc::new(AtomicBool::new(false));
        let waiter = {
            let raw = Arc::clone(&raw);
            let released = Arc::clone(&released);
            std::thread::spawn(move || {
                while !released.load(Ordering::Acquire) {
                    assert_eq!(raw.block(0), Ok(()));
                }
            })
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while raw.wake_many(2) == 0 {
            assert!(Instant::now() < deadline, "the waiter never blocked");
            std::thread::sleep(Duration::from_millis(1));
        }
        released.store(true, Ordering::Release);
        while !waiter.is_finished() {
            assert!(Instant::now() < deadline, "the waiter was not released");
            raw.wake_many(2);
            std::thread::sleep(Duration::from_millis(1));
        }
        waiter.join().unwrap();
    }
}
