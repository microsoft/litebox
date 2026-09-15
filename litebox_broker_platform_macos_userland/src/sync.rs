// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland broker synchronization primitives.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
};

use litebox_common_macos::{OsClockId, OsSyncFlags, OsSyncResult};

unsafe extern "C" {
    fn os_sync_wait_on_address(
        address: *mut libc::c_void,
        value: u64,
        size: usize,
        flags: OsSyncFlags,
    ) -> OsSyncResult;
    fn os_sync_wait_on_address_with_timeout(
        address: *mut libc::c_void,
        value: u64,
        size: usize,
        flags: OsSyncFlags,
        clock: OsClockId,
        timeout_ns: u64,
    ) -> OsSyncResult;
    fn os_sync_wake_by_address_any(
        address: *mut libc::c_void,
        size: usize,
        flags: OsSyncFlags,
    ) -> OsSyncResult;
    fn os_sync_wake_by_address_all(
        address: *mut libc::c_void,
        size: usize,
        flags: OsSyncFlags,
    ) -> OsSyncResult;
}

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

impl MacosRawMutex {
    fn address(&self) -> *mut libc::c_void {
        self.state.as_ptr().cast()
    }

    fn wait(
        &self,
        expected: u32,
        timeout_ns: Option<u64>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // Also fault in the word before the kernel's potentially non-faulting
        // copyin. The native compare-and-wait closes the race with a later store.
        if self.state.load(Ordering::Relaxed) != expected {
            return Err(ImmediatelyWokenUp);
        }
        // SAFETY: the aligned AtomicU32 stays live for the entire call. Waits
        // and wakes use the same address, size, and process-private flags.
        // Timed calls only receive nonzero, bounded nanosecond durations.
        let result = unsafe {
            match timeout_ns {
                Some(timeout_ns) => os_sync_wait_on_address_with_timeout(
                    self.address(),
                    u64::from(expected),
                    size_of::<u32>(),
                    OsSyncFlags::empty(),
                    OsClockId::MachAbsoluteTime,
                    timeout_ns,
                ),
                None => os_sync_wait_on_address(
                    self.address(),
                    u64::from(expected),
                    size_of::<u32>(),
                    OsSyncFlags::empty(),
                ),
            }
        };
        if result.is_success() {
            // Like the guest platform, a native value-mismatch racing with
            // the precheck is indistinguishable from a wakeup here.
            return Ok(UnblockedOrTimedOut::Unblocked);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            // Documented transient failures are equivalent to spurious wakes.
            Some(libc::EINTR | libc::EFAULT | libc::ENOMEM) => Ok(UnblockedOrTimedOut::Unblocked),
            _ => panic!("failed to block on broker mutex: {error}"),
        }
    }
}

/// Bound native conversions without truncating the caller's timeout. Only an
/// expired chunk advances to the next; a wake or changed value returns at once.
/// Keeping this arithmetic separate also lets tests cover multi-day waits.
fn wait_in_chunks(
    mut timeout: Duration,
    mut wait: impl FnMut(u64) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp>,
) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
    let mut has_waited = false;
    while !timeout.is_zero() {
        // Avoid both u64 nanosecond overflow and enormous native deadlines.
        let chunk = timeout.min(Duration::from_hours(24));
        match wait(u64::try_from(chunk.as_nanos()).unwrap()) {
            Ok(UnblockedOrTimedOut::Unblocked) => return Ok(UnblockedOrTimedOut::Unblocked),
            Ok(UnblockedOrTimedOut::TimedOut) => {
                timeout -= chunk;
                has_waited = true;
            }
            Err(ImmediatelyWokenUp) => {
                // A value change after an expired chunk is no longer immediate.
                return if has_waited {
                    Ok(UnblockedOrTimedOut::Unblocked)
                } else {
                    Err(ImmediatelyWokenUp)
                };
            }
        }
    }
    // A zero timeout must not be passed to libSystem (which rejects it).
    Ok(UnblockedOrTimedOut::TimedOut)
}

impl RawMutexTrait for MacosRawMutex {
    const INIT: Self = Self {
        state: AtomicU32::new(0),
    };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.state
    }

    fn wake_many(&self, count: usize) -> usize {
        assert!(count > 0, "wake count must be nonzero");
        if count >= i32::MAX as usize {
            // SAFETY: the aligned word is live and matches the private wait ABI.
            let result = unsafe {
                os_sync_wake_by_address_all(self.address(), size_of::<u32>(), OsSyncFlags::empty())
            };
            if !result.is_success() {
                let error = std::io::Error::last_os_error();
                assert_eq!(error.raw_os_error(), Some(libc::ENOENT), "{error}");
            }
            // The wake-all API does not report how many waiters were woken.
            return 0;
        }

        let mut woken = 0;
        for _ in 0..count {
            // SAFETY: same address, size and private flags as the matching wait.
            let result = unsafe {
                os_sync_wake_by_address_any(self.address(), size_of::<u32>(), OsSyncFlags::empty())
            };
            if result.is_success() {
                woken += 1;
            } else {
                let error = std::io::Error::last_os_error();
                assert_eq!(error.raw_os_error(), Some(libc::ENOENT), "{error}");
                break;
            }
        }
        woken
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.wait(expected, None)? {
            UnblockedOrTimedOut::Unblocked => Ok(()),
            UnblockedOrTimedOut::TimedOut => unreachable!(),
        }
    }

    fn block_or_timeout(
        &self,
        expected: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // Preserve changed-value precedence even for a zero timeout.
        if self.state.load(Ordering::Relaxed) != expected {
            return Err(ImmediatelyWokenUp);
        }
        wait_in_chunks(timeout, |timeout_ns| self.wait(expected, Some(timeout_ns)))
    }
}

#[cfg(test)]
mod tests;
