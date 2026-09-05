// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(windows, target_arch = "x86_64"))]

use core::ffi::c_void;
use core::sync::atomic::AtomicU32;
use core::time::Duration;

use litebox_platform::sync::{ImmediatelyWokenUp, RawMutex, RawMutexProvider, UnblockedOrTimedOut};
use windows_sys::Win32::Foundation::{ERROR_TIMEOUT, GetLastError};
use windows_sys::Win32::System::Threading::{
    INFINITE, WaitOnAddress, WakeByAddressAll, WakeByAddressSingle,
};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct WindowsSyncPrimitivesProvider;

impl RawMutexProvider for WindowsSyncPrimitivesProvider {
    type RawMutex = WindowsRawMutex;
}

pub(super) struct WindowsRawMutex {
    state: AtomicU32,
}

impl WindowsRawMutex {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }

    fn block_or_maybe_timeout(
        &self,
        expected: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        let timeout_ms = timeout.map_or(INFINITE, |timeout| {
            u32::try_from(timeout.as_millis().min(u128::from(INFINITE - 1))).unwrap()
        });
        // SAFETY: Both pointers remain valid for the duration of the call and
        // identify equally sized u32 values as required by WaitOnAddress.
        let unblocked = unsafe {
            WaitOnAddress(
                (&raw const self.state).cast::<c_void>(),
                (&raw const expected).cast::<c_void>(),
                size_of::<u32>(),
                timeout_ms,
            ) != 0
        };
        if unblocked {
            Ok(UnblockedOrTimedOut::Unblocked)
        } else {
            // SAFETY: GetLastError has no preconditions.
            match unsafe { GetLastError() } {
                ERROR_TIMEOUT => Ok(UnblockedOrTimedOut::TimedOut),
                error => panic!("WaitOnAddress failed with error {error}"),
            }
        }
    }
}

impl RawMutex for WindowsRawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.state
    }

    fn wake_many(&self, count: usize) -> usize {
        assert!(count > 0, "wake count must be nonzero");
        let address = core::ptr::from_ref(&self.state).cast::<c_void>();
        // SAFETY: `address` points to the aligned AtomicU32 used by waiters and
        // remains valid for the duration of each wake call.
        unsafe {
            if count == 1 {
                WakeByAddressSingle(address);
            } else if count >= i32::MAX as usize {
                WakeByAddressAll(address);
            } else {
                for _ in 0..count {
                    WakeByAddressSingle(address);
                }
            }
        }
        0
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_or_maybe_timeout(expected, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => unreachable!(),
            Err(error) => Err(error),
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
