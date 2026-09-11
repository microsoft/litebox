// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-userland broker synchronization primitives.

use core::ffi::c_void;
use core::sync::atomic::AtomicU32;
use core::time::Duration;

use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
};
use windows_sys::Win32::Foundation::{ERROR_TIMEOUT, GetLastError};
use windows_sys::Win32::System::Threading::{
    INFINITE, WaitOnAddress, WakeByAddressAll, WakeByAddressSingle,
};

/// Blocking synchronization primitives for a Windows-userland broker.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsSyncPrimitivesProvider;

impl RawMutexProvider for WindowsSyncPrimitivesProvider {
    type RawMutex = WindowsRawMutex;
}

/// Raw blocking mutex used by the Windows-userland broker.
pub struct WindowsRawMutex {
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
    ) -> UnblockedOrTimedOut {
        let timeout_ms = timeout.map_or(INFINITE, |timeout| {
            u32::try_from(timeout.as_millis().min(u128::from(INFINITE - 1))).unwrap()
        });
        // SAFETY: Both pointers remain valid for the call and identify equally sized u32 values.
        let unblocked = unsafe {
            WaitOnAddress(
                (&raw const self.state).cast::<c_void>(),
                (&raw const expected).cast::<c_void>(),
                size_of::<u32>(),
                timeout_ms,
            ) != 0
        };
        if unblocked {
            UnblockedOrTimedOut::Unblocked
        } else {
            // SAFETY: GetLastError has no preconditions.
            match unsafe { GetLastError() } {
                ERROR_TIMEOUT => UnblockedOrTimedOut::TimedOut,
                error => panic!("WaitOnAddress failed with error {error}"),
            }
        }
    }
}

impl RawMutexTrait for WindowsRawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.state
    }

    fn wake_many(&self, count: usize) -> usize {
        assert!(count > 0, "wake count must be nonzero");
        let address = core::ptr::from_ref(&self.state).cast::<c_void>();
        // SAFETY: `address` points to the aligned AtomicU32 used by waiters and stays valid here.
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
            UnblockedOrTimedOut::Unblocked => Ok(()),
            UnblockedOrTimedOut::TimedOut => unreachable!(),
        }
    }

    fn block_or_timeout(
        &self,
        expected: u32,
        timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        Ok(self.block_or_maybe_timeout(expected, Some(timeout)))
    }
}
