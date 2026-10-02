// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Clock sources supplied through [`crate::BootConfig`].

pub trait ClockSource: Sync {
    /// Nanoseconds since an arbitrary origin that is fixed for the kernel's
    /// lifetime. Never decreases.
    fn monotonic_nanos(&self) -> u64;
}

/// Requires a single CPU and a constant TSC rate; neither is checked.
pub struct TscClock {
    khz: u64,
}

impl TscClock {
    /// # Panics
    ///
    /// Panics if `khz` is zero.
    pub fn new(khz: u64) -> Self {
        assert!(khz != 0, "TSC frequency must not be zero");
        Self { khz }
    }
}

impl ClockSource for TscClock {
    fn monotonic_nanos(&self) -> u64 {
        // Safety: RDTSC has no side effects.
        let tsc = u128::from(unsafe { core::arch::x86_64::_rdtsc() });
        u64::try_from(tsc * 1_000_000 / u128::from(self.khz)).unwrap_or(u64::MAX)
    }
}
