// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-userland broker time capabilities.

use core::time::Duration;

use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};
use windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise;

/// Time capabilities for a Windows-userland broker.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsTimeProvider;

impl TimeProvider for WindowsTimeProvider {
    type Instant = WindowsInstant;
    type SystemTime = WindowsSystemTime;

    /// Unbiased interrupt time, which, as `CLOCK_MONOTONIC`, excludes time
    /// the system sleeps.
    fn now(&self) -> Self::Instant {
        let mut ticks = 0_u64;
        // SAFETY: `ticks` outlives the call, which writes only it.
        unsafe { QueryUnbiasedInterruptTimePrecise(&raw mut ticks) };
        // In 100 ns units.
        WindowsInstant(Duration::from_nanos(ticks.saturating_mul(100)))
    }

    fn current_time(&self) -> Self::SystemTime {
        WindowsSystemTime(std::time::SystemTime::now())
    }
}

/// Monotonic clock value for a Windows-userland broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowsInstant(Duration);

impl InstantTrait for WindowsInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    fn saturating_add(&self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration))
    }
}

/// Wall-clock value for a Windows-userland broker.
#[derive(Clone, Copy, Debug)]
pub struct WindowsSystemTime(std::time::SystemTime);

impl SystemTimeTrait for WindowsSystemTime {
    const UNIX_EPOCH: Self = Self(std::time::SystemTime::UNIX_EPOCH);

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.0
            .duration_since(earlier.0)
            .map_err(|error| error.duration())
    }
}
