// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland broker time capabilities.

use core::time::Duration;

use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};

/// Time capabilities for a macOS-userland broker.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacosTimeProvider;

impl TimeProvider for MacosTimeProvider {
    type Instant = MacosInstant;
    type SystemTime = MacosSystemTime;

    /// `CLOCK_UPTIME_RAW`, which, as Linux's `CLOCK_MONOTONIC`, excludes time
    /// the system sleeps; macOS's `CLOCK_MONOTONIC` includes it.
    fn now(&self) -> Self::Instant {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `now` outlives the call, which writes only it.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_UPTIME_RAW, &raw mut now) };
        assert_eq!(result, 0, "clock_gettime(CLOCK_UPTIME_RAW) failed");
        // `CLOCK_UPTIME_RAW` is never negative, and its nanoseconds are below
        // one second.
        let seconds = u64::try_from(now.tv_sec).unwrap_or(0);
        let nanoseconds = u32::try_from(now.tv_nsec).unwrap_or(0);
        MacosInstant(Duration::new(seconds, nanoseconds))
    }

    fn current_time(&self) -> Self::SystemTime {
        MacosSystemTime(std::time::SystemTime::now())
    }
}

/// Monotonic clock value for a macOS-userland broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MacosInstant(Duration);

impl InstantTrait for MacosInstant {
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

/// Wall-clock value for a macOS-userland broker.
#[derive(Clone, Copy, Debug)]
pub struct MacosSystemTime(std::time::SystemTime);

impl SystemTimeTrait for MacosSystemTime {
    const UNIX_EPOCH: Self = Self(std::time::SystemTime::UNIX_EPOCH);

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.0
            .duration_since(earlier.0)
            .map_err(|error| error.duration())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_advance_with_time() {
        let earlier = MacosTimeProvider.now();
        std::thread::sleep(Duration::from_millis(10));
        let later = MacosTimeProvider.now();
        let elapsed = later.checked_duration_since(&earlier).unwrap();
        assert!(elapsed >= Duration::from_millis(10), "{elapsed:?}");
        assert_eq!(earlier.checked_duration_since(&later), None);
    }
}
