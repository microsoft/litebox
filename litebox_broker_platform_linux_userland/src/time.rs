// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland broker time capabilities.

use core::time::Duration;

use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};

/// Time capabilities for a Linux-userland broker.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxTimeProvider;

impl TimeProvider for LinuxTimeProvider {
    type Instant = LinuxInstant;
    type SystemTime = LinuxSystemTime;

    fn now(&self) -> Self::Instant {
        LinuxInstant(std::time::Instant::now())
    }

    fn current_time(&self) -> Self::SystemTime {
        LinuxSystemTime(std::time::SystemTime::now())
    }
}

/// Monotonic clock value for a Linux-userland broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinuxInstant(std::time::Instant);

impl InstantTrait for LinuxInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
}

/// Wall-clock value for a Linux-userland broker.
#[derive(Clone, Copy, Debug)]
pub struct LinuxSystemTime(std::time::SystemTime);

impl SystemTimeTrait for LinuxSystemTime {
    const UNIX_EPOCH: Self = Self(std::time::SystemTime::UNIX_EPOCH);

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.0
            .duration_since(earlier.0)
            .map_err(|error| error.duration())
    }
}
