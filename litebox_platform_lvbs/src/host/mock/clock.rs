// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host clocks for software-only kernel tests; no Hyper-V MSR access.

extern crate std;

use super::MockHostInterface;
use core::time::Duration;
use litebox::platform::{Instant, SystemTime, TimeProvider};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MockInstant(std::time::Instant);

impl Instant for MockInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
}

pub struct MockSystemTime(std::time::SystemTime);

impl SystemTime for MockSystemTime {
    const UNIX_EPOCH: Self = Self(std::time::UNIX_EPOCH);

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        self.0
            .duration_since(earlier.0)
            .map_err(|error| error.duration())
    }
}

impl TimeProvider for MockHostInterface {
    type Instant = MockInstant;
    type SystemTime = MockSystemTime;

    fn now(&self) -> Self::Instant {
        MockInstant(std::time::Instant::now())
    }

    fn current_time(&self) -> Self::SystemTime {
        MockSystemTime(std::time::SystemTime::now())
    }
}

#[test]
fn kernel_instant_type_follows_the_host_clock() {
    use super::MockKernel;

    // The associated type must be the mock's, not a Hyper-V instant selected
    // by shared kernel code. No privileged kernel construction is needed.
    let now: <MockKernel as TimeProvider>::Instant = MockHostInterface {}.now();
    let later = now.checked_add(Duration::from_nanos(1)).unwrap();
    assert_eq!(
        later.checked_duration_since(&now),
        Some(Duration::from_nanos(1))
    );
    assert_eq!(now.checked_duration_since(&later), None);
}

#[test]
fn kernel_wall_time_type_follows_the_host_clock() {
    use super::MockKernel;

    let epoch = <MockKernel as TimeProvider>::SystemTime::UNIX_EPOCH;
    let later: <MockKernel as TimeProvider>::SystemTime =
        MockSystemTime(std::time::UNIX_EPOCH + Duration::from_secs(1));
    assert_eq!(later.duration_since(&epoch), Ok(Duration::from_secs(1)));
    assert_eq!(epoch.duration_since(&later), Err(Duration::from_secs(1)));
}
