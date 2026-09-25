// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS time-provider binding. Monotonic time uses the Hyper-V reference clock;
//! wall-clock time remains unsupported, as before this extraction.

use super::HostLvbsInterface;
use crate::mshv::clock::Instant;
use litebox::platform::TimeProvider;

impl TimeProvider for HostLvbsInterface {
    type Instant = Instant;
    type SystemTime = UnsupportedSystemTime;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn current_time(&self) -> Self::SystemTime {
        unimplemented!()
    }
}

/// Placeholder required by `TimeProvider`; LVBS does not supply wall time yet.
pub struct UnsupportedSystemTime();

impl litebox::platform::SystemTime for UnsupportedSystemTime {
    const UNIX_EPOCH: Self = Self();

    fn duration_since(
        &self,
        _earlier: &Self,
    ) -> Result<core::time::Duration, core::time::Duration> {
        unimplemented!()
    }
}
