// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform time capability contracts.

use core::time::Duration;

/// An interface to platform clocks.
pub trait TimeProvider {
    /// Monotonic instant type.
    type Instant: Instant;
    /// Wall-clock time type.
    type SystemTime: SystemTime;

    /// Returns an instant corresponding to now.
    fn now(&self) -> Self::Instant;

    /// Returns the current wall-clock time.
    fn current_time(&self) -> Self::SystemTime;
}

/// An opaque measurement of a monotonically nondecreasing clock.
pub trait Instant: Copy + Clone + PartialEq + Eq + PartialOrd + Ord + Send + Sync {
    /// Returns the duration elapsed since `earlier`, or `None` if it is later.
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration>;

    /// Returns the duration elapsed since `earlier`, saturating at zero.
    fn duration_since(&self, earlier: &Self) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }

    /// Returns a new instant advanced by `duration`, or `None` on overflow.
    fn checked_add(&self, duration: Duration) -> Option<Self>;
}

/// A measurement of the system wall clock.
pub trait SystemTime: Send + Sync {
    /// The Unix epoch.
    const UNIX_EPOCH: Self;

    /// Returns the duration elapsed since `earlier`.
    ///
    /// If the clock precedes `earlier`, returns the absolute difference as an
    /// error.
    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration>;
}
