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

    /// Returns the CPU time used by the calling thread, or `None` if the platform does not
    /// measure it.
    fn thread_cpu_time(&self) -> Option<CpuTime> {
        None
    }

    /// Returns the CPU time used by all threads of the current process, excluding its children,
    /// or `None` if the platform does not measure it.
    fn process_cpu_time(&self) -> Option<CpuTime> {
        None
    }
}

/// CPU time used by a thread or process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuTime {
    /// Time spent running in user mode.
    pub user: Duration,
    /// Time spent running in system mode.
    pub system: Duration,
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

    /// Returns a new instant advanced by `duration`, or the latest instant the platform can
    /// represent on overflow.
    #[must_use]
    fn saturating_add(&self, duration: Duration) -> Self;
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
