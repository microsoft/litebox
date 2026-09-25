// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V partition reference clock, independent of VTL transitions and timers.

use super::HV_X64_MSR_TIME_REF_COUNT;
use crate::arch::instrs::rdmsr;
use core::time::Duration;

/// Partition reference counter granularity: 100 ns ticks, 10 per microsecond.
pub(crate) const REF_TICKS_PER_MICRO: u64 = 10;
const REF_COUNTER_TICK_NANOS: u64 = 1_000 / REF_TICKS_PER_MICRO;

/// Read the Hyper-V partition reference counter in 100 ns units.
///
/// The hypervisor maintains this monotonic, frequency-invariant counter across
/// TSC scaling and live migration. Call only on the initialized Hyper-V kernel
/// platform, where the reference-counter MSR is available.
pub(crate) fn reference_time_100ns() -> u64 {
    rdmsr(HV_X64_MSR_TIME_REF_COUNT)
}

/// Monotonic instant measured by the Hyper-V partition reference counter.
///
/// Keep native ticks rather than converting absolute readings to nanoseconds:
/// only duration differences need conversion, with checked overflow. This
/// preserves LVBS's existing 100 ns resolution and checked-arithmetic behavior.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    pub(crate) fn now() -> Self {
        Self(reference_time_100ns())
    }
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        let ticks = self.0.checked_sub(earlier.0)?;
        let nanos = ticks.checked_mul(REF_COUNTER_TICK_NANOS)?;
        Some(Duration::from_nanos(nanos))
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        let nanos: u64 = duration.as_nanos().try_into().ok()?;
        let ticks = nanos / REF_COUNTER_TICK_NANOS;
        Some(Self(self.0.checked_add(ticks)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::Instant as _;

    #[test]
    fn elapsed_time_uses_reference_counter_units() {
        assert_eq!(
            Instant(17).checked_duration_since(&Instant(10)),
            Some(Duration::from_nanos(700))
        );
        assert_eq!(
            Instant(10).checked_duration_since(&Instant(10)),
            Some(Duration::ZERO)
        );
        assert_eq!(Instant(10).checked_duration_since(&Instant(17)), None);
        assert!(Instant(10) < Instant(17));
    }

    #[test]
    fn addition_preserves_sub_tick_truncation() {
        for (nanos, ticks) in [
            (0, 0),
            (1, 0),
            (99, 0),
            (100, 1),
            (101, 1),
            (199, 1),
            (200, 2),
        ] {
            assert_eq!(
                Instant(10).checked_add(Duration::from_nanos(nanos)),
                Some(Instant(10 + ticks))
            );
        }
        assert_eq!(
            Instant(10).checked_add(Duration::from_secs(1)),
            Some(Instant(10_000_010))
        );
    }

    #[test]
    fn duration_conversion_checks_overflow_not_absolute_reading() {
        let max_ticks = u64::MAX / REF_COUNTER_TICK_NANOS;
        assert_eq!(
            Instant(max_ticks).checked_duration_since(&Instant(0)),
            Some(Duration::from_nanos(max_ticks * REF_COUNTER_TICK_NANOS))
        );
        assert_eq!(
            Instant(max_ticks + 1).checked_duration_since(&Instant(0)),
            None
        );
        assert_eq!(
            Instant(u64::MAX).checked_duration_since(&Instant(u64::MAX - 1)),
            Some(Duration::from_nanos(100))
        );
        assert_eq!(Instant(0).checked_duration_since(&Instant(u64::MAX)), None);
    }

    #[test]
    fn addition_checks_tick_overflow() {
        assert_eq!(
            Instant(u64::MAX).checked_add(Duration::from_nanos(99)),
            Some(Instant(u64::MAX))
        );
        assert_eq!(
            Instant(u64::MAX).checked_add(Duration::from_nanos(100)),
            None
        );
        assert_eq!(
            Instant(u64::MAX - 1).checked_add(Duration::from_nanos(100)),
            Some(Instant(u64::MAX))
        );
    }

    #[test]
    fn addition_preserves_duration_conversion_limit() {
        // Preserve the existing rejection of durations exceeding u64 nanos,
        // even if their converted tick count would fit.
        let max = Duration::from_nanos(u64::MAX);
        assert_eq!(
            Instant(0).checked_add(max),
            Some(Instant(u64::MAX / REF_COUNTER_TICK_NANOS))
        );
        assert_eq!(Instant(0).checked_add(max + Duration::from_nanos(1)), None);
    }
}
