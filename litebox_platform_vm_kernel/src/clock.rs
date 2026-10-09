// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Clock sources and deadline timers supplied through [`crate::BootConfig`].

pub trait ClockSource: Sync {
    /// Nanoseconds since an arbitrary origin that is fixed for the kernel's
    /// lifetime. Never decreases.
    fn monotonic_nanos(&self) -> u64;
}

/// A one-shot timer interrupt, as in LVBS's preemption timer (arm, disarm,
/// EOI). Times are [`ClockSource::monotonic_nanos`].
pub trait DeadlineTimer: Sync {
    /// The external interrupt vector it fires; not a CPU exception's (< 32).
    fn vector(&self) -> u8;

    /// Fires once at `deadline` (at once if it has passed), replacing any
    /// armed deadline. May fire early, e.g., if `deadline` exceeds the
    /// hardware's range, but never late; callers check the time.
    fn arm(&self, deadline: u64);

    fn disarm(&self);

    /// Acknowledges a delivered interrupt.
    fn end_of_interrupt(&self);
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
