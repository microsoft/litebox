//! Time management using TSC (Time Stamp Counter) and PIT (Programmable Interval Timer)

use core::sync::atomic::{AtomicU64, Ordering};

/// Monotonic timestamp based on CPU cycles
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    tsc: u64,
}

impl Instant {
    /// Get the current instant
    pub fn now() -> Self {
        Self {
            tsc: unsafe { core::arch::x86_64::_rdtsc() },
        }
    }

    /// Calculate duration since another instant in nanoseconds
    pub fn duration_since(&self, earlier: Self) -> u64 {
        let cycles = self.tsc.saturating_sub(earlier.tsc);
        let cpu_mhz = crate::get_cpu_mhz();
        if cpu_mhz == 0 {
            return 0;
        }
        // Convert cycles to nanoseconds: cycles * 1000 / cpu_mhz
        cycles * 1000 / cpu_mhz
    }
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        let nanos = self.duration_since(*earlier);
        Some(core::time::Duration::from_nanos(nanos))
    }
}

/// System time (wall clock) - starts from boot time
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemTime {
    nanos_since_boot: u64,
}

static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

impl SystemTime {
    /// Initialize boot time
    pub fn init_boot_time() {
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        BOOT_TSC.store(tsc, Ordering::Relaxed);
    }

    /// Get current system time
    pub fn now() -> Self {
        let current_tsc = unsafe { core::arch::x86_64::_rdtsc() };
        let boot_tsc = BOOT_TSC.load(Ordering::Relaxed);
        let cycles = current_tsc.saturating_sub(boot_tsc);
        let cpu_mhz = crate::get_cpu_mhz();
        let nanos_since_boot = if cpu_mhz == 0 {
            0
        } else {
            cycles * 1000 / cpu_mhz
        };

        Self { nanos_since_boot }
    }

    /// Get duration since Unix epoch (fake - just returns boot time)
    pub fn duration_since_epoch(&self) -> (u64, u32) {
        // Return boot time + current offset
        // For simplicity, we use a fixed fake epoch (Jan 1, 2024)
        const FAKE_EPOCH_SECS: u64 = 1704067200; // 2024-01-01 00:00:00 UTC
        let secs = FAKE_EPOCH_SECS + (self.nanos_since_boot / 1_000_000_000);
        let nanos = (self.nanos_since_boot % 1_000_000_000) as u32;
        (secs, nanos)
    }
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = Self {
        nanos_since_boot: 0,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        if self.nanos_since_boot >= earlier.nanos_since_boot {
            let diff = self.nanos_since_boot - earlier.nanos_since_boot;
            Ok(core::time::Duration::from_nanos(diff))
        } else {
            let diff = earlier.nanos_since_boot - self.nanos_since_boot;
            Err(core::time::Duration::from_nanos(diff))
        }
    }
}
