//! This module provides a high-resolution performance counter using
//! `QueryPerformanceCounter` and `QueryPerformanceFrequency` from the Windows API.
//!
//! The code was from `std::time` in the Rust standard library

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use windows_sys::Win32::Foundation::GetLastError;

const NANOS_PER_SEC: u64 = 1_000_000_000;

pub struct PerformanceCounterInstant {
    ts: i64,
}
impl PerformanceCounterInstant {
    pub fn now() -> Self {
        Self { ts: query() }
    }

    // Per microsoft docs, the margin of error for cross-thread time comparisons
    // using QueryPerformanceCounter is 1 "tick" -- defined as 1/frequency().
    // Reference: https://docs.microsoft.com/en-us/windows/desktop/SysInfo
    //                   /acquiring-high-resolution-time-stamps
    pub fn epsilon() -> Duration {
        let epsilon = NANOS_PER_SEC / (frequency() as u64);
        Duration::from_nanos(epsilon)
    }
}
impl From<PerformanceCounterInstant> for super::Instant {
    fn from(other: PerformanceCounterInstant) -> Self {
        let freq = frequency() as u64;
        let instant_nsec = mul_div_u64(other.ts as u64, NANOS_PER_SEC, freq);
        Self {
            inner: Duration::from_nanos(instant_nsec),
        }
    }
}

fn frequency() -> i64 {
    // Either the cached result of `QueryPerformanceFrequency` or `0` for
    // uninitialized. Storing this as a single `AtomicU64` allows us to use
    // `Relaxed` operations, as we are only interested in the effects on a
    // single memory location.
    static FREQUENCY: AtomicU64 = AtomicU64::new(0);

    let cached = FREQUENCY.load(Ordering::Relaxed);
    // If a previous thread has filled in this global state, use that.
    if cached != 0 {
        return cached as i64;
    }
    // ... otherwise learn for ourselves ...
    let mut frequency = 0;
    assert!(
        unsafe {
            windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency)
        } != 0,
        "QueryPerformanceFrequency failed {}",
        unsafe { GetLastError() }
    );

    FREQUENCY.store(frequency as u64, Ordering::Relaxed);
    frequency
}

fn query() -> i64 {
    let mut qpc_value: i64 = 0;
    assert!(
        unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut qpc_value) }
            != 0,
        "QueryPerformanceCounter failed {}",
        unsafe { GetLastError() }
    );
    qpc_value
}

// Computes (value*numer)/denom without overflow, as long as both
// (numer*denom) and the overall result fit into i64 (which is the case
// for our time conversions).
pub fn mul_div_u64(value: u64, numer: u64, denom: u64) -> u64 {
    let q = value / denom;
    let r = value % denom;
    // Decompose value as (value/denom*denom + value%denom),
    // substitute into (value*numer)/denom and simplify.
    // r < denom, so (denom*numer) is the upper bound of (r*numer)
    q * numer + r * numer / denom
}
