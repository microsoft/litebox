// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! QEMU backend facilities, independent of any shim. The shared LinuxKernel
//! provides kernel mechanisms and delegates capabilities here; no OP-TEE
//! platform wrapper, VTL peer, fake protection, or scheduler is needed.

use core::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use litebox::platform::{
    CrngProvider, DerivedKeyError, DerivedKeyProvider, Instant, KDFParams, RawMutexProvider,
    SystemTime, TimeProvider,
};
use litebox_common_linux::vmap::{
    NoopPhysPageMapInfo, PhysPageAddrArray, PhysPageMapPermissions, PhysPointerError, VmapManager,
};
use litebox_platform_lvbs::{backend::KernelBackend, execution::ExecutionTimer};
pub struct QemuBackend {
    tsc_origin: u64,
    tsc_hz: u64,
    pub timer: FiniteTestTimer,
}

impl QemuBackend {
    pub fn new() -> Self {
        let tsc_hz = calibrate_tsc();
        assert_ne!(
            core::arch::x86_64::__cpuid(1).ecx & (1 << 30),
            0,
            "RDRAND required for OP-TEE random provider"
        );
        Self {
            tsc_origin: tsc(),
            tsc_hz,
            timer: FiniteTestTimer::default(),
        }
    }
}

fn tsc() -> u64 {
    // LFENCE orders the reading relative to surrounding test work.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
}

/// Calibrate against QEMU's PIT channel 2 for ~10 ms. No interrupts required.
/// This is a UP debugging clock; migration/SMP stability is not promised.
fn calibrate_tsc() -> u64 {
    fn out(port: u16, value: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack, nomem));
        }
    }
    fn input(port: u16) -> u8 {
        let value: u8;
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nostack, nomem));
        }
        value
    }
    const COUNT: u16 = 11932;
    let saved = input(0x61);
    out(0x61, saved & !3); // gate low, speaker off
    out(0x43, 0xb0); // channel 2, low/high byte, one-shot mode 0
    out(0x42, COUNT.to_le_bytes()[0]);
    out(0x42, COUNT.to_le_bytes()[1]);
    let start = tsc();
    out(0x61, (saved & !2) | 1);
    let mut complete = false;
    for _ in 0..10_000_000 {
        if input(0x61) & 0x20 != 0 {
            complete = true;
            break;
        }
        core::hint::spin_loop();
    }
    let elapsed = tsc().checked_sub(start).expect("TSC moved backwards");
    out(0x61, saved);
    assert!(complete && elapsed > 0, "PIT calibration failed");
    elapsed.checked_mul(1_193_182).unwrap() / u64::from(COUNT)
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClockInstant(u64);
impl Instant for ClockInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }
    fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0
            .checked_add(duration.as_nanos().try_into().ok()?)
            .map(Self)
    }
}
pub struct NoWallTime;
impl SystemTime for NoWallTime {
    const UNIX_EPOCH: Self = Self;
    fn duration_since(&self, _earlier: &Self) -> Result<Duration, Duration> {
        panic!("no wall clock in QEMU OP-TEE test");
    }
}
impl TimeProvider for QemuBackend {
    type Instant = ClockInstant;
    type SystemTime = NoWallTime;
    fn now(&self) -> Self::Instant {
        let ticks = tsc()
            .checked_sub(self.tsc_origin)
            .expect("TSC moved backwards");
        ClockInstant(
            u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(self.tsc_hz)).unwrap(),
        )
    }
    fn current_time(&self) -> Self::SystemTime {
        panic!("no wall clock in QEMU OP-TEE test");
    }
}
impl CrngProvider for QemuBackend {
    fn fill_bytes_crng(&self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let mut value = 0;
            let mut ready = false;
            for _ in 0..100 {
                if unsafe { core::arch::x86_64::_rdrand64_step(&mut value) } == 1 {
                    ready = true;
                    break;
                }
                core::hint::spin_loop();
            }
            assert!(ready, "RDRAND unavailable");
            chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
        }
    }
}
impl DerivedKeyProvider for QemuBackend {
    fn derive_key<E>(
        &self,
        _kdf: Option<fn(&[u8], KDFParams) -> Result<(), E>>,
        _params: KDFParams,
    ) -> Result<(), DerivedKeyError<E>> {
        Err(DerivedKeyError::UnsupportedRebootPersistentKey)
    }
}
// SAFETY: all foreign-memory operations deny access. The test exchanges value
// parameters through TA-owned userspace, not untrusted guest physical pointers.
unsafe impl VmapManager<4096> for QemuBackend {
    type MapInfo = NoopPhysPageMapInfo;
    fn validate_unowned(&self, _pages: &PhysPageAddrArray<4096>) -> Result<(), PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }
    unsafe fn protect(
        &self,
        _pages: &PhysPageAddrArray<4096>,
        _perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }
}
impl litebox_platform_lvbs::console::DiagnosticOutput for QemuBackend {
    fn print(args: core::fmt::Arguments<'_>) {
        super::console(args);
    }
}

impl KernelBackend for QemuBackend {
    type Memory = super::QemuMemory;
    type Timer = FiniteTestTimer;
    fn execution_timer(&self) -> &Self::Timer {
        &self.timer
    }
}
impl RawMutexProvider for QemuBackend {
    type RawMutex = litebox_platform_lvbs::backend::no_scheduler::NoSchedulerMutex;
}

/// Explicit no-hardware-timer choice for trusted finite test payloads. The
/// host process timeout bounds regressions; this is not for untrusted workloads.
#[derive(Default)]
pub struct FiniteTestTimer {
    arms: AtomicUsize,
    user_exceptions: AtomicUsize,
}
impl FiniteTestTimer {
    pub fn counts(&self) -> (usize, usize) {
        (
            self.arms.load(Ordering::Relaxed),
            self.user_exceptions.load(Ordering::Relaxed),
        )
    }
}
impl ExecutionTimer for FiniteTestTimer {
    fn arm(&self) {
        self.arms.fetch_add(1, Ordering::Relaxed);
    }
    fn on_user_exception(&self, _exception: litebox::shim::Exception) {
        self.user_exceptions.fetch_add(1, Ordering::Relaxed);
    }
}
