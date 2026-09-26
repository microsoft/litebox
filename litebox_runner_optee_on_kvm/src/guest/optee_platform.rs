// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner-owned OP-TEE capabilities. Kernel operations delegate to the shared
//! VM kernel. No VTL peer, fake protection, persistent key, or scheduler.

use super::Platform as Kernel;
use core::{ops::Range, time::Duration};
use litebox::{
    mm::vmem::{PageFaultError, VmFlags, VmemPageFaultHandler},
    platform::page_mgmt::{
        AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
        PageManagementProvider, PermissionUpdateError, RemapError,
    },
    platform::{
        ArchSpecificError, ArchSpecificProvider, ArchSpecificRegister, CrngProvider,
        DerivedKeyError, DerivedKeyProvider, Instant, KDFParams, RawMutexProvider,
        RawPointerProvider, SystemInfoProvider, SystemTime, TimeProvider,
    },
};
use litebox_common_linux::vmap::{
    NoopPhysPageMapInfo, PhysPageAddrArray, PhysPageMapPermissions, PhysPointerError, VmapManager,
};
use zerocopy::{FromBytes, IntoBytes};

pub(super) struct OpteePlatform {
    pub kernel: &'static Kernel,
    tsc_origin: u64,
    tsc_hz: u64,
}

impl OpteePlatform {
    pub fn new(kernel: &'static Kernel) -> Self {
        let tsc_hz = calibrate_tsc();
        assert_ne!(
            core::arch::x86_64::__cpuid(1).ecx & (1 << 30),
            0,
            "RDRAND required for OP-TEE random provider"
        );
        Self {
            kernel,
            tsc_origin: tsc(),
            tsc_hz,
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
pub(super) struct ClockInstant(u64);
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
pub(super) struct NoWallTime;
impl SystemTime for NoWallTime {
    const UNIX_EPOCH: Self = Self;
    fn duration_since(&self, _earlier: &Self) -> Result<Duration, Duration> {
        panic!("no wall clock in QEMU OP-TEE test");
    }
}
impl TimeProvider for OpteePlatform {
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
impl CrngProvider for OpteePlatform {
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
impl DerivedKeyProvider for OpteePlatform {
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
unsafe impl VmapManager<4096> for OpteePlatform {
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
impl RawPointerProvider for OpteePlatform {
    type RawConstPointer<T: FromBytes> = <Kernel as RawPointerProvider>::RawConstPointer<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = <Kernel as RawPointerProvider>::RawMutPointer<T>;
}
impl RawMutexProvider for OpteePlatform {
    type RawMutex = <Kernel as RawMutexProvider>::RawMutex;
}
impl ArchSpecificProvider for OpteePlatform {
    fn set_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
        val: usize,
    ) -> Result<(), ArchSpecificError> {
        self.kernel.set_arch_specific_register(reg, val)
    }
    fn get_arch_specific_register(
        &self,
        reg: &ArchSpecificRegister,
    ) -> Result<usize, ArchSpecificError> {
        self.kernel.get_arch_specific_register(reg)
    }
}
impl SystemInfoProvider for OpteePlatform {
    fn get_syscall_entry_point(&self) -> usize {
        self.kernel.get_syscall_entry_point()
    }
    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}
impl PageManagementProvider<4096> for OpteePlatform {
    const TASK_ADDR_MIN: usize = <Kernel as PageManagementProvider<4096>>::TASK_ADDR_MIN;
    const TASK_ADDR_MAX: usize = <Kernel as PageManagementProvider<4096>>::TASK_ADDR_MAX;
    fn allocate_pages(
        &self,
        range: Range<usize>,
        perms: MemoryRegionPermissions,
        grow: bool,
        populate: bool,
        fixed: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        <Kernel as PageManagementProvider<4096>>::allocate_pages(
            self.kernel,
            range,
            perms,
            grow,
            populate,
            fixed,
        )
    }
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError> {
        unsafe { <Kernel as PageManagementProvider<4096>>::deallocate_pages(self.kernel, range) }
    }
    unsafe fn remap_pages(
        &self,
        old: Range<usize>,
        new: Range<usize>,
        perms: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        unsafe {
            <Kernel as PageManagementProvider<4096>>::remap_pages(self.kernel, old, new, perms)
        }
    }
    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        perms: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        unsafe {
            <Kernel as PageManagementProvider<4096>>::update_permissions(self.kernel, range, perms)
        }
    }
    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>> {
        <Kernel as PageManagementProvider<4096>>::reserved_pages(self.kernel)
    }
}
impl VmemPageFaultHandler for OpteePlatform {
    unsafe fn handle_page_fault(
        &self,
        addr: usize,
        flags: VmFlags,
        error: u64,
    ) -> Result<(), PageFaultError> {
        unsafe { self.kernel.handle_page_fault(addr, flags, error) }
    }
    fn access_error(error: u64, flags: VmFlags) -> bool {
        Kernel::access_error(error, flags)
    }
}
