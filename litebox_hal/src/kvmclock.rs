// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The wall clock from KVM's paravirtual clock (kvm-clock), as Linux reads it
//! as a KVM guest: the host's wall time at the VM's start
//! (`MSR_KVM_WALL_CLOCK_NEW`) plus the VM's time since then
//! (`MSR_KVM_SYSTEM_TIME_NEW`), which KVM writes into guest memory. Read
//! once; there is none without KVM (e.g., under QEMU's TCG).

use crate::dma::{DmaRegion, Hal, PAGE_SIZE};
use core::arch::x86_64::__cpuid_count as cpuid;
use core::sync::atomic::{Ordering, fence};
use x86_64::registers::model_specific::Msr;

const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
/// In the system-time MSR's value: KVM keeps the structure updated.
const SYSTEM_TIME_ENABLE: u64 = 1;
/// CPUID `0x4000_0001` EAX: the two MSRs above.
const KVM_FEATURE_CLOCKSOURCE2: u32 = 1 << 3;

/// `struct pvclock_wall_clock`: the host's wall time at the VM's start.
#[repr(C)]
#[derive(Clone, Copy)]
struct WallClockInfo {
    version: u32,
    sec: u32,
    nsec: u32,
}

/// `struct pvclock_vcpu_time_info`: the VM's time since its start at a TSC
/// value, and how to scale TSC ticks to nanoseconds.
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeInfo {
    version: u32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    pad: [u8; 2],
}

/// Where in the page each structure goes.
const WALL_CLOCK_OFFSET: usize = 0;
const TIME_OFFSET: usize = 64;

/// The Unix time in nanoseconds at a TSC value, as `(unix_ns, tsc)`; `None`
/// without kvm-clock or memory for it.
#[expect(
    clippy::cast_ptr_alignment,
    reason = "the region is page-aligned, and the structures' offsets are aligned"
)]
pub fn wall_clock(hal: &'static dyn Hal) -> Option<(u64, u64)> {
    if !has_kvm_clock() {
        return None;
    }
    let region = DmaRegion::new(hal, PAGE_SIZE)?;
    let wall_clock = region.ptr(WALL_CLOCK_OFFSET, size_of::<WallClockInfo>());
    let time = region.ptr(TIME_OFFSET, size_of::<TimeInfo>());
    let time_pa = region.pa() + TIME_OFFSET as u64;
    // Safety: KVM writes the wall-clock structure during this write, and the
    // time structure while the system-time MSR is enabled; both are in the
    // region, which nothing else uses. The MSR is disabled before the region
    // is freed.
    let (system_ns, tsc) = unsafe {
        Msr::new(MSR_KVM_WALL_CLOCK_NEW).write(region.pa() + WALL_CLOCK_OFFSET as u64);
        Msr::new(MSR_KVM_SYSTEM_TIME_NEW).write(time_pa | SYSTEM_TIME_ENABLE);
        let now = system_time(time.cast());
        Msr::new(MSR_KVM_SYSTEM_TIME_NEW).write(0);
        now
    };
    // Safety: KVM wrote it during the MSR write, and writes it no more.
    let start = unsafe { consistent(wall_clock.cast::<WallClockInfo>(), |info| info.version) };
    let start_ns = u64::from(start.sec) * 1_000_000_000 + u64::from(start.nsec);
    Some((start_ns.checked_add(system_ns)?, tsc))
}

/// KVM, with kvm-clock's MSRs.
fn has_kvm_clock() -> bool {
    kvm_leaves().is_some_and(|base| cpuid(base + 1, 0).eax & KVM_FEATURE_CLOCKSOURCE2 != 0)
}

/// The base of KVM's CPUID leaves: as Linux, every `0x100` from
/// `0x4000_0000`, since another hypervisor's interface may come first (e.g.,
/// Hyper-V's, with KVM's Hyper-V enlightenments, moving KVM's to
/// `0x4000_0100`).
fn kvm_leaves() -> Option<u32> {
    const KVM: [u32; 3] = [0x4b4d_564b, 0x564b_4d56, 0x0000_004d]; // "KVMKVMKVM\0\0\0"
    if cpuid(1, 0).ecx & (1 << 31) == 0 {
        return None;
    }
    (0x4000_0000..0x4001_0000).step_by(0x100).find(|&base| {
        let leaf = cpuid(base, 0);
        [leaf.ebx, leaf.ecx, leaf.edx] == KVM && leaf.eax > base
    })
}

/// The VM's time since its start, in nanoseconds, at a TSC value read with
/// it.
///
/// # Safety
///
/// `info` must be the enabled time structure.
unsafe fn system_time(info: *const TimeInfo) -> (u64, u64) {
    let mut tsc = 0;
    // Safety: forwarded to the caller.
    let info = unsafe {
        consistent(info, |info| {
            // As pvclock: not before the structure is read.
            core::arch::x86_64::_mm_lfence();
            tsc = crate::clock::now();
            info.version
        })
    };
    let delta = tsc.wrapping_sub(info.tsc_timestamp);
    // Shifts KVM would never set (64 or more, either way) give zero.
    let shift = u32::from(info.tsc_shift.unsigned_abs());
    let delta = if info.tsc_shift >= 0 {
        delta.checked_shl(shift)
    } else {
        delta.checked_shr(shift)
    }
    .unwrap_or(0);
    let scaled = (u128::from(delta) * u128::from(info.tsc_to_system_mul)) >> 32;
    let since = u64::try_from(scaled).unwrap_or(u64::MAX);
    (info.system_time.saturating_add(since), tsc)
}

/// A copy of `*structure` that KVM was not updating: its version, which KVM
/// makes odd while updating, is even and the same before and after. `read`
/// returns the copy's version, and runs before the version is read again.
///
/// # Safety
///
/// `structure` must be valid for reads and aligned.
unsafe fn consistent<T: Copy>(structure: *const T, mut read: impl FnMut(&T) -> u32) -> T {
    let version = structure.cast::<u32>();
    loop {
        // Safety: forwarded to the caller; the version is the first field.
        let before = unsafe { version.read_volatile() };
        fence(Ordering::Acquire);
        // Safety: as above.
        let copy = unsafe { structure.read_volatile() };
        let copied = read(&copy);
        fence(Ordering::Acquire);
        // Safety: as above.
        let after = unsafe { version.read_volatile() };
        if before % 2 == 0 && before == after && copied == before {
            return copy;
        }
        core::hint::spin_loop();
    }
}
