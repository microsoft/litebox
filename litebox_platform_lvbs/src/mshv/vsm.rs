// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-side VSM bring-up and control-register locking.

use crate::{
    debug_serial_println,
    host::{bootparam::get_vtl1_memory_info, per_cpu_variables::with_per_cpu_variables},
    mshv::{
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HV_REGISTER_VSM_PARTITION_CONFIG,
        HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, HV_X64_REGISTER_APIC_BASE, HV_X64_REGISTER_CR0,
        HV_X64_REGISTER_CR4, HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER, HV_X64_REGISTER_LSTAR,
        HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR, HV_X64_REGISTER_SYSENTER_CS,
        HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP, HvCrInterceptControlFlags,
        HvPageProtFlags, HvRegisterVsmPartitionConfig, HvRegisterVsmVpSecureVtlConfig, X86Cr0Flags,
        X86Cr4Flags,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers},
        vtl_switch::mshv_vsm_get_code_page_offsets,
    },
};
use x86_64::{
    PhysAddr,
    structures::paging::{PhysFrame, Size4KiB, frame::PhysFrameRange},
};

use alloc::vec::Vec;
use core::ops::Range;
use rangemap::RangeSet;
use spin::{Once, rwlock::RwLock as SpinRwLock};

pub(crate) fn init(is_bsp: bool) {
    assert!(
        !(is_bsp && mshv_vsm_configure_partition().is_err()),
        "Failed to configure VSM partition"
    );

    assert!(
        mshv_vsm_get_code_page_offsets().is_ok(),
        "Failed to retrieve Hypercall page offsets to execute VTL returns"
    );

    assert!(
        mshv_vsm_secure_config_vtl0().is_ok(),
        "Failed to secure VTL0 configuration"
    );

    if is_bsp {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            let Some(end) = start.checked_add(size) else {
                panic!("Failed to protect VTL1 memory");
            };
            debug_serial_println!("VSM: Protect GPAs from {:#x} to {:#x}", start, end);
            let Ok(end) = PhysAddr::try_new(end) else {
                panic!("Failed to protect VTL1 memory");
            };
            let start = PhysAddr::new(start);
            if protect_vtl1_physical_memory_range(PhysFrame::range(
                PhysFrame::from_start_address(start)
                    .expect("VTL1 memory start address is not page-aligned"),
                PhysFrame::from_start_address(end)
                    .expect("VTL1 memory end address is not page-aligned"),
            ))
            .is_err()
            {
                panic!("Failed to protect VTL1 memory");
            }
        } else {
            panic!("Failed to get VTL1 memory info");
        }
    }
}

/// VSM function for enforcing certain security features of VTL0
pub(crate) fn mshv_vsm_secure_config_vtl0() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Secure VTL0 configuration");

    let mut config = HvRegisterVsmVpSecureVtlConfig::new();
    config.set_mbec_enabled(true);
    config.set_tlb_locked(true);

    hvcall_set_vp_registers(HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, config.as_u64())
        .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

/// VSM function to configure a VSM partition for VTL1
pub(crate) fn mshv_vsm_configure_partition() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Configure partition");

    let mut config = HvRegisterVsmPartitionConfig::new();
    config.set_default_vtl_protection_mask(HvPageProtFlags::HV_PAGE_FULL_ACCESS.bits());
    config.set_enable_vtl_protection(true);

    hvcall_set_vp_registers(HV_REGISTER_VSM_PARTITION_CONFIG, config.as_u64())
        .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

/// VSM function for locking VTL0's control registers.
///
/// The end-of-boot guard is enforced by the runner-side dispatcher (which owns
/// the `HekiState`) before this is called.
///
/// Returns the common wire error type so the runner can uniformly combine this
/// platform-owned operation with the `litebox_service_heki` handlers.
pub(crate) fn mshv_vsm_lock_regs() -> Result<i64, VsmError> {
    debug_serial_println!("VSM: Lock control registers");

    let flag = HvCrInterceptControlFlags::CR0_WRITE.bits()
        | HvCrInterceptControlFlags::CR4_WRITE.bits()
        | HvCrInterceptControlFlags::GDTR_WRITE.bits()
        | HvCrInterceptControlFlags::IDTR_WRITE.bits()
        | HvCrInterceptControlFlags::LDTR_WRITE.bits()
        | HvCrInterceptControlFlags::TR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_LSTAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_STAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_CSTAR_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_APIC_BASE_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_EFER_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_CS_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_ESP_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SYSENTER_EIP_WRITE.bits()
        | HvCrInterceptControlFlags::MSR_SFMASK_WRITE.bits();

    save_vtl0_locked_regs().map_err(VsmError::HypercallFailed)?;

    hvcall_set_vp_registers(HV_REGISTER_CR_INTERCEPT_CONTROL, flag)
        .map_err(VsmError::HypercallFailed)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR4_MASK,
        X86Cr4Flags::CR4_PIN_MASK.bits().into(),
    )
    .map_err(VsmError::HypercallFailed)?;

    hvcall_set_vp_registers(
        HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        X86Cr0Flags::CR0_PIN_MASK.bits().into(),
    )
    .map_err(VsmError::HypercallFailed)?;

    Ok(0)
}

pub const NUM_CONTROL_REGS: usize = 11;

/// Data structure for maintaining MSRs and control registers whose values are locked.
/// This structure is expected to be stored in per-core kernel context, so we do not protect it with a lock.
#[derive(Debug, Clone, Copy)]
pub struct ControlRegMap {
    pub entries: [(u32, u64); NUM_CONTROL_REGS],
}

impl ControlRegMap {
    pub fn init(&mut self) {
        [
            HV_X64_REGISTER_CR0,
            HV_X64_REGISTER_CR4,
            HV_X64_REGISTER_LSTAR,
            HV_X64_REGISTER_STAR,
            HV_X64_REGISTER_CSTAR,
            HV_X64_REGISTER_APIC_BASE,
            HV_X64_REGISTER_EFER,
            HV_X64_REGISTER_SYSENTER_CS,
            HV_X64_REGISTER_SYSENTER_ESP,
            HV_X64_REGISTER_SYSENTER_EIP,
            HV_X64_REGISTER_SFMASK,
        ]
        .iter()
        .enumerate()
        .for_each(|(i, &reg_name)| {
            self.entries[i] = (reg_name, 0);
        });
    }

    pub fn get(&self, reg_name: u32) -> Option<u64> {
        for entry in &self.entries {
            if entry.0 == reg_name {
                return Some(entry.1);
            }
        }
        None
    }

    pub fn set(&mut self, reg_name: u32, value: u64) {
        for entry in &mut self.entries {
            if entry.0 == reg_name {
                entry.1 = value;
                return;
            }
        }
    }

    // consider implementing a mutable iterator (if we plan to lock many control registers)
    pub fn reg_names(&self) -> [u32; NUM_CONTROL_REGS] {
        let mut names = [0; NUM_CONTROL_REGS];
        for (i, entry) in self.entries.iter().enumerate() {
            names[i] = entry.0;
        }
        names
    }
}

#[allow(clippy::unnecessary_wraps)]
fn save_vtl0_locked_regs() -> Result<u64, HypervCallError> {
    let reg_names = with_per_cpu_variables(|per_cpu_variables| {
        let mut regs = per_cpu_variables.vtl0_locked_regs.get();
        regs.init();
        per_cpu_variables.vtl0_locked_regs.set(regs);
        regs.reg_names()
    });
    for reg_name in reg_names {
        if let Ok(value) = hvcall_get_vp_vtl0_registers(reg_name) {
            with_per_cpu_variables(|per_cpu_variables| {
                let mut regs = per_cpu_variables.vtl0_locked_regs.get();
                regs.set(reg_name, value);
                per_cpu_variables.vtl0_locked_regs.set(regs);
            });
        }
    }

    Ok(0)
}

/// This function protects a VTL1 physical memory range, securing VTL1's own pages.
/// VTL0 should never access VTL1 memory, so the memory attribute is always empty (no read, write, or execute).
///
/// Note. This function doesn't check whether `phys_frame_range` belongs to VTL1 because it is called by BSP
/// before the kernel platform data structure is initialized. To this end, one might call this function with
/// a VTL0 physical memory range which only restricts access to the range.
#[inline]
pub(crate) fn protect_vtl1_physical_memory_range(
    phys_frame_range: PhysFrameRange<Size4KiB>,
) -> Result<(), VsmError> {
    let pa = phys_frame_range.start.start_address().as_u64();
    let num_pages = phys_frame_range.count() as u64;
    if num_pages > 0 {
        hv_modify_vtl_protection_mask(pa, num_pages, HvPageProtFlags::HV_PAGE_ACCESS_NONE)
            .map_err(VsmError::HypercallFailed)?;
    }
    Ok(())
}

// --- Protected-frame registry -----------------------------------------------
//
// VTL0 protected-frame registry (mutual-exclusion guard). This is the platform's
// authority over which VTL0 frames are non-writable or reserved by in-flight
// module/kexec validation. Ordinary writable foreign mappings acquire a shared
// access guard (see `LvbsPhysPageMapInfo` and `vmap`) so a concurrent VTL
// protection change cannot alias a writable VTL0 mapping.
//
// The registry is driven by the VSM/HEKI service through the `Vtl0Mediation` trait,
// so its public surface speaks the common wire error type `VsmError`.

use litebox_common_lvbs::{HypervCallError, ReservationStatus, VsmError};

/// RAII reservation over VTL0 physical frames, shared by module load and kexec validation.
/// On drop without `commit`, every newly reserved range is restored to VTL0 read/write,
/// non-executable access.
pub(crate) struct FrameReservation {
    owned_ranges: Vec<PhysFrameRange<Size4KiB>>,
    owned_frames: RangeSet<u64>,
    committed: bool,
}

impl Default for FrameReservation {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReservation {
    pub(crate) fn new() -> Self {
        Self {
            owned_ranges: Vec::new(),
            owned_frames: RangeSet::new(),
            committed: false,
        }
    }

    fn classify(
        owned: &RangeSet<u64>,
        registry: &ProtectedFrameUpdateGuard<'_>,
        range: Range<u64>,
    ) -> Result<ReservationStatus, VsmError> {
        if owned.gaps(&range).next().is_none() {
            return Ok(ReservationStatus::AlreadyOwned);
        }
        if owned.overlaps(&range) || registry.overlaps(&range) {
            Err(VsmError::ProtectedFrameOverlap)
        } else {
            Ok(ReservationStatus::New)
        }
    }

    /// Reserve `frames`. Ranges fully owned before this call are accepted idempotently. Overlap
    /// within this batch, partial overlap with prior ownership, and overlap with VTL1, protected
    /// frames, or another reservation are rejected.
    ///
    /// Validation and insertion are atomic under exclusive registry access. On rejection, only
    /// claims added by this call are rolled back.
    pub(crate) fn reserve(
        &mut self,
        frames: impl IntoIterator<Item = PhysFrameRange<Size4KiB>>,
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        let vtl1 = crate::platform_low().vtl1_phys_frame_range();
        let vtl1_start = vtl1.start.start_address().as_u64();
        let vtl1_end = vtl1.end.start_address().as_u64();

        protected_frame_registry().with_exclusive(|protected| {
            // Idempotence applies only to ranges owned before this call.
            let owned_before = self.owned_frames.clone();
            let mut seen = RangeSet::new();
            let mut statuses = Vec::new();
            // Frames this call adds, so a later overlap rolls back only them.
            let rollback_from = self.owned_ranges.len();
            for phys_frame_range in frames {
                let start = phys_frame_range.start.start_address().as_u64();
                let end = phys_frame_range.end.start_address().as_u64();
                if start >= end {
                    statuses.push(ReservationStatus::AlreadyOwned);
                    continue;
                }
                // `protected` holds existing non-writable frames, this reservation's earlier
                // claims, and any other concurrent reservation's in-flight claims.
                let range = start..end;
                let status = if seen.overlaps(&range) || (start < vtl1_end && vtl1_start < end) {
                    Err(VsmError::ProtectedFrameOverlap)
                } else {
                    Self::classify(&owned_before, protected, range.clone())
                };
                let status = match status {
                    Ok(status) => status,
                    Err(error) => {
                        for undo in &self.owned_ranges[rollback_from..] {
                            let range = undo.start.start_address().as_u64()
                                ..undo.end.start_address().as_u64();
                            protected.remove(range.clone());
                            self.owned_frames.remove(range);
                        }
                        self.owned_ranges.truncate(rollback_from);
                        return Err(error);
                    }
                };
                seen.insert(range.clone());
                if status == ReservationStatus::AlreadyOwned {
                    statuses.push(status);
                    continue;
                }
                protected.insert(range.clone());
                self.owned_frames.insert(range);
                self.owned_ranges.push(phys_frame_range);
                statuses.push(status);
            }
            Ok(statuses)
        })
    }

    /// Mark the reserved frames as committed; drop becomes a no-op.
    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for FrameReservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Rollback: restore every newly reserved range to VTL0 read/write, non-executable access.
        // Drop cannot report failure, so debug builds assert it.
        for &phys_frame_range in &self.owned_ranges {
            let result = unprotect_physical_memory_range(phys_frame_range);
            debug_assert!(
                result.is_ok(),
                "Failed to restore VTL0 read/write access for reserved frames"
            );
        }
    }
}

/// Registry of VTL0 frames that are non-writable to VTL0 or reserved by in-flight module or kexec
/// validation. Ordinary writable mappings retain shared access for their lifetime; reservations and
/// VTL0 protection updates use exclusive access. Privileged HEKI and ring-buffer mappings bypass
/// the registry.
pub(crate) struct ProtectedFrameRegistry {
    frames: SpinRwLock<RangeSet<u64>>,
}

/// Opaque guard that holds shared registry access for an ordinary writable mapping, blocking
/// exclusive protection and reservation updates until dropped.
pub(crate) struct ProtectedFrameAccessGuard<'a> {
    _guard: spin::rwlock::RwLockReadGuard<'a, RangeSet<u64>>,
}

struct ProtectedFrameUpdateGuard<'a> {
    guard: spin::rwlock::RwLockWriteGuard<'a, RangeSet<u64>>,
}

impl ProtectedFrameUpdateGuard<'_> {
    fn overlaps(&self, range: &Range<u64>) -> bool {
        self.guard.overlaps(range)
    }

    fn insert(&mut self, range: Range<u64>) {
        self.guard.insert(range);
    }

    fn remove(&mut self, range: Range<u64>) {
        self.guard.remove(range);
    }

    fn record_protection(&mut self, phys_frame_range: PhysFrameRange<Size4KiB>, protect: bool) {
        let start = phys_frame_range.start.start_address().as_u64();
        let end = phys_frame_range.end.start_address().as_u64();
        if start >= end {
            return;
        }
        if protect {
            self.insert(start..end);
        } else {
            self.remove(start..end);
        }
    }
}

impl ProtectedFrameRegistry {
    fn new() -> Self {
        Self {
            frames: SpinRwLock::new(RangeSet::new()),
        }
    }

    /// Validates that no requested page is registered as protected or reserved and returns a shared
    /// guard that prevents protection or reservation updates until dropped.
    pub(crate) fn acquire_access_guard<const ALIGN: usize>(
        &self,
        pages: &litebox_common_linux::vmap::PhysPageAddrArray<ALIGN>,
    ) -> Result<ProtectedFrameAccessGuard<'_>, litebox_common_linux::vmap::PhysPointerError> {
        let guard = self.frames.read();
        for page in pages {
            let start = page.as_usize() as u64;
            let end = start
                .checked_add(ALIGN as u64)
                .ok_or(litebox_common_linux::vmap::PhysPointerError::Overflow)?;
            if guard.overlaps(&(start..end)) {
                return Err(
                    litebox_common_linux::vmap::PhysPointerError::InvalidPhysicalAddress(
                        page.as_usize(),
                    ),
                );
            }
        }
        Ok(ProtectedFrameAccessGuard { _guard: guard })
    }

    /// Runs `f` with exclusive registry access.
    fn with_exclusive<R>(&self, f: impl FnOnce(&mut ProtectedFrameUpdateGuard<'_>) -> R) -> R {
        f(&mut ProtectedFrameUpdateGuard {
            guard: self.frames.write(),
        })
    }
}

pub(crate) fn protected_frame_registry() -> &'static ProtectedFrameRegistry {
    static REGISTRY: Once<ProtectedFrameRegistry> = Once::new();
    REGISTRY.call_once(ProtectedFrameRegistry::new)
}

/// Protect a VTL0 physical memory range using VTL protection mask (e.g., kernel code integrity).
///
/// The registry tracks non-writable VTL0 ranges and temporary validation reservations.
/// See [`protected_frame_registry`].
///
/// If the requested range overlaps with VTL1 working memory, the VTL1 portion is silently
/// skipped and only the remaining VTL0 portions are protected. If the range falls entirely
/// within VTL1, this function returns `Ok(())` without issuing a hypercall.
///
/// `phys_frame_range` specifies the range whose VTL0 permissions are updated; VTL1 working-memory
/// portions are ignored.
/// `page_prot` specifies the hypervisor page-protection flags (VTL0's allowed access) to apply.
pub(crate) fn protect_physical_memory_range(
    phys_frame_range: PhysFrameRange<Size4KiB>,
    page_prot: HvPageProtFlags,
) -> Result<(), VsmError> {
    let protect = !page_prot.contains(HvPageProtFlags::HV_PAGE_WRITABLE);
    let vtl1_range = crate::platform_low().vtl1_phys_frame_range();

    // Range fully within VTL1 — nothing to protect for VTL0.
    if phys_frame_range.start >= vtl1_range.start && phys_frame_range.end <= vtl1_range.end {
        return Ok(());
    }

    // Fast path: no overlap with VTL1 — protect the entire range directly.
    let overlaps_vtl1 =
        phys_frame_range.start < vtl1_range.end && vtl1_range.start < phys_frame_range.end;

    protected_frame_registry().with_exclusive(|protected| {
        if !overlaps_vtl1 {
            let pa = phys_frame_range.start.start_address().as_u64();
            let num_pages = phys_frame_range.count() as u64;
            hv_modify_vtl_protection_mask(pa, num_pages, page_prot)
                .map_err(VsmError::HypercallFailed)?;
            protected.record_protection(phys_frame_range, protect);
            return Ok(());
        }

        // Partial overlap: split into the portions before and after VTL1, skipping VTL1 pages.
        let sub_ranges: [PhysFrameRange<Size4KiB>; 2] = {
            let before = PhysFrame::range(
                phys_frame_range.start,
                core::cmp::min(phys_frame_range.end, vtl1_range.start),
            );
            let after = PhysFrame::range(
                core::cmp::max(phys_frame_range.start, vtl1_range.end),
                phys_frame_range.end,
            );
            [before, after]
        };

        for sub_range in sub_ranges {
            if sub_range.start >= sub_range.end {
                continue;
            }
            let pa = sub_range.start.start_address().as_u64();
            let num_pages = sub_range.count() as u64;
            hv_modify_vtl_protection_mask(pa, num_pages, page_prot)
                .map_err(VsmError::HypercallFailed)?;
            protected.record_protection(sub_range, protect);
        }
        Ok(())
    })
}

/// Restore VTL0 read/write access while leaving execution disabled, and removes the registry entry.
pub(crate) fn unprotect_physical_memory_range(
    phys_frame_range: PhysFrameRange<Size4KiB>,
) -> Result<(), VsmError> {
    protect_physical_memory_range(
        phys_frame_range,
        HvPageProtFlags::HV_PAGE_READABLE
            | HvPageProtFlags::HV_PAGE_USER_EXECUTABLE
            | HvPageProtFlags::HV_PAGE_WRITABLE,
    )
}
