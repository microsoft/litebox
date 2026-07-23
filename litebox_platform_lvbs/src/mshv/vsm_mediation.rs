// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Platform-side implementation of the [`litebox_common_lvbs::Vtl0Mediation`]
//! and [`litebox_common_lvbs::VsmMediation`] traits.

use alloc::vec::Vec;
use litebox::utils::TruncateExt;
use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{
    FrameTxn, MemAttr, PAGE_SHIFT, PAGE_SIZE, PRK_LEN, ReservationStatus, VsmError, VsmMediation,
    Vtl0Mediation,
};
use x86_64::{
    PhysAddr,
    structures::paging::{Size4KiB, frame::PhysFrameRange},
};
use zerocopy::FromBytes;
use zeroize::Zeroizing;

use crate::host::linux::CpuMask;
use crate::mshv::HvPageProtFlags;
use crate::mshv::vsm::{
    FrameReservation, protect_physical_memory_range, unprotect_physical_memory_range,
};

/// A guarded, read-only physical pointer into foreign (VTL0) physical memory.
type Vtl0PhysConstPtr<T, const ALIGN: usize> = super::Vtl0PhysConstPtr<T, ALIGN>;

/// A mutable VTL0 pointer reserved for validated HEKI text patching and the
/// fixed-address log ring buffer.
type PrivilegedVtl0PhysMutPtr<T, const ALIGN: usize> = super::PrivilegedVtl0PhysMutPtr<T, ALIGN>;

/// Zero-sized live adapter implementing [`Vtl0Mediation`] and [`VsmMediation`]
/// over the platform's enforcement primitives.
///
/// Holding one grants the privileged VTL0 capability (including
/// protection-mask-bypassing writes); the private field limits construction to
/// [`LvbsVsmMediation::mint`]. Like a `PunchthroughToken`, this is an
/// auditability aid, not a boundary: it funnels all privileged VTL0 access
/// through one greppable mint point.
pub struct LvbsVsmMediation {
    /// Private, so the capability is built only via [`LvbsVsmMediation::mint`],
    /// never a bare literal.
    _private: (),
}

impl LvbsVsmMediation {
    /// Mint the privileged VTL0 mediation capability. Reserved for VTL1-trusted
    /// composition-root code (the runner); the audit point for all privileged
    /// VTL0 access.
    #[must_use]
    pub fn mint() -> Self {
        Self { _private: () }
    }
}

/// Maps a [`MemAttr`] permission set (the Vtl0Mediation permission type) to the
/// corresponding Hyper-V page-protection flags.
pub(crate) fn mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();
    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }
    flags
}

/// Restricted transaction handle for a `protect_frames_transactionally` closure.
/// Wraps the private platform [`FrameReservation`] guard so the service can
/// never hold or leak a reservation across the trait boundary.
struct PlatformFrameTxn<'a> {
    guard: &'a mut FrameReservation,
}

impl FrameTxn for PlatformFrameTxn<'_> {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        self.guard.reserve(ranges.iter().copied())
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        protect_physical_memory_range(range, mem_attr_to_hv_page_prot_flags(attr))
    }
}

impl Vtl0Mediation for LvbsVsmMediation {
    fn read_vtl0_bytes(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), VsmError> {
        let ptr = Vtl0PhysConstPtr::<u8, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.read_slice_at_offset(0, out)
            .map_err(|_| VsmError::Vtl0CopyFailed)
    }

    fn write_vtl0_privileged(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), VsmError> {
        let ptr = PrivilegedVtl0PhysMutPtr::<u8, PAGE_SIZE>::new(pages, offset)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        ptr.write_slice_at_offset(0, bytes)
            .map_err(|_| VsmError::Vtl0CopyFailed)
    }

    fn protect_frame(
        &self,
        range: PhysFrameRange<Size4KiB>,
        attr: MemAttr,
    ) -> Result<(), VsmError> {
        protect_physical_memory_range(range, mem_attr_to_hv_page_prot_flags(attr))
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        unprotect_physical_memory_range(range)
    }

    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        let mut guard = FrameReservation::new();
        guard.reserve(initial.iter().copied())?;
        let mut txn = PlatformFrameTxn { guard: &mut guard };
        let result = f(&mut txn);
        if result.is_ok() {
            txn.guard.commit();
        }
        // On `Err`, `guard` drops uncommitted, rolling back every reserved range.
        result
    }

    fn install_ringbuffer(&self, pa: u64, size: usize) {
        let _ = crate::mshv::ringbuffer::set_ringbuffer(PhysAddr::new(pa), size);
    }

    fn lock_control_registers(&self) -> Result<(), VsmError> {
        crate::mshv::vsm::mshv_vsm_lock_regs().map(|_| ())
    }
}

impl VsmMediation for LvbsVsmMediation {
    fn boot_aps(&self, cpu_online_mask_pfn: u64) -> Result<(), VsmError> {
        let mask_pa = cpu_online_mask_pfn
            .checked_shl(PAGE_SHIFT.trunc())
            .and_then(|pa| PhysAddr::try_new(pa).ok())
            .ok_or(VsmError::InvalidPhysicalAddress)?;

        // Read exactly the fixed-size cpu_online_mask (MAX_CORES bits); bits
        // beyond MAX_CORES are outside the ABI and cannot drive AP boots.
        let mut mask_bytes = [0u8; core::mem::size_of::<CpuMask>()];
        self.read_vtl0_contiguous(mask_pa.as_u64(), &mut mask_bytes)
            .map_err(|_| VsmError::CpuOnlineMaskCopyFailed)?;
        let cpu_online_mask =
            CpuMask::read_from_bytes(&mask_bytes).map_err(|_| VsmError::CpuOnlineMaskCopyFailed)?;

        // Best-effort: attempt every online CPU, surfacing the last init failure.
        let mut error = None;
        cpu_online_mask.for_each_cpu(|cpu_id| {
            if let Err(e) = crate::mshv::hvcall_vp::init_vtl_ap(TruncateExt::<u32>::trunc(cpu_id)) {
                error = Some(e);
            }
        });
        match error {
            Some(e) => Err(VsmError::ApInitFailed(e)),
            None => Ok(()),
        }
    }

    fn set_platform_root_key(&self, key_pa: u64) -> Result<(), VsmError> {
        let key_pa = PhysAddr::try_new(key_pa).map_err(|_| VsmError::InvalidPhysicalAddress)?;
        let mut keybuf = Zeroizing::new([0u8; PRK_LEN]);
        self.read_vtl0_contiguous(key_pa.as_u64(), &mut *keybuf)
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        crate::host::set_platform_root_key(&keybuf);
        Ok(())
    }
}
