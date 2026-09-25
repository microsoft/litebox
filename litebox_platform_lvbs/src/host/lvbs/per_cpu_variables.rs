// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS per-CPU composition and VTL transition state.
//!
//! The shared kernel prefix is at GS offset zero. Hyper-V communication pages
//! and VTL0 state follow it; shared kernel code neither names nor accesses them.

use crate::arch::{instrs::rdmsr, mm::PAGE_SIZE};
use crate::mshv::{
    HV_REGISTER_VP_INDEX, HvMessage, HvMessagePage, HvVpAssistPage, vsm::ControlRegMap,
    vtl_switch::VtlState,
};
use crate::per_cpu_variables::{PerCpuVariables, XSAVE_ALIGNMENT, XSAVE_MASK, current_per_cpu_ptr};
use aligned_vec::avec;
use alloc::boxed::Box;
use core::cell::{Cell, UnsafeCell};
use core::mem::offset_of;
use litebox::utils::TruncateExt;
use litebox_common_linux::wrgsbase;
use litebox_common_lvbs::MAX_CORES;

#[repr(C, align(4096))]
pub struct LvbsPerCpuVariables {
    pub(crate) kernel: PerCpuVariables,
    // These pages must remain page-aligned. Hyper-V accesses their contents
    // outside Rust's reference model, so each is held in UnsafeCell.
    hv_vp_assist_page: UnsafeCell<[u8; PAGE_SIZE]>,
    hv_simp_page: UnsafeCell<[u8; PAGE_SIZE]>,
    hvcall_input: UnsafeCell<[u8; PAGE_SIZE]>,
    hvcall_output: UnsafeCell<[u8; PAGE_SIZE]>,
    pub(crate) vtl0_asm: Vtl0PerCpuVariablesAsm,
    /// Assembly pushes/pops to this Cell's storage outside Rust reference
    /// scopes. Rust accesses it only between save and load while VTL1 runs.
    pub(crate) vtl0_state: Cell<VtlState>,
    pub(crate) vtl0_locked_regs: Cell<ControlRegMap>,
    /// u32::MAX means that the Hyper-V VP index has not been cached yet.
    vp_index: Cell<u32>,
}

const _: () = assert!(offset_of!(LvbsPerCpuVariables, kernel) == 0);
const _: () = assert!(offset_of!(LvbsPerCpuVariables, hv_vp_assist_page) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(LvbsPerCpuVariables, hv_simp_page) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(LvbsPerCpuVariables, hvcall_input) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(LvbsPerCpuVariables, hvcall_output) % PAGE_SIZE == 0);

impl LvbsPerCpuVariables {
    fn new_boxed() -> Box<Self> {
        let mut storage = Box::<Self>::new_uninit();
        // SAFETY: initialize in place to avoid exhausting the boot stack.
        // Zero is valid for LVBS's integer/byte/Cell fields. Initialize the
        // common prefix through its owner, then fix the VP index sentinel.
        unsafe {
            let ptr = storage.as_mut_ptr();
            ptr.write_bytes(0, 1);
            PerCpuVariables::initialize_at(core::ptr::addr_of_mut!((*ptr).kernel));
            core::ptr::addr_of_mut!((*ptr).vp_index).write(Cell::new(u32::MAX));
            storage.assume_init()
        }
    }

    fn init(&self) {
        self.kernel.init_stacks();
        // Cell<VtlState> has the same address as its inner state. Assembly
        // writes only outside Rust reference scopes, between VTL entries.
        self.vtl0_asm
            .state_top_addr
            .set(self.vtl0_state.as_ptr() as usize + core::mem::size_of::<VtlState>());
    }

    pub(crate) fn hv_vp_assist_page_as_u64(&self) -> u64 {
        self.hv_vp_assist_page.get() as u64
    }

    pub(crate) fn hv_simp_page_as_u64(&self) -> u64 {
        self.hv_simp_page.get() as u64
    }

    /// Copy a pending SynIC message and release its slot. SynIC does not
    /// overwrite a slot with non-zero message_type; clear it only after copying.
    pub(crate) fn take_sint_message(&self, sint_index: usize) -> HvMessage {
        // SAFETY: the SynIC protocol excludes a concurrent write to this slot.
        let simp_page = unsafe { &mut *self.hv_simp_page.get().cast::<HvMessagePage>() };
        let msg = simp_page.sint_message[sint_index];
        simp_page.sint_message[sint_index].header.message_type = 0;
        msg
    }

    /// Access the assist page after Hyper-V has finished writing it on entry.
    pub(crate) fn with_vp_assist_page<R>(&self, f: impl FnOnce(&HvVpAssistPage) -> R) -> R {
        // SAFETY: Hyper-V finishes writing before VTL1 entry; there is no
        // concurrent modification while this reference exists.
        f(unsafe { &*self.hv_vp_assist_page.get().cast::<HvVpAssistPage>() })
    }

    /// Access the hypercall input page. The closure must not re-enter this
    /// method, which would create aliasing mutable references.
    pub(crate) fn with_hvcall_input<T, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        const { assert!(core::mem::size_of::<T>() <= PAGE_SIZE) };
        const { assert!(core::mem::align_of::<T>() <= PAGE_SIZE) };
        // SAFETY: the page is aligned and large enough, and the reference is
        // confined to this non-reentrant closure.
        f(unsafe { &mut *self.hvcall_input.get().cast::<T>() })
    }

    /// Access the hypercall output page. The closure must not re-enter this
    /// method. Hyper-V writes synchronously during the hypercall.
    pub(crate) fn with_hvcall_output<T, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        const { assert!(core::mem::size_of::<T>() <= PAGE_SIZE) };
        const { assert!(core::mem::align_of::<T>() <= PAGE_SIZE) };
        // SAFETY: the page is aligned and large enough, and the reference is
        // confined to this non-reentrant closure.
        f(unsafe { &mut *self.hvcall_output.get().cast::<T>() })
    }

    pub fn set_vtl_return_value(&self, value: u64) {
        let mut state = self.vtl0_state.get();
        state.r8 = value;
        self.vtl0_state.set(state);
    }

    /// Return this CPU's cached Hyper-V VP index.
    ///
    /// # Panics
    /// Panics if the index exceeds the configured processor mask.
    pub fn vp_index(&self) -> u32 {
        let idx = self.vp_index.get();
        if idx == u32::MAX {
            let vp_index: u32 = rdmsr(HV_REGISTER_VP_INDEX).trunc();
            assert!(
                vp_index < u32::try_from(MAX_CORES).unwrap(),
                "VP index {vp_index} exceeds the configured processor mask"
            );
            self.vp_index.set(vp_index);
            vp_index
        } else {
            idx
        }
    }

    fn allocate_xsave_areas(&self) {
        assert_eq!(
            self.vtl0_asm.xsave_area_addr.get(),
            0,
            "XSAVE areas are already allocated"
        );
        // Hyper-V VTLs share XCR0. Preserve all VTL0-enabled state while our
        // kernel/user runtime uses x87+SSE only. VTL0 must not expand XCR0 after
        // this allocation (the existing LVBS boot/HVCI/HEKI contract).
        let vtl0_xsave_mask = xgetbv0();
        assert_eq!(
            XSAVE_MASK & !vtl0_xsave_mask,
            0,
            "VTL1 cannot have extended states that VTL0 does not enable"
        );
        let size = get_xsave_area_size();
        let area = Box::leak(
            avec![[{ XSAVE_ALIGNMENT }] | 0u8; size]
                .into_boxed_slice()
                .into(),
        );
        self.vtl0_asm.xsave_area_addr.set(area.as_ptr() as usize);
        self.vtl0_asm.xsave_mask_lo.set(vtl0_xsave_mask.trunc());
        self.vtl0_asm
            .xsave_mask_hi
            .set((vtl0_xsave_mask >> 32).trunc());
        self.kernel.allocate_xsave_areas();
    }
}

/// VTL0 save/restore and return metadata accessed by assembly. Offset methods
/// return offsets from GSBASE, including the enclosing LVBS layout.
#[repr(C)]
pub(crate) struct Vtl0PerCpuVariablesAsm {
    return_addr: Cell<usize>,
    state_top_addr: Cell<usize>,
    xsave_area_addr: Cell<usize>,
    xsave_mask_lo: Cell<u32>,
    xsave_mask_hi: Cell<u32>,
}

impl Vtl0PerCpuVariablesAsm {
    pub(crate) fn set_return_addr(&self, addr: usize) {
        self.return_addr.set(addr);
    }
    pub(crate) fn get_return_addr(&self) -> usize {
        self.return_addr.get()
    }
    pub(crate) const fn return_addr_offset() -> usize {
        offset_of!(LvbsPerCpuVariables, vtl0_asm) + offset_of!(Self, return_addr)
    }
    pub(crate) const fn state_top_addr_offset() -> usize {
        offset_of!(LvbsPerCpuVariables, vtl0_asm) + offset_of!(Self, state_top_addr)
    }
    pub(crate) const fn xsave_area_addr_offset() -> usize {
        offset_of!(LvbsPerCpuVariables, vtl0_asm) + offset_of!(Self, xsave_area_addr)
    }
    pub(crate) const fn xsave_mask_lo_offset() -> usize {
        offset_of!(LvbsPerCpuVariables, vtl0_asm) + offset_of!(Self, xsave_mask_lo)
    }
    pub(crate) const fn xsave_mask_hi_offset() -> usize {
        offset_of!(LvbsPerCpuVariables, vtl0_asm) + offset_of!(Self, xsave_mask_hi)
    }
}

/// Access the current CPU's concrete LVBS allocation. Only LVBS code may use
/// this accessor; the LVBS boot path installs this layout before any call.
pub(crate) fn with_per_cpu_variables<F, R>(f: F) -> R
where
    F: FnOnce(&LvbsPerCpuVariables) -> R,
    R: 'static,
{
    // SAFETY: LVBS installs this exact layout, whose kernel prefix is at zero.
    f(unsafe { &*current_per_cpu_ptr().cast::<LvbsPerCpuVariables>() })
}

/// Allocate the current CPU's state and install GSBASE. FSGSBASE and extended
/// state support must be enabled, and the BSP must have seeded the allocator.
/// Each CPU calls this once, before switching to its permanent kernel stack.
pub fn allocate_per_cpu_variables() {
    let cpu = Box::leak(LvbsPerCpuVariables::new_boxed());
    unsafe {
        wrgsbase(core::ptr::from_mut(cpu) as usize);
    }
}

/// Initialize stack pointers and the VTL0 save-area pointer after allocation.
pub fn init_per_cpu_variables() {
    with_per_cpu_variables(LvbsPerCpuVariables::init);
}

/// Allocate all XSAVE buffers after switching to the full kernel stack.
pub fn allocate_xsave_area() {
    with_per_cpu_variables(LvbsPerCpuVariables::allocate_xsave_areas);
}

fn get_xsave_area_size() -> usize {
    let cpuid = raw_cpuid::CpuId::new();
    let finfo = cpuid
        .get_feature_info()
        .expect("Failed to get cpuid feature info");
    assert!(finfo.has_xsave(), "XSAVE is not supported");
    let sinfo = cpuid
        .get_extended_state_info()
        .expect("Failed to get cpuid extended state info");
    sinfo.xsave_area_size_enabled_features() as usize
}

#[allow(clippy::inline_always)]
#[inline(always)]
fn xgetbv0() -> u64 {
    let eax: u32;
    let edx: u32;
    // SAFETY: the LVBS boot path has enabled OSXSAVE and verified XCR0 before
    // installing per-CPU state or allocating XSAVE buffers.
    unsafe {
        core::arch::asm!("xgetbv", in("ecx") 0, out("eax") eax, out("edx") edx, options(nostack, preserves_flags));
    }
    (u64::from(edx) << 32) | u64::from(eax)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_and_vtl0_offsets_match_storage() {
        let cpu = LvbsPerCpuVariables::new_boxed();
        cpu.init();
        let base = &raw const *cpu as usize;
        assert_eq!(&raw const cpu.kernel as usize, base);
        for page in [
            cpu.hv_vp_assist_page.get(),
            cpu.hv_simp_page.get(),
            cpu.hvcall_input.get(),
            cpu.hvcall_output.get(),
        ] {
            assert_eq!(page as usize % PAGE_SIZE, 0);
        }
        for (offset, address) in [
            (
                Vtl0PerCpuVariablesAsm::return_addr_offset(),
                cpu.vtl0_asm.return_addr.as_ptr() as usize,
            ),
            (
                Vtl0PerCpuVariablesAsm::state_top_addr_offset(),
                cpu.vtl0_asm.state_top_addr.as_ptr() as usize,
            ),
            (
                Vtl0PerCpuVariablesAsm::xsave_area_addr_offset(),
                cpu.vtl0_asm.xsave_area_addr.as_ptr() as usize,
            ),
            (
                Vtl0PerCpuVariablesAsm::xsave_mask_lo_offset(),
                cpu.vtl0_asm.xsave_mask_lo.as_ptr() as usize,
            ),
            (
                Vtl0PerCpuVariablesAsm::xsave_mask_hi_offset(),
                cpu.vtl0_asm.xsave_mask_hi.as_ptr() as usize,
            ),
        ] {
            assert_eq!(base + offset, address);
        }
        assert_eq!(
            cpu.vtl0_asm.state_top_addr.get(),
            cpu.vtl0_state.as_ptr() as usize + core::mem::size_of::<VtlState>()
        );
        assert_eq!(cpu.vp_index.get(), u32::MAX);
        assert_eq!(cpu.vtl0_asm.get_return_addr(), 0);
        cpu.vtl0_asm.set_return_addr(0x1000);
        assert_eq!(cpu.vtl0_asm.get_return_addr(), 0x1000);
        cpu.set_vtl_return_value(42);
        assert_eq!(cpu.vtl0_state.get().r8, 42);
    }
}
