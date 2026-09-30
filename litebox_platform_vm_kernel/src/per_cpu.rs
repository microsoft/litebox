// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-CPU kernel variables, reached through GSBASE.

use crate::arch::{gdt, mm::paging::UnmapOptions};
use alloc::{
    alloc::{alloc_zeroed, handle_alloc_error},
    boxed::Box,
    sync::Arc,
};
use core::alloc::Layout;
use core::cell::{Cell, UnsafeCell};
use core::mem::offset_of;
use litebox_common_linux::vmem::PAGE_SIZE;
use litebox_common_linux::{rdgsbase, wrgsbase};
use x86_64::VirtAddr;

// Include guards in the power-of-two allocation to avoid buddy-allocator waste.
const DOUBLE_FAULT_STACK_SIZE: usize = 4 * PAGE_SIZE;
const NMI_STACK_SIZE: usize = 4 * PAGE_SIZE;
const EXCEPTION_STACK_SIZE: usize = 4 * PAGE_SIZE;
#[cfg(debug_assertions)]
const KERNEL_STACK_SIZE: usize = 111 * PAGE_SIZE;
#[cfg(not(debug_assertions))]
const KERNEL_STACK_SIZE: usize = 47 * PAGE_SIZE;

#[repr(C)]
pub(crate) struct PerCpuVariables {
    /// Must be first: assembly reads it at `gs:[offset]`.
    pub(crate) asm: PerCpuVariablesAsm,
    pub(crate) gdt: Cell<Option<&'static gdt::GdtWrapper>>,
    pub(crate) tls: Cell<*mut ()>,
    /// Keeps the task page table in CR3 alive (`None`: the base table).
    active_page_table: UnsafeCell<Option<(usize, Arc<crate::mm::PageTable<PAGE_SIZE>>)>>,
    stacks: PerCpuStacks,
}

/// Layout only: allocate as raw memory, never create a reference to the whole arena.
#[repr(C, align(4096))]
struct PerCpuStackArena {
    guard_0: [u8; PAGE_SIZE],
    double_fault_stack: [u8; DOUBLE_FAULT_STACK_SIZE],
    guard_1: [u8; PAGE_SIZE],
    nmi_stack: [u8; NMI_STACK_SIZE],
    guard_2: [u8; PAGE_SIZE],
    exception_stack: [u8; EXCEPTION_STACK_SIZE],
    guard_3: [u8; PAGE_SIZE],
    kernel_stack: [u8; KERNEL_STACK_SIZE],
    guard_4: [u8; PAGE_SIZE],
}

const DOUBLE_FAULT_STACK_OFFSET: usize = offset_of!(PerCpuStackArena, double_fault_stack);
const NMI_STACK_OFFSET: usize = offset_of!(PerCpuStackArena, nmi_stack);
const EXCEPTION_STACK_OFFSET: usize = offset_of!(PerCpuStackArena, exception_stack);
const KERNEL_STACK_OFFSET: usize = offset_of!(PerCpuStackArena, kernel_stack);
const STACK_GUARD_OFFSETS: [usize; 5] = [
    offset_of!(PerCpuStackArena, guard_0),
    offset_of!(PerCpuStackArena, guard_1),
    offset_of!(PerCpuStackArena, guard_2),
    offset_of!(PerCpuStackArena, guard_3),
    offset_of!(PerCpuStackArena, guard_4),
];

struct PerCpuStacks {
    base: usize,
}

impl PerCpuStacks {
    const LAYOUT: Layout = Layout::new::<PerCpuStackArena>();

    fn allocate() -> Self {
        // Safety: nonzero, page-aligned layout. Retain the allocation for the CPU's lifetime.
        let base = unsafe { alloc_zeroed(Self::LAYOUT) };
        if base.is_null() {
            handle_alloc_error(Self::LAYOUT);
        }
        Self {
            base: base as usize,
        }
    }
}

/// XSAVE requires 64-byte alignment: 512 legacy bytes + a 64-byte header.
#[repr(C, align(64))]
struct XsaveArea([u8; PerCpuVariables::XSAVE_AREA_SIZE]);

impl PerCpuVariables {
    /// x87 and SSE: the XCR0 components `enable_extended_states` enables.
    const XSAVE_MASK: u64 = 0b11;
    const XSAVE_AREA_SIZE: usize = 512 + 64;
    const XSAVE_MXCSR_OFFSET: usize = 24;
    const XSAVE_HEADER_OFFSET: usize = 512;
    const XSAVE_HEADER_SIZE: usize = 64;
    const MXCSR_DEFAULT: u32 = 0x1f80;

    // Exclusive page-aligned ends satisfy the 16-byte stack alignment.

    fn kernel_stack_top(&self) -> usize {
        self.stacks.base + KERNEL_STACK_OFFSET + KERNEL_STACK_SIZE
    }

    pub(crate) fn double_fault_stack_top(&self) -> usize {
        self.stacks.base + DOUBLE_FAULT_STACK_OFFSET + DOUBLE_FAULT_STACK_SIZE
    }

    pub(crate) fn nmi_stack_top(&self) -> usize {
        self.stacks.base + NMI_STACK_OFFSET + NMI_STACK_SIZE
    }

    pub(crate) fn exception_stack_top(&self) -> usize {
        self.stacks.base + EXCEPTION_STACK_OFFSET + EXCEPTION_STACK_SIZE
    }

    pub(crate) fn segment_selectors(&self) -> Option<gdt::Selectors> {
        self.gdt.get().map(gdt::GdtWrapper::selectors)
    }

    /// XSAVE buffers must outlive all kernel/user transitions on this core.
    pub(crate) fn allocate_xsave_area(pcv_asm: &PerCpuVariablesAsm) {
        assert!(
            pcv_asm.kernel_xsave_area_addr.get() == 0,
            "XSAVE areas are already allocated"
        );
        let kernel_xsave_area = Box::leak(Box::new(XsaveArea([0; Self::XSAVE_AREA_SIZE])));
        let user_xsave_area = Box::leak(Box::new(XsaveArea([0; Self::XSAVE_AREA_SIZE])));
        pcv_asm.set_kernel_xsave_area_addr(kernel_xsave_area.0.as_ptr() as usize);
        pcv_asm.set_user_xsave_area_addr(user_xsave_area.0.as_ptr() as usize);
        pcv_asm.set_xsave_mask(Self::XSAVE_MASK);
    }

    pub(crate) fn active_page_table(
        &self,
        page_table_id: usize,
    ) -> Option<Arc<crate::mm::PageTable<PAGE_SIZE>>> {
        // Safety: only this core accesses the field.
        unsafe { &*self.active_page_table.get() }
            .as_ref()
            .filter(|(id, _)| *id == page_table_id)
            .map(|(_, page_table)| Arc::clone(page_table))
    }

    /// # Safety
    ///
    /// CR3 must no longer reference the previous table. A new ID must match
    /// CR3. Interrupts must be disabled, and this must not run in exception context.
    pub(crate) unsafe fn replace_active_page_table(
        &self,
        page_table: Option<(usize, Arc<crate::mm::PageTable<PAGE_SIZE>>)>,
    ) -> Option<(usize, Arc<crate::mm::PageTable<PAGE_SIZE>>)> {
        // Safety: Core-local, IRQs are disabled, and the update cannot fault.
        // Return the old owner so the caller can drop it outside that section.
        unsafe { core::mem::replace(&mut *self.active_page_table.get(), page_table) }
    }
}

/// Tracks an XSAVE area. XSAVEOPT is only valid after an XRSTOR of the area.
/// The `XSAVE_ASM`/`XRSTOR_ASM` macros use these values as literals.
#[repr(u8)]
#[derive(Clone, Copy, Default)]
enum XsaveState {
    /// XSAVE sets `Saved`; XRSTOR loads init state and leaves `NeverSaved`.
    #[default]
    NeverSaved = 0,
    /// Use XSAVE; XRSTOR restores the saved state and sets `Restored`.
    Saved = 1,
    /// Use XSAVEOPT; XRSTOR restores the saved state.
    Restored = 2,
}

const _: () = assert!(
    XsaveState::NeverSaved as u8 == 0
        && XsaveState::Saved as u8 == 1
        && XsaveState::Restored as u8 == 2
);

/// Assembly ABI: GS-relative offsets must match the `*_offset` accessors.
#[repr(C)]
#[derive(Default)]
pub struct PerCpuVariablesAsm {
    kernel_stack_ptr: Cell<usize>,
    scratch: Cell<usize>,
    /// User-mode RFLAGS captured at `syscall` entry
    user_rflags: Cell<usize>,
    cur_kernel_stack_ptr: Cell<usize>,
    cur_kernel_base_ptr: Cell<usize>,
    /// Top of the `PtRegs` the user context is pushed into
    user_context_top_addr: Cell<usize>,
    kernel_xsave_area_addr: Cell<usize>,
    user_xsave_area_addr: Cell<usize>,
    /// EAX operand for XSAVE/XRSTOR.
    xsave_mask_lo: Cell<u32>,
    /// EDX operand for XSAVE/XRSTOR.
    xsave_mask_hi: Cell<u32>,
    kernel_xsaved: Cell<XsaveState>,
    /// User XSAVE state; reset at each thread entry.
    user_xsaved: Cell<XsaveState>,
    exception_trapno: Cell<u8>,
    /// 1 while inside `run_thread_arch`, i.e., while a valid thread context
    /// exists for kernel page faults to use.
    is_in_user: Cell<u8>,
}

impl PerCpuVariablesAsm {
    pub(crate) fn set_kernel_stack_ptr(&self, sp: usize) {
        self.kernel_stack_ptr.set(sp);
    }
    pub(crate) fn set_kernel_xsave_area_addr(&self, addr: usize) {
        self.kernel_xsave_area_addr.set(addr);
    }
    pub(crate) fn set_user_xsave_area_addr(&self, addr: usize) {
        self.user_xsave_area_addr.set(addr);
    }
    pub(crate) fn set_xsave_mask(&self, mask: u64) {
        self.xsave_mask_lo.set((mask & 0xffff_ffff) as u32);
        self.xsave_mask_hi.set(((mask >> 32) & 0xffff_ffff) as u32);
    }
    /// Prevent extended-state leakage across user entries.
    pub(crate) fn reset_user_xsave(&self) {
        self.user_xsaved.set(XsaveState::NeverSaved);

        let area = self.user_xsave_area_addr.get() as *mut u8;
        debug_assert!(!area.is_null(), "user XSAVE area is not allocated");
        if area.is_null() {
            return;
        }
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "XSAVE areas are 64-byte aligned and each offset preserves the write alignment"
        )]
        // Safety: this core owns the 64-byte-aligned XSAVE area; both writes
        // are aligned and within its 576 bytes.
        unsafe {
            area.add(PerCpuVariables::XSAVE_MXCSR_OFFSET)
                .cast::<u32>()
                .write(PerCpuVariables::MXCSR_DEFAULT);
            // Clear XSTATE_BV, XCOMP_BV, and all reserved header bytes.
            area.add(PerCpuVariables::XSAVE_HEADER_OFFSET)
                .write_bytes(0, PerCpuVariables::XSAVE_HEADER_SIZE);
        }
    }
    pub const fn kernel_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, kernel_stack_ptr)
    }
    pub(crate) const fn scratch_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, scratch)
    }
    pub(crate) const fn user_rflags_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_rflags)
    }
    pub(crate) const fn cur_kernel_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, cur_kernel_stack_ptr)
    }
    pub(crate) const fn cur_kernel_base_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, cur_kernel_base_ptr)
    }
    pub(crate) const fn user_context_top_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_context_top_addr)
    }
    pub(crate) const fn kernel_xsave_area_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, kernel_xsave_area_addr)
    }
    pub(crate) const fn user_xsave_area_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_xsave_area_addr)
    }
    pub(crate) const fn xsave_mask_lo_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, xsave_mask_lo)
    }
    pub(crate) const fn xsave_mask_hi_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, xsave_mask_hi)
    }
    pub(crate) const fn kernel_xsaved_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, kernel_xsaved)
    }
    pub(crate) const fn user_xsaved_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_xsaved)
    }
    pub(crate) const fn exception_trapno_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, exception_trapno)
    }
    pub(crate) const fn is_in_user_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, is_in_user)
    }
    pub(crate) fn exception(&self) -> litebox::shim::Exception {
        litebox::shim::Exception(self.exception_trapno.get())
    }
}

/// Requires kernel GSBASE from [`allocate_per_cpu_variables`].
///
/// # Panics
/// Panics if GSBASE is not set or contains a non-canonical address.
pub(crate) fn with_per_cpu_variables<F, R>(f: F) -> R
where
    F: FnOnce(&PerCpuVariables) -> R,
    R: 'static,
{
    let ptr = per_cpu_variables_ptr();
    // Safety: only this core accesses its per-CPU data.
    let pcv = unsafe { &*ptr };
    f(pcv)
}

fn per_cpu_variables_ptr() -> *mut PerCpuVariables {
    // Safety: FSGSBASE is enabled before any per-CPU access.
    let gsbase = unsafe { rdgsbase() };
    assert!(
        gsbase != 0,
        "GSBASE not set. Call allocate_per_cpu_variables() first"
    );
    assert!(
        VirtAddr::try_new(gsbase as u64).is_ok(),
        "GS contains a non-canonical address"
    );
    gsbase as *mut PerCpuVariables
}

/// Call once per core after enabling FSGSBASE and seeding the global allocator,
/// before [`init_per_cpu_variables`].
///
/// # Panics
/// Panics if the allocation fails.
pub fn allocate_per_cpu_variables() {
    let pcv = Box::leak(Box::new(PerCpuVariables {
        asm: PerCpuVariablesAsm::default(),
        gdt: Cell::new(None),
        tls: Cell::new(core::ptr::null_mut()),
        active_page_table: UnsafeCell::new(None),
        stacks: PerCpuStacks::allocate(),
    }));
    // Safety: FSGSBASE is enabled, and `pcv` lives forever.
    unsafe { wrgsbase(core::ptr::from_ref(pcv) as usize) };
}

/// The arena must remain allocated after its guard pages are unmapped.
pub(crate) fn unmap_stack_guards(page_table: &crate::mm::PageTable<PAGE_SIZE>) {
    use litebox_common_linux::vmem::PageRange;

    let base = with_per_cpu_variables(|pcv| pcv.stacks.base);
    for offset in STACK_GUARD_OFFSETS {
        let start = base + offset;
        let range = PageRange {
            start,
            end: start + PAGE_SIZE,
        };
        // Safety: aligned, unused guards in a leaked allocation. Retain backing
        // frames and shared page tables.
        unsafe { page_table.unmap_pages(range, UnmapOptions::KEEP_FRAMES) }
            .expect("failed to unmap a stack guard page");
    }
}

/// Allocate the current core's XSAVE areas. Must run after
/// [`allocate_per_cpu_variables`] and [`crate::arch::enable_extended_states`].
pub fn allocate_xsave_area() {
    with_per_cpu_variables(|pcv| {
        PerCpuVariables::allocate_xsave_area(&pcv.asm);
    });
}

/// Call before switching to the per-CPU kernel stack.
pub fn init_per_cpu_variables() {
    with_per_cpu_variables(|pcv| pcv.asm.set_kernel_stack_ptr(pcv.kernel_stack_top()));
}
