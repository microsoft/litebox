// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-CPU kernel variables, each CPU's reached through its GSBASE.

use crate::AddressSpaceId;
use crate::arch::{gdt, mm::paging::UnmapOptions};
use crate::cpu::CpuId;
use alloc::{
    alloc::{alloc_zeroed, handle_alloc_error},
    boxed::Box,
    sync::Arc,
};
use core::alloc::Layout;
use core::cell::{Cell, UnsafeCell};
use core::mem::offset_of;
use litebox::arch::x86_64::{rdgsbase, wrgsbase};
use litebox_common_linux::PAGE_SIZE;
use x86_64::VirtAddr;
use x86_64::registers::model_specific::KernelGsBase;

// Include guards in the power-of-two allocation to avoid buddy-allocator waste.
const DOUBLE_FAULT_STACK_SIZE: usize = 4 * PAGE_SIZE;
const NMI_STACK_SIZE: usize = 4 * PAGE_SIZE;
const EXCEPTION_STACK_SIZE: usize = 4 * PAGE_SIZE;
#[cfg(debug_assertions)]
pub(crate) const KERNEL_STACK_SIZE: usize = 111 * PAGE_SIZE;
#[cfg(not(debug_assertions))]
pub(crate) const KERNEL_STACK_SIZE: usize = 47 * PAGE_SIZE;

#[repr(C)]
pub(crate) struct PerCpuVariables {
    /// Must be first: assembly reads it at `gs:[offset]`.
    pub(crate) asm: PerCpuVariablesAsm,
    pub(crate) cpu: CpuId,
    pub(crate) gdt: Cell<Option<&'static gdt::GdtWrapper>>,
    pub(crate) tls: Cell<*mut ()>,
    /// See [`crate::cpu::local`].
    pub(crate) local: Cell<usize>,
    pub(crate) worker: crate::worker::Worker,
    pub(crate) kthread: crate::kthread::KthreadCpu,
    /// Keeps the task page table in CR3 alive (`None`: the base table).
    active_page_table: UnsafeCell<Option<(AddressSpaceId, Arc<crate::mm::PageTable<PAGE_SIZE>>)>>,
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

impl PerCpuVariables {
    // Exclusive page-aligned ends satisfy the 16-byte stack alignment.

    pub(crate) fn kernel_stack_top(&self) -> usize {
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

    pub(crate) fn active_page_table(
        &self,
        page_table_id: AddressSpaceId,
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
        page_table: Option<(AddressSpaceId, Arc<crate::mm::PageTable<PAGE_SIZE>>)>,
    ) -> Option<(AddressSpaceId, Arc<crate::mm::PageTable<PAGE_SIZE>>)> {
        // Safety: Core-local, IRQs are disabled, and the update cannot fault.
        // Return the old owner so the caller can drop it outside that section.
        unsafe { core::mem::replace(&mut *self.active_page_table.get(), page_table) }
    }
}

/// Tracks a user XSAVE area. XSAVEOPT is only valid after an XRSTOR of the
/// area. The `XSAVE_ASM`/`XRSTOR_ASM` macros use these values as literals.
#[repr(u8)]
#[derive(Clone, Copy, Default)]
pub(crate) enum XsaveState {
    /// Reset or a copy of a reset area: XSAVE sets `Saved`; XRSTOR loads it,
    /// i.e., initializes every component, and leaves `NeverSaved`.
    #[default]
    NeverSaved = 0,
    /// Use XSAVE; XRSTOR restores the saved state and sets `Restored`.
    Saved = 1,
    /// Use XSAVEOPT; XRSTOR restores the saved state.
    Restored = 2,
}

impl XsaveState {
    /// The state of a copy of an area in this state. XSAVEOPT may save to a
    /// buffer only after an XRSTOR from it, so the copy, a new buffer, is
    /// saved with XSAVE until restored.
    pub(crate) fn copied(self) -> Self {
        match self {
            Self::NeverSaved => Self::NeverSaved,
            Self::Saved | Self::Restored => Self::Saved,
        }
    }
}

const _: () = assert!(
    XsaveState::NeverSaved as u8 == 0
        && XsaveState::Saved as u8 == 1
        && XsaveState::Restored as u8 == 2
);

/// Assembly ABI: GS-relative offsets must match the `*_offset` accessors.
#[repr(C)]
#[derive(Default)]
pub(crate) struct PerCpuVariablesAsm {
    scratch: Cell<usize>,
    /// User-mode RFLAGS captured at `syscall` entry
    user_rflags: Cell<usize>,
    cur_kernel_stack_ptr: Cell<usize>,
    cur_kernel_base_ptr: Cell<usize>,
    /// Top of the `PtRegs` the user context is pushed into
    user_context_top_addr: Cell<usize>,
    /// The running thread's XSAVE area, of [`XsaveLayout::get`]'s size;
    /// zero between runs.
    ///
    /// [`XsaveLayout::get`]: litebox::arch::x86_64::xstate::XsaveLayout::get
    user_xsave_area_addr: Cell<usize>,
    /// The running thread's XSAVE area's tracking state.
    user_xsaved: Cell<XsaveState>,
    exception_trapno: Cell<u8>,
    /// 1 while inside `run_thread_arch`, i.e., while a valid thread context
    /// exists for kernel page faults to use.
    is_in_user: Cell<u8>,
}

impl PerCpuVariablesAsm {
    /// Makes a thread's `area`, with its tracking `state`, the user XSAVE
    /// area for one run. `area` must stay valid until
    /// [`Self::uninstall_user_xsave`].
    pub(crate) fn install_user_xsave(&self, area: *mut u8, state: XsaveState) {
        debug_assert!(
            self.user_xsave_area_addr.get() == 0,
            "a user XSAVE area is already installed"
        );
        self.user_xsave_area_addr.set(area as usize);
        self.user_xsaved.set(state);
    }

    /// Ends [`Self::install_user_xsave`], returning the area's tracking state.
    pub(crate) fn uninstall_user_xsave(&self) -> XsaveState {
        self.user_xsave_area_addr.set(0);
        self.user_xsaved.replace(XsaveState::NeverSaved)
    }

    /// The area [`Self::install_user_xsave`] installed, with its tracking
    /// state; `None` between runs.
    pub(crate) fn installed_user_xsave(&self) -> Option<(*const u8, XsaveState)> {
        let area = self.user_xsave_area_addr.get() as *const u8;
        (!area.is_null()).then(|| (area, self.user_xsaved.get()))
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
    pub(crate) const fn user_xsave_area_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_xsave_area_addr)
    }
    pub(crate) const fn user_xsaved_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_xsaved)
    }
    pub(crate) const fn exception_trapno_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, exception_trapno)
    }
    /// Whether a thread is in a run (see the field).
    pub(crate) fn is_in_user(&self) -> bool {
        self.is_in_user.get() != 0
    }

    pub(crate) const fn is_in_user_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, is_in_user)
    }
    pub(crate) fn exception(&self) -> litebox::shim::Exception {
        litebox::shim::Exception(self.exception_trapno.get())
    }
}

/// Requires kernel GSBASE from [`install`], and interrupts disabled, as
/// kernel code runs: code that runs with them enabled may be preempted, and
/// go on on another CPU (see [`crate::preempt::NoPreempt`]).
///
/// # Panics
/// Panics if GSBASE is not set or contains a non-canonical address; in debug
/// builds, if interrupts are enabled.
pub(crate) fn with_per_cpu_variables<F, R>(f: F) -> R
where
    F: FnOnce(&PerCpuVariables) -> R,
    R: 'static,
{
    debug_assert!(
        !x86_64::instructions::interrupts::are_enabled(),
        "per-CPU data accessed with interrupts enabled"
    );
    let ptr = per_cpu_variables_ptr();
    // Safety: only this core accesses its per-CPU data.
    let pcv = unsafe { &*ptr };
    f(pcv)
}

fn per_cpu_variables_ptr() -> *mut PerCpuVariables {
    // Safety: FSGSBASE is enabled before any per-CPU access.
    let gsbase = unsafe { rdgsbase() };
    assert!(gsbase != 0, "GSBASE not set. Call install() first");
    assert!(
        VirtAddr::try_new(gsbase as u64).is_ok(),
        "GS contains a non-canonical address"
    );
    gsbase as *mut PerCpuVariables
}

/// The mode an external interrupt interrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Interrupted {
    /// In [`crate::cpu::halt`] or [`crate::cpu::relax`], or a kernel thread:
    /// the only kernel code that takes interrupts.
    Kernel,
    User,
}

/// The CPU an external interrupt arrived on, for its handler, without GS,
/// which user mode may have changed: the kernel's GS base is GS's in
/// kernel mode, and in `IA32_KERNEL_GS_BASE` in user mode (see
/// `switch_to_user`).
pub(crate) fn interrupted_cpu(interrupted: Interrupted) -> CpuId {
    let mut base = match interrupted {
        // Safety: FSGSBASE is enabled before interrupts are.
        Interrupted::Kernel => (unsafe { rdgsbase() }) as u64,
        // Safety: reads an MSR, which has no side effects.
        Interrupted::User => unsafe { KernelGsBase::MSR.read() },
    };
    // No speculation past the choice with the other base, which user code
    // may control (as after SWAPGS); through `base`, so that neither moves
    // across it.
    // Safety: a fence only.
    unsafe {
        core::arch::asm!("lfence /* {base} */", base = inout(reg) base, options(nostack, preserves_flags));
    };
    let pcv = base as *const PerCpuVariables;
    // Safety: the CPU's variables (see above), which live for good; reads
    // only `cpu`, which never changes.
    unsafe { (&raw const (*pcv).cpu).read() }
}

/// `cpu`'s variables and stacks, for [`install`]; they live as long as the
/// CPU.
///
/// # Panics
/// Panics if the allocation fails.
pub(crate) fn allocate_per_cpu_variables(cpu: CpuId) -> &'static PerCpuVariables {
    Box::leak(Box::new(PerCpuVariables {
        asm: PerCpuVariablesAsm::default(),
        cpu,
        gdt: Cell::new(None),
        tls: Cell::new(core::ptr::null_mut()),
        local: Cell::new(0),
        worker: crate::worker::Worker::new(),
        kthread: crate::kthread::KthreadCpu::new(),
        active_page_table: UnsafeCell::new(None),
        stacks: PerCpuStacks::allocate(),
    }))
}

/// Makes `pcv` the calling CPU's.
///
/// # Safety
///
/// FSGSBASE must be enabled. `pcv` must be no other CPU's: from here on, only
/// this one may use it.
pub(crate) unsafe fn install(pcv: &'static PerCpuVariables) {
    // Safety: FSGSBASE is enabled, and `pcv` lives forever.
    unsafe { wrgsbase(core::ptr::from_ref(pcv) as usize) };
}

impl PerCpuVariables {
    /// Unmaps the guard pages of the CPU's stacks, which stay allocated. Only
    /// that CPU uses its stacks, so other CPUs' TLBs need no flush.
    pub(crate) fn unmap_stack_guards(&self, page_table: &crate::mm::PageTable<PAGE_SIZE>) {
        for offset in STACK_GUARD_OFFSETS {
            // Safety: aligned, unused guards in a leaked allocation.
            unsafe { unmap_guard(page_table, self.stacks.base + offset) };
        }
    }
}

/// Unmaps the stack guard page at `start`, keeping its frame and shared page
/// tables.
///
/// # Safety
///
/// `start` is an aligned, unused page of an allocation that is not freed
/// unless [`restore_guard`] maps the page back first.
pub(crate) unsafe fn unmap_guard(page_table: &crate::mm::PageTable<PAGE_SIZE>, start: usize) {
    let range = litebox::mm::page::PageRange::new(start, start + PAGE_SIZE)
        .expect("stack guard page must be aligned and non-empty");
    // Safety: see the function's.
    unsafe { page_table.unmap_pages(range, UnmapOptions::KEEP_FRAMES) }
        .expect("failed to unmap a stack guard page");
}

/// Maps back the guard page at `start`.
///
/// # Safety
///
/// [`unmap_guard`] unmapped it from `page_table`; its allocation is not freed.
pub(crate) unsafe fn restore_guard(page_table: &crate::mm::PageTable<PAGE_SIZE>, start: usize) {
    let page = x86_64::structures::paging::Page::from_start_address(VirtAddr::new(start as u64))
        .expect("stack guard page must be aligned");
    // Safety: a page of the heap, so of the direct map, whose tables remain.
    unsafe { page_table.remap_direct(page) };
}
