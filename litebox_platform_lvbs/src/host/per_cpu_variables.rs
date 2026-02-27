// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-CPU VTL1 kernel variables

use crate::{
    arch::{gdt, instrs::rdmsr},
    mshv::{
        HV_REGISTER_VP_INDEX, HvMessage, HvMessagePage, HvVpAssistPage, vsm::ControlRegMap,
        vtl_switch::VtlState, vtl1_mem_layout::PAGE_SIZE,
    },
};
use aligned_vec::avec;
use alloc::boxed::Box;
use core::cell::{Cell, UnsafeCell};
use core::mem::offset_of;
use litebox::utils::TruncateExt;
use litebox_common_linux::{rdgsbase, wrgsbase};
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_STACK_SIZE: usize = 2 * PAGE_SIZE;
pub const EXCEPTION_STACK_SIZE: usize = PAGE_SIZE;
pub const KERNEL_STACK_SIZE: usize = 10 * PAGE_SIZE;

/// Per-CPU VTL1 kernel variables
#[repr(C, align(4096))]
pub struct PerCpuVariables {
    /// Assembly-accessible fields at GS offset 0 (`gs:[offset]` in inline asm).
    ///
    /// All fields use `Cell<T>` for interior mutability, so they can be accessed
    /// through `&PerCpuVariables` without requiring `&mut`.
    pub(crate) asm: PerCpuVariablesAsm,
    /// The hypervisor writes to this page asynchronously (e.g., `vtl_entry_reason`),
    /// so `UnsafeCell` is required for soundness even though Rust only reads it.
    hv_vp_assist_page: UnsafeCell<[u8; PAGE_SIZE]>,
    hv_simp_page: UnsafeCell<[u8; PAGE_SIZE]>,
    double_fault_stack: [u8; DOUBLE_FAULT_STACK_SIZE],
    _guard_page_0: [u8; PAGE_SIZE],
    exception_stack: [u8; EXCEPTION_STACK_SIZE],
    kernel_stack: [u8; KERNEL_STACK_SIZE],
    _guard_page_1: [u8; PAGE_SIZE],
    hvcall_input: UnsafeCell<[u8; PAGE_SIZE]>,
    hvcall_output: UnsafeCell<[u8; PAGE_SIZE]>,
    /// VTL0 general-purpose register state, saved/restored by assembly
    /// (`SAVE_VTL_STATE_ASM`/`LOAD_VTL_STATE_ASM`) via raw pushes/pops to
    /// the address cached in `PerCpuVariablesAsm::vtl0_state_top_addr`.
    /// Rust code accesses it only between save and load (i.e., while VTL1
    /// is executing), so there is no data race with the assembly.
    pub(crate) vtl0_state: Cell<VtlState>,
    pub(crate) vtl0_locked_regs: Cell<ControlRegMap>,
    pub(crate) gdt: Cell<Option<&'static gdt::GdtWrapper>>,
    pub(crate) tls: Cell<VirtAddr>,
    /// Cached VP index from the hypervisor. Lazily initialized on first access
    /// via `rdmsr(HV_REGISTER_VP_INDEX)` and immutable thereafter.
    /// Uses `u32::MAX` as the "uninitialized" sentinel.
    vp_index: Cell<u32>,

    // Debug-only re-entrancy guards for closure-based accessors.
    #[cfg(debug_assertions)]
    hvcall_input_in_use: Cell<bool>,
    #[cfg(debug_assertions)]
    hvcall_output_in_use: Cell<bool>,
    #[cfg(debug_assertions)]
    simp_page_in_use: Cell<bool>,
    #[cfg(debug_assertions)]
    vp_assist_page_in_use: Cell<bool>,
}

// These Hyper-V pages must be page-aligned.
// These compile-time assertions guard against layout regressions.
const _: () = assert!(offset_of!(PerCpuVariables, hv_vp_assist_page) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(PerCpuVariables, hv_simp_page) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(PerCpuVariables, hvcall_input) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(PerCpuVariables, hvcall_output) % PAGE_SIZE == 0);

impl PerCpuVariables {
    const XSAVE_ALIGNMENT: usize = 64; // XSAVE and XRSTORE require a 64-byte aligned buffer
    pub const VTL1_XSAVE_MASK: u64 = 0b11; // let XSAVE and XRSTORE deal with x87 and SSE states
    // XSAVE area size for VTL1: 512 bytes (legacy x87+SSE area) + 64 bytes (XSAVE header)
    const VTL1_XSAVE_AREA_SIZE: usize = 512 + 64;

    pub(crate) fn kernel_stack_top(&self) -> u64 {
        &raw const self.kernel_stack as u64 + (self.kernel_stack.len() - 1) as u64
    }

    pub(crate) fn double_fault_stack_top(&self) -> u64 {
        &raw const self.double_fault_stack as u64 + (self.double_fault_stack.len() - 1) as u64
    }

    pub(crate) fn exception_stack_top(&self) -> u64 {
        &raw const self.exception_stack as u64 + (self.exception_stack.len() - 1) as u64
    }

    pub(crate) fn hv_vp_assist_page_as_u64(&self) -> u64 {
        self.hv_vp_assist_page.get() as u64
    }

    /// Run a closure with a shared reference to the VP assist page.
    ///
    /// The hypervisor writes to this page *before* entering VTL1 (e.g.,
    /// `vtl_entry_reason`). No concurrent modification.
    pub(crate) fn with_vp_assist_page<R>(&self, f: impl FnOnce(&HvVpAssistPage) -> R) -> R {
        #[cfg(debug_assertions)]
        {
            assert!(
                !self.vp_assist_page_in_use.get(),
                "with_vp_assist_page called re-entrantly"
            );
            self.vp_assist_page_in_use.set(true);
        }
        // SAFETY: interior mutability via `UnsafeCell`. The hypervisor
        // finishes writing before VTL1 entry, so no concurrent write is
        // possible while this reference exists.
        let result = f(unsafe { &*self.hv_vp_assist_page.get().cast::<HvVpAssistPage>() });
        #[cfg(debug_assertions)]
        self.vp_assist_page_in_use.set(false);
        result
    }

    /// Take the pending SynIC message from SIMP slot `sint_index`.
    ///
    /// Returns a copy of the message and clears the slot's `message_type`
    /// to `HvMessageTypeNone`, signaling the hypervisor that the slot is
    /// free for reuse.
    ///
    /// This is safe because the SynIC protocol guarantees the hypervisor
    /// will not overwrite a slot whose `message_type` is non-zero. By
    /// reading first and clearing last, no concurrent write is possible.
    pub(crate) fn take_sint_message(&self, sint_index: usize) -> HvMessage {
        #[cfg(debug_assertions)]
        {
            assert!(
                !self.simp_page_in_use.get(),
                "take_sint_message called re-entrantly"
            );
            self.simp_page_in_use.set(true);
        }
        // SAFETY: interior mutability via `UnsafeCell`. The SynIC protocol
        // ensures the hypervisor does not concurrently write to this slot
        // while `message_type != HvMessageTypeNone`.
        let simp_page = unsafe { &mut *self.hv_simp_page.get().cast::<HvMessagePage>() };
        let msg = simp_page.sint_message[sint_index];
        simp_page.sint_message[sint_index].header.message_type = 0; // HvMessageTypeNone
        #[cfg(debug_assertions)]
        self.simp_page_in_use.set(false);
        msg
    }

    pub(crate) fn hv_simp_page_as_u64(&self) -> u64 {
        self.hv_simp_page.get() as u64
    }

    /// Run a closure with a mutable reference to the hypercall input page,
    /// reinterpreted as `T`.
    ///
    /// # Panics
    /// - Compile-time: if `size_of::<T>() > PAGE_SIZE` or `align_of::<T>() > PAGE_SIZE`.
    /// - Debug builds: if called re-entrantly (would create aliasing `&mut`).
    pub(crate) fn with_hvcall_input<T, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        const { assert!(core::mem::size_of::<T>() <= PAGE_SIZE) };
        const { assert!(core::mem::align_of::<T>() <= PAGE_SIZE) };
        #[cfg(debug_assertions)]
        {
            assert!(
                !self.hvcall_input_in_use.get(),
                "with_hvcall_input called re-entrantly"
            );
            self.hvcall_input_in_use.set(true);
        }
        // SAFETY: interior mutability via `UnsafeCell`; the `&mut T` is
        // confined to this closure. The page is page-aligned (4096), which
        // satisfies any T with align_of::<T>() <= PAGE_SIZE.
        let result = f(unsafe { &mut *self.hvcall_input.get().cast::<T>() });
        #[cfg(debug_assertions)]
        self.hvcall_input_in_use.set(false);
        result
    }

    /// Run a closure with a mutable reference to the hypercall output page,
    /// reinterpreted as `T`.
    ///
    /// # Panics
    /// - Compile-time: if `size_of::<T>() > PAGE_SIZE` or `align_of::<T>() > PAGE_SIZE`.
    /// - Debug builds: if called re-entrantly (would create aliasing `&mut`).
    pub(crate) fn with_hvcall_output<T, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        const { assert!(core::mem::size_of::<T>() <= PAGE_SIZE) };
        const { assert!(core::mem::align_of::<T>() <= PAGE_SIZE) };
        #[cfg(debug_assertions)]
        {
            assert!(
                !self.hvcall_output_in_use.get(),
                "with_hvcall_output called re-entrantly"
            );
            self.hvcall_output_in_use.set(true);
        }
        // SAFETY: interior mutability via `UnsafeCell`; the `&mut T` is
        // confined to this closure. The page is page-aligned (4096), which
        // satisfies any T with align_of::<T>() <= PAGE_SIZE.
        // The hypervisor synchronously writes to this page during the hypercall.
        let result = f(unsafe { &mut *self.hvcall_output.get().cast::<T>() });
        #[cfg(debug_assertions)]
        self.hvcall_output_in_use.set(false);
        result
    }

    pub fn set_vtl_return_value(&self, value: u64) {
        let mut state = self.vtl0_state.get();
        state.r8 = value; // LVBS uses R8 to return a value from VTL1 to VTL0
        self.vtl0_state.set(state);
    }

    /// Return the cached Hyper-V VP index for this core (which never changes during
    /// the lifetime of the core).
    ///
    /// # Panics
    /// Panics if the VP index returned by the hypervisor is ≥ `MAX_CORES`.
    pub fn vp_index(&self) -> u32 {
        let idx = self.vp_index.get();
        if idx == u32::MAX {
            let vp_index: u32 = rdmsr(HV_REGISTER_VP_INDEX).truncate();
            assert!(
                vp_index < u32::MAX,
                "Hypervisor returned an invalid VP index"
            );
            self.vp_index.set(vp_index);
            vp_index
        } else {
            idx
        }
    }

    /// Return kernel code, user code, and user data segment selectors
    pub(crate) fn get_segment_selectors(&self) -> Option<(u16, u16, u16)> {
        self.gdt.get().map(gdt::GdtWrapper::get_segment_selectors)
    }

    /// Allocate XSAVE areas for saving/restoring the extended states of each core.
    /// These buffers are allocated once and never deallocated.
    ///
    /// VTL0 xsave area address and mask are stored directly in the provided `PerCpuVariablesAsm`
    /// for assembly access. VTL1 kernel and user xsave area addresses are also stored in
    /// `PerCpuVariablesAsm` for assembly-based save/restore in `run_thread_arch`.
    pub(crate) fn allocate_xsave_area(pcv_asm: &PerCpuVariablesAsm) {
        assert!(
            pcv_asm.vtl1_kernel_xsave_area_addr.get() == 0,
            "XSAVE areas are already allocated"
        );
        // We should use VTL0's XSAVE mask (XCR0) to save and restore VTL0's extended states
        // to satisfy the requirement of XSAVE/XRSTOR instructions.
        // Hyper-V VTLs share the same XCR0 register, so we use xgetbv instruction.
        // Here, we cache VTL0's XSAVE mask for better performance. This is safe because
        // Linux kernel (VTL0) initializes XCR0 during boot and does not expands it to
        // cover other extended states (which require nontrivial per-CPU xsave buffer changes).
        let vtl0_xsave_mask = xgetbv0();
        let vtl1_xsave_mask = PerCpuVariables::VTL1_XSAVE_MASK;
        assert_eq!(
            vtl1_xsave_mask & !vtl0_xsave_mask,
            0,
            "VTL1 cannot have extended states that VTL0 does not enable"
        );
        let vtl0_xsave_area_size = get_xsave_area_size();
        // Leaking `xsave_area` buffers are okay because they are never reused
        // until the core gets reset.
        // TODO: let's revisit this if VTL0 is allowed to modify XCR0 such that xsave area size may change.
        let vtl0_xsave_area = Box::leak(
            avec![[{ Self::XSAVE_ALIGNMENT }] | 0u8; vtl0_xsave_area_size]
                .into_boxed_slice()
                .into(),
        );
        let vtl1_kernel_xsave_area = Box::leak(
            avec![[{ Self::XSAVE_ALIGNMENT }] | 0u8; Self::VTL1_XSAVE_AREA_SIZE]
                .into_boxed_slice()
                .into(),
        );
        let vtl1_user_xsave_area = Box::leak(
            avec![[{ Self::XSAVE_ALIGNMENT }] | 0u8; Self::VTL1_XSAVE_AREA_SIZE]
                .into_boxed_slice()
                .into(),
        );
        // Store VTL0 xsave values directly in PerCpuVariablesAsm for assembly access
        pcv_asm.set_vtl0_xsave_area_addr(vtl0_xsave_area.as_ptr() as usize);
        pcv_asm.set_vtl0_xsave_mask(vtl0_xsave_mask);
        // Store VTL1 kernel and user xsave area addresses in PerCpuVariablesAsm for assembly access
        pcv_asm.set_vtl1_kernel_xsave_area_addr(vtl1_kernel_xsave_area.as_ptr() as usize);
        pcv_asm.set_vtl1_user_xsave_area_addr(vtl1_user_xsave_area.as_ptr() as usize);
        pcv_asm.set_vtl1_xsave_mask(vtl1_xsave_mask);
    }
}

/// Assembly-accessible per-CPU fields at the start of [`PerCpuVariables`].
///
/// Unlike `litebox_platform_linux_userland`, this kernel platform does not rely on
/// the `tbss` section to specify FS/GS offsets for per CPU variables because
/// there is no ELF loader that will set up it.
///
/// Note that kernel & host and user & guest are interchangeable in this context.
/// We use "kernel" and "user" here to emphasize that there must be hardware-enforced
/// mode transitions (i.e., ring transitions through iretq/syscall) unlike userland
/// platforms.
///
/// Page-aligned (`align(4096)`) so that the following fields in
/// [`PerCpuVariables`] (HV pages, stacks, etc.) remain page-aligned.
#[non_exhaustive]
#[cfg(target_arch = "x86_64")]
#[repr(C, align(4096))]
#[derive(Clone)]
pub struct PerCpuVariablesAsm {
    /// Initial kernel stack pointer to reset the kernel stack on VTL switch
    kernel_stack_ptr: Cell<usize>,
    /// Double fault stack pointer (TSS.IST1)
    double_fault_stack_ptr: Cell<usize>,
    /// Exception stack pointer (TSS.RSP0)
    exception_stack_ptr: Cell<usize>,
    /// Return address for call-based VTL switching
    vtl_return_addr: Cell<usize>,
    /// Scratch pad
    scratch: Cell<usize>,
    /// Top address of VTL0 VtlState
    vtl0_state_top_addr: Cell<usize>,
    /// Current kernel stack pointer
    cur_kernel_stack_ptr: Cell<usize>,
    /// Current kernel base pointer
    cur_kernel_base_ptr: Cell<usize>,
    /// Top address of the user context area
    user_context_top_addr: Cell<usize>,
    /// Address of the VTL0 XSAVE area
    vtl0_xsave_area_addr: Cell<usize>,
    /// Lower 32 bits of VTL0 XSAVE mask (for eax in xsave/xrstor)
    vtl0_xsave_mask_lo: Cell<u32>,
    /// Upper 32 bits of VTL0 XSAVE mask (for edx in xsave/xrstor)
    vtl0_xsave_mask_hi: Cell<u32>,
    /// Address of the VTL1 kernel XSAVE area (saved/restored in run_thread_arch)
    vtl1_kernel_xsave_area_addr: Cell<usize>,
    /// Address of the VTL1 user XSAVE area (saved/restored around user mode transitions)
    vtl1_user_xsave_area_addr: Cell<usize>,
    /// Lower 32 bits of VTL1 XSAVE mask (for eax in xsave/xrstor)
    vtl1_xsave_mask_lo: Cell<u32>,
    /// Upper 32 bits of VTL1 XSAVE mask (for edx in xsave/xrstor)
    vtl1_xsave_mask_hi: Cell<u32>,
    /// XSAVE/XRSTOR state tracking for VTL1 kernel:
    ///   0: never saved - XSAVE uses plain xsave, XRSTOR skips
    ///   1: saved but not restored - XSAVE uses plain xsave, XRSTOR executes and sets to 2
    ///   2: restored at least once - XSAVE uses xsaveopt (safe), XRSTOR executes
    /// Reset to 0 at each VTL1 entry (OP-TEE SMC call) since returning to VTL0 invalidates CPU tracking.
    vtl1_kernel_xsaved: Cell<u8>,
    /// XSAVE/XRSTOR state tracking for VTL1 user (see `vtl1_kernel_xsaved` for state values and reset).
    vtl1_user_xsaved: Cell<u8>,
    /// Exception info: exception vector number
    exception_trapno: Cell<u8>,
}

impl PerCpuVariablesAsm {
    pub fn set_kernel_stack_ptr(&self, sp: usize) {
        self.kernel_stack_ptr.set(sp);
    }
    pub fn set_double_fault_stack_ptr(&self, sp: usize) {
        self.double_fault_stack_ptr.set(sp);
    }
    pub fn get_double_fault_stack_ptr(&self) -> usize {
        self.double_fault_stack_ptr.get()
    }
    pub fn set_exception_stack_ptr(&self, sp: usize) {
        self.exception_stack_ptr.set(sp);
    }
    pub fn get_exception_stack_ptr(&self) -> usize {
        self.exception_stack_ptr.get()
    }
    pub fn set_vtl_return_addr(&self, addr: usize) {
        self.vtl_return_addr.set(addr);
    }
    pub fn get_vtl_return_addr(&self) -> usize {
        self.vtl_return_addr.get()
    }
    pub fn set_vtl0_state_top_addr(&self, addr: usize) {
        self.vtl0_state_top_addr.set(addr);
    }
    pub fn set_vtl0_xsave_area_addr(&self, addr: usize) {
        self.vtl0_xsave_area_addr.set(addr);
    }
    pub fn set_vtl0_xsave_mask(&self, mask: u64) {
        self.vtl0_xsave_mask_lo.set((mask & 0xffff_ffff) as u32);
        self.vtl0_xsave_mask_hi
            .set(((mask >> 32) & 0xffff_ffff) as u32);
    }
    pub fn set_vtl1_kernel_xsave_area_addr(&self, addr: usize) {
        self.vtl1_kernel_xsave_area_addr.set(addr);
    }
    pub fn set_vtl1_user_xsave_area_addr(&self, addr: usize) {
        self.vtl1_user_xsave_area_addr.set(addr);
    }
    pub fn set_vtl1_xsave_mask(&self, mask: u64) {
        self.vtl1_xsave_mask_lo.set((mask & 0xffff_ffff) as u32);
        self.vtl1_xsave_mask_hi
            .set(((mask >> 32) & 0xffff_ffff) as u32);
    }
    pub const fn kernel_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, kernel_stack_ptr)
    }
    pub const fn double_fault_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, double_fault_stack_ptr)
    }
    pub const fn exception_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, exception_stack_ptr)
    }
    pub const fn vtl_return_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl_return_addr)
    }
    pub const fn scratch_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, scratch)
    }
    pub const fn vtl0_state_top_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl0_state_top_addr)
    }
    pub const fn cur_kernel_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, cur_kernel_stack_ptr)
    }
    pub const fn cur_kernel_base_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, cur_kernel_base_ptr)
    }
    pub const fn user_context_top_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_context_top_addr)
    }
    pub const fn vtl0_xsave_area_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl0_xsave_area_addr)
    }
    pub const fn vtl0_xsave_mask_lo_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl0_xsave_mask_lo)
    }
    pub const fn vtl0_xsave_mask_hi_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl0_xsave_mask_hi)
    }
    pub const fn vtl1_kernel_xsave_area_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl1_kernel_xsave_area_addr)
    }
    pub const fn vtl1_user_xsave_area_addr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl1_user_xsave_area_addr)
    }
    pub const fn vtl1_xsave_mask_lo_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl1_xsave_mask_lo)
    }
    pub const fn vtl1_xsave_mask_hi_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl1_xsave_mask_hi)
    }
    pub const fn vtl1_kernel_xsaved_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl1_kernel_xsaved)
    }
    pub const fn vtl1_user_xsaved_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl1_user_xsaved)
    }
    pub const fn exception_trapno_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, exception_trapno)
    }
    pub fn get_exception(&self) -> litebox::shim::Exception {
        litebox::shim::Exception(self.exception_trapno.get())
    }
    pub fn get_user_context_top_addr(&self) -> usize {
        self.user_context_top_addr.get()
    }
    /// Reset VTL1 xsaved flags to 0 at each VTL1 entry (OP-TEE SMC call).
    /// This ensures:
    /// - XRSTOR is skipped until XSAVE populates valid data (no spurious restores on fresh entry)
    /// - XSAVEOPT is only used after XRSTOR establishes tracking within this VTL1 invocation
    pub fn reset_vtl1_xsaved(&self) {
        self.vtl1_kernel_xsaved.set(0);
        self.vtl1_user_xsaved.set(0);
    }
}

/// Execute a closure with a shared reference to the current core's per-CPU variables.
///
/// # Safety
/// The GSBASE register must point to a valid, heap-allocated `PerCpuVariables`
/// (set by [`allocate_per_cpu_variables`]). Each core must have a distinct
/// GSBASE value.
///
/// # Panics
/// Panics if GSBASE is not set or contains a non-canonical address.
pub fn with_per_cpu_variables<F, R>(f: F) -> R
where
    F: FnOnce(&PerCpuVariables) -> R,
    R: Sized + 'static,
{
    let ptr = get_per_cpu_variables_ptr();
    // Safety: per-CPU data is exclusive to this core; no other core can
    // access it.
    let pcv = unsafe { &*ptr };
    f(pcv)
}

/// Get a raw pointer to the current core's `PerCpuVariables` from GSBASE.
///
/// # Panics
/// Panics if GSBASE is zero or non-canonical.
fn get_per_cpu_variables_ptr() -> *mut PerCpuVariables {
    let gsbase = unsafe { rdgsbase() };
    assert!(
        gsbase != 0,
        "GSBASE not set. Call allocate_per_cpu_variables() first"
    );
    let _ = VirtAddr::try_new(gsbase as u64).expect("GS contains a non-canonical address");
    gsbase as *mut PerCpuVariables
}

/// Heap-allocate this core's per-CPU variables and set GSBASE to point at them.
///
/// Every core (BSP and AP) calls this exactly once during its boot path,
/// **before** [`init_per_cpu_variables`].
///
/// GSBASE will point directly at the `PerCpuVariables` struct, so assembly
/// code can access the `asm` field at GS offset 0 (guaranteed by `#[repr(C)]`).
///
/// The caller must have already:
///   1. Enabled FSGSBASE (`enable_fsgsbase()`).
///   2. Enabled extended CPU states (`enable_extended_states()`).
///   3. (BSP only) Seeded the global heap (`seed_initial_heap()`).
///
/// # Panics
/// Panics if the heap allocation fails.
pub fn allocate_per_cpu_variables() {
    let mut per_cpu_variables = Box::<PerCpuVariables>::new_uninit();
    // Safety: `PerCpuVariables` is too large for the stack, so we zero-init
    // via `write_bytes` then fix up the `vp_index` sentinel. Zero is valid
    // for all other field types:
    // - `[u8; N]`, `VtlState`, `ControlRegMap`: all-zeroes is their default.
    // - `Cell<T>` / `UnsafeCell<T>`: `#[repr(transparent)]`, same as inner T.
    let per_cpu_variables = unsafe {
        let ptr = per_cpu_variables.as_mut_ptr();
        ptr.write_bytes(0, 1);
        // Set the "uninitialized" sentinel for vp_index (0 is a valid VP index).
        core::ptr::addr_of_mut!((*ptr).vp_index).write(Cell::new(u32::MAX));
        per_cpu_variables.assume_init()
    };

    // Leak the box so it lives for the core's lifetime.
    let pcv = Box::leak(per_cpu_variables);
    let addr = &raw const *pcv as u64;
    unsafe {
        wrgsbase(addr.truncate());
    }
}

/// Allocate XSAVE areas for the current core.
///
/// Must be called **after** [`allocate_per_cpu_variables`] (so GSBASE is
/// set) and **after** switching to the kernel stack. The CPUID queries and
/// `avec!` allocations inside `PerCpuVariables::allocate_xsave_area` use
/// significant stack space that exceeds the 4 KiB boot stack.
pub fn allocate_xsave_area() {
    with_per_cpu_variables(|pcv| {
        PerCpuVariables::allocate_xsave_area(&pcv.asm);
    });
}

/// Initialize PerCpuVariable and PerCpuVariableAsm for the current core.
///
/// Currently, it initializes the kernel and interrupt stack pointers and the top address of VTL0 VtlState
/// in the PerCpuVariablesAsm area.
///
/// # Panics
/// Panics if the per-CPU variables are not properly initialized.
pub fn init_per_cpu_variables() {
    const STACK_ALIGNMENT: usize = 16;
    with_per_cpu_variables(|per_cpu_variables| {
        let kernel_sp = TruncateExt::<usize>::truncate(per_cpu_variables.kernel_stack_top())
            & !(STACK_ALIGNMENT - 1);
        let double_fault_sp =
            TruncateExt::<usize>::truncate(per_cpu_variables.double_fault_stack_top())
                & !(STACK_ALIGNMENT - 1);
        let exception_sp = TruncateExt::<usize>::truncate(per_cpu_variables.exception_stack_top())
            & !(STACK_ALIGNMENT - 1);
        // `Cell<VtlState>` is `#[repr(transparent)]`, so its address equals
        // the inner `VtlState`'s address. Assembly code (`SAVE_VTL_STATE_ASM`
        // / `LOAD_VTL_STATE_ASM`) pushes/pops registers directly to/from this
        // address. This is sound because the assembly executes outside any
        // Rust reference scope and the Cell is only accessed in Rust between
        // the save and load points (i.e., while VTL1 is executing).
        let vtl0_state_top_addr =
            TruncateExt::<usize>::truncate(&raw const per_cpu_variables.vtl0_state as u64)
                + core::mem::size_of::<VtlState>();
        per_cpu_variables.asm.set_kernel_stack_ptr(kernel_sp);
        per_cpu_variables
            .asm
            .set_double_fault_stack_ptr(double_fault_sp);
        per_cpu_variables.asm.set_exception_stack_ptr(exception_sp);
        per_cpu_variables
            .asm
            .set_vtl0_state_top_addr(vtl0_state_top_addr);
    });
}

/// Get the XSAVE area size for VTL0 based on enabled features in XCR0
///
/// VTL0 and VTL1 share the same XCR0 register. This function assumes that VTL1 maintains VTL0's
/// XCR0. If VTL1 should program XCR0, we need to save and restore VTL0's XCR0 and call
/// this function against the stored value.
/// In addition, HVCI/HEKI prevents VTL0 from modifying XCR0.
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
    // Safety: We have already verified XSAVE support in get_xsave_area_size()
    // which is called before any xgetbv0() call.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") 0,
            out("eax") eax,
            out("edx") edx,
            options(nostack, preserves_flags)
        );
    }
    (u64::from(edx) << 32) | u64::from(eax)
}
