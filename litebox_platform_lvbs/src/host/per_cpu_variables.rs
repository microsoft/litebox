// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-CPU VTL1 kernel variables

use crate::{
    arch::{MAX_CORES, gdt, instrs::rdmsr},
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
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_STACK_SIZE: usize = 2 * PAGE_SIZE;
pub const EXCEPTION_STACK_SIZE: usize = PAGE_SIZE;
pub const KERNEL_STACK_SIZE: usize = 32 * PAGE_SIZE;

/// Size and alignment of [`PerCpuVariables`]. Must be a power of two so the
/// per-CPU base can be derived by masking any in-struct stack pointer.
pub const PER_CPU_ALIGN: usize = 262144;

/// Per-CPU VTL1 kernel variables
///
/// This kernel is *gsbase-less* (Coconut-SVSM-style, see issue #514): kernel
/// mode never executes `swapgs`/`rdgsbase`/`wrgsbase` and never addresses
/// through `gs:`. Instead, the per-CPU base is derived positionally from RSP:
/// the struct is aligned to **and** exactly [`PER_CPU_ALIGN`] bytes in size,
/// and every stack the kernel ever runs on after boot (kernel stack,
/// TSS.RSP0 exception stack, TSS.IST1 double-fault stack) is a field *inside*
/// this struct. Therefore `rsp & !(PER_CPU_ALIGN - 1)` recovers the struct
/// base from any kernel context. The invariant "every kernel-mode stack lives
/// inside the 256 KiB-aligned `PerCpuVariables`" is load-bearing: code must
/// never run on a foreign stack (the `self_ptr` canary converts violations
/// into panics on Rust paths). The one path with an untrusted RSP (syscall
/// entry) is anchored by per-core LSTAR stubs instead (see `syscall_entry`).
#[repr(C, align(262144))]
pub struct PerCpuVariables {
    /// Assembly-accessible fields at offset 0 (addressed as `[base + offset]`
    /// in inline asm, where `base` is the masked per-CPU pointer).
    ///
    /// All fields use `Cell<T>` for interior mutability, so they can be accessed
    /// through `&PerCpuVariables` without requiring `&mut`.
    pub(crate) asm: PerCpuVariablesAsm,
    double_fault_stack: [u8; DOUBLE_FAULT_STACK_SIZE],
    _guard_page_0: [u8; PAGE_SIZE],
    exception_stack: [u8; EXCEPTION_STACK_SIZE],
    kernel_stack: [u8; KERNEL_STACK_SIZE],
    _guard_page_1: [u8; PAGE_SIZE],
    /// The below four pages are used for communication with the hypervisor and
    /// must be page-aligned. `UnsafeCell` is used for interior mutability since
    /// the hypervisor can write to or read from them with loose Rust guarantees.
    hv_vp_assist_page: UnsafeCell<[u8; PAGE_SIZE]>,
    hv_simp_page: UnsafeCell<[u8; PAGE_SIZE]>,
    hvcall_input: UnsafeCell<[u8; PAGE_SIZE]>,
    hvcall_output: UnsafeCell<[u8; PAGE_SIZE]>,
    /// VTL0 general-purpose register state, saved/restored by the
    /// `vtl_switch` assembly via direct `[base + offset]` stores/loads.
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
    /// Set once this CPU's preemption timer is configured (see `arch::timer`).
    /// Zero-initialized to `false`.
    pub(crate) preemption_timer_enabled: Cell<bool>,
    /// True while the preemption timer is armed (see `arch::timer`).
    /// Zero-initialized to `false`.
    pub(crate) preemption_armed: Cell<bool>,
    /// Set when a preemption timer killed user-mode code.
    pub(crate) preemption_timeout_killed_user: Cell<bool>,
    /// Canary holding this struct's own address, set once by
    /// [`allocate_per_cpu_variables`]. [`get_per_cpu_variables_ptr`] asserts
    /// it against the RSP-derived base, converting any "kernel code running
    /// on a foreign stack" bug from silent corruption into a panic.
    self_ptr: Cell<usize>,
}

// These Hyper-V pages must be page-aligned.
// These compile-time assertions guard against layout regressions.
const _: () = assert!(offset_of!(PerCpuVariables, hv_vp_assist_page) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(PerCpuVariables, hv_simp_page) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(PerCpuVariables, hvcall_input) % PAGE_SIZE == 0);
const _: () = assert!(offset_of!(PerCpuVariables, hvcall_output) % PAGE_SIZE == 0);

// RSP-mask derivation requires size == align (a power of two): masking any
// address inside the struct with `!(PER_CPU_ALIGN - 1)` must yield the struct
// base. `repr(C, align(N))` rounds the size up to the alignment, so equality
// also proves the fields fit in one 256 KiB block. If a future field/stack
// growth trips this, size/align/mask must all move to 512 KiB together
// (doubling per-core memory) — a deliberate policy decision, not a tweak.
// The size == align invariant also guarantees the allocation is served by the
// buddy allocator (256 KiB > slab MAX_ALLOC_SIZE), which returns naturally
// size-aligned power-of-two blocks.
const _: () = assert!(align_of::<PerCpuVariables>() == PER_CPU_ALIGN);
const _: () = assert!(size_of::<PerCpuVariables>() == PER_CPU_ALIGN);
// Every kernel-mode stack must be strictly interior to the struct so that
// masking any RSP within it (including a full stack) recovers the base.
const _: () = {
    assert!(offset_of!(PerCpuVariables, double_fault_stack) > 0);
    assert!(
        offset_of!(PerCpuVariables, double_fault_stack) + DOUBLE_FAULT_STACK_SIZE < PER_CPU_ALIGN
    );
    assert!(offset_of!(PerCpuVariables, exception_stack) > 0);
    assert!(offset_of!(PerCpuVariables, exception_stack) + EXCEPTION_STACK_SIZE < PER_CPU_ALIGN);
    assert!(offset_of!(PerCpuVariables, kernel_stack) > 0);
    assert!(offset_of!(PerCpuVariables, kernel_stack) + KERNEL_STACK_SIZE < PER_CPU_ALIGN);
};

impl PerCpuVariables {
    const XSAVE_ALIGNMENT: usize = 64; // XSAVE and XRSTORE require a 64-byte aligned buffer
    pub const VTL1_XSAVE_MASK: u64 = 0b11; // let XSAVE and XRSTORE deal with x87 and SSE states
    // XSAVE area size for VTL1: 512 bytes (legacy x87+SSE area) + 64 bytes (XSAVE header)
    const VTL1_XSAVE_AREA_SIZE: usize = 512 + 64;

    pub fn kernel_stack_top(&self) -> u64 {
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

    pub(crate) fn hv_simp_page_as_u64(&self) -> u64 {
        self.hv_simp_page.get() as u64
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
        // SAFETY: interior mutability via `UnsafeCell`. The SynIC protocol
        // ensures the hypervisor does not concurrently write to this slot
        // while `message_type != HvMessageTypeNone`.
        let simp_page = unsafe { &mut *self.hv_simp_page.get().cast::<HvMessagePage>() };
        let msg = simp_page.sint_message[sint_index];
        simp_page.sint_message[sint_index].header.message_type = 0; // HvMessageTypeNone
        msg
    }

    /// Run a closure with a shared reference to the VP assist page.
    ///
    /// The hypervisor writes to this page *before* entering VTL1 (e.g.,
    /// `vtl_entry_reason`). No concurrent modification.
    pub(crate) fn with_vp_assist_page<R>(&self, f: impl FnOnce(&HvVpAssistPage) -> R) -> R {
        // SAFETY: interior mutability via `UnsafeCell`. The hypervisor
        // finishes writing before VTL1 entry, so no concurrent write is
        // possible while this reference exists.
        f(unsafe { &*self.hv_vp_assist_page.get().cast::<HvVpAssistPage>() })
    }

    /// Run a closure with a mutable reference to the hypercall input page,
    /// reinterpreted as `T`.
    ///
    /// **Not re-entrant**: the closure must not call back into this method,
    /// as that would create aliasing mutable references to the same page.
    pub(crate) fn with_hvcall_input<T, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        const { assert!(core::mem::size_of::<T>() <= PAGE_SIZE) };
        const { assert!(core::mem::align_of::<T>() <= PAGE_SIZE) };
        // SAFETY: interior mutability via `UnsafeCell`; the `&mut T` is
        // confined to this closure. The page is page-aligned (4096), which
        // satisfies any T with align_of::<T>() <= PAGE_SIZE.
        f(unsafe { &mut *self.hvcall_input.get().cast::<T>() })
    }

    /// Run a closure with a mutable reference to the hypercall output page,
    /// reinterpreted as `T`.
    ///
    /// **Not re-entrant**: the closure must not call back into this method,
    /// as that would create aliasing mutable references to the same page.
    pub(crate) fn with_hvcall_output<T, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        const { assert!(core::mem::size_of::<T>() <= PAGE_SIZE) };
        const { assert!(core::mem::align_of::<T>() <= PAGE_SIZE) };
        // SAFETY: interior mutability via `UnsafeCell`; the `&mut T` is
        // confined to this closure. The page is page-aligned (4096), which
        // satisfies any T with align_of::<T>() <= PAGE_SIZE.
        // The hypervisor synchronously writes to this page during the hypercall.
        f(unsafe { &mut *self.hvcall_output.get().cast::<T>() })
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
    /// Address of this core's `SyscallSlot` (see `syscall_entry`), cached so
    /// the syscall entry path can fetch the stub-spilled user `rax` with one
    /// indirection from the per-CPU base.
    syscall_slot_ptr: Cell<usize>,
    /// Scratch pad
    scratch: Cell<usize>,
    /// User-mode RFLAGS captured at `syscall` entry
    user_rflags: Cell<usize>,
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
    /// Set to 1 while inside `run_thread_arch` where TA is running or
    /// handling its syscalls/exceptions. Analogous to
    /// `is_in_guest` on the userland platforms.
    is_in_user: Cell<u8>,
}

impl PerCpuVariablesAsm {
    pub fn set_syscall_slot_ptr(&self, addr: usize) {
        self.syscall_slot_ptr.set(addr);
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
    pub const fn syscall_slot_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, syscall_slot_ptr)
    }
    pub const fn scratch_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, scratch)
    }
    pub const fn user_rflags_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, user_rflags)
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
    pub const fn is_in_user_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, is_in_user)
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
/// The caller must be executing on a stack inside this core's
/// `PerCpuVariables` (kernel/exception/double-fault stack) — true for every
/// kernel context after the boot stack switch. Boot code running on the
/// shared boot stack must not call this; it receives the pointer returned by
/// [`allocate_per_cpu_variables`] explicitly instead.
///
/// # Panics
/// Panics if the RSP-derived base fails the `self_ptr` canary check
/// (i.e., the current stack is not inside a `PerCpuVariables`).
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

/// Get a raw pointer to the current core's `PerCpuVariables` by masking RSP.
///
/// Every post-boot kernel stack lives inside the 256 KiB-aligned
/// `PerCpuVariables` (see the struct doc), so `rsp & !(PER_CPU_ALIGN - 1)`
/// is the struct base regardless of which in-struct stack is active.
///
/// # Panics
/// Panics if the derived base fails the `self_ptr` canary check. This is a
/// release-mode assert on purpose: it replaces the two release asserts the
/// old GSBASE-based accessor performed (gsbase != 0 + canonical check) at
/// cost parity (one dependent load + compare), and it turns execution on a
/// foreign stack from silent corruption into a panic.
fn get_per_cpu_variables_ptr() -> *mut PerCpuVariables {
    let rsp: usize;
    // Safety: reading RSP has no side effects.
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nomem, nostack, preserves_flags)
        );
    }
    let ptr = (rsp & !(PER_CPU_ALIGN - 1)) as *mut PerCpuVariables;
    // Safety: if the invariant holds, `ptr` is this core's PerCpuVariables;
    // if it does not, this read is the canary check that catches it (the
    // masked address is at worst a wild kernel read that faults loudly).
    assert!(
        unsafe { (*ptr).self_ptr.get() } == ptr as usize,
        "per-CPU derivation on a stack outside PerCpuVariables"
    );
    ptr
}

/// Heap-allocate this core's per-CPU variables and return them.
///
/// Every core (BSP and AP) calls this exactly once during its boot path,
/// while still on the boot stack. The returned reference must be passed
/// explicitly to boot code that needs it (e.g., to compute the kernel stack
/// pointer); [`with_per_cpu_variables`] only works after the caller has
/// switched RSP onto the in-struct kernel stack.
///
/// The caller must have already:
///   1. Enabled extended CPU states (`enable_extended_states()`).
///   2. (BSP only) Seeded the global heap (`seed_initial_heap()`).
///
/// # Panics
/// Panics if the heap allocation fails or returns a block that is not
/// `PER_CPU_ALIGN`-aligned (the RSP-mask derivation depends on it).
pub fn allocate_per_cpu_variables() -> &'static PerCpuVariables {
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
    let addr = &raw const *pcv as usize;
    // The 256 KiB layout is served by the buddy allocator, whose power-of-two
    // blocks are naturally size-aligned. Assert so any future allocator
    // change that breaks the RSP-mask invariant fails loudly here rather
    // than corrupting per-CPU state at the first masked access.
    assert!(
        addr.is_multiple_of(PER_CPU_ALIGN),
        "PerCpuVariables allocation is not PER_CPU_ALIGN-aligned"
    );
    pcv.self_ptr.set(addr);
    pcv
}

/// Allocate XSAVE areas for the current core.
///
/// Must be called **after** switching to the in-struct kernel stack (so the
/// RSP-mask accessor works). The CPUID queries and `avec!` allocations
/// inside `PerCpuVariables::allocate_xsave_area` also use significant stack
/// space that exceeds the 4 KiB boot stack.
pub fn allocate_xsave_area() {
    with_per_cpu_variables(|pcv| {
        PerCpuVariables::allocate_xsave_area(&pcv.asm);
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
