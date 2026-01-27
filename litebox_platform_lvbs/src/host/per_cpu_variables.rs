// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-CPU VTL1 kernel variables

use crate::{
    arch::{MAX_CORES, gdt, get_core_id},
    host::bootparam::get_num_possible_cpus,
    mshv::{
        HvMessagePage, HvVpAssistPage,
        vsm::{ControlRegMap, NUM_CONTROL_REGS},
        vtl_switch::VtlState,
        vtl1_mem_layout::PAGE_SIZE,
    },
};
use aligned_vec::avec;
use alloc::boxed::Box;
use core::cell::{Cell, RefCell};
use core::mem::offset_of;
use litebox_common_linux::{rdgsbase, wrgsbase};
use x86_64::VirtAddr;

pub const INTERRUPT_STACK_SIZE: usize = 2 * PAGE_SIZE;
pub const KERNEL_STACK_SIZE: usize = 10 * PAGE_SIZE;

/// Per-CPU VTL1 kernel variables
#[repr(align(4096))]
#[derive(Clone, Copy)]
pub struct PerCpuVariables {
    hv_vp_assist_page: [u8; PAGE_SIZE],
    hv_simp_page: [u8; PAGE_SIZE],
    interrupt_stack: [u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [u8; PAGE_SIZE],
    kernel_stack: [u8; KERNEL_STACK_SIZE],
    _guard_page_1: [u8; PAGE_SIZE],
    hvcall_input: [u8; PAGE_SIZE],
    hvcall_output: [u8; PAGE_SIZE],
    pub vtl0_state: VtlState,
    pub vtl0_locked_regs: ControlRegMap,
    pub gdt: Option<&'static gdt::GdtWrapper>,
    vtl1_xsave_area_addr: VirtAddr,
    vtl1_xsaved: bool,
    pub tls: VirtAddr,
}

impl PerCpuVariables {
    const XSAVE_ALIGNMENT: usize = 64; // XSAVE and XRSTORE require a 64-byte aligned buffer
    const VTL1_XSAVE_MASK: u64 = 0b11; // let XSAVE and XRSTORE deal with x87 and SSE states
    // XSAVE area size for VTL1: 512 bytes (legacy x87+SSE area) + 64 bytes (XSAVE header)
    const VTL1_XSAVE_AREA_SIZE: usize = 512 + 64;

    pub(crate) fn kernel_stack_top(&self) -> u64 {
        &raw const self.kernel_stack as u64 + (self.kernel_stack.len() - 1) as u64
    }

    pub(crate) fn interrupt_stack_top(&self) -> u64 {
        &raw const self.interrupt_stack as u64 + (self.interrupt_stack.len() - 1) as u64
    }

    pub(crate) fn hv_vp_assist_page_as_ptr(&self) -> *const HvVpAssistPage {
        (&raw const self.hv_vp_assist_page).cast::<HvVpAssistPage>()
    }

    pub(crate) fn hv_vp_assist_page_as_u64(&self) -> u64 {
        &raw const self.hv_vp_assist_page as u64
    }

    pub(crate) fn hv_simp_page_as_mut_ptr(&mut self) -> *mut HvMessagePage {
        (&raw mut self.hv_simp_page).cast::<HvMessagePage>()
    }

    pub(crate) fn hv_simp_page_as_u64(&self) -> u64 {
        &raw const self.hv_simp_page as u64
    }

    pub(crate) fn hv_hypercall_input_page_as_mut_ptr(&mut self) -> *mut [u8; PAGE_SIZE] {
        &raw mut self.hvcall_input
    }

    pub(crate) fn hv_hypercall_output_page_as_mut_ptr(&mut self) -> *mut [u8; PAGE_SIZE] {
        &raw mut self.hvcall_output
    }

    pub(crate) fn set_vtl_return_value(&mut self, value: u64) {
        self.vtl0_state.r8 = value; // LVBS uses R8 to return a value from VTL1 to VTL0
    }

    /// Return kernel code, user code, and user data segment selectors
    pub(crate) fn get_segment_selectors(&self) -> Option<(u16, u16, u16)> {
        self.gdt.map(gdt::GdtWrapper::get_segment_selectors)
    }

    /// Allocate XSAVE areas for saving/restoring the extended states of each core.
    /// These buffers are allocated once and never deallocated.
    ///
    /// VTL0 xsave area address and mask are stored directly in the provided `PerCpuVariablesAsm`
    /// for assembly access. VTL1 xsave area address is stored in `PerCpuVariables` for Rust code.
    pub(crate) fn allocate_xsave_area(&mut self, pcv_asm: &PerCpuVariablesAsm) {
        assert!(
            self.vtl1_xsave_area_addr.is_null(),
            "XSAVE areas are already allocated"
        );
        // We should use VTL0's XSAVE mask (XCR0) to save and restore VTL0's extended states
        // to satisfy the requirement of XSAVE/XRSTOR instructions.
        // Hyper-V VTLs share the same XCR0 register, so we use xgetbv instruction.
        // Here, we cache VTL0's XSAVE mask for better performance. This is safe because
        // Linux kernel (VTL0) initializes XCR0 during boot and does not expands it to
        // cover other extended states (which require nontrivial per-CPU xsave buffer changes).
        let vtl0_xsave_mask = xgetbv0();
        assert_eq!(
            Self::VTL1_XSAVE_MASK & !vtl0_xsave_mask,
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
        let vtl1_xsave_area = Box::leak(
            avec![[{ Self::XSAVE_ALIGNMENT }] | 0u8; Self::VTL1_XSAVE_AREA_SIZE]
                .into_boxed_slice()
                .into(),
        );
        // Store VTL0 xsave values directly in PerCpuVariablesAsm for assembly access
        pcv_asm.set_vtl0_xsave_area_addr(vtl0_xsave_area.as_ptr() as usize);
        pcv_asm.set_vtl0_xsave_mask(vtl0_xsave_mask);
        self.vtl1_xsave_area_addr = VirtAddr::new(vtl1_xsave_area.as_ptr() as u64);
    }

    /// Save VTL1 extended states (x87, SSE).
    ///
    /// NOTE: VTL0 extended states are saved/restored in assembly (`vtl_switch_loop_asm`).
    ///
    /// NOTE: We use standard XSAVE format (not compacted XSAVES) because XSAVES causes GP fault
    /// in VTL1. This may be due to Hyper-V not virtualizing XSAVES/XRSTORS for VTL1 or requiring
    /// specific IA32_XSS MSR configuration.
    pub(crate) fn save_vtl1_extended_states(&mut self) {
        assert!(
            !self.vtl1_xsave_area_addr.is_null(),
            "VTL1 XSAVE area is not allocated"
        );
        let xsave_area_addr = self.vtl1_xsave_area_addr.as_u64();
        let mask = Self::VTL1_XSAVE_MASK;
        // The first instruction to save the extended states must be XSAVE,
        // and subsequent instructions can use XSAVEOPT for better performance.
        // Safety: xsave_area_addr is valid and properly aligned
        unsafe {
            if self.vtl1_xsaved {
                core::arch::asm!(
                    "xsaveopt [{}]",
                    in(reg) xsave_area_addr,
                    in("eax") mask & 0xffff_ffff,
                    in("edx") (mask & 0xffff_ffff_0000_0000) >> 32,
                    options(nostack, preserves_flags)
                );
            } else {
                core::arch::asm!(
                    "xsave [{}]",
                    in(reg) xsave_area_addr,
                    in("eax") mask & 0xffff_ffff,
                    in("edx") (mask & 0xffff_ffff_0000_0000) >> 32,
                    options(nostack, preserves_flags)
                );
                self.vtl1_xsaved = true;
            }
        }
    }

    /// Restore VTL1 extended states (x87, SSE).
    ///
    /// NOTE: VTL0 extended states are saved/restored in assembly (`vtl_switch_loop_asm`).
    ///
    /// This function is a no-op if the state was never saved.
    pub(crate) fn restore_vtl1_extended_states(&self) {
        assert!(
            !self.vtl1_xsave_area_addr.is_null(),
            "VTL1 XSAVE area is not allocated"
        );
        // Skip restore if state was never saved
        if !self.vtl1_xsaved {
            return;
        }
        let xsave_area_addr = self.vtl1_xsave_area_addr.as_u64();
        let mask = Self::VTL1_XSAVE_MASK;
        // Safety: xsave_area_addr is valid, properly aligned, and contains
        // valid XSAVE data from a previous save_vtl1_extended_states() call.
        unsafe {
            core::arch::asm!(
                "xrstor [{}]",
                in(reg) xsave_area_addr,
                in("eax") mask & 0xffff_ffff,
                in("edx") (mask & 0xffff_ffff_0000_0000) >> 32,
                options(nostack, preserves_flags)
            );
        }
    }
}

/// per-CPU variables for core 0 (or BSP). This must use static memory because kernel heap is not ready.
static mut BSP_VARIABLES: PerCpuVariables = PerCpuVariables {
    hv_vp_assist_page: [0u8; PAGE_SIZE],
    hv_simp_page: [0u8; PAGE_SIZE],
    interrupt_stack: [0u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [0u8; PAGE_SIZE],
    kernel_stack: [0u8; KERNEL_STACK_SIZE],
    _guard_page_1: [0u8; PAGE_SIZE],
    hvcall_input: [0u8; PAGE_SIZE],
    hvcall_output: [0u8; PAGE_SIZE],
    vtl0_state: VtlState {
        rbp: 0,
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
    },
    vtl0_locked_regs: ControlRegMap {
        entries: [(0, 0); NUM_CONTROL_REGS],
    },
    gdt: const { None },
    vtl1_xsave_area_addr: VirtAddr::zero(),
    vtl1_xsaved: false,
    tls: VirtAddr::zero(),
};

/// Specify the layout of PerCpuVariables for Assembly area.
///
/// Unlike `litebox_platform_linux_userland`, this kernel platform does't rely on
/// the `tbss` section to specify FS/GS offsets for per CPU variables because
/// there is no ELF loader that will set up it.
///
/// Note that kernel & host and user & guest are interchangeable in this context.
/// We use "kernel" and "user" here to emphasize that there must be hardware-enforced
/// mode transitions (i.e., ring transitions through iretq/syscall) unlike userland
/// platforms.
///
/// TODO: Consider unifying with `PerCpuVariables` if possible.
#[non_exhaustive]
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone)]
pub struct PerCpuVariablesAsm {
    /// Initial kernel stack pointer to reset the kernel stack on VTL switch
    kernel_stack_ptr: Cell<usize>,
    /// Initial interrupt stack pointer for x86 IST
    interrupt_stack_ptr: Cell<usize>,
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
    /// Flag indicating if VTL0 extended states have been saved at least once (0 = no, 1 = yes)
    vtl0_xsaved: Cell<u8>,
}

impl PerCpuVariablesAsm {
    pub fn set_kernel_stack_ptr(&self, sp: usize) {
        self.kernel_stack_ptr.set(sp);
    }
    pub fn set_interrupt_stack_ptr(&self, sp: usize) {
        self.interrupt_stack_ptr.set(sp);
    }
    pub fn get_interrupt_stack_ptr(&self) -> usize {
        self.interrupt_stack_ptr.get()
    }
    pub fn set_vtl_return_addr(&self, addr: usize) {
        self.vtl_return_addr.set(addr);
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
    pub const fn kernel_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, kernel_stack_ptr)
    }
    pub const fn interrupt_stack_ptr_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, interrupt_stack_ptr)
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
    pub const fn vtl0_xsaved_offset() -> usize {
        offset_of!(PerCpuVariablesAsm, vtl0_xsaved)
    }
}

/// Wrapper struct to maintain `RefCell` along with `PerCpuVariablesAsm`.
/// This struct allows assembly code to read/write some PerCpuVariables area via the GS register (e.g., to
/// save/restore RIP/RSP). Currently, `PerCpuVariables` is protected by `RefCell` such that
/// assembly code cannot easily access it.
///
/// TODO: Let's consider whether we should maintain these two types of Per CPU variable areas (for Rust and
/// assembly, respectively). This design secures Rust-side access to `PerCpuVariables` with `RefCell`,
/// but it might be unnecessarily complex. Instead, we could use assembly code in all cases, but
/// this might be unsafe.
#[repr(C)]
pub struct RefCellWrapper<T> {
    /// Make some PerCpuVariablesAsm area be accessible via the GS register. This is mainly for assembly code
    pcv_asm: PerCpuVariablesAsm,
    /// RefCell which will be stored in the GS register
    inner: RefCell<T>,
}
impl<T> RefCellWrapper<T> {
    pub const fn new(value: T) -> Self {
        Self {
            pcv_asm: PerCpuVariablesAsm {
                kernel_stack_ptr: Cell::new(0),
                interrupt_stack_ptr: Cell::new(0),
                vtl_return_addr: Cell::new(0),
                scratch: Cell::new(0),
                vtl0_state_top_addr: Cell::new(0),
                cur_kernel_stack_ptr: Cell::new(0),
                cur_kernel_base_ptr: Cell::new(0),
                user_context_top_addr: Cell::new(0),
                vtl0_xsave_area_addr: Cell::new(0),
                vtl0_xsave_mask_lo: Cell::new(0),
                vtl0_xsave_mask_hi: Cell::new(0),
                vtl0_xsaved: Cell::new(0),
            },
            inner: RefCell::new(value),
        }
    }
    pub fn get_refcell(&self) -> &RefCell<T> {
        &self.inner
    }
}

/// Store the addresses of per-CPU variables. The kernel threads are expected to access
/// the corresponding per-CPU variables via the GS registers which will store the addresses later.
/// Instead of maintaining this map, we might be able to use a hypercall to directly program each core's GS register.
static mut PER_CPU_VARIABLE_ADDRESSES: [RefCellWrapper<*mut PerCpuVariables>; MAX_CORES] =
    [const { RefCellWrapper::new(core::ptr::null_mut()) }; MAX_CORES];
static mut PER_CPU_VARIABLE_ADDRESSES_IDX: usize = 0;

/// Execute a closure with a reference to the current core's per-CPU variables.
///
/// # Safety
/// This function assumes the following:
/// - The GSBASE register values of individual cores must be properly set (i.e., they must be different).
/// - `get_core_id()` must return distinct APIC IDs for different cores.
///
/// If we cannot guarantee these assumptions, this function may result in unsafe or undefined behaviors.
///
/// # Panics
/// Panics if GSBASE is not set, it contains a non-canonical address, or no per-CPU variables are allocated.
/// Panics if this function is recursively called (`BorrowMutError`).
pub fn with_per_cpu_variables<F, R>(f: F) -> R
where
    F: FnOnce(&PerCpuVariables) -> R,
    R: Sized + 'static,
{
    let Some(refcell) = get_or_init_refcell_of_per_cpu_variables() else {
        panic!("No per-CPU variables are allocated");
    };
    let borrow = refcell.borrow();
    let per_cpu_variables = unsafe { &**borrow };

    f(per_cpu_variables)
}

/// Execute a closure with a mutable reference to the current core's per-CPU variables.
///
/// # Safety
/// This function assumes the following:
/// - The GSBASE register values of individual cores must be properly set (i.e., they must be different).
/// - `get_core_id()` must return distinct APIC IDs for different cores.
///
/// If we cannot guarantee these assumptions, this function may result in unsafe or undefined behaviors.
///
/// # Panics
/// Panics if GSBASE is not set, it contains a non-canonical address, or no per-CPU variables are allocated.
/// Panics if this function is recursively called (`BorrowMutError`).
pub fn with_per_cpu_variables_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut PerCpuVariables) -> R,
    R: Sized + 'static,
{
    let Some(refcell) = get_or_init_refcell_of_per_cpu_variables() else {
        panic!("No per-CPU variables are allocated");
    };
    let mut borrow = refcell.borrow_mut();
    let per_cpu_variables = unsafe { &mut **borrow };

    f(per_cpu_variables)
}

/// Execute a closure with a reference to the current PerCpuVariablesAsm.
///
/// # Panics
/// Panics if GSBASE is not set or it contains a non-canonical address.
pub fn with_per_cpu_variables_asm<F, R>(f: F) -> R
where
    F: FnOnce(&PerCpuVariablesAsm) -> R,
    R: Sized + 'static,
{
    let pcv_asm_addr = unsafe {
        let gsbase = rdgsbase();
        let addr = VirtAddr::try_new(u64::try_from(gsbase).unwrap())
            .expect("GS contains a non-canonical address");
        addr.as_ptr::<RefCellWrapper<*mut PerCpuVariables>>()
            .cast::<PerCpuVariablesAsm>()
    };
    let pcv_asm = unsafe { &*pcv_asm_addr };

    f(pcv_asm)
}

/// Get or initialize a `RefCell` that contains a pointer to the current core's per-CPU variables.
/// This `RefCell` is expected to be stored in the GS register.
fn get_or_init_refcell_of_per_cpu_variables() -> Option<&'static RefCell<*mut PerCpuVariables>> {
    let gsbase = unsafe { rdgsbase() };
    if gsbase == 0 {
        let core_id = get_core_id();
        let refcell_wrapper = if core_id == 0 {
            let addr = &raw mut BSP_VARIABLES;
            unsafe {
                PER_CPU_VARIABLE_ADDRESSES[0] = RefCellWrapper::new(addr);
                &PER_CPU_VARIABLE_ADDRESSES[0]
            }
        } else {
            assert!(
                unsafe { PER_CPU_VARIABLE_ADDRESSES_IDX < MAX_CORES },
                "PER_CPU_VARIABLE_ADDRESSES_IDX exceeds MAX_CORES",
            );
            unsafe { &PER_CPU_VARIABLE_ADDRESSES[PER_CPU_VARIABLE_ADDRESSES_IDX] }
        };
        unsafe {
            PER_CPU_VARIABLE_ADDRESSES_IDX += 1;
        }
        let refcell = refcell_wrapper.get_refcell();
        if refcell.borrow().is_null() {
            None
        } else {
            let addr = x86_64::VirtAddr::new(&raw const *refcell_wrapper as u64);
            unsafe {
                wrgsbase(usize::try_from(addr.as_u64()).unwrap());
            }
            Some(refcell)
        }
    } else {
        let addr = x86_64::VirtAddr::try_new(u64::try_from(gsbase).unwrap())
            .expect("GS contains a non-canonical address");
        let refcell_wrapper = unsafe { &*addr.as_ptr::<RefCellWrapper<*mut PerCpuVariables>>() };
        let refcell = refcell_wrapper.get_refcell();
        if refcell.borrow().is_null() {
            None
        } else {
            Some(refcell)
        }
    }
}

/// Allocate per-CPU variables in heap for all possible cores. We expect that the BSP will call
/// this function to allocate per-CPU variables for other APs because our per-CPU variables are
/// huge such that each AP without a proper stack cannot allocate its own per-CPU variables.
/// # Panics
/// Panics if the number of possible CPUs exceeds `MAX_CORES`
pub fn allocate_per_cpu_variables() {
    let num_cores =
        usize::try_from(get_num_possible_cpus().expect("Failed to get number of possible CPUs"))
            .unwrap();
    assert!(
        num_cores <= MAX_CORES,
        "# of possible CPUs ({num_cores}) exceeds MAX_CORES",
    );

    // Allocate xsave area for BSP (core 0)
    with_per_cpu_variables_asm(|pcv_asm| {
        with_per_cpu_variables_mut(|per_cpu_variables| {
            per_cpu_variables.allocate_xsave_area(pcv_asm);
        });
    });

    // TODO: use `cpu_online_mask` to selectively allocate per-CPU variables only for online CPUs.
    // Note. `PER_CPU_VARIABLE_ADDRESSES[0]` is expected to be already initialized to point to
    // `BSP_VARIABLES` before calling this function by `get_or_init_refcell_of_per_cpu_variables()`.
    #[allow(clippy::needless_range_loop)]
    for i in 1..num_cores {
        let mut per_cpu_variables = Box::<PerCpuVariables>::new_uninit();
        // Safety: `PerCpuVariables` is larger than the stack size, so we manually `memset` it to zero.
        let per_cpu_variables = unsafe {
            let ptr = per_cpu_variables.as_mut_ptr();
            ptr.write_bytes(0, 1);
            per_cpu_variables.assume_init()
        };
        unsafe {
            PER_CPU_VARIABLE_ADDRESSES[i] = RefCellWrapper::new(Box::into_raw(per_cpu_variables));
            // Allocate xsave area for this core, writing directly to its PerCpuVariablesAsm
            let pcv_asm = &PER_CPU_VARIABLE_ADDRESSES[i].pcv_asm;
            (*(*PER_CPU_VARIABLE_ADDRESSES[i].inner.as_ptr())).allocate_xsave_area(pcv_asm);
        }
    }
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
    with_per_cpu_variables_mut(|per_cpu_variables| {
        let kernel_sp =
            usize::try_from(per_cpu_variables.kernel_stack_top()).unwrap() & !(STACK_ALIGNMENT - 1);
        let interrupt_sp = usize::try_from(per_cpu_variables.interrupt_stack_top()).unwrap()
            & !(STACK_ALIGNMENT - 1);
        let vtl0_state_top_addr = usize::try_from(
            &raw const per_cpu_variables.vtl0_state as u64
                + core::mem::size_of::<VtlState>() as u64,
        )
        .unwrap();
        with_per_cpu_variables_asm(|pcv_asm| {
            pcv_asm.set_kernel_stack_ptr(kernel_sp);
            pcv_asm.set_interrupt_stack_ptr(interrupt_sp);
            pcv_asm.set_vtl0_state_top_addr(vtl0_state_top_addr);
        });
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
    usize::try_from(sinfo.xsave_area_size_enabled_features()).unwrap()
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
