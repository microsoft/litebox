//! VTL1 kernel context

use crate::{
    arch::gdt,
    mshv::{
        HvMessagePage, HvVpAssistPage,
        vsm::{ControlRegMap, NUM_CONTROL_REGS},
        vtl_switch::VtlState,
        vtl1_mem_layout::PAGE_SIZE,
    },
};
use x86_64::structures::tss::TaskStateSegment;

pub const MAX_CORES: usize = 8; // TODO: use cpumask
pub const INTERRUPT_STACK_SIZE: usize = 2 * PAGE_SIZE;
pub const KERNEL_STACK_SIZE: usize = 10 * PAGE_SIZE;

/// Per-core VTL1 kernel context
#[repr(align(4096))]
#[derive(Clone, Copy)]
pub struct KernelContext {
    pub hv_vp_assist_page: [u8; PAGE_SIZE],
    pub hv_simp_page: [u8; PAGE_SIZE],
    pub interrupt_stack: [u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [u8; PAGE_SIZE],
    pub kernel_stack: [u8; KERNEL_STACK_SIZE],
    _guard_page_1: [u8; PAGE_SIZE],
    pub hvcall_input: [u8; PAGE_SIZE],
    pub hvcall_output: [u8; PAGE_SIZE],
    pub tss: gdt::AlignedTss,
    pub vtl0_state: VtlState,
    pub vtl1_state: VtlState,
    pub vtl0_locked_regs: ControlRegMap,
    pub gdt: Option<&'static gdt::GdtWrapper>,
}

impl KernelContext {
    pub fn kernel_stack_top(&self) -> u64 {
        &raw const self.kernel_stack as u64 + (self.kernel_stack.len() - 1) as u64
    }

    pub fn interrupt_stack_top(&self) -> u64 {
        &raw const self.interrupt_stack as u64 + (self.interrupt_stack.len() - 1) as u64
    }

    pub fn hv_vp_assist_page_as_ptr(&self) -> *const HvVpAssistPage {
        (&raw const self.hv_vp_assist_page).cast::<HvVpAssistPage>()
    }

    pub fn hv_vp_assist_page_as_mut_ptr(&mut self) -> *mut HvVpAssistPage {
        (&raw mut self.hv_vp_assist_page).cast::<HvVpAssistPage>()
    }

    pub fn hv_vp_assist_page_as_u64(&self) -> u64 {
        &raw const self.hv_vp_assist_page as u64
    }

    pub fn hv_simp_page_as_mut_ptr(&mut self) -> *mut HvMessagePage {
        (&raw mut self.hv_simp_page).cast::<HvMessagePage>()
    }

    pub fn hv_simp_page_as_u64(&self) -> u64 {
        &raw const self.hv_simp_page as u64
    }

    pub fn hv_hypercall_page_as_u64(&self) -> u64 {
        get_hypercall_page_address()
    }

    pub fn hv_hypercall_input_page_as_mut_ptr(&mut self) -> *mut [u8; PAGE_SIZE] {
        &raw mut self.hvcall_input
    }

    pub fn hv_hypercall_output_page_as_mut_ptr(&mut self) -> *mut [u8; PAGE_SIZE] {
        &raw mut self.hvcall_output
    }

    pub fn set_vtl_return_value(&mut self, value: u64) {
        self.vtl0_state.r8 = value; // LVBS uses R8 to return a value from VTL1 to VTL0
    }
}

// TODO: use heap
static mut PER_CORE_KERNEL_CONTEXT: [KernelContext; MAX_CORES] = [KernelContext {
    hv_vp_assist_page: [0u8; PAGE_SIZE],
    hv_simp_page: [0u8; PAGE_SIZE],
    interrupt_stack: [0u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [0u8; PAGE_SIZE],
    kernel_stack: [0u8; KERNEL_STACK_SIZE],
    _guard_page_1: [0u8; PAGE_SIZE],
    hvcall_input: [0u8; PAGE_SIZE],
    hvcall_output: [0u8; PAGE_SIZE],
    tss: gdt::AlignedTss(TaskStateSegment::new()),
    vtl0_state: VtlState {
        rbp: 0,
        cr2: 0,
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
    vtl1_state: VtlState {
        rbp: 0,
        cr2: 0,
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
}; MAX_CORES];

/// Get the APIC ID of the current core.
#[inline]
pub fn get_core_id() -> usize {
    use core::arch::x86_64::__cpuid_count as cpuid_count;
    const CPU_VERSION_INFO: u32 = 1;

    let result = unsafe { cpuid_count(CPU_VERSION_INFO, 0x0) };
    let apic_id = (result.ebx >> 24) & 0xff;

    apic_id as usize
}

/// Get the per-core kernel context
pub fn get_per_core_kernel_context() -> &'static mut KernelContext {
    let core_id = get_core_id();
    unsafe { &mut PER_CORE_KERNEL_CONTEXT[core_id] }
}

// A hypercall page is a shared read-only code page, so it's better not to use heap.
unsafe extern "C" {
    static _hypercall_page_start: u8;
}

#[unsafe(link_section = ".hypercall_page")]
pub static HYPERCALL_PAGE: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

/// Get the hypercall page address
#[inline]
pub fn get_hypercall_page_address() -> u64 {
    &raw const _hypercall_page_start as u64
}
