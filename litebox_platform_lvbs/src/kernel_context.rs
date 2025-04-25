use crate::{
    arch::gdt,
    mshv::{mshv_bindings::hv_vp_assist_page, vtl1_mem_layout::PAGE_SIZE},
};
use x86_64::structures::tss::TaskStateSegment;

pub const MAX_CORES: usize = 8; // for now
pub const INTERRUPT_STACK_SIZE: usize = 2 * PAGE_SIZE;
pub const KERNEL_STACK_SIZE: usize = 8 * PAGE_SIZE;

// Per-core VTL1 kernel context
#[repr(align(4096))]
#[derive(Clone, Copy)]
pub struct KernelContext {
    pub hv_vp_assist_page: hv_vp_assist_page,
    pub interrupt_stack: [u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [u8; PAGE_SIZE],
    pub kernel_stack: [u8; KERNEL_STACK_SIZE],
    _guard_page_1: [u8; PAGE_SIZE],
    pub tss: gdt::AlignedTss,
    pub gdt: Option<&'static gdt::GdtWrapper>,
}

// TODO: use heap later
static mut PER_CORE_KERNEL_CONTEXT: [KernelContext; MAX_CORES] = [KernelContext {
    hv_vp_assist_page: unsafe { core::mem::zeroed() },
    interrupt_stack: [0u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [0u8; PAGE_SIZE],
    kernel_stack: [0u8; KERNEL_STACK_SIZE],
    _guard_page_1: [0u8; PAGE_SIZE],
    tss: gdt::AlignedTss(TaskStateSegment::new()),
    gdt: const { None },
}; MAX_CORES];

#[inline]
pub fn get_core_id() -> usize {
    use core::arch::x86_64::__cpuid_count as cpuid_count;
    const CPU_VERSION_INFO: u32 = 1;

    let result = unsafe { cpuid_count(CPU_VERSION_INFO, 0x0) };
    let apic_id = (result.ebx >> 24) & 0xff;

    apic_id as usize
}

pub fn get_per_core_kernel_context() -> &'static mut KernelContext {
    let core_id = get_core_id();
    unsafe { &mut PER_CORE_KERNEL_CONTEXT[core_id] }
}
