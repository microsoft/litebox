use crate::mshv::vtl1_mem_layout::PAGE_SIZE;
use x86_64::PrivilegeLevel;
use x86_64::structures::gdt::{GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

const MAX_CORES: usize = 8; // for now
const INTERRUPT_STACK_SIZE: usize = 2 * PAGE_SIZE;
const KERNEL_STACK_SIZE: usize = 8 * PAGE_SIZE;
// const DOUBLE_FAULT_IST_INDEX: u16 = 0;

#[expect(dead_code)]
#[repr(align(16))]
#[derive(Clone, Copy)]
struct AlignedTss(TaskStateSegment);

#[expect(dead_code)]
#[derive(Clone, Copy)]
struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    tss: SegmentSelector,
    user_data: SegmentSelector,
    user_code: SegmentSelector,
}

#[expect(dead_code)]
impl Selectors {
    pub fn new() -> Self {
        Selectors {
            kernel_code: SegmentSelector::new(0, PrivilegeLevel::Ring3),
            kernel_data: SegmentSelector::new(0, PrivilegeLevel::Ring3),
            tss: SegmentSelector::new(0, PrivilegeLevel::Ring3),
            user_data: SegmentSelector::new(0, PrivilegeLevel::Ring3),
            user_code: SegmentSelector::new(0, PrivilegeLevel::Ring3),
        }
    }
}

#[expect(dead_code)]
struct GdtWrapper {
    gdt: GlobalDescriptorTable,
    selectors: Selectors,
}

// Per-core VTL1 kernel context
#[expect(dead_code)]
#[repr(align(4096))]
#[derive(Clone, Copy)]
struct KernelContext {
    hv_vp_assist_page: [u8; PAGE_SIZE],
    interrupt_stack: [u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [u8; PAGE_SIZE],
    kernel_stack: [u8; KERNEL_STACK_SIZE],
    _guard_page_1: [u8; PAGE_SIZE],
    tss: AlignedTss,
    gdt: Option<&'static GdtWrapper>,
}

// TODO: use heap later
#[expect(dead_code)]
static mut PER_CORE_KERNEL_CONTEXT: [KernelContext; MAX_CORES] = [KernelContext {
    hv_vp_assist_page: [0u8; PAGE_SIZE],
    interrupt_stack: [0u8; INTERRUPT_STACK_SIZE],
    _guard_page_0: [0u8; PAGE_SIZE],
    kernel_stack: [0u8; KERNEL_STACK_SIZE],
    _guard_page_1: [0u8; PAGE_SIZE],
    tss: AlignedTss(TaskStateSegment::new()),
    gdt: const { None },
}; MAX_CORES];
