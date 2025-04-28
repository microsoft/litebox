//! Global Descriptor Table (GDT) and Task State Segment (TSS)

use crate::kernel_context::{MAX_CORES, get_core_id, get_per_core_kernel_context};
use core::mem::MaybeUninit;
use x86_64::{
    PrivilegeLevel, VirtAddr,
    instructions::{
        segmentation::{CS, DS, Segment},
        tables::load_tss,
    },
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
};

/// TSS with 16-byte alignment (HW requirement)
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct AlignedTss(pub TaskStateSegment);

#[derive(Clone, Copy)]
struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    tss: SegmentSelector,
    user_data: SegmentSelector,
    user_code: SegmentSelector,
}

impl Selectors {
    pub fn new() -> Self {
        Selectors {
            kernel_code: SegmentSelector::new(0, PrivilegeLevel::Ring0),
            kernel_data: SegmentSelector::new(0, PrivilegeLevel::Ring0),
            tss: SegmentSelector::new(0, PrivilegeLevel::Ring0),
            user_data: SegmentSelector::new(0, PrivilegeLevel::Ring3),
            user_code: SegmentSelector::new(0, PrivilegeLevel::Ring3),
        }
    }
}

impl Default for Selectors {
    fn default() -> Self {
        Selectors::new()
    }
}

/// Package GDT and selectors
pub struct GdtWrapper {
    gdt: GlobalDescriptorTable,
    selectors: Selectors,
}

impl GdtWrapper {
    pub fn new() -> Self {
        GdtWrapper {
            gdt: GlobalDescriptorTable::new(),
            selectors: Selectors::new(),
        }
    }
}

impl Default for GdtWrapper {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: use heap
static mut GDT_STORAGE: [MaybeUninit<GdtWrapper>; MAX_CORES] =
    [const { MaybeUninit::uninit() }; MAX_CORES];

fn setup_gdt_tss() {
    let core_id = get_core_id();
    let kernel_context = get_per_core_kernel_context();

    let stack_top = kernel_context.interrupt_stack_top();
    let tss = &mut kernel_context.tss;
    tss.0.interrupt_stack_table[0] = VirtAddr::new(stack_top);

    let gdt = unsafe { &mut *GDT_STORAGE[core_id].as_mut_ptr() };
    *gdt = GdtWrapper::new();

    gdt.selectors.kernel_code = gdt.gdt.append(Descriptor::kernel_code_segment());
    gdt.selectors.kernel_data = gdt.gdt.append(Descriptor::kernel_data_segment());
    gdt.selectors.tss = gdt.gdt.append(Descriptor::tss_segment(&tss.0));
    gdt.selectors.user_code = gdt.gdt.append(Descriptor::user_code_segment());
    gdt.selectors.user_data = gdt.gdt.append(Descriptor::user_data_segment());

    gdt.gdt.load();

    unsafe {
        CS::set_reg(gdt.selectors.kernel_code);
        DS::set_reg(gdt.selectors.kernel_data);
        load_tss(gdt.selectors.tss);
    }

    kernel_context.gdt = Some(gdt);
}

/// Set up GDT and TSS (for a core)
pub fn init() {
    setup_gdt_tss();
}
