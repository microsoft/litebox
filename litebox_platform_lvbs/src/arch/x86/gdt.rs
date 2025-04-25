use crate::kernel_context::{
    INTERRUPT_STACK_SIZE, MAX_CORES, get_core_id, get_per_core_kernel_context,
};
use core::mem::MaybeUninit;
use x86_64::instructions::{
    segmentation::{CS, DS, Segment},
    tables::load_tss,
};
use x86_64::structures::{
    gdt::{Descriptor, DescriptorFlags, GlobalDescriptorTable, SegmentSelector},
    tss::TaskStateSegment,
};
use x86_64::{PrivilegeLevel, VirtAddr};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct AlignedTss(pub TaskStateSegment);

#[derive(Clone, Copy)]
pub struct Selectors {
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

pub struct GdtWrapper {
    pub gdt: GlobalDescriptorTable,
    pub selectors: Selectors,
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

    let tss = &mut kernel_context.tss;
    let stack_start = VirtAddr::from_ptr(&raw const kernel_context.kernel_stack);
    let stack_end = stack_start + (INTERRUPT_STACK_SIZE - 1) as u64;
    tss.0.interrupt_stack_table[0] = stack_end;

    let gdt = unsafe { &mut *GDT_STORAGE[core_id].as_mut_ptr() };

    *gdt = GdtWrapper::new();
    let kernel_data_flags =
        DescriptorFlags::USER_SEGMENT | DescriptorFlags::PRESENT | DescriptorFlags::WRITABLE;
    gdt.selectors.kernel_code = gdt.gdt.append(Descriptor::kernel_code_segment());
    gdt.selectors.kernel_data = gdt
        .gdt
        .append(Descriptor::UserSegment(kernel_data_flags.bits()));
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

pub fn init() {
    setup_gdt_tss();
}

#[inline]
pub fn set_usermode_segs() -> (u16, u16) {
    let kernel_context = get_per_core_kernel_context();

    let mut cs = kernel_context.gdt.unwrap().selectors.user_code;
    let mut ds = kernel_context.gdt.unwrap().selectors.user_data;
    cs.0 |= PrivilegeLevel::Ring3 as u16;
    ds.0 |= PrivilegeLevel::Ring3 as u16;
    unsafe {
        DS::set_reg(ds);
    }
    (cs.0, ds.0)
}
