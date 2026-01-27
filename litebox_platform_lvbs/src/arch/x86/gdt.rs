// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Global Descriptor Table (GDT) and Task State Segment (TSS)

use crate::host::per_cpu_variables::{
    PerCpuVariablesAsm, with_per_cpu_variables_asm, with_per_cpu_variables_mut,
};
use alloc::boxed::Box;
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

    /// Return kernel code, user code, and user data segment selectors
    pub fn get_segment_selectors(&self) -> (u16, u16, u16) {
        (
            self.selectors.kernel_code.0,
            self.selectors.user_code.0,
            self.selectors.user_data.0,
        )
    }
}

impl Default for GdtWrapper {
    fn default() -> Self {
        Self::new()
    }
}

fn setup_gdt_tss() {
    let stack_top = with_per_cpu_variables_asm(PerCpuVariablesAsm::get_interrupt_stack_ptr);
    let stack_top = u64::try_from(stack_top).unwrap();

    let mut tss = Box::new(AlignedTss(TaskStateSegment::new()));
    tss.0.interrupt_stack_table[0] = VirtAddr::new(stack_top);
    // `tss_segment()` requires `&'static TaskStateSegment`. Leaking `tss` is fine because
    // it will be used until the LVBS kernel resets.
    let tss = Box::leak(tss);

    // Canonical x86_64 GDT layout
    // Index 0 -> NULL
    // Index 1 -> KERNEL_CS (0x08)
    // Index 2 -> KERNEL_DS (0x10)
    // Index 3 -> TSS_LOW   (0x18)
    // Index 4 -> TSS_HIGH  (0x20)
    // Index 5 -> USER_DS   (0x28|3 = 0x2B)
    // Index 6 -> USER_CS   (0x30|3 = 0x33)
    let mut gdt = Box::new(GdtWrapper::new());
    gdt.selectors.kernel_code = gdt.gdt.append(Descriptor::kernel_code_segment());
    gdt.selectors.kernel_data = gdt.gdt.append(Descriptor::kernel_data_segment());
    gdt.selectors.tss = gdt.gdt.append(Descriptor::tss_segment(&tss.0));
    gdt.selectors.user_data = gdt.gdt.append(Descriptor::user_data_segment());
    gdt.selectors.user_code = gdt.gdt.append(Descriptor::user_code_segment());

    // `gdt.load()` requires `&'static self`. Leaking `gdt` is fine because
    // it will be used until the LVBS kernel resets.
    let gdt = Box::leak(gdt);
    gdt.gdt.load();

    unsafe {
        CS::set_reg(gdt.selectors.kernel_code);
        DS::set_reg(gdt.selectors.kernel_data);
        load_tss(gdt.selectors.tss);
    }

    with_per_cpu_variables_mut(|per_cpu_variables| {
        per_cpu_variables.gdt = Some(gdt);
    });
}

/// Set up GDT and TSS (for a core)
pub fn init() {
    setup_gdt_tss();
}
