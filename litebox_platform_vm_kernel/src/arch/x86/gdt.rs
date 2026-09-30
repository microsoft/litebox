// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! GDT and TSS

use crate::per_cpu::with_per_cpu_variables;
use alloc::boxed::Box;
use x86_64::{
    VirtAddr,
    instructions::{
        segmentation::{CS, DS, Segment},
        tables::load_tss,
    },
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
};

/// The TSS must be 16-byte aligned.
#[repr(align(16))]
struct AlignedTss(TaskStateSegment);

#[derive(Clone, Copy)]
pub(crate) struct Selectors {
    pub(crate) kernel_code: SegmentSelector,
    pub(crate) kernel_data: SegmentSelector,
    tss: SegmentSelector,
    pub(crate) user_data: SegmentSelector,
    pub(crate) user_code: SegmentSelector,
}

pub(crate) struct GdtWrapper {
    gdt: GlobalDescriptorTable,
    selectors: Selectors,
}

impl GdtWrapper {
    pub(crate) fn selectors(&self) -> Selectors {
        self.selectors
    }
}

/// Set up the current core's GDT and TSS. Needs its per-CPU variables.
pub fn init() {
    let (double_fault_stack_top, nmi_stack_top, exception_stack_top) =
        with_per_cpu_variables(|pcv| {
            (
                pcv.double_fault_stack_top(),
                pcv.nmi_stack_top(),
                pcv.exception_stack_top(),
            )
        });

    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[0] = VirtAddr::new(double_fault_stack_top as u64);
    // An NMI may interrupt the syscall stack switch; its stack must be independent.
    tss.interrupt_stack_table[1] = VirtAddr::new(nmi_stack_top as u64);
    tss.privilege_stack_table[0] = VirtAddr::new(exception_stack_top as u64);
    let tss = Box::leak(Box::new(AlignedTss(tss)));

    // STAR and user-return assembly require this order: CS=0x08, DS=0x10,
    // TSS=0x18, user DS=0x2b, user CS=0x33.
    let mut gdt = GlobalDescriptorTable::new();
    let selectors = Selectors {
        kernel_code: gdt.append(Descriptor::kernel_code_segment()),
        kernel_data: gdt.append(Descriptor::kernel_data_segment()),
        tss: gdt.append(Descriptor::tss_segment(&tss.0)),
        user_data: gdt.append(Descriptor::user_data_segment()),
        user_code: gdt.append(Descriptor::user_code_segment()),
    };
    let gdt = Box::leak(Box::new(GdtWrapper { gdt, selectors }));
    gdt.gdt.load();

    // Safety: the selectors index the GDT just loaded, which lives forever, as
    // does the TSS.
    unsafe {
        CS::set_reg(selectors.kernel_code);
        DS::set_reg(selectors.kernel_data);
        load_tss(selectors.tss);
    }

    with_per_cpu_variables(|pcv| pcv.gdt.set(Some(gdt)));
}
