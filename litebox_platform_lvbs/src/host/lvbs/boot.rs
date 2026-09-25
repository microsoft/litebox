// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS boot policy: VTL1-owned memory and the executable hypercall page.
//! The shared kernel receives the resulting mappings, not linker symbols or
//! assumptions about a VTL peer.

use super::{HostLvbsInterface, LvbsLinuxKernel};
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB, frame::PhysFrameRange},
};

/// Enable extended-state instructions without modifying the XCR0 shared with
/// VTL0. VTL0 must already have enabled the states used by the kernel.
///
/// # Panics
/// Panics if XCR0 lacks x87 or SSE.
pub fn enable_extended_states() {
    crate::arch::enable_extended_states();
    let xcr0 = x86_64::registers::xcontrol::XCr0::read();
    assert!(
        xcr0.contains(x86_64::registers::xcontrol::XCr0Flags::X87),
        "XCR0 must have x87 enabled by VTL0"
    );
    assert!(
        xcr0.contains(x86_64::registers::xcontrol::XCr0Flags::SSE),
        "XCR0 must have SSE enabled by VTL0"
    );
}

impl LvbsLinuxKernel {
    /// Build the VTL1 kernel address space with DEP and retain its ownership
    /// range. Text and the Hyper-V hypercall page are executable; all other
    /// pages are NX. Early boot page-table reclamation remains with the runner.
    ///
    /// # Safety
    /// Call once, after relocation to `PA + KERNEL_OFFSET` and allocator
    /// seeding. The supplied VTL1 range must cover every live kernel allocation,
    /// code and stack. The text bounds and hypercall linker symbol must describe
    /// the code pages that must remain executable after the CR3 switch.
    pub unsafe fn new(
        phys_start: PhysAddr,
        phys_end: PhysAddr,
        text_phys_start: PhysAddr,
        text_phys_end: PhysAddr,
    ) -> &'static Self {
        let range = PhysFrame::range(
            PhysFrame::containing_address(phys_start),
            PhysFrame::containing_address(phys_end.align_up(Size4KiB::SIZE)),
        );
        #[allow(unused_mut)]
        let mut exec_ranges = alloc::vec![text_phys_start..text_phys_end];
        #[cfg(not(test))]
        {
            use crate::mm::MemoryProvider;
            let hypercall =
                Self::va_to_pa(x86_64::VirtAddr::new(super::hv_hypercall_page_address()));
            exec_ranges.push(hypercall..hypercall + Size4KiB::SIZE);
        }
        let host = HostLvbsInterface {
            vtl1_phys_frame_range: range,
            end_of_boot: AtomicBool::new(false),
        };
        // SAFETY: the caller supplies the live VTL1 range and relocated text;
        // LVBS adds its other required executable mapping, the hypercall page.
        unsafe { Self::from_memory(host, range, &exec_ranges) }
    }

    pub(crate) fn end_of_boot_reached(&self) -> bool {
        self.host.end_of_boot.load(Ordering::SeqCst)
    }

    pub(crate) fn signal_end_of_boot(&self) {
        self.host.end_of_boot.store(true, Ordering::SeqCst);
    }

    pub fn vtl1_phys_frame_range(&self) -> PhysFrameRange<Size4KiB> {
        self.host.vtl1_phys_frame_range
    }
}
