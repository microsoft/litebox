pub mod gdt;
pub mod instrs;
pub mod ioport;
pub mod mm;
pub mod msr;

#[cfg(feature = "interrupt")]
pub mod interrupts;

pub(crate) use x86_64::{
    addr::{PhysAddr, VirtAddr},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageSize, PageTableFlags, PhysFrame, Size4KiB},
    },
};

#[cfg(test)]
pub(crate) use x86_64::structures::paging::mapper::{MappedFrame, TranslateResult};
