pub mod mm;

pub(crate) use x86_64::{
    addr::{PhysAddr, VirtAddr},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageSize, PageTableFlags, PhysFrame, Size4KiB},
    },
};

pub mod msr;

#[cfg(test)]
pub(crate) use x86_64::structures::paging::mapper::{MappedFrame, TranslateResult};
