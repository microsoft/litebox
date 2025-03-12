pub mod mm;

pub(crate) use x86_64::{
    addr::{PhysAddr, VirtAddr},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    },
};

#[cfg(test)]
pub(crate) use x86_64::structures::paging::mapper::{MappedFrame, TranslateResult};
