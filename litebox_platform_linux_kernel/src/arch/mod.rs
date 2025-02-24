//! Arch-specific code

mod x86;

pub use x86::{
    Page, PageFaultErrorCode, PageSize, PageTableFlags, PhysAddr, PhysFrame, Size4KiB,
    TranslateResult, VirtAddr, X64PageTable,
};

pub const PAGE_SIZE: usize = Size4KiB::SIZE as usize;
