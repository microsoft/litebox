use thiserror::Error;

use crate::arch::{
    PAGE_SIZE, Page, PageFaultErrorCode, PageTableFlags, PhysAddr, PhysFrame, Size4KiB, VirtAddr,
};

/// Page table allocator
pub(crate) struct PageTableAllocator<M: super::MemoryProvider> {
    _provider: core::marker::PhantomData<M>,
}

impl<M: super::MemoryProvider> Default for PageTableAllocator<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: super::MemoryProvider> PageTableAllocator<M> {
    pub fn new() -> Self {
        Self {
            _provider: core::marker::PhantomData,
        }
    }

    /// Allocate a frame
    ///
    /// # Panics
    ///
    /// Panics if the address is not correctly aligned (i.e. is not a valid frame start)
    pub fn allocate_frame(&mut self, clear: bool) -> Option<PhysFrame<Size4KiB>> {
        M::mem_allocate_pages(0).map(|addr| {
            if clear {
                unsafe {
                    core::intrinsics::write_bytes(addr, 0, PAGE_SIZE);
                }
            }
            PhysFrame::from_start_address(M::make_pa_private(M::va_to_pa(VirtAddr::new(
                addr as u64,
            ))))
            .unwrap()
        })
    }
}

pub(crate) trait PageTableImpl {
    /// [`PageTableFlags::WRITABLE`] | [`PageTableFlags::USER_ACCESSIBLE`] | [`PageTableFlags::NO_EXECUTE`]
    const MPROTECT_PTE_MASK: u64 = PageTableFlags::WRITABLE.bits()
        | PageTableFlags::USER_ACCESSIBLE.bits()
        | PageTableFlags::NO_EXECUTE.bits();

    /// Initialize the page table with the physical address of the top-level page table.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `p` is valid and properly aligned.
    unsafe fn init(p: PhysAddr) -> Self;

    /// Translate a virtual address to a physical address
    fn translate(&self, addr: VirtAddr) -> crate::arch::TranslateResult;

    /// Handle page fault
    ///
    /// `flush` indicates whether the TLB should be flushed after the page fault is handled.
    /// `flags` presents the PTE flags to be set for the page.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `p` is valid and properly aligned.
    /// The caller must also ensure that the `page` is valid and user has
    /// access to it.
    unsafe fn handle_page_fault(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
        error_code: PageFaultErrorCode,
        flush: bool,
    ) -> Result<(), PageFaultError>;

    /// Unmap 4KiB pages from the page table
    ///
    /// `flush` indicates whether the TLB should be flushed after the pages are unmapped.
    /// `free_page` indicates whether the unmapped pages should be freed (This may be helpful
    /// when implementing [`Self::remap_pages`]. If we maintain refcnt for pages, we may not
    /// need this).
    ///
    /// # Safety
    ///
    /// `start` and `len` must be aligned to 4KiB.
    ///
    /// # Panics
    ///
    /// panic if `start` or `len` is misaligned.
    unsafe fn unmap_pages(&mut self, start: VirtAddr, len: usize, free_page: bool, flush: bool);

    /// Remap 4KiB pages in the page table from `old_addr` to `new_addr`
    ///
    /// `flush` indicates whether the TLB should be flushed after the pages are remapped.
    ///
    /// # Safety
    ///
    /// The caller must also ensure that the [`new_addr`, `new_addr` + `len`]
    /// is not already mapped, and `old_addr` and `new_addr` do not overlap.
    /// `old_addr`, `new_addr`, and `len` must be aligned to 4KiB.
    unsafe fn remap_pages(
        &mut self,
        old_addr: VirtAddr,
        new_addr: VirtAddr,
        len: usize,
        flush: bool,
    ) -> Result<(), PageTableWalkError>;

    /// Change the page table flags for 4KiB pages
    ///
    /// # Safety
    ///
    /// The caller must also ensure that [`start`, `start` + `len`) is okay
    /// to be changed to `new_flags`.
    unsafe fn mprotect_pages(
        &mut self,
        start: VirtAddr,
        len: usize,
        new_flags: PageTableFlags,
        flush: bool,
    ) -> Result<(), PageTableWalkError>;
}

#[derive(Error, Debug)]
pub(crate) enum PageTableWalkError {
    #[error("Given page is part of an already mapped huge page")]
    MappedToHugePage,
    #[error("Page table allocation failed")]
    AllocationFailed,
}

#[derive(Error, Debug)]
pub(crate) enum PageFaultError {
    #[error("no access: {0}")]
    AccessError(&'static str),
    #[error("allocation failed")]
    AllocationFailed,
    #[error("given page is part of an already mapped huge page")]
    HugePage,
}
