use crate::arch::{
    Page, PageFaultErrorCode, PageTableFlags, PhysAddr, PhysFrame, Size4KiB, TranslateResult,
    VirtAddr, PAGE_SIZE,
};

/// Page table allocator
pub struct PageTableAllocator<M: super::MemoryProvider> {
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

pub trait PageTableImpl {
    /// Initialize the page table
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `p4` is valid and properly aligned.
    unsafe fn init(p: PhysAddr) -> Self;

    fn translate(&self, addr: VirtAddr) -> TranslateResult;

    /// Handle page fault
    ///
    /// `flush` indicates whether the TLB should be flushed after the page fault is handled.
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
    ///
    /// `start` and `len` must be aligned to 4KiB.
    fn unmap_pages(&mut self, start: VirtAddr, len: usize, free_page: bool, flush: bool);

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

#[derive(Debug)]
pub enum PageTableWalkError {
    NotMapped,
    MappedToHugePage,
    AllocationFailed,
}

#[derive(Debug)]
pub enum PageFaultError {
    AccessError,
    OOM,
    HugePage,
}
