use litebox::mm::vm::VmemBackend;
use sealed::sealed;
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
    pub fn allocate_frame(clear: bool) -> Option<PhysFrame<Size4KiB>> {
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

#[sealed(pub(crate))]
pub trait PageTableImpl: VmemBackend {
    /// Flags that `mprotect` can change:
    /// [`PageTableFlags::WRITABLE`] | [`PageTableFlags::USER_ACCESSIBLE`] | [`PageTableFlags::NO_EXECUTE`]
    const MPROTECT_PTE_MASK: PageTableFlags = PageTableFlags::from_bits_truncate(
        PageTableFlags::WRITABLE.bits()
            | PageTableFlags::USER_ACCESSIBLE.bits()
            | PageTableFlags::NO_EXECUTE.bits(),
    );

    /// Initialize the page table with the physical address of the top-level page table.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `p` is valid and properly aligned.
    unsafe fn init(p: PhysAddr) -> Self;

    /// Translate a virtual address to a physical address
    #[cfg(test)]
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
    ) -> Result<(), PageFaultError>;
}

#[derive(Error, Debug)]
pub enum PageFaultError {
    #[error("no access: {0}")]
    AccessError(&'static str),
    #[error("allocation failed")]
    AllocationFailed,
    #[error("given page is part of an already mapped huge page")]
    HugePage,
}
