// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_common_linux::vmem::PAGE_SIZE;
use litebox_common_linux::vmem::PageFaultError;

use crate::arch::{
    Page, PageFaultErrorCode, PageTableFlags, PhysAddr, PhysFrame, Size4KiB, VirtAddr,
};

pub(crate) struct PageTableAllocator<M: super::MemoryProvider> {
    _provider: core::marker::PhantomData<M>,
}

impl<M: super::MemoryProvider> Default for PageTableAllocator<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: super::MemoryProvider> PageTableAllocator<M> {
    pub(crate) fn new() -> Self {
        Self {
            _provider: core::marker::PhantomData,
        }
    }

    /// Allocate a zeroed frame.
    pub(crate) fn allocate_frame() -> Option<PhysFrame<Size4KiB>> {
        M::mem_allocate_pages(0).map(|addr| {
            // Safety: `PageAllocator`'s contract makes this a valid, page-aligned,
            // exclusively owned page in the kernel mapping.
            unsafe { core::slice::from_raw_parts_mut(addr, PAGE_SIZE).fill(0) };
            PhysFrame::from_start_address(M::va_to_pa(VirtAddr::new(addr as u64))).unwrap()
        })
    }
}

pub(crate) trait PageTableImpl<const ALIGN: usize> {
    /// Flags that `mprotect` can change.
    const MPROTECT_PTE_MASK: PageTableFlags = PageTableFlags::WRITABLE
        .union(PageTableFlags::USER_ACCESSIBLE)
        .union(PageTableFlags::NO_EXECUTE);

    /// # Safety
    ///
    /// `p` must be the page-aligned address of a valid top-level table that
    /// outlives the returned object.
    unsafe fn init(p: PhysAddr) -> Self;

    #[cfg(test)]
    fn translate(&self, addr: VirtAddr) -> x86_64::structures::paging::mapper::TranslateResult;

    /// Map `page` with `flags` if it is not mapped yet.
    ///
    /// # Safety
    ///
    /// The caller must have checked that the access to `page` is allowed.
    unsafe fn handle_page_fault(
        &self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
        error_code: PageFaultErrorCode,
    ) -> Result<(), PageFaultError>;
}
