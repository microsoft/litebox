// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_common_linux::PAGE_SIZE;
use litebox_common_linux::vmem::PageFaultError;

use crate::arch::{
    Page, PageFaultErrorCode, PageTableFlags, PhysAddr, PhysFrame, Size4KiB, VirtAddr,
};

// A non-present user leaf that still owns the frame stored in its address bits.
pub(crate) const PROT_NONE: PageTableFlags = PageTableFlags::BIT_9;

// A user leaf whose frame other leaves may map too (see `SHARED_FRAMES`):
// never writable; a write fault copies the frame, or takes it over once no
// other leaf maps it.
pub(crate) const COW: PageTableFlags = PageTableFlags::BIT_10;

// A user leaf of shared memory, which clones map writable too instead of copy-on-write (see
// `SHARED_FRAMES`), as Linux `MAP_SHARED` memory.
pub(crate) const SHARED: PageTableFlags = PageTableFlags::BIT_11;

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
        .union(PageTableFlags::NO_EXECUTE)
        .union(PageTableFlags::PRESENT)
        .union(PROT_NONE);

    /// # Safety
    ///
    /// `p` must be the page-aligned address of a valid top-level table that
    /// outlives the returned object.
    unsafe fn init(p: PhysAddr) -> Self;

    #[cfg(test)]
    fn translate(&self, addr: VirtAddr) -> x86_64::structures::paging::mapper::TranslateResult;

    /// Resolves a fault on `page`, after which it is mapped with `flags`,
    /// the permissions its mapping allows: maps it with a fresh frame if it
    /// is not mapped yet, or, for a write to a [`COW`] leaf, maps a copy of
    /// its frame, or the frame itself once no other leaf maps it.
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
