use litebox::mm::vm::{ProtectError, RemapError, VmFlags, VmemBackend};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::{
        idt::PageFaultErrorCode,
        paging::{
            FrameAllocator, FrameDeallocator, MappedPageTable, Mapper, Page, PageSize, PageTable,
            PageTableFlags, PhysFrame, Size4KiB, Translate,
            mapper::{
                FlagUpdateError, MapToError, PageTableFrameMapping, TranslateResult, UnmapError,
            },
        },
    },
};

use crate::mm::{
    MemoryProvider,
    pgtable::{PageFaultError, PageTableAllocator, PageTableImpl},
};

#[cfg(not(test))]
const FLUSH_TLB: bool = true;
#[cfg(test)]
const FLUSH_TLB: bool = false;

#[inline]
fn frame_to_pointer<M: MemoryProvider>(frame: PhysFrame) -> *mut PageTable {
    let virt = M::pa_to_va(frame.start_address());
    virt.as_mut_ptr()
}

pub struct X64PageTable<'a, M: MemoryProvider> {
    inner: MappedPageTable<'a, FrameMapping<M>>,
}

struct FrameMapping<M: MemoryProvider> {
    _provider: core::marker::PhantomData<M>,
}

unsafe impl<M: MemoryProvider> PageTableFrameMapping for FrameMapping<M> {
    fn frame_to_pointer(&self, frame: PhysFrame) -> *mut PageTable {
        frame_to_pointer::<M>(frame)
    }
}

unsafe impl<M: MemoryProvider> FrameAllocator<Size4KiB> for PageTableAllocator<M> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        Self::allocate_frame(true)
    }
}

impl<M: MemoryProvider> FrameDeallocator<Size4KiB> for PageTableAllocator<M> {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let vaddr = M::pa_to_va(frame.start_address());
        unsafe { M::mem_free_pages(vaddr.as_mut_ptr(), 0) };
    }
}

pub(crate) fn vmflags_to_pteflags(values: VmFlags) -> PageTableFlags {
    let mut flags = PageTableFlags::empty();
    if values.intersects(VmFlags::VM_READ | VmFlags::VM_WRITE) {
        flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    if values.contains(VmFlags::VM_WRITE) {
        flags |= PageTableFlags::WRITABLE;
    }
    if !values.contains(VmFlags::VM_EXEC) {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

impl<M: MemoryProvider> VmemBackend for X64PageTable<'_, M> {
    /// Unmap 4KiB pages from the page table
    ///
    /// Note it does not free the allocated frames for page table itself (only those allocated to
    /// user space).
    unsafe fn unmap_pages(&mut self, va: usize, len: usize, free_page: bool) {
        let va = VirtAddr::new(va as _);
        assert!(va.is_aligned(Size4KiB::SIZE));
        assert!(len as u64 % Size4KiB::SIZE == 0);

        let start = Page::<Size4KiB>::from_start_address(va).unwrap();
        let end = Page::<Size4KiB>::from_start_address(va + len as _).unwrap();
        let mut allocator = PageTableAllocator::<M>::new();

        // Note this implementation is slow as each page requires a full page table walk.
        // If we have N pages, it will be N times slower.
        for page in Page::range(start, end) {
            match self.inner.unmap(page) {
                Ok((frame, fl)) => {
                    if free_page {
                        unsafe { allocator.deallocate_frame(frame) };
                    }
                    if FLUSH_TLB {
                        fl.flush();
                    }
                }
                Err(UnmapError::PageNotMapped) => {}
                Err(UnmapError::ParentEntryHugePage) => {
                    panic!("Huge page cannot be unmapped");
                }
                Err(UnmapError::InvalidFrameAddress(pa)) => {
                    panic!("Invalid frame address: {:#x}", pa);
                }
            }
        }
    }

    unsafe fn remap_pages(
        &mut self,
        old_addr: usize,
        new_addr: usize,
        len: usize,
    ) -> Result<(), RemapError> {
        let old_addr = VirtAddr::new(old_addr as _);
        let new_addr = VirtAddr::new(new_addr as _);
        assert!(old_addr.is_aligned(Size4KiB::SIZE));
        assert!(new_addr.is_aligned(Size4KiB::SIZE));
        assert!(len as u64 % Size4KiB::SIZE == 0);

        // Note this implementation is slow as each page requires three full page table walks.
        // If we have N pages, it will be 3N times slower.
        let mut allocator = PageTableAllocator::<M>::new();
        let mut start: Page<Size4KiB> = Page::from_start_address(old_addr).unwrap();
        let mut new_start: Page<Size4KiB> = Page::from_start_address(new_addr).unwrap();
        let end: Page<Size4KiB> = Page::from_start_address(old_addr + len as _).unwrap();
        while start < end {
            match self.inner.translate(start.start_address()) {
                TranslateResult::Mapped {
                    frame: _,
                    offset: _,
                    flags,
                } => match self.inner.unmap(start) {
                    Ok((frame, fl)) => {
                        match unsafe { self.inner.map_to(new_start, frame, flags, &mut allocator) }
                        {
                            Ok(_) => {}
                            Err(e) => match e {
                                MapToError::PageAlreadyMapped(_) => {
                                    panic!("Page already mapped")
                                }
                                MapToError::ParentEntryHugePage => {
                                    return Err(RemapError::RemapToHugePage);
                                }
                                MapToError::FrameAllocationFailed => {
                                    return Err(RemapError::OutOfMemory);
                                }
                            },
                        }
                        if FLUSH_TLB {
                            fl.flush();
                        }
                    }
                    Err(UnmapError::PageNotMapped) => {
                        unreachable!()
                    }
                    Err(UnmapError::ParentEntryHugePage) => {
                        return Err(RemapError::RemapToHugePage);
                    }
                    Err(UnmapError::InvalidFrameAddress(pa)) => {
                        panic!("Invalid frame address: {:#x}", pa);
                    }
                },
                TranslateResult::NotMapped => {}
                TranslateResult::InvalidFrameAddress(pa) => {
                    panic!("Invalid frame address: {:#x}", pa);
                }
            }
            start += 1;
            new_start += 1;
        }

        Ok(())
    }

    unsafe fn mprotect_pages(
        &mut self,
        start: usize,
        len: usize,
        new_flags: VmFlags,
    ) -> Result<(), ProtectError> {
        let start = VirtAddr::new(start as _);
        let new_flags = vmflags_to_pteflags(new_flags) & Self::MPROTECT_PTE_MASK;
        let begin: Page<Size4KiB> = Page::containing_address(start);
        let end: Page<Size4KiB> = Page::containing_address(start + len as _ - 1);

        // TODO: this implementation is slow as each page requires two full page table walks.
        // If we have N pages, it will be 2N times slower.
        for page in Page::range(begin, end + 1) {
            match self.inner.translate(page.start_address()) {
                TranslateResult::Mapped {
                    frame: _,
                    offset: _,
                    flags,
                } => {
                    // If it is changed to writable, we leave it to page fault handler (COW)
                    let change_to_write = new_flags.contains(PageTableFlags::WRITABLE)
                        && !flags.contains(PageTableFlags::WRITABLE);
                    let new_flags = if change_to_write {
                        new_flags - PageTableFlags::WRITABLE
                    } else {
                        new_flags
                    };
                    if flags != new_flags {
                        match unsafe {
                            self.inner
                                .update_flags(page, (flags & !Self::MPROTECT_PTE_MASK) | new_flags)
                        } {
                            Ok(fl) => {
                                if FLUSH_TLB {
                                    fl.flush();
                                }
                            }
                            Err(e) => match e {
                                FlagUpdateError::PageNotMapped => unreachable!(),
                                FlagUpdateError::ParentEntryHugePage => {
                                    return Err(ProtectError::ProtectHugePage);
                                }
                            },
                        }
                    }
                }
                TranslateResult::NotMapped => {}
                TranslateResult::InvalidFrameAddress(pa) => {
                    panic!("Invalid frame address: {:#x}", pa);
                }
            }
        }

        Ok(())
    }
}

impl<M: MemoryProvider> PageTableImpl for X64PageTable<'_, M> {
    unsafe fn init(p4: PhysAddr) -> Self {
        assert!(p4.is_aligned(Size4KiB::SIZE));
        let frame = PhysFrame::from_start_address(p4).unwrap();
        let mapping = FrameMapping::<M> {
            _provider: core::marker::PhantomData,
        };
        let p4_va = mapping.frame_to_pointer(frame);
        let p4 = unsafe { &mut *p4_va };
        X64PageTable {
            inner: unsafe { MappedPageTable::new(p4, mapping) },
        }
    }

    fn translate(&self, addr: VirtAddr) -> TranslateResult {
        self.inner.translate(addr)
    }

    unsafe fn handle_page_fault(
        &mut self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
        error_code: PageFaultErrorCode,
    ) -> Result<(), crate::mm::pgtable::PageFaultError> {
        match self.inner.translate(page.start_address()) {
            TranslateResult::Mapped {
                frame: _,
                offset: _,
                flags,
            } => {
                if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
                    if flags.contains(PageTableFlags::WRITABLE) {
                        // probably set by other threads concurrently
                        return Ok(());
                    } else {
                        // Copy-on-Write
                        todo!("COW");
                    }
                }

                if !error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
                    // not present error but PTE says it is present, probably due to race condition
                    return Ok(());
                }

                panic!("Page fault on present page: {:#x}", page.start_address());
            }
            TranslateResult::NotMapped => {
                let mut allocator = PageTableAllocator::<M>::new();
                // TODO: if it is file-backed, we need to read the page from file
                let frame = PageTableAllocator::<M>::allocate_frame(true).unwrap();
                let table_flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE;
                match unsafe {
                    self.inner.map_to_with_table_flags(
                        page,
                        frame,
                        flags | PageTableFlags::PRESENT,
                        table_flags,
                        &mut allocator,
                    )
                } {
                    Ok(fl) => {
                        if FLUSH_TLB {
                            fl.flush();
                        }
                    }
                    Err(e) => {
                        unsafe { allocator.deallocate_frame(frame) };
                        match e {
                            MapToError::PageAlreadyMapped(_) => {
                                unreachable!()
                            }
                            MapToError::ParentEntryHugePage => {
                                return Err(PageFaultError::HugePage);
                            }
                            MapToError::FrameAllocationFailed => {
                                return Err(PageFaultError::AllocationFailed);
                            }
                        }
                    }
                }
            }
            TranslateResult::InvalidFrameAddress(pa) => {
                panic!("Invalid frame address: {:#x}", pa);
            }
        }
        Ok(())
    }
}
