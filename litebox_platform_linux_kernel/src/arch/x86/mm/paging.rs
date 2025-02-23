use x86_64::{
    structures::{
        idt::PageFaultErrorCode,
        paging::{
            mapper::{
                FlagUpdateError, MapToError, MapperFlush, PageTableFrameMapping, TranslateResult,
            },
            page_table::{FrameError, PageTableEntry},
            FrameAllocator, FrameDeallocator, MappedPageTable, Mapper, Page, PageSize, PageTable,
            PageTableFlags, PageTableIndex, PhysFrame, Size4KiB, Translate,
        },
    },
    PhysAddr, VirtAddr,
};

use crate::mm::{
    pgtable::{
        PageFaultError, PageTableAllocator, PageTableImpl, PageTableRangeWalker, PageTableWalkError,
    },
    MemoryProvider,
};

pub const PGDIR_SHIFT: u64 = 39;
pub const PGDIR_SIZE: u64 = 0x8000000000; // 1 << PGDIR_SHIFT;
pub const PGDIR_MASK: u64 = !(PGDIR_SIZE - 1);
pub const PUD_SHIFR: u64 = 30;
pub const PUD_SIZE: u64 = 0x40000000; // 1 << PUD_SHIFR;
pub const PUD_MASK: u64 = !(PUD_SIZE - 1);
pub const PMD_SHIFT: u64 = 21;
pub const PMD_SIZE: u64 = 0x200000; // 1 << PMD_SHIFT;
pub const PMD_MASK: u64 = !(PMD_SIZE - 1);

struct PageTablePGDWalker;
struct PageTablePUDWalker;
struct PageTablePMDWalker;
struct PageTablePTEWalker;

#[inline]
fn frame_to_pointer<M: MemoryProvider>(frame: PhysFrame) -> *mut PageTable {
    let virt = M::pa_to_va(frame.start_address());
    virt.as_mut_ptr()
}

impl From<FrameError> for PageTableWalkError {
    fn from(value: FrameError) -> Self {
        match value {
            FrameError::FrameNotPresent => PageTableWalkError::NotMapped,
            FrameError::HugeFrame => PageTableWalkError::MappedToHugePage,
        }
    }
}

impl<M: MemoryProvider> PageTableRangeWalker<M> for PageTablePGDWalker {
    type NextLevelWalker = PageTablePUDWalker;

    fn index(addr: VirtAddr) -> PageTableIndex {
        addr.p1_index()
    }

    fn next_addr(addr: VirtAddr, end: VirtAddr) -> VirtAddr {
        let boundary = (addr.as_u64() + PGDIR_SIZE) & PGDIR_MASK;
        if boundary - 1 < end.as_u64() - 1 {
            VirtAddr::new(boundary)
        } else {
            end
        }
    }
}

impl<M: MemoryProvider> PageTableRangeWalker<M> for PageTablePUDWalker {
    type NextLevelWalker = PageTablePMDWalker;

    fn index(addr: VirtAddr) -> PageTableIndex {
        addr.p2_index()
    }

    fn next_addr(addr: VirtAddr, end: VirtAddr) -> VirtAddr {
        let boundary = (addr.as_u64() + PUD_SIZE) & PUD_MASK;
        if boundary - 1 < end.as_u64() - 1 {
            VirtAddr::new(boundary)
        } else {
            end
        }
    }
}

impl<M: MemoryProvider> PageTableRangeWalker<M> for PageTablePMDWalker {
    type NextLevelWalker = PageTablePTEWalker;

    fn index(addr: VirtAddr) -> PageTableIndex {
        addr.p3_index()
    }

    fn next_addr(addr: VirtAddr, end: VirtAddr) -> VirtAddr {
        let boundary = (addr.as_u64() + PMD_SIZE) & PMD_MASK;
        if boundary - 1 < end.as_u64() - 1 {
            VirtAddr::new(boundary)
        } else {
            end
        }
    }
}

impl<M: MemoryProvider> PageTableRangeWalker<M> for PageTablePTEWalker {
    type NextLevelWalker = PageTablePTEWalker;

    fn index(addr: VirtAddr) -> PageTableIndex {
        addr.p4_index()
    }

    fn next_addr(addr: VirtAddr, _end: VirtAddr) -> VirtAddr {
        addr + Size4KiB::SIZE
    }

    unsafe fn walk_page_table_mut<F>(pt: &mut PageTable, start: VirtAddr, end: VirtAddr, cb: &mut F)
    where
        F: FnMut(VirtAddr, &mut PageTableEntry),
    {
        let mut addr = start;
        while addr < end {
            let next = <Self as PageTableRangeWalker<M>>::next_addr(addr, end);
            let entry = &mut pt[<Self as PageTableRangeWalker<M>>::index(addr)];
            cb(addr, entry);
            addr = next;
        }
    }

    unsafe fn walk_two_different_page_tables<F>(
        src_pt: &PageTable,
        dst_pt: &mut PageTable,
        addr1: VirtAddr,
        addr1_end: VirtAddr,
        addr2: VirtAddr,
        _allocator: &mut PageTableAllocator<M>,
        cb: &mut F,
    ) -> Result<(), PageTableWalkError>
    where
        F: FnMut(&PageTableEntry, &mut PageTableEntry),
    {
        let mut addr1_start = addr1;
        let mut addr2_start = addr2;
        while addr1_start < addr1_end {
            let next = <Self as PageTableRangeWalker<M>>::next_addr(addr1_start, addr1_end);
            let src_entry = &src_pt[<Self as PageTableRangeWalker<M>>::index(addr1_start)];
            let dst_entry = &mut dst_pt[<Self as PageTableRangeWalker<M>>::index(addr2_start)];
            cb(src_entry, dst_entry);
            addr1_start = next;
            addr2_start = <Self as PageTableRangeWalker<M>>::next_addr(
                addr2_start,
                <Self as PageTableRangeWalker<M>>::VADDR_MAX,
            );
        }
        Ok(())
    }

    unsafe fn walk_two_but_same_page_table<F>(
        _pt: &mut PageTable,
        _addr1: VirtAddr,
        _addr1_end: VirtAddr,
        _addr2: VirtAddr,
        _allocator: &mut PageTableAllocator<M>,
        _cb: &mut F,
    ) -> Result<(), PageTableWalkError>
    where
        F: FnMut(&PageTableEntry, &mut PageTableEntry),
    {
        unimplemented!()
    }
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
        self.allocate_frame(true)
    }
}

impl<M: MemoryProvider> FrameDeallocator<Size4KiB> for PageTableAllocator<M> {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let vaddr = M::pa_to_va(frame.start_address());
        M::mem_free_pages(vaddr.as_mut_ptr(), 0);
    }
}

impl<'a, M: MemoryProvider> PageTableImpl for X64PageTable<'a, M> {
    unsafe fn init(p4: PhysAddr) -> Self {
        assert!(p4.is_aligned(Size4KiB::SIZE));
        let frame = PhysFrame::from_start_address(p4).unwrap();
        let mapping = FrameMapping::<M> {
            _provider: core::marker::PhantomData,
        };
        let p4_va = mapping.frame_to_pointer(frame);
        let p4 = &mut *p4_va;
        X64PageTable {
            inner: MappedPageTable::new(p4, mapping),
        }
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
                let frame = allocator.allocate_frame(true).unwrap();
                let table_flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE;
                match self.inner.map_to_with_table_flags(
                    page,
                    frame,
                    flags,
                    table_flags,
                    &mut allocator,
                ) {
                    Ok(flush) => flush.flush(),
                    Err(e) => {
                        allocator.deallocate_frame(frame);
                        match e {
                            MapToError::PageAlreadyMapped(_) => {
                                unreachable!()
                            }
                            MapToError::ParentEntryHugePage => {
                                return Err(PageFaultError::HugePage)
                            }
                            MapToError::FrameAllocationFailed => return Err(PageFaultError::OOM),
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

    /// Unmap 4KiB pages from the page table
    ///
    /// Note it does not free the allocated frames for page table itself (only those allocated to
    /// user space).
    fn unmap_pages(&mut self, va: VirtAddr, len: usize, free_page: bool) {
        let start = va.align_down(Size4KiB::SIZE);
        let end = (va + len as u64).align_up(Size4KiB::SIZE);
        let mut allocator = PageTableAllocator::<M>::new();

        let pt = self.inner.level_4_table_mut();
        unsafe {
            <PageTablePGDWalker as PageTableRangeWalker<M>>::walk_page_table_mut(
                pt,
                start,
                end,
                &mut |va, entry| match entry.frame() {
                    Ok(frame) => {
                        entry.set_unused();
                        let page = Page::<Size4KiB>::from_start_address(va).unwrap();
                        MapperFlush::new(page).flush();
                        // TODO: once we have implmented reference counting (to support shared pages),
                        // we need to check it before deallocating the frame (instead of relying on the caller)
                        if free_page {
                            allocator.deallocate_frame(frame);
                        }
                    }
                    Err(FrameError::FrameNotPresent) => {}
                    Err(FrameError::HugeFrame) => {
                        panic!("Huge page cannot be unmapped");
                    }
                },
            )
        };
    }

    unsafe fn remap_pages(
        &mut self,
        old_addr: VirtAddr,
        new_addr: VirtAddr,
        len: usize,
    ) -> Result<(), PageTableWalkError> {
        assert!(old_addr.is_aligned(Size4KiB::SIZE));
        assert!(new_addr.is_aligned(Size4KiB::SIZE));
        assert!(len % Size4KiB::SIZE as usize == 0);

        let pt = self.inner.level_4_table_mut();
        let mut allocator = PageTableAllocator::<M>::new();
        <PageTablePGDWalker as PageTableRangeWalker<M>>::walk_two_but_same_page_table(
            pt,
            old_addr,
            old_addr + len as _,
            new_addr,
            &mut allocator,
            &mut |src_entry, dst_entry| {
                if let Ok(frame) = src_entry.frame() {
                    dst_entry.set_frame(frame, src_entry.flags());
                }
            },
        )?;

        self.unmap_pages(old_addr, len, false);
        Ok(())
    }

    unsafe fn mprotect_pages(
        &mut self,
        start: VirtAddr,
        len: usize,
        new_flags: PageTableFlags,
    ) -> Result<(), PageTableWalkError> {
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
                        match self.inner.update_flags(page, new_flags) {
                            Ok(flush) => flush.flush(),
                            Err(e) => match e {
                                FlagUpdateError::PageNotMapped => unreachable!(),
                                FlagUpdateError::ParentEntryHugePage => {
                                    return Err(PageTableWalkError::MappedToHugePage)
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
