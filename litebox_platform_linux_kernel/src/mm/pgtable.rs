use crate::arch::{
    Page, PageFaultErrorCode, PageTable, PageTableEntry, PageTableFlags, PageTableIndex, PhysAddr,
    PhysFrame, Size4KiB, VirtAddr, PAGE_SIZE,
};

pub struct PageTableAllocator<M: super::MemoryProvider> {
    _provider: core::marker::PhantomData<M>,
}

impl<M: super::MemoryProvider> PageTableAllocator<M> {
    pub fn new() -> Self {
        Self {
            _provider: core::marker::PhantomData,
        }
    }

    pub fn allocate_frame(&mut self, init: bool) -> Option<PhysFrame<Size4KiB>> {
        M::mem_allocate_pages(0).map(|addr| {
            if init {
                unsafe {
                    core::intrinsics::write_bytes(addr, 0, PAGE_SIZE as usize);
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

    /// Handle page fault
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

    /// Unmap 4KiB pages from the page table
    fn unmap_pages(&mut self, start: VirtAddr, len: usize, free_page: bool);

    /// Remap 4KiB pages in the page table from `old_addr` to `new_addr`
    ///
    /// # Safety
    ///
    /// The caller must also ensure that the [`new_addr`, `new_addr` + `len`]
    /// is not already mapped, and `old_addr` and `new_addr` do not overlap.
    unsafe fn remap_pages(
        &mut self,
        old_addr: VirtAddr,
        new_addr: VirtAddr,
        len: usize,
    ) -> Result<(), PageTableWalkError>;

    unsafe fn mprotect_pages(
        &mut self,
        start: VirtAddr,
        len: usize,
        flags: PageTableFlags,
    ) -> Result<(), PageTableWalkError>;
}

#[derive(Debug)]
pub enum PageTableWalkError {
    NotMapped,
    MappedToHugePage,
    AllocationFailed,
}

#[inline]
fn frame_to_pointer<M: super::MemoryProvider>(frame: PhysFrame) -> *mut PageTable {
    let virt = M::pa_to_va(frame.start_address());
    virt.as_mut_ptr()
}

pub trait PageTableRangeWalker<M: super::MemoryProvider> {
    type NextLevelWalker: PageTableRangeWalker<M>;

    const VADDR_MAX: VirtAddr = VirtAddr::new(usize::MAX as _);

    unsafe fn walk_page_table_mut<F>(pt: &mut PageTable, start: VirtAddr, end: VirtAddr, cb: &mut F)
    where
        F: FnMut(VirtAddr, &mut PageTableEntry),
    {
        let mut addr = start;
        while addr < end {
            let next = Self::next_addr(addr, end);
            let entry = &mut pt[Self::index(addr)];
            if let Ok(pgtable) = Self::next_table_mut(entry) {
                Self::NextLevelWalker::walk_page_table_mut(pgtable, addr, next, cb);
            }
            addr = next;
        }
    }

    unsafe fn walk_two_but_same_page_table<F>(
        pt: &mut PageTable,
        addr1: VirtAddr,
        addr1_end: VirtAddr,
        addr2: VirtAddr,
        allocator: &mut PageTableAllocator<M>,
        cb: &mut F,
    ) -> Result<(), PageTableWalkError>
    where
        F: FnMut(&PageTableEntry, &mut PageTableEntry),
    {
        let mut addr1_start = addr1;
        let mut addr2_start = addr2;
        while addr1_start < addr1_end {
            let next = Self::next_addr(addr1_start, addr1_end);
            let (i, j) = (Self::index(addr1_start), Self::index(addr2_start));
            if i == j {
                if let Ok(next_pt) = Self::next_table_mut(&mut pt[i]) {
                    Self::NextLevelWalker::walk_two_but_same_page_table(
                        next_pt,
                        addr1_start,
                        addr1_end,
                        addr2_start,
                        allocator,
                        cb,
                    )?;
                }
            } else {
                let src_pt: &mut [PageTableEntry; PAGE_SIZE / size_of::<PageTableEntry>()] =
                    core::mem::transmute(&mut *pt);
                let ptr = src_pt.as_mut_ptr();
                let src_entry = &*ptr.add(u16::from(i) as usize);
                if let Ok(src_next_pt) = Self::next_table(src_entry) {
                    let dst_entry = &mut *ptr.add(u16::from(i) as usize);
                    let dst_next_pt = Self::create_next_table(dst_entry, allocator)?;
                    Self::NextLevelWalker::walk_two_different_page_tables(
                        src_next_pt,
                        dst_next_pt,
                        addr1_start,
                        next,
                        addr2_start,
                        allocator,
                        cb,
                    )?;
                }
            }
            addr1_start = next;
            addr2_start = Self::next_addr(addr2_start, Self::VADDR_MAX);
        }

        Ok(())
    }

    unsafe fn walk_two_different_page_tables<F>(
        src_pt: &PageTable,
        dst_pt: &mut PageTable,
        addr1: VirtAddr,
        addr1_end: VirtAddr,
        addr2: VirtAddr,
        allocator: &mut PageTableAllocator<M>,
        cb: &mut F,
    ) -> Result<(), PageTableWalkError>
    where
        F: FnMut(&PageTableEntry, &mut PageTableEntry),
    {
        let mut addr1_start = addr1;
        let mut addr2_start = addr2;
        while addr1_start < addr1_end {
            let next = Self::next_addr(addr1_start, addr1_end);
            let src_entry = &src_pt[Self::index(addr1_start)];
            if let Ok(src_next_pt) = Self::next_table(src_entry) {
                let dst_entry = &mut dst_pt[Self::index(addr2_start)];
                let dst_next_pt = Self::create_next_table(dst_entry, allocator)?;
                Self::NextLevelWalker::walk_two_different_page_tables(
                    src_next_pt,
                    dst_next_pt,
                    addr1_start,
                    next,
                    addr2_start,
                    allocator,
                    cb,
                )?;
            }
            addr1_start = next;
            addr2_start = Self::next_addr(addr2_start, Self::VADDR_MAX);
        }

        Ok(())
    }

    fn index(addr: VirtAddr) -> PageTableIndex;

    fn next_addr(addr: VirtAddr, end: VirtAddr) -> VirtAddr;

    /// Get a mutable reference to the page table of the next level.
    fn next_table_mut<'a>(
        entry: &'a mut PageTableEntry,
    ) -> Result<&'a mut PageTable, PageTableWalkError> {
        let page_table_ptr = frame_to_pointer::<M>(entry.frame()?);
        let page_table: &mut PageTable = unsafe { &mut *page_table_ptr };

        Ok(page_table)
    }

    /// Get a reference to the page table of the next level.
    fn next_table<'a>(entry: &'a PageTableEntry) -> Result<&'a PageTable, PageTableWalkError> {
        let page_table_ptr = frame_to_pointer::<M>(entry.frame()?);
        let page_table: &PageTable = unsafe { &*page_table_ptr };

        Ok(page_table)
    }

    /// Create the page table of the next level if needed.
    ///
    /// If the passed entry is unused, a new frame is allocated from the given allocator, zeroed,
    /// and the entry is updated to that address. If the passed entry is already mapped, the next
    /// table is returned directly.
    fn create_next_table_with_flags<'a>(
        entry: &'a mut PageTableEntry,
        flags: PageTableFlags,
        allocator: &mut PageTableAllocator<M>,
    ) -> Result<&'a mut PageTable, PageTableWalkError> {
        if entry.is_unused() {
            if let Some(frame) = allocator.allocate_frame(true) {
                entry.set_frame(frame, flags);
            } else {
                return Err(PageTableWalkError::AllocationFailed);
            }
        }

        let page_table = match Self::next_table_mut(entry) {
            Ok(page_table) => page_table,
            Err(PageTableWalkError::MappedToHugePage) => {
                return Err(PageTableWalkError::MappedToHugePage)
            }
            Err(PageTableWalkError::NotMapped) | Err(PageTableWalkError::AllocationFailed) => {
                panic!("mapped")
            }
        };
        Ok(page_table)
    }

    fn create_next_table<'a>(
        entry: &'a mut PageTableEntry,
        allocator: &mut PageTableAllocator<M>,
    ) -> Result<&'a mut PageTable, PageTableWalkError> {
        let flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        Self::create_next_table_with_flags(entry, flags, allocator)
    }
}

pub enum PageFaultError {
    AccessError,
    OOM,
    HugePage,
}
