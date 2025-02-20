use x86_64::structures::{
    idt::PageFaultErrorCode,
    paging::{
        mapper::{MapToError, TranslateResult},
        FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageSize, PageTable,
        PageTableFlags, PhysFrame, Size4KiB, Translate,
    },
};

struct PageTableAllocator<M: super::MemoryProvider> {
    _provider: core::marker::PhantomData<M>,
}

impl<M: super::MemoryProvider> PageTableAllocator<M> {
    pub(super) fn new() -> Self {
        Self {
            _provider: core::marker::PhantomData,
        }
    }

    pub(super) fn allocate_frame(&mut self, init: bool) -> Option<PhysFrame<Size4KiB>> {
        M::mem_allocate_pages(0).map(|addr| {
            if init {
                unsafe {
                    core::intrinsics::write_bytes(addr, 0, Size4KiB::SIZE as usize);
                }
            }
            PhysFrame::from_start_address(M::make_pa_private(M::va_to_pa(x86_64::VirtAddr::new(
                addr as u64,
            ))))
            .unwrap()
        })
    }
}

unsafe impl<M: super::MemoryProvider> FrameAllocator<Size4KiB> for PageTableAllocator<M> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_frame(true)
    }
}

impl<M: super::MemoryProvider> FrameDeallocator<Size4KiB> for PageTableAllocator<M> {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let vaddr = M::pa_to_va(frame.start_address());
        M::mem_free_pages(vaddr.as_mut_ptr(), 0);
    }
}

unsafe fn pgtable_init<M: super::MemoryProvider>(p4: &mut PageTable) -> OffsetPageTable<'_> {
    OffsetPageTable::new(p4, M::GVA_OFFSET)
}

unsafe fn handle_page_fault<M: super::MemoryProvider>(
    p: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    flags: PageTableFlags,
    error_code: PageFaultErrorCode,
) -> Result<(), MapToError<Size4KiB>> {
    match p.translate(page.start_address()) {
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
            match p.map_to_with_table_flags(page, frame, flags, table_flags, &mut allocator) {
                Ok(flush) => flush.flush(),
                Err(e) => {
                    allocator.deallocate_frame(frame);
                    return Err(e);
                }
            }
        }
        TranslateResult::InvalidFrameAddress(pa) => {
            panic!("Invalid frame address: {:#x}", pa);
        }
    }
    Ok(())
}
