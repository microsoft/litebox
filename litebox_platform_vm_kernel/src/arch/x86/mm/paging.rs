// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use arrayvec::ArrayVec;
use core::ops::Range;
use litebox::platform::page_mgmt;
use litebox::utils::TruncateExt;
use litebox_common_linux::vmem::{PageFaultError, PageRange, VmFlags, VmemPageFaultHandler};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::{
        idt::PageFaultErrorCode,
        paging::{
            FrameAllocator, FrameDeallocator, MappedPageTable, Mapper, Page, PageSize, PageTable,
            PageTableFlags, PhysFrame, Size4KiB, Translate,
            frame::PhysFrameRange,
            mapper::{
                CleanUp, FlagUpdateError, MapToError, PageTableFrameMapping, TranslateResult,
                UnmapError as X64UnmapError,
            },
            page_table::PageTableEntry,
        },
    },
};

use crate::UserMutPtr;
use crate::mm::{
    MemoryProvider,
    pgtable::{PageTableAllocator, PageTableImpl},
};

/// Above this many pages, a full TLB flush is cheaper than `invlpg` per page
/// (Linux's `tlb_single_page_flush_ceiling`).
#[cfg(not(test))]
const TLB_SINGLE_PAGE_FLUSH_CEILING: usize = 33;

const PAGE_SHIFT: usize = Size4KiB::SIZE.trailing_zeros() as usize;
const PAGE_TABLE_LEVEL_BITS: usize = 9;
const P2_SHIFT: usize = PAGE_SHIFT + PAGE_TABLE_LEVEL_BITS;
const P3_SHIFT: usize = P2_SHIFT + PAGE_TABLE_LEVEL_BITS;
const PML4_SHIFT: usize = P3_SHIFT + PAGE_TABLE_LEVEL_BITS;
const PML4_INDEX_MASK: u64 = (1 << PAGE_TABLE_LEVEL_BITS) - 1;

/// Kernel slots share fixed P3/P2/P1 tables; lower slots must be privately owned.
pub(crate) const KERNEL_PML4_START: usize =
    ((crate::KERNEL_OFFSET >> PML4_SHIFT) & PML4_INDEX_MASK) as usize;

/// Flush the local TLB only; correct for a single CPU.
/// TODO(SMP): shoot down other cores.
#[cfg(not(test))]
fn flush_tlb_range(start: Page<Size4KiB>, count: usize) {
    if count == 0 {
        return;
    }
    if count <= TLB_SINGLE_PAGE_FLUSH_CEILING {
        let base = start.start_address().as_u64();
        for i in 0..count {
            x86_64::instructions::tlb::flush(VirtAddr::new(base + (i as u64) * Size4KiB::SIZE));
        }
    } else {
        x86_64::instructions::tlb::flush_all();
    }
}

#[cfg(test)]
fn flush_tlb_range(_start: Page<Size4KiB>, _count: usize) {}

#[inline]
fn frame_to_pointer<M: MemoryProvider>(frame: PhysFrame) -> *mut PageTable {
    let virt = M::pa_to_va(frame.start_address());
    virt.as_mut_ptr()
}

pub(crate) struct X64PageTable<'a, M: MemoryProvider, const ALIGN: usize> {
    inner: spin::mutex::SpinMutex<MappedPageTable<'a, FrameMapping<M>>>,
}

struct FrameMapping<M: MemoryProvider> {
    _provider: core::marker::PhantomData<M>,
}

// Safety: page-table frames come from `M`, whose memory is in the kernel
// mapping, so `pa_to_va` yields a valid pointer to each table.
unsafe impl<M: MemoryProvider> PageTableFrameMapping for FrameMapping<M> {
    fn frame_to_pointer(&self, frame: PhysFrame) -> *mut PageTable {
        frame_to_pointer::<M>(frame)
    }
}

// Safety: `allocate_frame` returns fresh, exclusively owned frames from `M`.
unsafe impl<M: MemoryProvider> FrameAllocator<Size4KiB> for PageTableAllocator<M> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        Self::allocate_frame()
    }
}

impl<M: MemoryProvider> FrameDeallocator<Size4KiB> for PageTableAllocator<M> {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let vaddr = M::pa_to_va(frame.start_address());
        // Safety: the caller passes a frame from `allocate_frame`, i.e., an
        // order-0 allocation from `M`, that is no longer used.
        unsafe { M::mem_free_pages(vaddr.as_mut_ptr(), 0) };
    }
}

pub(crate) fn vmflags_to_pteflags(values: VmFlags) -> PageTableFlags {
    let mut flags = PageTableFlags::empty();
    if values.intersects(VmFlags::VM_ACCESS_FLAGS) {
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

#[derive(Clone, Copy)]
pub(crate) struct UnmapOptions {
    /// Must be false for frames owned elsewhere, including stack guards.
    pub(crate) free_frames: bool,
    /// May be false only for a table that will never be loaded again.
    pub(crate) flush_tlb: bool,
    /// Must be false for shared intermediate tables.
    pub(crate) free_empty_tables: bool,
}

impl UnmapOptions {
    pub(crate) const RELEASE: Self = Self {
        free_frames: true,
        flush_tlb: true,
        free_empty_tables: false,
    };
    pub(crate) const KEEP_FRAMES: Self = Self {
        free_frames: false,
        flush_tlb: true,
        free_empty_tables: false,
    };
}

impl<M: MemoryProvider, const ALIGN: usize> X64PageTable<'_, M, ALIGN> {
    /// # Safety
    ///
    /// `range` must be user address space the caller may map with `flags`, and
    /// nothing may be mapped in it yet.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if populating runs out of frames; the pages populated so
    /// far are unmapped again.
    pub(crate) unsafe fn map_pages(
        &self,
        range: PageRange<ALIGN>,
        flags: VmFlags,
        populate_pages: bool,
    ) -> Result<UserMutPtr<u8>, page_mgmt::AllocationError> {
        if populate_pages {
            let flags = vmflags_to_pteflags(flags);
            for addr in range {
                let page =
                    Page::<Size4KiB>::from_start_address(VirtAddr::new(addr as u64)).unwrap();
                // Safety: the caller may map `range` with `flags`.
                match unsafe {
                    PageTableImpl::handle_page_fault(self, page, flags, PageFaultErrorCode::empty())
                } {
                    Ok(()) => {}
                    Err(PageFaultError::AllocationFailed) => {
                        if addr != range.start {
                            let populated = PageRange::new(range.start, addr)
                                .expect("a nonempty prefix of an aligned range is aligned");
                            // Safety: mapped above and not yet handed out.
                            unsafe { self.unmap_pages(populated, UnmapOptions::RELEASE) }
                                .expect("unmapping an aligned range cannot fail");
                        }
                        return Err(page_mgmt::AllocationError::OutOfMemory);
                    }
                    // This table has no huge pages, and `range` was unmapped.
                    Err(e) => panic!("BUG: populating {addr:#x}: {e:?}"),
                }
            }
        }
        Ok(UserMutPtr::from_ptr(range.start as *mut u8))
    }

    /// # Safety
    ///
    /// Nothing may use the pages it unmaps. Without `flush_tlb`, the table must
    /// never be loaded again, as stale TLB entries may still reach the freed
    /// frames.
    pub(crate) unsafe fn unmap_pages(
        &self,
        range: PageRange<ALIGN>,
        options: UnmapOptions,
    ) -> Result<(), page_mgmt::DeallocationError> {
        // Batches stay below `TLB_SINGLE_PAGE_FLUSH_CEILING`.
        const UNMAP_BATCH: usize = 32;
        if range.is_empty() {
            return Ok(());
        }
        let start = Page::<Size4KiB>::from_start_address(VirtAddr::new(range.start as _))
            .or(Err(page_mgmt::DeallocationError::Unaligned))?;
        let end = Page::<Size4KiB>::from_start_address(VirtAddr::new(range.end as _))
            .or(Err(page_mgmt::DeallocationError::Unaligned))?;
        let mut allocator = PageTableAllocator::<M>::new();

        let mut inner = self.inner.lock();

        let mut unmap_one = |page: Page<Size4KiB>| -> Option<PhysFrame<Size4KiB>> {
            match inner.unmap(page) {
                Ok((frame, _)) => Some(frame),
                Err(X64UnmapError::PageNotMapped) => None,
                Err(X64UnmapError::ParentEntryHugePage) => {
                    litebox_util_log::error!("BUG: attempt to unmap a huge page");
                    None
                }
                Err(X64UnmapError::InvalidFrameAddress(pa)) => {
                    litebox_util_log::error!(pa:? = pa; "BUG: attempt to unmap an invalid frame address");
                    None
                }
            }
        };

        match (options.free_frames, options.flush_tlb) {
            (false, false) => {
                for page in Page::range(start, end) {
                    let _ = unmap_one(page);
                }
            }
            (false, true) => {
                for page in Page::range(start, end) {
                    let _ = unmap_one(page);
                }
                let count =
                    ((end.start_address() - start.start_address()) / Size4KiB::SIZE).trunc();
                flush_tlb_range(start, count);
            }
            (true, false) => {
                for page in Page::range(start, end) {
                    if let Some(frame) = unmap_one(page) {
                        // Safety: unmapped, and the caller guarantees no use or
                        // stale translation remains.
                        unsafe { allocator.deallocate_frame(frame) };
                    }
                }
            }
            (true, true) => {
                // Flush stale translations before any frame can be reused.
                let mut unmapped_frames: ArrayVec<PhysFrame<Size4KiB>, UNMAP_BATCH> =
                    ArrayVec::new();
                let mut flush_start = start;
                for (i, page) in Page::range(start, end).enumerate() {
                    if let Some(frame) = unmap_one(page) {
                        unmapped_frames.push(frame);
                    }
                    if (i + 1) % UNMAP_BATCH == 0 {
                        if !unmapped_frames.is_empty() {
                            flush_tlb_range(flush_start, UNMAP_BATCH);
                            for frame in unmapped_frames.drain(..) {
                                // Safety: unmapped and flushed; the caller
                                // guarantees nothing else uses it.
                                unsafe { allocator.deallocate_frame(frame) };
                            }
                        }
                        flush_start = page + 1;
                    }
                }

                if !unmapped_frames.is_empty() {
                    let count = ((end.start_address() - flush_start.start_address())
                        / Size4KiB::SIZE)
                        .trunc();
                    flush_tlb_range(flush_start, count);
                    for frame in unmapped_frames.drain(..) {
                        // Safety: as above.
                        unsafe { allocator.deallocate_frame(frame) };
                    }
                }
            }
        }

        if options.free_empty_tables {
            // Safety: all leaf entries in the range have been unmapped above;
            // the caller guarantees this VA range is no longer in use.
            unsafe {
                inner.clean_up_addr_range(Page::range_inclusive(start, end - 1u64), &mut allocator);
            }
        }

        Ok(())
    }

    pub(crate) unsafe fn mprotect_pages(
        &self,
        range: PageRange<ALIGN>,
        new_flags: VmFlags,
    ) -> Result<(), page_mgmt::PermissionUpdateError> {
        let start = VirtAddr::new(range.start as _);
        let end = VirtAddr::new(range.end as _);
        let new_flags = vmflags_to_pteflags(new_flags) & Self::MPROTECT_PTE_MASK;
        let start: Page<Size4KiB> =
            Page::from_start_address(start).or(Err(page_mgmt::PermissionUpdateError::Unaligned))?;
        let end: Page<Size4KiB> = Page::containing_address(end - 1);

        let mut inner = self.inner.lock();
        for page in Page::range(start, end + 1) {
            match inner.translate(page.start_address()) {
                TranslateResult::Mapped {
                    frame: _,
                    offset: _,
                    flags,
                } => {
                    // COW is unsupported: install WRITABLE eagerly. Teardown
                    // assumes exclusive frame ownership, not refcounts.
                    if flags != new_flags {
                        // Safety: changes only permission bits of a present
                        // leaf; stale TLB entries are flushed below.
                        match unsafe {
                            inner.update_flags(page, (flags & !Self::MPROTECT_PTE_MASK) | new_flags)
                        } {
                            Ok(_) => {}
                            Err(e) => match e {
                                FlagUpdateError::PageNotMapped => unreachable!(),
                                FlagUpdateError::ParentEntryHugePage => {
                                    #[cfg(debug_assertions)]
                                    todo!("BUG: attempt to protect a huge page");
                                    #[cfg(not(debug_assertions))]
                                    {
                                        litebox_util_log::error!(
                                            "BUG: attempt to protect a huge page"
                                        );
                                        return Err(page_mgmt::PermissionUpdateError::Unaligned);
                                    }
                                }
                            },
                        }
                    }
                }
                TranslateResult::NotMapped => {}
                TranslateResult::InvalidFrameAddress(pa) => {
                    #[cfg(debug_assertions)]
                    todo!("Invalid frame address: {:#x}", pa);
                    #[cfg(not(debug_assertions))]
                    {
                        litebox_util_log::error!(pa:? = pa; "invalid frame address");
                        return Err(page_mgmt::PermissionUpdateError::Unaligned);
                    }
                }
            }
        }

        let page_count = (end.start_address() - start.start_address()) / Size4KiB::SIZE + 1;
        // Stale TLB entries may grant the old, wider permissions.
        flush_tlb_range(start, page_count.trunc());

        Ok(())
    }

    /// Requires an inactive table. Kernel mappings must not demand-fault.
    pub(crate) fn map_kernel_ram(
        &self,
        frame_range: PhysFrameRange<Size4KiB>,
        text: &Range<PhysAddr>,
    ) -> Result<(), MapToError<Size4KiB>> {
        let mut allocator = PageTableAllocator::<M>::new();
        // Parent entries are permissive; leaves carry the restrictions.
        // ACCESSED and DIRTY are preset so the page walker never has to set them.
        let table_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::ACCESSED
            | PageTableFlags::DIRTY;

        let mut inner = self.inner.lock();
        for frame in frame_range {
            let page = Page::containing_address(M::pa_to_va(frame.start_address()));
            let flags = if text.contains(&frame.start_address()) {
                PageTableFlags::PRESENT
            } else {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE
            };
            // Safety: `frame` is kernel-owned RAM, mapped only here.
            unsafe {
                inner.map_to_with_table_flags(page, frame, flags, table_flags, &mut allocator)
            }?
            .ignore();
        }
        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the frame allocation fails.
    pub(crate) fn new_top_level() -> Self {
        let frame = PageTableAllocator::<M>::allocate_frame()
            .expect("Failed to allocate a new page table frame");
        // Safety: a fresh zeroed frame is a valid, empty top-level table, owned
        // by the returned object.
        unsafe { Self::init(frame.start_address()) }
    }

    /// Share `source`'s kernel P3/P2/P1 tables (see [`KERNEL_PML4_START`]).
    /// Entries already present in `self` are kept.
    pub(crate) fn copy_pml4_entries_from(&self, source: &Self) {
        let mut dst = self.inner.lock();
        let src = source.inner.lock();
        for (dst_entry, src_entry) in dst
            .level_4_table_mut()
            .iter_mut()
            .zip(src.level_4_table().iter())
            .skip(KERNEL_PML4_START)
        {
            if !src_entry.is_unused() && dst_entry.is_unused() {
                dst_entry.set_addr(src_entry.addr(), src_entry.flags());
            }
        }
    }

    /// Load this table into CR3, keeping the CR3 flags, and return the previous
    /// P4 frame.
    ///
    /// # Safety
    ///
    /// The table must map the whole kernel (code, data, and stacks), as the base
    /// table and the tables sharing its kernel entries do.
    #[expect(clippy::similar_names, reason = "p4_va/p4_pa name the same table")]
    pub(crate) unsafe fn load(&self) -> PhysFrame {
        let p4_va = core::ptr::from_ref::<PageTable>(self.inner.lock().level_4_table());
        let p4_pa = M::va_to_pa(VirtAddr::new(p4_va as u64));
        let p4_frame = PhysFrame::containing_address(p4_pa);

        let (frame, flags) = x86_64::registers::control::Cr3::read();
        // Safety: the caller guarantees the table maps the kernel, so the
        // running code stays mapped.
        unsafe {
            x86_64::registers::control::Cr3::write(p4_frame, flags);
        }

        frame
    }

    #[expect(clippy::similar_names, reason = "p4_va/p4_pa name the same table")]
    pub(crate) fn physical_frame(&self) -> PhysFrame {
        let p4_va = core::ptr::from_ref::<PageTable>(self.inner.lock().level_4_table());
        let p4_pa = M::va_to_pa(VirtAddr::new(p4_va as u64));
        PhysFrame::containing_address(p4_pa)
    }
}

impl<M: MemoryProvider, const ALIGN: usize> Drop for X64PageTable<'_, M, ALIGN> {
    /// Requires exclusive user frames and a prior non-PCID CR3 reload.
    #[expect(clippy::similar_names, reason = "p4_va/p4_pa name the same table")]
    fn drop(&mut self) {
        let mut allocator = PageTableAllocator::<M>::new();
        let mut inner = self.inner.lock();
        let p4 = inner.level_4_table_mut();

        // Skip the shared kernel PML4 entries.
        for (p4_index, p4_entry) in p4.iter_mut().enumerate().take(KERNEL_PML4_START) {
            let Ok(p3_frame) = p4_entry.frame() else {
                p4_entry.set_unused();
                continue;
            };
            // Safety: a private intermediate table of this page table, which
            // is being dropped, so nothing else references it.
            let p3 = unsafe { &mut *frame_to_pointer::<M>(p3_frame) };

            for (p3_index, p3_entry) in p3.iter_mut().enumerate() {
                if p3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    litebox_util_log::error!("BUG: huge pages are not supported");
                    debug_assert!(false, "huge pages are not supported");
                    p3_entry.set_unused();
                    continue;
                }
                let Ok(p2_frame) = p3_entry.frame() else {
                    p3_entry.set_unused();
                    continue;
                };
                // Safety: as for P3.
                let p2 = unsafe { &mut *frame_to_pointer::<M>(p2_frame) };

                for (p2_index, p2_entry) in p2.iter_mut().enumerate() {
                    if p2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                        litebox_util_log::error!("BUG: huge pages are not supported");
                        debug_assert!(false, "huge pages are not supported");
                        p2_entry.set_unused();
                        continue;
                    }
                    let Ok(p1_frame) = p2_entry.frame() else {
                        p2_entry.set_unused();
                        continue;
                    };
                    // Safety: as for P3.
                    let p1 = unsafe { &mut *frame_to_pointer::<M>(p1_frame) };

                    for (p1_index, p1_entry) in p1.iter_mut().enumerate() {
                        // Indices >= 256 cannot fall in the user range.
                        let page_address = (p4_index << PML4_SHIFT)
                            | (p3_index << P3_SHIFT)
                            | (p2_index << P2_SHIFT)
                            | (p1_index << PAGE_SHIFT);
                        if (crate::USER_ADDR_MIN..crate::USER_ADDR_MAX).contains(&page_address) {
                            match p1_entry.frame() {
                                Ok(frame) => {
                                    // Safety: task user leaf frames are exclusively owned.
                                    unsafe { allocator.deallocate_frame(frame) };
                                }
                                Err(_) if !p1_entry.is_unused() => {
                                    litebox_util_log::error!(
                                        "BUG: leaking malformed task leaf during destruction"
                                    );
                                    debug_assert!(false, "malformed task leaf during destruction");
                                }
                                Err(_) => {}
                            }
                        }
                        p1_entry.set_unused();
                    }
                }
            }
        }

        let p4_va = core::ptr::from_mut::<PageTable>(p4).cast::<u8>();
        let p4_pa = M::va_to_pa(VirtAddr::new(p4_va as u64));
        let start = Page::<Size4KiB>::containing_address(VirtAddr::new(0));
        let end = Page::<Size4KiB>::containing_address(VirtAddr::new(crate::KERNEL_OFFSET - 1));
        debug_assert_eq!(usize::from(end.p4_index()), KERNEL_PML4_START - 1);

        // Safety: all private leaves were cleared above.
        unsafe {
            inner.clean_up_addr_range(Page::range_inclusive(start, end), &mut allocator);
        }
        debug_assert!(
            inner
                .level_4_table()
                .iter()
                .take(KERNEL_PML4_START)
                .all(PageTableEntry::is_unused),
            "task page table dropped with live private mappings"
        );
        drop(inner);

        // Safety: owned P4 frame.
        unsafe { allocator.deallocate_frame(PhysFrame::containing_address(p4_pa)) };
    }
}

impl<M: MemoryProvider, const ALIGN: usize> PageTableImpl<ALIGN> for X64PageTable<'_, M, ALIGN> {
    unsafe fn init(p4: PhysAddr) -> Self {
        assert!(p4.is_aligned(Size4KiB::SIZE));
        let frame = PhysFrame::from_start_address(p4).unwrap();
        let mapping = FrameMapping::<M> {
            _provider: core::marker::PhantomData,
        };
        let p4_va = mapping.frame_to_pointer(frame);
        // Safety: the caller passes a valid top-level table that outlives `Self`,
        // which owns all access to it.
        let p4 = unsafe { &mut *p4_va };
        X64PageTable {
            // Safety: `mapping` translates every frame of this table (see
            // `FrameMapping`).
            inner: unsafe { MappedPageTable::new(p4, mapping) }.into(),
        }
    }

    #[cfg(test)]
    fn translate(&self, addr: VirtAddr) -> TranslateResult {
        self.inner.lock().translate(addr)
    }

    unsafe fn handle_page_fault(
        &self,
        page: Page<Size4KiB>,
        flags: PageTableFlags,
        error_code: PageFaultErrorCode,
    ) -> Result<(), PageFaultError> {
        let mut inner = self.inner.lock();
        match inner.translate(page.start_address()) {
            TranslateResult::Mapped {
                frame: _,
                offset: _,
                flags,
            } => {
                if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
                    if flags.contains(PageTableFlags::WRITABLE) {
                        return Ok(());
                    } else {
                        #[cfg(debug_assertions)]
                        todo!("COW");
                        #[cfg(not(debug_assertions))]
                        {
                            litebox_util_log::error!("BUG: Copy-on-Write not implemented");
                            return Err(PageFaultError::AllocationFailed);
                        }
                    }
                }

                if !error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
                    return Ok(());
                }

                #[cfg(debug_assertions)]
                todo!("Page fault on present page: {:#x}", page.start_address());
                #[cfg(not(debug_assertions))]
                {
                    litebox_util_log::error!(addr:? = page.start_address(); "page fault on a present page");
                    return Err(PageFaultError::AccessError("Page fault on present page"));
                }
            }
            TranslateResult::NotMapped => {
                let mut allocator = PageTableAllocator::<M>::new();
                // TODO: if it is file-backed, we need to read the page from file
                let frame = PageTableAllocator::<M>::allocate_frame()
                    .ok_or(PageFaultError::AllocationFailed)?;
                // ACCESSED and DIRTY are preset so the page walker never has to set them.
                let table_flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE
                    | PageTableFlags::ACCESSED
                    | PageTableFlags::DIRTY;
                // Safety: `frame` is fresh and exclusively owned; the caller
                // checked that the access is allowed.
                match unsafe {
                    inner.map_to_with_table_flags(
                        page,
                        frame,
                        flags | PageTableFlags::PRESENT,
                        table_flags,
                        &mut allocator,
                    )
                } {
                    Ok(_fl) => {}
                    Err(e) => {
                        // Safety: never mapped.
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
                #[cfg(debug_assertions)]
                todo!("Invalid frame address: {:#x}", pa);
                #[cfg(not(debug_assertions))]
                {
                    litebox_util_log::error!(pa:? = pa; "invalid frame address");
                    return Err(PageFaultError::AccessError("Invalid frame address"));
                }
            }
        }
        Ok(())
    }
}

impl<M: MemoryProvider, const ALIGN: usize> VmemPageFaultHandler for X64PageTable<'_, M, ALIGN> {
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(fault_addr as u64));
        let error_code = PageFaultErrorCode::from_bits_truncate(error_code);
        let flags = vmflags_to_pteflags(flags);
        // Safety: called from the page fault handler (per the caller), after
        // the VMA check.
        unsafe { PageTableImpl::handle_page_fault(self, page, flags, error_code) }
    }

    fn access_error(error_code: u64, flags: VmFlags) -> bool {
        let error_code = PageFaultErrorCode::from_bits_truncate(error_code);
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            return !flags.contains(VmFlags::VM_WRITE);
        }

        if error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
            return true;
        }

        if (flags & VmFlags::VM_ACCESS_FLAGS).is_empty() {
            return true;
        }

        false
    }
}
