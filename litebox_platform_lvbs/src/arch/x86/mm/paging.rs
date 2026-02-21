// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::mm::linux::{PageFaultError, PageRange, VmFlags, VmemPageFaultHandler};
use litebox::platform::page_mgmt;
use litebox::utils::TruncateExt;
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
        },
    },
};

use crate::UserMutPtr;
use crate::mm::{
    MemoryProvider,
    pgtable::{PageTableAllocator, PageTableImpl},
};

#[cfg(not(test))]
const FLUSH_TLB: bool = true;
#[cfg(test)]
const FLUSH_TLB: bool = false;

/// When we flush multiple TLB entries, flushing the entire TLB (e.g., write to CR3)
/// can be more efficient than flushing individual entries (e.g., `invlpg`).
/// This threshold is a heuristic from the Linux kernel:
/// <https://elixir.bootlin.com/linux/v6.18.6/source/arch/x86/mm/tlb.c#L1394>
#[cfg(not(test))]
const TLB_SINGLE_PAGE_FLUSH_CEILING: usize = 33;

/// Flush TLB entries for a contiguous page range.
///
/// When `all_cores` is `true`, uses Hyper-V hypercalls for TLB flush so that
/// remote cores sharing the same page table also see the invalidation.
///
/// When `all_cores` is `false`, only the **local** VP's TLB is flushed.
/// The local flush is still needed under Hyper-V because the virtual
/// TLB may cache not-present translations (TLFS §11.6.1).
#[cfg(not(test))]
fn flush_tlb_range(start: Page<Size4KiB>, count: usize, all_cores: bool) {
    use crate::mshv::{hvcall_mm, is_hvcall_ready};

    if count == 0 {
        return;
    }

    // If the current VP is the BSP, it might use MM operations **before** the hypercall page is set up.
    // In that case, we fall back to local TLB flushes. This is safe because no AP enters VTL1 yet.
    if !all_cores || !is_hvcall_ready() {
        if count <= TLB_SINGLE_PAGE_FLUSH_CEILING {
            let base = start.start_address().as_u64();
            for i in 0..count {
                x86_64::instructions::tlb::flush(VirtAddr::new(base + (i as u64) * Size4KiB::SIZE));
            }
        } else {
            x86_64::instructions::tlb::flush_all();
        }
        return;
    }

    let result = if count <= TLB_SINGLE_PAGE_FLUSH_CEILING {
        hvcall_mm::hv_flush_virtual_address_list(start.start_address().as_u64(), count)
    } else {
        hvcall_mm::hv_flush_virtual_address_space()
    };

    if let Err(e) = result {
        // Hypercall failed — fall back to local flush so this core is at least coherent.
        debug_assert!(false, "TLB flush hypercall failed: {e:?}");
        x86_64::instructions::tlb::flush_all();
    }
}

#[cfg(test)]
fn flush_tlb_range(_start: Page<Size4KiB>, _count: usize, _all_cores: bool) {}

#[inline]
fn frame_to_pointer<M: MemoryProvider>(frame: PhysFrame) -> *mut PageTable {
    let virt = M::pa_to_va(frame.start_address());
    virt.as_mut_ptr()
}

pub struct X64PageTable<'a, M: MemoryProvider, const ALIGN: usize> {
    inner: spin::mutex::SpinMutex<MappedPageTable<'a, FrameMapping<M>>>,
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

impl<M: MemoryProvider, const ALIGN: usize> X64PageTable<'_, M, ALIGN> {
    pub(crate) unsafe fn new(item: PhysAddr) -> Self {
        unsafe { Self::init(item) }
    }

    pub(crate) fn map_pages(
        &self,
        range: PageRange<ALIGN>,
        flags: VmFlags,
        populate_pages: bool,
    ) -> UserMutPtr<u8> {
        if populate_pages {
            let flags = vmflags_to_pteflags(flags);
            for page in range {
                let page =
                    Page::<Size4KiB>::from_start_address(VirtAddr::new(page as u64)).unwrap();
                unsafe {
                    PageTableImpl::handle_page_fault(self, page, flags, PageFaultErrorCode::empty())
                }
                .expect("Failed to handle page fault");
            }
        }
        UserMutPtr::from_ptr(range.start as *mut u8)
    }

    /// Unmap a range of 4KiB pages from the page table.
    ///
    /// Set `dealloc_frames` to `true` to free the corresponding physical frames. Skip this
    /// when the corresponding physical frames are managed elsewhere (e.g., VTL0).
    /// Set `flush_tlb` to `true` to flush TLB entries after unmapping (not needed when
    /// the page table is being destroyed).
    /// Set `clean_up_page_tables` to `true` to free intermediate page-table frames
    /// (P1/P2/P3) that become empty after unmapping. Skip this when the VA range
    /// will be reused soon, as the intermediate frames would just be re-allocated.
    pub(crate) unsafe fn unmap_pages(
        &self,
        range: PageRange<ALIGN>,
        dealloc_frames: bool,
        flush_tlb: bool,
        clean_up_page_tables: bool,
    ) -> Result<(), page_mgmt::DeallocationError> {
        if range.is_empty() {
            return Ok(());
        }
        let start = Page::<Size4KiB>::from_start_address(VirtAddr::new(range.start as _))
            .or(Err(page_mgmt::DeallocationError::Unaligned))?;
        let end = Page::<Size4KiB>::from_start_address(VirtAddr::new(range.end as _))
            .or(Err(page_mgmt::DeallocationError::Unaligned))?;
        let mut allocator = PageTableAllocator::<M>::new();

        // Note: TLB entries are batch-flushed after all pages are unmapped, consistent
        // with the Linux kernel's mmu_gather approach.
        // Note this implementation is slow as each page requires a full page table walk.
        // If we have N pages, it will be N times slower.
        let mut inner = self.inner.lock();
        for page in Page::range(start, end) {
            match inner.unmap(page) {
                Ok((frame, _)) => {
                    if dealloc_frames {
                        unsafe { allocator.deallocate_frame(frame) };
                    }
                }
                Err(X64UnmapError::PageNotMapped) => {}
                Err(X64UnmapError::ParentEntryHugePage) => {
                    unreachable!("we do not support huge pages");
                }
                Err(X64UnmapError::InvalidFrameAddress(pa)) => {
                    todo!("Invalid frame address: {:#x}", pa);
                }
            }
        }

        if flush_tlb {
            let page_count = (end.start_address() - start.start_address()) / Size4KiB::SIZE;
            // Present → not-present: other cores may hold stale entries.
            flush_tlb_range(start, page_count.truncate(), true);
        }

        if clean_up_page_tables {
            // Safety: all leaf entries in the range have been unmapped above;
            // the caller guarantees this VA range is no longer in use.
            unsafe {
                inner.clean_up_addr_range(Page::range_inclusive(start, end - 1u64), &mut allocator);
            }
        }

        Ok(())
    }

    /// Unmap and deallocate all user pages and their page table frames.
    ///
    /// User pages are identified by their virtual address being in range
    /// [user_addr_min, user_addr_max). This works because:
    /// - Kernel memory uses addresses outside this range (e.g., low addresses for
    ///   identity mapped VA == PA, or future designs with high kernel addresses)
    /// - User memory uses addresses in [user_addr_min, user_addr_max), allocated via mmap
    ///
    /// This method deallocates:
    /// 1. All user data frames (pages with VA in [user_addr_min, user_addr_max))
    /// 2. ALL page table frames (P1/P2/P3) regardless of address range
    ///    (because each user page table has its own PT frame allocations,
    ///    including for the kernel identity mapping)
    ///
    /// Kernel data frames (physical memory) are NOT deallocated - only their
    /// page table entries are cleaned up.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no references to the unmapped pages exist.
    /// Once we implement page fault handling for user pages with memcpy_fallible in the LVBS platform,
    /// this safety requirement can be relaxed.
    pub(crate) unsafe fn cleanup_user_mappings(&self, user_addr_min: usize, user_addr_max: usize) {
        use x86_64::structures::paging::mapper::CleanUp;

        // Unmap and deallocate user data pages
        // No TLB flush needed - this page table is being destroyed and will never be reused
        let user_range = PageRange::<ALIGN> {
            start: user_addr_min,
            end: user_addr_max,
        };
        // Safety: The caller ensures no references to the unmapped pages exist.
        let _ = unsafe { self.unmap_pages(user_range, true, false, false) };

        // Clean up all empty P1 - P3 tables
        let mut allocator = PageTableAllocator::<M>::new();
        // Safety: The page table is being destroyed and will not be reused.
        unsafe {
            self.inner.lock().clean_up(&mut allocator);
        }
    }

    pub(crate) unsafe fn remap_pages(
        &self,
        old_range: PageRange<ALIGN>,
        new_range: PageRange<ALIGN>,
    ) -> Result<UserMutPtr<u8>, page_mgmt::RemapError> {
        let mut start: Page<Size4KiB> =
            Page::from_start_address(VirtAddr::new(old_range.start as u64))
                .or(Err(page_mgmt::RemapError::Unaligned))?;
        let mut new_start: Page<Size4KiB> =
            Page::from_start_address(VirtAddr::new(new_range.start as u64))
                .or(Err(page_mgmt::RemapError::Unaligned))?;
        let end: Page<Size4KiB> = Page::from_start_address(VirtAddr::new(old_range.end as u64))
            .or(Err(page_mgmt::RemapError::Unaligned))?;

        // Note: TLB entries for the old addresses are batch-flushed after all pages
        // are remapped, consistent with the Linux kernel's approach. Only the old
        // (unmapped) addresses need flushing; the new addresses are not-present →
        // present transitions and do not require flushing.
        // Note this implementation is slow as each page requires three full page table walks.
        // If we have N pages, it will be 3N times slower.
        let mut allocator = PageTableAllocator::<M>::new();
        let mut inner = self.inner.lock();
        let flush_start = start;
        while start < end {
            match inner.translate(start.start_address()) {
                TranslateResult::Mapped {
                    frame: _,
                    offset: _,
                    flags,
                } => match inner.unmap(start) {
                    Ok((frame, _)) => {
                        match unsafe { inner.map_to(new_start, frame, flags, &mut allocator) } {
                            Ok(_) => {}
                            Err(e) => match e {
                                MapToError::PageAlreadyMapped(_) => {
                                    return Err(page_mgmt::RemapError::AlreadyAllocated);
                                }
                                MapToError::ParentEntryHugePage => {
                                    todo!("return Err(page_mgmt::RemapError::RemapToHugePage);")
                                }
                                MapToError::FrameAllocationFailed => {
                                    return Err(page_mgmt::RemapError::OutOfMemory);
                                }
                            },
                        }
                    }
                    Err(X64UnmapError::PageNotMapped) => {
                        unreachable!()
                    }
                    Err(X64UnmapError::ParentEntryHugePage) => {
                        todo!("return Err(page_mgmt::RemapError::RemapToHugePage);")
                    }
                    Err(X64UnmapError::InvalidFrameAddress(pa)) => {
                        // TODO: `panic!()` -> `todo!()` because user-driven interrupts or exceptions must not halt the kernel.
                        // We should handle this exception carefully (i.e., clean up the context and data structures belonging to an errorneous process).
                        todo!("Invalid frame address: {:#x}", pa);
                    }
                },
                TranslateResult::NotMapped => {}
                TranslateResult::InvalidFrameAddress(pa) => {
                    todo!("Invalid frame address: {:#x}", pa);
                }
            }
            start += 1;
            new_start += 1;
        }

        // Flush old (unmapped) addresses — other cores may hold stale entries.
        let page_count = (end.start_address() - flush_start.start_address()) / Size4KiB::SIZE;
        flush_tlb_range(flush_start, page_count.truncate(), true);
        // Flush new (mapped) addresses — not-present → present; only the local
        // core's virtual TLB may cache the stale not-present translation
        // (see comment in `map_phys_frame_range`).
        let new_flush_start =
            Page::<Size4KiB>::from_start_address(VirtAddr::new(new_range.start as u64))
                .or(Err(page_mgmt::RemapError::Unaligned))?;
        flush_tlb_range(new_flush_start, page_count.truncate(), false);

        Ok(UserMutPtr::from_ptr(new_range.start as *mut u8))
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

        // Note: TLB entries are batch-flushed after all permission updates, consistent
        // with the Linux kernel's flush_tlb_range approach.
        // TODO: this implementation is slow as each page requires two full page table walks.
        // If we have N pages, it will be 2N times slower.
        let mut inner = self.inner.lock();
        for page in Page::range(start, end + 1) {
            match inner.translate(page.start_address()) {
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
                            inner.update_flags(page, (flags & !Self::MPROTECT_PTE_MASK) | new_flags)
                        } {
                            Ok(_) => {}
                            Err(e) => match e {
                                FlagUpdateError::PageNotMapped => unreachable!(),
                                FlagUpdateError::ParentEntryHugePage => {
                                    todo!("return Err(ProtectError::ProtectHugePage);")
                                }
                            },
                        }
                    }
                }
                TranslateResult::NotMapped => {}
                TranslateResult::InvalidFrameAddress(pa) => {
                    todo!("Invalid frame address: {:#x}", pa);
                }
            }
        }

        let page_count = (end.start_address() - start.start_address()) / Size4KiB::SIZE + 1;
        // Permission change: other cores may hold stale (wider) permissions.
        flush_tlb_range(start, page_count.truncate(), true);

        Ok(())
    }

    /// Map physical frame range to the page table
    ///
    /// Note it does not rely on the page fault handler based mapping to avoid double faults.
    pub(crate) fn map_phys_frame_range(
        &self,
        frame_range: PhysFrameRange<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<*mut u8, MapToError<Size4KiB>> {
        let mut allocator = PageTableAllocator::<M>::new();

        let mut inner = self.inner.lock();
        for target_frame in frame_range {
            let page: Page<Size4KiB> =
                Page::containing_address(M::pa_to_va(target_frame.start_address()));

            match inner.translate(page.start_address()) {
                TranslateResult::Mapped {
                    frame,
                    offset: _,
                    flags: _,
                } => {
                    assert!(
                        target_frame.start_address() == frame.start_address(),
                        "{page:?} is already mapped to {frame:?} instead of {target_frame:?}"
                    );

                    continue;
                }
                TranslateResult::NotMapped => {}
                TranslateResult::InvalidFrameAddress(pa) => {
                    todo!("Invalid frame address: {:#x}", pa);
                }
            }

            match unsafe {
                inner.map_to_with_table_flags(page, target_frame, flags, flags, &mut allocator)
            } {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }

        // Note: On bare-metal x86, TLB invalidation is not architecturally required
        // when changing a PTE from not-present to present (Intel SDM §4.10.4.3).
        // However, Hyper-V's virtual TLB may cache not-present translations, so
        // the guest must invalidate when transitioning from not-present to present.
        // See TLFS §11.6.1 "Recommendations for Address Spaces":
        //   "it is recommended that operating systems running as a guest of a
        //    hypervisor invalidate [...] TLB entries that correspond to a transition
        //    from a not-present to a present state"
        // Without this flush, the hypervisor may serve stale "not-present"
        // translations, causing spurious page faults.
        // Not-present → present: only the local core's virtual TLB can hold a
        // stale not-present translation.  No cross-core flush needed.
        let start =
            Page::<Size4KiB>::containing_address(M::pa_to_va(frame_range.start.start_address()));
        let page_count = frame_range.len();
        flush_tlb_range(start, page_count.truncate(), false);

        Ok(M::pa_to_va(frame_range.start.start_address()).as_mut_ptr())
    }

    /// Map non-contiguous physical frames to virtually contiguous addresses.
    ///
    /// This function maps each physical frame in `frames` to consecutive virtual addresses
    /// starting from `base_va`. Unlike `map_phys_frame_range`, this allows mapping
    /// non-contiguous physical pages to a contiguous virtual address range.
    ///
    /// # Arguments
    /// - `frames` - Slice of physical frames to map (non-contiguous, no duplicate)
    /// - `base_va` - Starting virtual address for the mapping
    /// - `flags` - Page table flags to apply to all mappings
    ///
    /// # Returns
    /// - `Ok(*mut u8)` — pointer to the start of the mapped virtual range
    /// - `Err(MapToError::PageAlreadyMapped)` if any VA is already mapped
    /// - `Err(MapToError::FrameAllocationFailed)` if page table allocation fails
    ///
    /// # Behavior
    /// - Any existing mapping is treated as an error
    /// - On error, all pages mapped by this call are unmapped (atomic)
    #[cfg(feature = "optee_syscall")]
    pub(crate) fn map_non_contiguous_phys_frames(
        &self,
        frames: &[PhysFrame<Size4KiB>],
        base_va: VirtAddr,
        flags: PageTableFlags,
    ) -> Result<*mut u8, MapToError<Size4KiB>> {
        let mut allocator = PageTableAllocator::<M>::new();
        let mut mapped_count: usize = 0;

        let mut inner = self.inner.lock();

        let start_page = Page::<Size4KiB>::from_start_address(base_va)
            .map_err(|_| MapToError::FrameAllocationFailed)?;
        let end_page = start_page + frames.len() as u64;

        let table_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        for (page, &target_frame) in Page::range(start_page, end_page).zip(frames.iter()) {
            // Note: Since we lock the entire page table for the duration of this function (`self.inner.lock()`),
            // there should be no concurrent modifications to the page table. If we allow concurrent mappings
            // in the future, we should re-check the VA here before mapping and return an error
            // if it is no longer unmapped.
            match unsafe {
                inner.map_to_with_table_flags(
                    page,
                    target_frame,
                    flags,
                    table_flags,
                    &mut allocator,
                )
            } {
                Ok(_) => {
                    mapped_count += 1;
                }
                Err(e) => {
                    debug_assert!(
                        false,
                        "vmap: map_to_with_table_flags failed at page {page:?}: {e:?}"
                    );
                    if mapped_count > 0 {
                        crate::debug_serial_println!(
                            "vmap: rolling back {mapped_count} pages mapped at {base_va:#x} due to error"
                        );
                        Self::rollback_mapped_pages(
                            &mut inner,
                            Page::range_inclusive(
                                start_page,
                                start_page + (mapped_count as u64 - 1),
                            ),
                            &mut allocator,
                        );
                    }
                    return Err(e);
                }
            }
        }

        // Not-present → present: local flush only (see `map_phys_frame_range`).
        flush_tlb_range(start_page, mapped_count, false);

        Ok(base_va.as_mut_ptr())
    }

    /// Rollback helper: unmap the pages in `pages` and free any intermediate
    /// page-table frames (P1/P2/P3) that became empty.
    ///
    /// Note: The caller must already hold the page table lock (`self.inner`).
    /// This function accepts the locked `MappedPageTable` directly.
    #[cfg(feature = "optee_syscall")]
    fn rollback_mapped_pages(
        inner: &mut MappedPageTable<'_, FrameMapping<M>>,
        pages: x86_64::structures::paging::page::PageRangeInclusive<Size4KiB>,
        allocator: &mut PageTableAllocator<M>,
    ) {
        let first_page = pages.start;
        let mut count: usize = 0;
        for page in pages {
            if inner.unmap(page).is_ok() {
                count += 1;
            }
        }

        // Rolling back just-mapped pages — only the current core touched
        // them, so a local flush suffices.
        flush_tlb_range(first_page, count, false);

        // Safety: all leaf entries in `pages` have been unmapped above while
        // holding `self.inner`, so any P1/P2/P3 frames that became empty can
        // be safely freed.
        unsafe {
            inner.clean_up_addr_range(pages, allocator);
        }
    }

    /// This function creates a new empty top-level page table.
    pub(crate) unsafe fn new_top_level() -> Self {
        let frame = PageTableAllocator::<M>::allocate_frame(true)
            .expect("Failed to allocate a new page table frame");
        unsafe { Self::init(frame.start_address()) }
    }

    /// This function changes the address space of the current processor/core using the given page table
    /// (e.g., its CR3 register) and returns the physical frame of the previous top-level page table.
    /// It preserves the CR3 flags.
    ///
    /// # Safety
    /// The caller must ensure that the page table is valid and maps the entire VTL1 kernel address space.
    /// Currently, we do not support KPTI-like kernel/user space page table separation.
    ///
    /// # Panics
    /// Panics if the page table is invalid
    #[allow(clippy::similar_names)]
    pub(crate) fn load(&self) -> PhysFrame {
        let p4_va = core::ptr::from_ref::<PageTable>(self.inner.lock().level_4_table());
        let p4_pa = M::va_to_pa(VirtAddr::new(p4_va as u64));
        let p4_frame = PhysFrame::containing_address(p4_pa);

        let (frame, flags) = x86_64::registers::control::Cr3::read();
        unsafe {
            x86_64::registers::control::Cr3::write(p4_frame, flags);
        }

        frame
    }

    /// This function returns the physical frame containing a top-level page table.
    /// When we handle a system call or interrupt, it is difficult to figure out the corresponding user context
    /// because kernel and user contexts are not tightly coupled (i.e., we do not know `userspace_id`).
    /// To this end, we use this function to match the physical frame of the page table contained in each user
    /// context structure with the CR3 value in a system call context (before changing the page table).
    #[allow(clippy::similar_names)]
    pub(crate) fn get_physical_frame(&self) -> PhysFrame {
        let p4_va = core::ptr::from_ref::<PageTable>(self.inner.lock().level_4_table());
        let p4_pa = M::va_to_pa(VirtAddr::new(p4_va as u64));
        PhysFrame::containing_address(p4_pa)
    }
}

impl<M: MemoryProvider, const ALIGN: usize> Drop for X64PageTable<'_, M, ALIGN> {
    /// Deallocate the physical frame of the top-level page table
    #[allow(clippy::similar_names)]
    fn drop(&mut self) {
        let mut allocator = PageTableAllocator::<M>::new();
        let p4_va =
            core::ptr::from_mut::<PageTable>(self.inner.lock().level_4_table_mut()).cast::<u8>();
        let p4_pa = M::va_to_pa(VirtAddr::new(p4_va as u64));
        unsafe {
            allocator.deallocate_frame(PhysFrame::containing_address(p4_pa));
        }
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
        let p4 = unsafe { &mut *p4_va };
        X64PageTable {
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

                todo!("Page fault on present page: {:#x}", page.start_address());
            }
            TranslateResult::NotMapped => {
                let mut allocator = PageTableAllocator::<M>::new();
                // TODO: if it is file-backed, we need to read the page from file
                let frame = PageTableAllocator::<M>::allocate_frame(true).unwrap();
                let table_flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE;
                match unsafe {
                    inner.map_to_with_table_flags(
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
                todo!("Invalid frame address: {:#x}", pa);
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
        unsafe { PageTableImpl::handle_page_fault(self, page, flags, error_code) }
    }

    fn access_error(error_code: u64, flags: VmFlags) -> bool {
        let error_code = PageFaultErrorCode::from_bits_truncate(error_code);
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            return !flags.contains(VmFlags::VM_WRITE);
        }

        // read, present
        if error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
            return true;
        }

        // read, not present
        if (flags & VmFlags::VM_ACCESS_FLAGS).is_empty() {
            return true;
        }

        false
    }
}
