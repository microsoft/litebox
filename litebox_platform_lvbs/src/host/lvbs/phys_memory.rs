// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS foreign-memory access and VTL0 protection.
//!
//! Mapping mechanics use the shared page tables and vmap VA allocator, but
//! authorization, protected-frame guards, and peer-access restrictions belong
//! to LVBS. This is deliberately not a default implementation for other VMs.

use super::LvbsLinuxKernel;
use crate::mm::vmap::vmap_allocator;
use crate::mshv;
use litebox::{
    mm::vmem::{PAGE_SIZE, PageRange},
    platform::page_mgmt::DeallocationError,
    utils::TruncateExt,
};
use litebox_common_linux::vmap::{
    PhysPageAddrArray, PhysPageMapInfo, PhysPageMapPermissions, PhysPointerError, VmapManager,
};
use x86_64::structures::paging::{
    PageOffset, PageSize, PageTableFlags, PhysFrame, Size4KiB, mapper::MapToError,
};

/// Mapping metadata. Ordinary writable mappings retain an opaque protected-frame access guard for
/// the mapping's lifetime.
pub struct LvbsPhysPageMapInfo {
    base: *mut u8,
    size: usize,
    protected_frame_access: Option<mshv::vsm::ProtectedFrameAccessGuard<'static>>,
}

impl LvbsPhysPageMapInfo {
    fn new(base: *mut u8, size: usize) -> Self {
        Self {
            base,
            size,
            protected_frame_access: None,
        }
    }
}

impl PhysPageMapInfo for LvbsPhysPageMapInfo {
    fn base(&self) -> *mut u8 {
        self.base
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl LvbsLinuxKernel {
    /// This function unmaps VTL0 pages from the page table.
    ///
    /// Allocator does not allocate memory frames for VTL0 pages, so frame deallocation is not needed.
    ///
    /// Note: VTL0 physical memory is external memory not owned by LiteBox, similar to DMA/shared
    /// physical memory. Physical pointer APIs access it by creating a temporary mapping, copying
    /// data to/from a LiteBox-owned buffer with fallible raw-pointer copies, and unmapping
    /// immediately. These APIs do not create Rust references to the mapped VTL0 memory.
    fn unmap_vtl0_pages(
        &self,
        page_addr: *const u8,
        length: usize,
    ) -> Result<(), DeallocationError> {
        let page_addr = x86_64::VirtAddr::new(page_addr as u64);
        if page_addr.page_offset() != PageOffset::new(0) {
            return Err(DeallocationError::Unaligned);
        }
        let end = x86_64::VirtAddr::try_new(
            page_addr
                .as_u64()
                .checked_add(length as u64)
                .ok_or(DeallocationError::Unaligned)?,
        )
        .map_err(|_| DeallocationError::Unaligned)?;
        unsafe {
            self.page_table_manager.current_page_table().unmap_pages(
                PageRange::<PAGE_SIZE>::new(
                    page_addr.as_u64().trunc(),
                    end.align_up(Size4KiB::SIZE).as_u64().trunc(),
                )
                .ok_or(DeallocationError::Unaligned)?,
                false,
                true,
                false,
            )
        }
    }
}

unsafe impl<const ALIGN: usize> VmapManager<ALIGN> for LvbsLinuxKernel {
    type MapInfo = LvbsPhysPageMapInfo;

    unsafe fn vmap(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        let protected_frame_access = if perms.contains(PhysPageMapPermissions::WRITE) {
            // This shared guard spans map/copy/unmap. It permits concurrent foreign-memory writes
            // but does not support re-entry into a VTL protection change.
            Some(mshv::vsm::protected_frame_registry().acquire_access_guard(pages)?)
        } else {
            None
        };
        // SAFETY: ordinary writable mappings were checked against protected and in-flight frames;
        // the guard is retained through map, access, and unmap. `vmap_privileged` provides the
        // shared raw mapping implementation.
        let mut map_info = unsafe { self.vmap_privileged(pages, perms)? };
        map_info.protected_frame_access = protected_frame_access;
        Ok(map_info)
    }

    unsafe fn vmap_privileged(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        if pages.is_empty() {
            return Err(PhysPointerError::InvalidPhysicalAddress(0));
        }

        if ALIGN != PAGE_SIZE {
            unimplemented!("ALIGN other than 4KiB is not supported yet");
        }

        self.validate_unowned(pages)?;

        // Reject duplicates early as an API-level validation. The page-table implementation also
        // rejects duplicate/shared mappings, but this keeps the error local to the input array.
        // A single page can never collide with itself, so skip the set allocation.
        if pages.len() > 1 {
            let mut seen = hashbrown::HashSet::with_capacity(pages.len());
            for page in pages {
                if !seen.insert(page.as_usize()) {
                    return Err(PhysPointerError::DuplicatePhysicalAddress(page.as_usize()));
                }
            }
        }

        // VTL0 memory must never be executable from VTL1 (DEP).
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;
        if perms.contains(PhysPageMapPermissions::WRITE) {
            flags |= PageTableFlags::WRITABLE;
        }

        // Always allocate a fresh, private virtual address window for the mapping. This lets
        // multiple cores map the same physical frame(s) concurrently at distinct VAs (used only for
        // transient data copy in/out via raw pointers), so a core unmapping its window never
        // disturbs another core's access to the same frame.
        //
        // `validate_unowned` rejects VTL1-owned PA before callers reach `vmap`, so these pages are
        // foreign and the vmap VA range never aliases VTL1-owned Rust memory.
        let frames: alloc::vec::Vec<PhysFrame<Size4KiB>> = pages
            .iter()
            .map(|p| {
                let address = p.as_usize();
                x86_64::PhysAddr::try_new(address as u64)
                    .map(PhysFrame::containing_address)
                    .map_err(|_| PhysPointerError::InvalidPhysicalAddress(address))
            })
            .collect::<Result<_, _>>()?;

        let base_va = vmap_allocator()
            .allocate_va(frames.len())
            .map_err(|e| match e {
                crate::mm::vmap::VmapAllocError::VaSpaceExhausted => {
                    PhysPointerError::VaSpaceExhausted
                }
                // `pages` was checked non-empty above and `frames` is built 1:1 from it, so the
                // allocator cannot report an empty input here.
                crate::mm::vmap::VmapAllocError::EmptyInput => {
                    unreachable!("frames is derived 1:1 from a non-empty pages slice")
                }
            })?;

        match self
            .page_table_manager
            .current_page_table()
            .map_non_contiguous_phys_frames(&frames, base_va, flags)
        {
            Ok(page_addr) => Ok(LvbsPhysPageMapInfo::new(page_addr, pages.len() * ALIGN)),
            Err(e) => {
                vmap_allocator().free_va(base_va, frames.len());
                match e {
                    MapToError::PageAlreadyMapped(_) => {
                        Err(PhysPointerError::AlreadyMapped(pages[0].as_usize()))
                    }
                    MapToError::FrameAllocationFailed => {
                        Err(PhysPointerError::FrameAllocationFailed)
                    }
                    MapToError::ParentEntryHugePage => Err(
                        PhysPointerError::InvalidPhysicalAddress(pages[0].as_usize()),
                    ),
                }
            }
        }
    }

    unsafe fn vunmap(
        &self,
        vmap_info: Self::MapInfo,
    ) -> Result<(), (PhysPointerError, Self::MapInfo)> {
        if ALIGN != PAGE_SIZE {
            unimplemented!("ALIGN other than 4KiB is not supported yet");
        }

        let base = vmap_info.base();
        let size = vmap_info.size();
        let base_va = x86_64::VirtAddr::new(base as u64);

        // Unmap the page table entries first. Only release the VA range back
        // to the allocator when unmapping succeeds; if it fails, stale PTE
        // entries remain and recycling the VA would cause collisions.
        if self.unmap_vtl0_pages(base, size).is_err() {
            return Err((PhysPointerError::Unmapped(base as usize), vmap_info));
        }

        // PTEs are already cleared at this point, so the mapping is functionally gone
        // and a retry would only re-fail against empty page-table entries. Return the VA
        // range to the allocator. `vmap_info` is consumed by value and never cloned, so this
        // range is freed exactly once.
        if crate::mm::vmap::is_vmap_address(base_va) {
            crate::mm::vmap::vmap_allocator().free_va(base_va, size / ALIGN);
        }

        Ok(())
    }

    fn validate_unowned(&self, pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError> {
        if pages.is_empty() {
            return Ok(());
        }
        let start_address = self.vtl1_phys_frame_range().start.start_address().as_u64();
        let end_address = self.vtl1_phys_frame_range().end.start_address().as_u64();
        for page in pages {
            let addr = page.as_usize() as u64;
            // a physical page belonging to LiteBox (VTL1) should not be used for `vmap`
            if addr >= start_address && addr < end_address {
                return Err(PhysPointerError::InvalidPhysicalAddress(page.as_usize()));
            }
        }
        Ok(())
    }

    unsafe fn protect(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        if ALIGN != PAGE_SIZE {
            unimplemented!("ALIGN other than 4KiB is not supported yet");
        }

        // Build a RangeSet so that adjacent pages are coalesced into contiguous
        // ranges, minimizing the number of hypercalls.
        let mut range_set = rangemap::RangeSet::new();
        for page in pages {
            let start = page.as_usize() as u64;
            let end = start
                .checked_add(ALIGN as u64)
                .ok_or(PhysPointerError::Overflow)?;
            range_set.insert(start..end);
        }

        let page_prot = if perms.contains(PhysPageMapPermissions::WRITE) {
            // VTL1 needs writable access, so deny VTL0 all access.
            mshv::HvPageProtFlags::HV_PAGE_ACCESS_NONE
        } else if perms.contains(PhysPageMapPermissions::READ) {
            // VTL1 wants to read data from the pages, preventing VTL0 from writing to the pages.
            mshv::HvPageProtFlags::HV_PAGE_READABLE | mshv::HvPageProtFlags::HV_PAGE_EXECUTABLE
        } else {
            // VTL1 no longer protects the pages.
            mshv::HvPageProtFlags::HV_PAGE_FULL_ACCESS
        };

        for range in range_set.iter() {
            let frame_range = PhysFrame::range(
                PhysFrame::<Size4KiB>::containing_address(x86_64::PhysAddr::new(range.start)),
                PhysFrame::<Size4KiB>::containing_address(x86_64::PhysAddr::new(range.end)),
            );
            mshv::vsm::protect_physical_memory_range(self, frame_range, page_prot)
                .map_err(|_| PhysPointerError::UnsupportedPermissions(perms.bits()))?;
        }

        Ok(())
    }
}
