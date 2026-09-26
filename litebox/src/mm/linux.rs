// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-style memory management operations.

use core::ops::Range;

use alloc::vec::Vec;

use super::{
    PageManager,
    vmem::{
        self, CreatePagesFlags, MappingError, NonZeroPageSize, PageRange, VmArea, VmFlags, Vmem,
        VmemResetError, VmemUnmapError,
    },
};
use crate::{
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{
            CowAllocationError, FixedAddressBehavior, MemoryRegionPermissions, RemapError,
            ReservationStore,
        },
    },
    sync::RawSyncPrimitivesProvider,
};

impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    /// Attempt a native copy-on-write mapping backed by static data.
    ///
    /// `suggested_start` is the hint address for where to create the pages if it is not `None`.
    ///
    /// `flags` controls fixed-address placement, no-replace behavior, and whether the mapping is
    /// shared. Other [`CreatePagesFlags`] options have no effect.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform cannot create a native copy-on-write mapping for
    /// `source_data` or if the requested placement is invalid.
    ///
    /// # Safety
    ///
    /// For replacement, the caller must ensure overlapping mappings are not in use.
    pub unsafe fn try_create_cow_pages(
        &self,
        suggested_start: Option<usize>,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, CowAllocationError> {
        unsafe {
            self.vmem
                .write()
                .try_create_cow_pages(suggested_start, source_data, permissions, flags)
        }
    }

    /// Set the initial program break address.
    ///
    /// This function should be called once to set the initial program break,
    /// which is usually the end of the data segment.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break is already set.
    pub fn set_initial_brk(&self, brk: usize) {
        let mut vmem = self.vmem.write();
        assert_eq!(vmem.brk, 0, "initial brk is already set");
        vmem.brk = brk;
    }

    /// Set the program break to the given address.
    ///
    /// Increasing the program break has the effect of allocating memory to the process;
    /// decreasing the break deallocates memory.
    /// Calling `brk` with 0 can be used to find the current location of the program break.
    ///
    /// Note the initial program break is set to zero and the first call to `brk` would set it
    /// to the given address, which is usually the end of the data segment.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new program break address.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break is not set yet.
    ///
    /// # Safety
    ///
    /// If shrinking the program break, the caller must ensure that the released memory region is no longer used.
    pub unsafe fn brk(&self, brk: usize) -> Result<usize, MappingError> {
        let mut vmem = self.vmem.write();
        assert_ne!(vmem.brk, 0, "initial brk is not set yet");
        if brk == 0 {
            // Calling `brk` with 0 can be used to find the current location of the program break.
            return Ok(vmem.brk);
        }

        let old_brk = vmem.brk.next_multiple_of(vmem::PAGE_SIZE);
        let new_brk = brk.next_multiple_of(vmem::PAGE_SIZE);
        if vmem.brk >= brk {
            // Shrink the memory region
            let brk = match unsafe {
                vmem.remove_mapping(
                    PageRange::new(new_brk, old_brk).ok_or(MappingError::UnAligned)?,
                )
            } {
                Ok(()) => {
                    vmem.brk = brk;
                    brk
                }
                Err(_) => {
                    vmem.brk // No change, return the old brk
                }
            };
            return Ok(brk);
        }

        if vmem.overlapping(old_brk..new_brk).next().is_some() {
            return Err(MappingError::OutOfMemory);
        }
        if let Some(range) = PageRange::<ALIGN>::new(old_brk, new_brk) {
            let (suggested_address, length) = range.start_and_length();
            let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
            unsafe {
                vmem.create_pages(
                    Some(suggested_address),
                    length,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                    perms,
                )
            }?;
        }
        vmem.brk = brk;
        Ok(brk)
    }

    /// Expands (or shrinks) an existing memory mapping
    ///
    /// `old_addr` is the old address of the virtual memory block that you want to expand (or shrink).
    ///
    /// `old_size` is the size of the old memory block.
    ///
    /// `new_size` is the new size of the memory block.
    ///
    /// `may_move` indicates whether the memory block can be moved to a new address if there is not sufficient
    /// space to expand the old memory block at its current location.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new address of the memory block.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remap_pages(
        &self,
        old_addr: Platform::RawMutPointer<u8>,
        old_size: usize,
        new_size: usize,
        may_move: bool,
    ) -> Result<Platform::RawMutPointer<u8>, RemapError> {
        let mut vmem = self.vmem.write();
        let old_range = PageRange::new(old_addr.as_usize(), old_addr.as_usize() + old_size)
            .ok_or(RemapError::Unaligned)?;
        match unsafe {
            vmem.resize_mapping(
                old_range,
                NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
            )
        } {
            Ok(()) => Ok(old_addr),
            Err(vmem::VmemResizeError::RangeOccupied(_)) => {
                // trying to remap a subset of an existing mapping
                if !may_move {
                    return Err(RemapError::OutOfMemory);
                }
                match unsafe {
                    vmem.move_mappings(
                        old_range,
                        None,
                        NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
                    )
                } {
                    Ok(new_addr) => Ok(new_addr),
                    Err(vmem::VmemMoveError::OutOfMemory) => Err(RemapError::OutOfMemory),
                    Err(vmem::VmemMoveError::UnAligned) => Err(RemapError::Unaligned),
                    Err(vmem::VmemMoveError::RemapError(err)) => Err(err),
                }
            }
            Err(vmem::VmemResizeError::NotExist(_)) => Err(RemapError::AlreadyUnallocated),
            Err(vmem::VmemResizeError::InvalidAddr { .. }) => Err(RemapError::AlreadyAllocated),
            Err(vmem::VmemResizeError::OutOfMemory) => Err(RemapError::OutOfMemory),
        }
    }

    /// Remove pages from the mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remove_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemUnmapError::UnAligned)?;
        unsafe { vmem.remove_mapping(range) }
    }

    /// Reset pages without removing its mapping.
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// After calling this function, the memory region remains mapped, but its contents are invalidated.
    /// Subsequent accesses to the region will result in repopulating the memory contents, either from
    /// the underlying mapped file (for file-backed mappings, which is supported) or as zero-filled pages
    /// (for anonymous mappings).
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub unsafe fn reset_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemResetError::UnAligned)?;
        unsafe { vmem.reset_pages(range, anonymous_only) }
    }
}

impl<Platform, const ALIGN: usize, Store> Vmem<Platform, ALIGN, Store>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
    Store: ReservationStore + Default,
{
    /// Attempt a native CoW mapping and register it in the VMA tracker.
    ///
    /// # Safety
    ///
    /// For replacement, the caller must ensure overlapping mappings are not in use.
    pub(super) unsafe fn try_create_cow_pages(
        &mut self,
        suggested_start: Option<usize>,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, CowAllocationError> {
        let behavior = FixedAddressBehavior::from(flags);
        if source_data.is_empty() || !source_data.len().is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }
        if suggested_start.is_none() && !matches!(behavior, FixedAddressBehavior::Hint(_)) {
            return Err(CowAllocationError::InternalFailure);
        }
        if let Some(start) = suggested_start {
            let end = start
                .checked_add(source_data.len())
                .ok_or(CowAllocationError::Unaligned)?;
            if start < Platform::TASK_ADDR_MIN || end > Platform::TASK_ADDR_MAX {
                return Err(CowAllocationError::InternalFailure);
            }
            let requested = super::vmem::PageRange::<ALIGN>::new(start, end)
                .ok_or(CowAllocationError::Unaligned)?;
            if behavior == FixedAddressBehavior::NoReplace && self.overlaps(requested.into(), true)
            {
                return Err(CowAllocationError::InternalFailure);
            }
        }
        let suggested_start = suggested_start.unwrap_or(0);

        let ptr = self.platform.try_allocate_cow_pages(
            suggested_start,
            source_data,
            permissions,
            behavior,
        )?;
        let actual_start = ptr.as_usize();
        let actual_end = actual_start
            .checked_add(source_data.len())
            .ok_or(CowAllocationError::InternalFailure)?;
        let actual = super::vmem::PageRange::new(actual_start, actual_end)
            .ok_or(CowAllocationError::InternalFailure)?;
        debug_assert!(
            matches!(behavior, FixedAddressBehavior::Hint(_)) || suggested_start == actual_start
        );
        debug_assert!(
            actual_start >= Platform::TASK_ADDR_MIN && actual_end <= Platform::TASK_ADDR_MAX
        );

        // TODO: also add the range to reservations once we allow using [`TrackedReservations`]
        // and update [`try_allocate_cow_pages`] to return the reservation handle.
        self.register_existing_mapping_overwrite(
            actual,
            VmArea::new(
                VmFlags::from(permissions)
                    | VmFlags::may_flags_for_mapping(
                        flags.contains(CreatePagesFlags::SHARED),
                        true,
                    ),
                true,
            ),
        );
        Ok(ptr)
    }

    /// Reset pages without removing its mapping (similar to Linux `madvise` with
    /// `MADV_DONTNEED` or `MADV_FREE`).
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// The current implementation effectively re-inserts the mapping with the same
    /// `VmArea` properties, which will cause the pages to be unmapped and mapped again.
    ///
    /// # Panics
    ///
    /// File-backed mapping is not supported yet.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub(super) unsafe fn reset_pages(
        &mut self,
        range: PageRange<ALIGN>,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let range: Range<usize> = range.into();
        // Any unmapped regions in the original range will result in this function returning `DeallocationError::AlreadyUnallocated`
        // while still resetting all of the existing vmas in the range.
        let unmapped_error = self.vmas.gaps(&range).next().is_some();
        let overlapping_ranges: Vec<(Range<usize>, VmArea)> = self
            .overlapping(range.clone())
            .map(|(r, vma)| (r.clone(), *vma))
            .collect();
        for (r, vma) in overlapping_ranges {
            if vma.is_file_backed() {
                if anonymous_only {
                    return Err(VmemResetError::FileBacked);
                }
                unimplemented!("resetting file-backed mappings is not supported yet");
            }
            let start = r.start.max(range.start);
            let end = r.end.min(range.end);
            let new_range = PageRange::new(start, end).unwrap();
            unsafe { self.insert_mapping(new_range, vma, false, FixedAddressBehavior::Replace) }
                .expect("failed to reset pages");
        }
        if unmapped_error {
            Err(VmemResetError::AlreadyUnallocated)
        } else {
            Ok(())
        }
    }
}
