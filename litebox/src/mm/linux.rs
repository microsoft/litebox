// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-style mappings with direct allocation or automatic reserve-then-commit backing.

use core::ops::Range;

use alloc::vec::Vec;

use super::{
    Linux, PageManager,
    vmem::{FindAreaRequest, VmArea, Vmem, VmemResizeError},
};
use crate::{
    platform::{
        PageManagementProvider, RawConstPointer, RawMutPointer, RawPointerProvider,
        page_mgmt::{
            AllocationError, CowAllocationError, FixedAddressBehavior, MemoryRegionPermissions,
            PageReservation, RemapError, ReservationStore,
        },
    },
    sync::RawSyncPrimitivesProvider,
};

pub use super::{
    CreatePagesFlags, DEFAULT_RESERVED_SPACE_SIZE, MappingError, NonZeroAddress, NonZeroPageSize,
    PAGE_SIZE, PageFaultError, PageRange, VmFlags, VmemMoveError, VmemPageFaultHandler,
    VmemProtectError, VmemResetError, VmemUnmapError,
};

/// If the backend also implements [`VmemPageFaultHandler`], it can handle Linux page faults.
impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN, Linux>
where
    Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<ALIGN>,
    Platform: VmemPageFaultHandler,
{
    /// Handle page fault at the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    pub unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let fault_addr = fault_addr & !(ALIGN - 1);
        if !(Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX).contains(&fault_addr) {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        let mut vmem = self.vmem.write();
        // Find the range closest to the fault address
        let (start, vma) = {
            let (range, vma) = vmem
                .vmas
                .overlapping(fault_addr..Platform::TASK_ADDR_MAX)
                .next()
                .ok_or(PageFaultError::AccessError("no mapping"))?;
            (range.start, *vma)
        };
        if fault_addr < start {
            // address is out of range, test if it is next to a stack
            if !vma.flags().contains(VmFlags::VM_GROWSDOWN) {
                return Err(PageFaultError::AccessError("no mapping"));
            }

            if !vmem
                .vmas
                .overlapping(Platform::TASK_ADDR_MIN..fault_addr)
                .next_back()
                .is_none_or(|(prev_range, prev_vma)| {
                    // Enforce gap between stack and other preceding non-stack mappings.
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    // or the previous mapping is far enough from the fault address
                    (prev_vma.flags().contains(VmFlags::VM_GROWSDOWN)
                        && !(prev_vma.flags() & VmFlags::VM_ACCESS_FLAGS).is_empty())
                        || fault_addr - prev_range.end
                            >= Vmem::<Platform, ALIGN, Linux>::STACK_GUARD_GAP
                })
            {
                return Err(PageFaultError::AllocationFailed);
            }
            let Some(range) = PageRange::new(fault_addr, start) else {
                unreachable!()
            };
            // SAFETY: The grown stack range has no existing mapping and inherits the stack's permissions.
            if let Err(err) =
                unsafe { vmem.insert_mapping(range, vma, false, FixedAddressBehavior::NoReplace) }
            {
                unimplemented!("failed to grow stack: {:?}", err)
            }
        }

        if <Platform as VmemPageFaultHandler>::access_error(error_code, vma.flags()) {
            return Err(PageFaultError::AccessError("access error"));
        }

        // SAFETY: The caller supplies kernel fault context; VMA lookup validated the address and access.
        unsafe {
            vmem.platform
                .handle_page_fault(fault_addr, vma.flags(), error_code)
        }
    }
}

impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN, Linux>
where
    Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<ALIGN>,
{
    /// Attempt a native CoW mapping and retain the returned reservation ownership.
    ///
    /// The provider call and ownership transfer are serialized with other mapping operations.
    /// This does not reserve anonymous pages or import the returned handle. Recoverable errors
    /// leave existing mappings and ownership unchanged, allowing the caller to fall back.
    ///
    /// # Safety
    ///
    /// For replacement, the caller must authorize replacing every mapping in the requested range
    /// and exclude its users. The source must meet the provider's CoW backing requirements.
    pub unsafe fn try_create_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        behavior: FixedAddressBehavior,
        shared: bool,
    ) -> Result<Platform::RawMutPointer<u8>, CowAllocationError> {
        // SAFETY: The caller authorizes replacement and excludes affected users; the write lock serializes ownership.
        unsafe {
            self.vmem.write().try_create_cow_pages(
                suggested_start,
                source_data,
                permissions,
                behavior,
                shared,
            )
        }
    }

    /// Reset anonymous pages without removing their mappings, for Linux `madvise`.
    ///
    /// The mappings and their permissions remain, but their contents are replaced with zeros.
    /// If `anonymous_only` is true and a file-backed mapping is encountered,
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// # Panics
    ///
    /// Panics if a file-backed mapping is encountered when `anonymous_only` is false,
    /// because resetting file-backed mappings is not supported yet.
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
        let range = PageRange::from_start_len(start, len).ok_or(VmemResetError::UnAligned)?;
        // SAFETY: The caller excludes accesses and relinquishes the previous contents.
        unsafe { vmem.reset_pages(range, anonymous_only) }
    }

    /// Create a Linux-style mapping with automatic reservation management.
    ///
    /// `suggested_new_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// `before_perms` and `after_perms` are the permissions to set before and after the call to `op`.
    /// Mapping placement may use uncommitted pages in existing reservations. Callers that need
    /// explicit reservation control must construct a [`crate::mm::WindowsPageManager`] instead.
    /// An optional native operation may reserve and commit the mapping in one step. Otherwise,
    /// fresh backing is rounded outward to the platform's reservation alignment and reserved
    /// before commitment. If a hint collides with native reservations, the entire mapping is
    /// relocated, never individual gaps. Only `length` bytes are committed.
    /// [`Self::unmap_pages`] applies alignment-based partial-unmap retention and releases
    /// touched reservations once they contain no committed pages.
    /// A failed replacement does not restore discarded old contents. The fallback rolls back
    /// completed commitments and releases unused acquisitions before returning an error.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    unsafe fn create_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        before_perms: MemoryRegionPermissions,
        after_perms: MemoryRegionPermissions,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let addr = {
            let mut vmem = self.vmem.write();
            unsafe { vmem.create_pages(suggested_address, length, flags, before_perms) }?
        };
        // call the user function with the pages
        // Note `op` may trigger page fault handler which requires write lock to `vmem`.
        if let Err(e) = op(addr) {
            // remove the mapping if the user function fails
            let mut vmem = self.vmem.write();
            unsafe {
                vmem.unmap_mapping(
                    PageRange::from_start_len(addr.as_usize(), length.as_usize()).unwrap(),
                );
            }
            return Err(e);
        }
        if before_perms != after_perms {
            let range = PageRange::from_start_len(addr.as_usize(), length.as_usize()).unwrap();
            // `protect` should succeed, as we just created the mapping.
            let mut vmem = self.vmem.write();
            unsafe { vmem.protect_mapping(range, after_perms) }.expect("failed to protect mapping");
        }
        Ok(addr)
    }

    /// Create pages with the requested final permissions.
    ///
    /// The pages are temporarily readable and writable while `op` initializes
    /// them, then changed to `permissions` before this function returns.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_pages_with_permissions<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        permissions: MemoryRegionPermissions,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                permissions,
                op,
            )
        }
    }

    /// Create readable and executable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_executable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the code)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE and turn on EXEC
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                op,
            )
        }
    }

    /// Create readable and writable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_writable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        unsafe { self.create_pages(suggested_address, length, flags, perms, perms, op) }
    }

    /// Create read-only pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_readable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the data)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE
                MemoryRegionPermissions::READ,
                op,
            )
        }
    }

    /// Create inaccessible pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_inaccessible_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                MemoryRegionPermissions::empty(),
                MemoryRegionPermissions::empty(),
                op,
            )
        }
    }

    /// Create stack pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_stack_pages(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let flags = CreatePagesFlags::IS_STACK | flags;
        unsafe { self.create_pages(suggested_address, length, flags, perms, perms, |_| Ok(0)) }
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
    /// Initialize the program break with [`Self::set_initial_brk`] before calling this method.
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

        let old_brk = vmem
            .brk
            .checked_next_multiple_of(ALIGN)
            .ok_or(MappingError::OutOfMemory)?;
        let new_brk = brk
            .checked_next_multiple_of(ALIGN)
            .ok_or(MappingError::OutOfMemory)?;
        if old_brk == new_brk {
            vmem.brk = brk;
            return Ok(brk);
        }
        if vmem.brk >= brk {
            // Shrink the memory region
            unsafe {
                vmem.unmap_mapping(
                    PageRange::new(new_brk, old_brk).ok_or(MappingError::UnAligned)?,
                );
            }
            vmem.brk = brk;
            return Ok(brk);
        }

        if vmem.vmas.overlapping(old_brk..new_brk).next().is_some() {
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
    /// The source range must be contained in one committed VMA, including no-access mappings.
    /// Reserved but uncommitted pages cannot be resized or moved.
    /// Native remapping is used when available. Otherwise, the manager prepares a destination,
    /// reusing uncommitted backing and reserving only missing gaps, then copies the contents
    /// before unmapping the source. Destination preparation failures preserve the source.
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
        let old_range = PageRange::from_start_len(old_addr.as_usize(), old_size)
            .ok_or(RemapError::Unaligned)?;
        match unsafe {
            vmem.resize_mapping(
                old_range,
                NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
            )
        } {
            Ok(()) => Ok(old_addr),
            Err(VmemResizeError::RangeOccupied(_) | VmemResizeError::OutOfMemory) => {
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
                    Err(VmemMoveError::OutOfMemory) => Err(RemapError::OutOfMemory),
                    Err(VmemMoveError::UnAligned) => Err(RemapError::Unaligned),
                    Err(VmemMoveError::RemapError(err)) => Err(err),
                }
            }
            Err(VmemResizeError::PermissionDenied) => Err(RemapError::PermissionDenied),
            Err(VmemResizeError::NotExist(_)) => Err(RemapError::AlreadyUnallocated),
            Err(VmemResizeError::InvalidAddr { .. }) => Err(RemapError::AlreadyAllocated),
        }
    }

    /// Unmap a Linux-style mapping using the provider's backing lifecycle.
    ///
    /// Partially live reservations are retained with the removed range decommitted.
    /// Empty touched reservations are released.
    /// Use [`PageManager::release_memory`] to additionally reclaim all empty reservations.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    /// Unreserved gaps must remain unmapped until this call returns.
    pub unsafe fn unmap_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::from_start_len(start, len).ok_or(VmemUnmapError::UnAligned)?;
        // SAFETY: The caller excludes users from the unmapped range.
        unsafe { vmem.unmap_mapping(range) };
        Ok(())
    }
}

impl VmFlags {
    fn for_new_mapping(flags: &CreatePagesFlags, file_backed: bool) -> Self {
        Self::may_flags_for_mapping(flags.contains(CreatePagesFlags::SHARED), file_backed)
            | if flags.contains(CreatePagesFlags::IS_STACK) {
                Self::VM_GROWSDOWN
            } else {
                Self::empty()
            }
    }
}

impl<Platform: PageManagementProvider<ALIGN> + RawPointerProvider + 'static, const ALIGN: usize>
    Vmem<Platform, ALIGN, Linux>
{
    /// Unmap guest pages, ignoring unreserved gaps.
    ///
    /// Partially live reservations are retained with removed pages decommitted. Empty touched
    /// reservations are released.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    /// The range must not overlap external memory reported by the platform at startup.
    /// Unreserved gaps must remain unmapped until this call returns.
    pub(super) unsafe fn unmap_mapping(&mut self, range: PageRange<ALIGN>) {
        let range: Range<usize> = range.into();
        // SAFETY: The caller excludes users and keeps unreserved gaps unmapped.
        unsafe {
            self.mappings.reservations.unmap::<Platform, ALIGN, _>(
                &mut self.mappings.vmas,
                self.platform,
                range,
            );
        }
    }

    /// Reset pages without removing its mapping (similar to Linux `madvise` with
    /// `MADV_DONTNEED` or `MADV_FREE`).
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// Replaces anonymous contents with zero-filled backing at the same addresses and permissions.
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
            .vmas
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
            // SAFETY: The caller relinquishes anonymous contents; replacement is clipped to the affected range.
            unsafe {
                self.insert_mapping(
                    PageRange::new(start, end).unwrap(),
                    vma,
                    false,
                    FixedAddressBehavior::Replace,
                )
            }
            .expect("failed to reset pages");
        }
        if unmapped_error {
            Err(VmemResetError::AlreadyUnallocated)
        } else {
            Ok(())
        }
    }

    /// Insert a range to its virtual address space.
    ///
    /// If the inserted range partially or completely overlaps any
    /// existing range in the map, then the existing range (or ranges) will be
    /// partially or completely replaced by the inserted range.
    ///
    /// If the inserted range either overlaps or is immediately adjacent
    /// any existing range _mapping to the same value_, then the ranges
    /// will be coalesced into a single contiguous range.
    ///
    /// # Panics
    ///
    /// Panics if a hint range overlaps an existing mapping. Hint placement must be
    /// resolved by the caller, as in [`Self::create_mapping`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is not used by any other (i.e., safe
    /// to unmap all overlapping mappings if any).
    pub(super) unsafe fn insert_mapping(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        vma: VmArea,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let (start, end) = (suggested_range.start, suggested_range.end);
        if start < Platform::TASK_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if end > Platform::TASK_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if self
            .vmas
            .overlapping(start..end)
            .any(|(_, existing)| existing.flags().is_empty())
        {
            return Err(AllocationError::AddressInUse);
        }
        if self.vmas.overlaps(&(start..end)) {
            match fixed_address_behavior {
                FixedAddressBehavior::NoReplace => return Err(AllocationError::AddressInUse),
                FixedAddressBehavior::Hint => {
                    unreachable!("hint placement must not overlap existing mappings")
                }
                FixedAddressBehavior::Replace => {}
            }
        }
        // SAFETY: The caller authorizes replacement of manager-owned mappings, and the mapping
        // state accurately represents all committed ownership.
        let actual = unsafe {
            self.mappings.reservations.mmap(
                &mut self.mappings.vmas,
                self.platform,
                crate::platform::page_mgmt::MmapRequest {
                    range: suggested_range.into(),
                    permissions: vma.flags().into(),
                    can_grow_down: vma.flags.contains(VmFlags::VM_GROWSDOWN),
                    populate: populate_pages_immediately,
                    behavior: fixed_address_behavior,
                },
            )
        }?;
        debug_assert_eq!(actual.len(), suggested_range.len());
        debug_assert!(
            fixed_address_behavior == FixedAddressBehavior::Hint || actual.start == start
        );
        self.mappings.vmas.insert(actual.clone(), vma);
        Ok(Platform::RawMutPointer::from_usize(actual.start))
    }

    /// Transfer CoW ownership directly between the provider and the manager's reservation index.
    ///
    /// # Safety
    ///
    /// The caller authorizes replacement of the destination range and excludes affected users.
    pub(super) unsafe fn try_create_cow_pages(
        &mut self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        behavior: FixedAddressBehavior,
        shared: bool,
    ) -> Result<Platform::RawMutPointer<u8>, CowAllocationError> {
        let end = suggested_start
            .checked_add(source_data.len())
            .ok_or(CowAllocationError::Unaligned)?;
        let requested =
            PageRange::<ALIGN>::new(suggested_start, end).ok_or(CowAllocationError::Unaligned)?;
        if (suggested_start < Platform::TASK_ADDR_MIN
            && !(suggested_start == 0 && behavior == FixedAddressBehavior::Hint))
            || end > Platform::TASK_ADDR_MAX
        {
            return Err(CowAllocationError::InternalFailure);
        }
        if behavior != FixedAddressBehavior::Hint
            && self
                .vmas
                .overlapping(Range::from(requested))
                .any(|(_, vma)| vma.flags().is_empty())
        {
            return Err(CowAllocationError::InternalFailure);
        }
        if behavior == FixedAddressBehavior::NoReplace && self.overlaps(requested.into(), true) {
            return Err(CowAllocationError::InternalFailure);
        }
        // SAFETY: All overlapping ownership is transferred in order; startup replacements are excluded above.
        let reservation = unsafe {
            self.platform.try_allocate_cow_pages(
                || {
                    // SAFETY: The provider invokes this supplier only for authorized replacement,
                    // and the mapping state represents all manager-owned committed pages.
                    self.mappings
                        .reservations
                        .take_replaced(&self.mappings.vmas, requested.into())
                        .into_iter()
                },
                suggested_start,
                source_data,
                permissions,
                behavior,
            )
        }?;
        let actual = reservation.range();
        assert_eq!(actual.len(), source_data.len());
        assert!(behavior == FixedAddressBehavior::Hint || actual.start == suggested_start);
        let pointer = Platform::RawMutPointer::from_usize(actual.start);
        self.reservations.insert(actual.start, reservation);
        self.vmas.insert(
            actual,
            VmArea::new_cow(
                VmFlags::from(permissions) | VmFlags::may_flags_for_mapping(shared, true),
            ),
        );
        Ok(pointer)
    }

    /// Create a Linux-style mapping using native allocation or the common reserve-then-commit
    /// fallback. Fresh backing respects reservation alignment; only the mapping is committed.
    /// A conflicting hint relocates the whole mapping, never individual gaps.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// Return the new address if the mapping is created successfully.
    /// The returned address is `ALIGN`-aligned.
    ///
    /// # Fixed Address Behavior
    ///
    /// - [`CreatePagesFlags::FIXED_ADDR`] alone: Forces allocation at the exact address, replacing
    ///   any existing overlapping mappings. Caller must ensure overlapping mappings are not in use.
    /// - [`CreatePagesFlags::FIXED_ADDR`] with [`CreatePagesFlags::NOREPLACE`]: Forces allocation at
    ///   the exact address, but fails with [`AllocationError::AddressInUse`] if any part of the
    ///   range is already mapped. This is safe to use without checking for existing mappings first.
    /// - Without [`CreatePagesFlags::FIXED_ADDR`], the address is treated as a hint.
    ///
    /// Note: `NOREPLACE` error responses (`AddressInUse` / `EEXIST`) can be used to probe memory
    /// layout. This matches Linux kernel behavior for `MAP_FIXED_NOREPLACE`.
    /// Uncommitted reservation pages are available to mapping placement. To acquire new
    /// address-space ownership instead, use a [`crate::mm::WindowsPageManager`].
    ///
    /// # Safety
    ///
    /// When using [`CreatePagesFlags::FIXED_ADDR`] without [`CreatePagesFlags::NOREPLACE`], the
    /// caller must ensure any overlapping mappings are not used by any other code, as they will be
    /// unmapped.
    pub(super) unsafe fn create_mapping(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        vma: VmArea,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let total_length = (length
            + if flags.contains(CreatePagesFlags::ENSURE_SPACE_AFTER) {
                DEFAULT_RESERVED_SPACE_SIZE
            } else {
                0
            })
        .ok_or(AllocationError::OutOfMemory)?;
        let behavior = if flags.contains(CreatePagesFlags::FIXED_ADDR) {
            if flags.contains(CreatePagesFlags::NOREPLACE) {
                FixedAddressBehavior::NoReplace
            } else {
                FixedAddressBehavior::Replace
            }
        } else {
            FixedAddressBehavior::Hint
        };
        let new_addr = self
            .get_unmmaped_area(suggested_address, total_length, behavior)?
            .ok_or(AllocationError::OutOfMemory)?;
        // new_addr must be ALIGN aligned
        let new_range = PageRange::from_start_len(new_addr, length.as_usize()).unwrap();
        // SAFETY: The caller authorizes fixed replacement; other placements exclude live mappings.
        unsafe {
            self.insert_mapping(
                new_range,
                vma,
                flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                behavior,
            )
        }
    }

    /// Resize a range contained in one committed VMA, including committed no-access pages.
    /// Shrink the range if it is larger than `new_size`.
    /// Shrinking unmaps the removed tail and releases any reservations left empty.
    /// Enlarge the range if it is smaller than `new_size` and will not overlap with
    /// next mapping after the expansion.
    ///
    /// It fails if it resizes more than one mapping or needs to split the current mapping
    /// (due to enlarging).
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mremap.c#L886> for reference.
    ///
    /// # Safety
    ///
    /// If it shrinks, the caller must ensure that the unmapped memory region is not used by any other.
    pub(super) unsafe fn resize_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<(), VmemResizeError> {
        let range = range.start..range.end;
        // `cur_range` contains `range.start`
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .filter(|(_, vma)| !vma.flags().is_empty())
            .ok_or(VmemResizeError::NotExist(range.start))?;
        if range.end > cur_range.end {
            // We can't remap across vm area boundaries.
            return Err(VmemResizeError::InvalidAddr {
                range: cur_range.clone(),
                addr: range.end,
            });
        }

        let new_end = range
            .start
            .checked_add(new_size.as_usize())
            .filter(|&end| end <= Platform::TASK_ADDR_MAX)
            .ok_or(VmemResizeError::OutOfMemory)?;
        match new_end.cmp(&range.end) {
            core::cmp::Ordering::Equal => {
                // no change
                return Ok(());
            }
            core::cmp::Ordering::Less => {
                // shrink
                let range = PageRange::new(new_end, range.end).unwrap();
                // SAFETY: The caller relinquishes the removed tail and excludes its users.
                unsafe { self.unmap_mapping(range) };
                return Ok(());
            }
            core::cmp::Ordering::Greater => {}
        }

        // grow
        if range.end == cur_range.end {
            // expand the current range
            let r = range.end..new_end;
            if self.vmas.overlaps(&r) {
                return Err(VmemResizeError::RangeOccupied(r));
            }
            if cur_vma.is_file_backed() {
                unimplemented!("file-backed mapping expansion is not supported yet");
            }
            let range = PageRange::new(range.end, new_end).unwrap();
            // Try to extend the mapping. Although we checked that there are no
            // litebox mappings in this range, this may fail if there are
            // platform mappings in the way.
            // SAFETY: The added range has no guest mapping; NoReplace preserves foreign ownership.
            match unsafe {
                self.insert_mapping(range, *cur_vma, false, FixedAddressBehavior::NoReplace)
            } {
                Ok(_) => {}
                Err(AllocationError::OutOfMemory) => return Err(VmemResizeError::OutOfMemory),
                Err(AllocationError::PermissionDenied) => {
                    return Err(VmemResizeError::PermissionDenied);
                }
                Err(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                ) => return Err(VmemResizeError::RangeOccupied(range.into())),
                Err(
                    AllocationError::Unaligned
                    | AllocationError::BelowMinAddress
                    | AllocationError::AboveMaxAddress,
                ) => unreachable!(),
            }
            return Ok(());
        }

        // has to split the current range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..cur_range.end))
    }

    /// Move a range within one committed VMA from `old_range` to a new mapping.
    /// Use it together with [`Vmem::resize_mapping`] to achieve `mremap`.
    ///
    /// `suggested_new_address` is used as a hint for the new address.
    /// If it is `None`, the manager chooses a suitable address.
    /// Emulated remapping may reuse uncommitted reservation backing. Native remapping uses a
    /// reservation-free destination when reservations are tracked explicitly.
    ///
    /// Returns the new address if the range is moved successfully, or an error otherwise.
    /// Returns an error if `old_range` is not covered by exactly one committed guest mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given `range` is safe to be unmapped.
    ///
    /// # Panics
    ///
    /// Panics if `new_size` is not larger than the size of `old_range`.
    pub(super) unsafe fn move_mappings(
        &mut self,
        old_range: PageRange<ALIGN>,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError> {
        assert!(new_size.as_usize() > old_range.len());

        // Check if the given range is covered by exactly one mapping
        let (_, vma) = self
            .vmas
            .get_key_value(&old_range.start)
            .filter(|(range, vma)| !vma.flags().is_empty() && range.end >= old_range.end)
            .ok_or(RemapError::AlreadyUnallocated)?;

        if vma.is_file_backed() {
            unimplemented!("file-backed mapping move is not supported yet");
        }
        let vma = *vma;
        // SAFETY: The source is one exclusively owned committed mapping. The store selects a
        // destination compatible with its native reservation representation.
        let result = unsafe {
            let platform = self.platform;
            let mappings = &mut self.mappings;
            mappings.reservations.remap::<Platform, ALIGN, _, _>(
                &mut mappings.vmas,
                platform,
                old_range.into(),
                vma.flags.into(),
                vma,
                |reservations, vmas, include_reservations| {
                    Vmem::<Platform, ALIGN, Linux>::find_area(
                        reservations,
                        vmas,
                        FindAreaRequest {
                            suggested_address: suggested_new_address,
                            length: new_size,
                            behavior: FixedAddressBehavior::Hint,
                            alignment: ALIGN,
                            include_reservations,
                            address_range: Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX,
                            top_down: true,
                        },
                    )
                    .ok()
                    .flatten()
                    .map(|start| start..start + new_size.as_usize())
                },
            )
        };
        let destination = match result {
            Ok(destination) => destination,
            Err(RemapError::UnsupportedByPlatform) => {
                let new_start = self
                    .get_unmmaped_area(suggested_new_address, new_size, FixedAddressBehavior::Hint)
                    .map_err(|_| VmemMoveError::OutOfMemory)?
                    .ok_or(VmemMoveError::OutOfMemory)?;
                let new_range = PageRange::from_start_len(new_start, new_size.as_usize()).unwrap();
                // SAFETY: Unsupported native remapping leaves the source unchanged and exclusively owned.
                return unsafe { self.remap_fallback_with_copy(old_range, new_range, vma) };
            }
            Err(error) => return Err(VmemMoveError::RemapError(error)),
        };
        assert_eq!(destination.len(), new_size.as_usize());
        let pointer = Platform::RawMutPointer::from_usize(destination.start);
        Ok(pointer)
    }

    /// Remap by copying while reusing uncommitted destination backing.
    ///
    /// # Safety
    ///
    /// The source must be committed with `vma`'s permissions and have no active users.
    /// The destination must be larger than the source and contain no committed mappings.
    ///
    /// # Panics
    ///
    /// Failures after destination preparation are fatal because copying or teardown may have begun.
    unsafe fn remap_fallback_with_copy(
        &mut self,
        old_range: PageRange<ALIGN>,
        new_range: PageRange<ALIGN>,
        vma: VmArea,
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError> {
        let permissions = MemoryRegionPermissions::from(vma.flags());
        let temporary = VmArea::new(vma.flags() | VmFlags::VM_READ | VmFlags::VM_WRITE, false);
        // SAFETY: Placement excludes committed pages; Hint preserves other ownership and may relocate.
        let destination =
            unsafe { self.insert_mapping(new_range, temporary, false, FixedAddressBehavior::Hint) }
                .map_err(|error| {
                    VmemMoveError::RemapError(match error {
                        AllocationError::OutOfMemory | AllocationError::AboveMaxAddress => {
                            RemapError::OutOfMemory
                        }
                        AllocationError::Unaligned | AllocationError::BelowMinAddress => {
                            RemapError::Unaligned
                        }
                        _ => RemapError::AlreadyAllocated,
                    })
                })?;
        let extent = destination.as_usize()..destination.as_usize() + new_range.len();
        if !permissions.contains(MemoryRegionPermissions::READ) {
            // SAFETY: These handles cover the committed source; the caller excludes all users.
            unsafe {
                self.platform.protect_pages(
                    || {
                        self.reservations
                            .overlapping(old_range.into())
                            .map(|(_, reservation)| reservation)
                    },
                    old_range.into(),
                    permissions | MemoryRegionPermissions::READ,
                )
            }
            .expect("failed to make remap source readable");
        }
        for offset in (0..old_range.len()).step_by(ALIGN) {
            let source = Platform::RawConstPointer::<u8>::from_usize(old_range.start + offset);
            let buffer = source
                .to_owned_slice(ALIGN)
                .expect("failed to read remap source");
            destination
                .copy_from_slice(offset, &buffer)
                .expect("failed to copy remap source");
        }
        // SAFETY: The destination is committed, exclusively owned, and no copies remain in progress.
        unsafe {
            self.platform.protect_pages(
                || {
                    self.reservations
                        .overlapping(extent.clone())
                        .map(|(_, reservation)| reservation)
                },
                extent.clone(),
                permissions,
            )
        }
        .expect("failed to restore remap destination permissions");
        self.vmas.insert(extent, vma);
        // SAFETY: Copying is complete; destination VMAs retain any shared reservation during source cleanup.
        unsafe { self.unmap_mapping(old_range) };
        Ok(destination)
    }

    /// Create a mapping with the given flags.
    ///
    /// `suggested_new_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `perms` specifies the permissions of the created pages.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    pub(super) unsafe fn create_pages(
        &mut self,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        perms: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let file_backed = flags.contains(CreatePagesFlags::MAP_FILE);
        let vma = VmArea::new(
            VmFlags::from(perms) | VmFlags::for_new_mapping(&flags, file_backed),
            file_backed,
        );
        // SAFETY: The caller supplies mapping flags and excludes users of any replaced pages.
        unsafe { self.create_mapping(suggested_new_address, length, vma, flags) }
            .map_err(MappingError::MapError)
    }

    /// Get an unmapped area in the virtual address space.
    /// `suggested_range` and `behavior` describe the requested mmap placement.
    ///
    /// Returns `None` if no area found. Otherwise, returns the start address of a page-aligned area.
    #[inline]
    fn get_unmmaped_area(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        behavior: FixedAddressBehavior,
    ) -> Result<Option<usize>, AllocationError> {
        // Fresh automatic mappings need room for reservation-aligned native backing.
        // Explicit addresses remain guest-page aligned and are validated as requested.
        let address_range_end = if suggested_address.is_none() {
            Platform::TASK_ADDR_MAX & !(Platform::RESERVATION_ALIGNMENT - 1)
        } else {
            Platform::TASK_ADDR_MAX
        };
        let alignment = if suggested_address.is_none() {
            Platform::RESERVATION_ALIGNMENT
        } else {
            ALIGN
        };
        Self::find_area(
            &self.reservations,
            &self.vmas,
            FindAreaRequest {
                suggested_address,
                length,
                behavior,
                alignment,
                include_reservations: false,
                address_range: Platform::TASK_ADDR_MIN..address_range_end,
                top_down: true,
            },
        )
    }
}
