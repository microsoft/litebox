// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management related functionality
//!
//! Common implementation of memory management related syscalls, eg., `mmap`, `munmap`, etc.

use core::ops::Range;

use alloc::vec::Vec;
use litebox::{
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{
            AllocationDirection, CowAllocationError, DeallocationError, MemoryRegionPermissions,
            RemapError,
        },
    },
    sync::{RawSyncPrimitivesProvider, RwLock},
};

use crate::{
    MRemapFlags, MapFlags, ProtFlags, UserPtrMut,
    errno::Errno,
    vmem::{
        self, CreatePagesFlags, LinuxReservationStore, MappingError, NonZeroAddress,
        NonZeroPageSize, PAGE_SIZE, PageFaultError, PageRange, VmFlags, Vmem, VmemPageFaultHandler,
        VmemProtectError, VmemResetError, VmemUnmapError,
    },
};

/// A page manager to support `mmap`, `munmap`, and etc.
pub struct VmemManager<Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    vmem: RwLock<Platform, Vmem<Platform, ALIGN>>,
}

impl<Platform, const ALIGN: usize> VmemManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
    Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
{
    /// Create a new `VmemManager` instance.
    pub fn new(platform: &'static Platform) -> Self {
        let vmem = RwLock::new(Vmem::new(platform));
        Self { vmem }
    }

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

    /// Create a mapping with the given flags.
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
                vmem.remove_mapping(
                    PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize()).unwrap(),
                )
            }
            .unwrap();
            return Err(e);
        }
        if before_perms != after_perms {
            let range =
                PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize()).unwrap();
            let mut vmem = self.vmem.write();
            // `op` runs unlocked, so another thread may have unmapped or replaced part of the range.
            if let Err(e) = unsafe { vmem.protect_mapping(range, after_perms) } {
                // TODO: Another thread may have unmapped or replaced part of the range while `op` ran unlocked.
                // We may end up removing another thread's mapping if another thread unmaps and remaps this
                // range before cleanup.
                let _ = unsafe { vmem.remove_mapping(range) };
                return Err(e.into());
            }
        }
        Ok(addr)
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

    /// Release every memory mapping and reservation.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the released memory regions are no longer used.
    pub unsafe fn release_memory(&self) -> Result<(), VmemUnmapError> {
        unsafe { self.vmem.write().release_all() }.map_err(VmemUnmapError::UnmapError)
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
        let old_end = old_addr
            .as_usize()
            .checked_add(old_size)
            .ok_or(RemapError::InvalidRange)?;
        if old_end > Platform::TASK_ADDR_MAX {
            return Err(RemapError::InvalidRange);
        }
        let old_range =
            PageRange::new(old_addr.as_usize(), old_end).ok_or(RemapError::Unaligned)?;
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
            Err(vmem::VmemResizeError::InvalidRange(_)) => Err(RemapError::InvalidRange),
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
        let end = start
            .checked_add(len)
            .ok_or(VmemUnmapError::InvalidRange(start..usize::MAX))?;
        let range = PageRange::new(start, end).ok_or(VmemUnmapError::UnAligned)?;
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

    /// Internal common function used by `make_pages_*` to change page permissions.
    fn change_page_permissions(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let end = start.saturating_add(len);
        let range = PageRange::new(start, end).ok_or(VmemProtectError::InvalidRange(start..end))?;
        unsafe { vmem.protect_mapping(range, new_permissions) }
    }

    /// Make pages readable and writable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `execute` access to the memory region.
    pub unsafe fn make_pages_writable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
        )
    }

    /// Make pages readable and executable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write` access to the memory region.
    pub unsafe fn make_pages_executable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        )
    }

    /// Make pages readable only.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write/execute` access to the memory region.
    pub unsafe fn make_pages_readable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::READ)
    }

    /// Make pages inaccessible.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent access to the memory region.
    pub unsafe fn make_pages_inaccessible(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::empty())
    }

    /// Make pages readable, writable and executable.
    ///
    /// # Safety
    ///
    /// This operation is inherently dangerous and should be used with extreme caution.
    /// Allowing pages to be both writable and executable can lead to severe security vulnerabilities,
    /// such as code injection attacks or exploitation of memory corruption bugs.
    ///
    /// The caller must ensure the following:
    /// 1. The memory region is only used for legitimate purposes, such as JIT compilation,
    ///    where writable and executable permissions are strictly necessary.
    /// 2. The memory region is properly sanitized and does not contain malicious or unintended code.
    ///
    /// It is highly recommended to minimize the use of this function and to prefer safer alternatives
    /// whenever possible. If this function must be used, ensure that the memory region is locked down
    /// and access is strictly controlled.
    pub unsafe fn make_pages_rwx(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ
                | MemoryRegionPermissions::WRITE
                | MemoryRegionPermissions::EXEC,
        )
    }

    /// Returns all mappings in a vector.
    pub fn mappings(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem
            .read()
            .iter()
            .map(|(r, vma)| (r.start..r.end, vma.flags()))
            .collect()
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `ptr` specifies the start address of the memory range.
    /// `len` specifies the length of the memory range.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    /// A memory range is invalid if it contains:
    /// - Unmapped pages
    /// - Memory pages with different permissions
    pub fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<ALIGN>,
        len: NonZeroPageSize<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let vmem = self.vmem.read();
        let start = ptr.as_usize();
        let end = start + len.as_usize();
        let page_range = PageRange::<ALIGN>::new(start, end)?;
        vmem.get_memory_permissions(page_range)
    }
}

/// If Backend also implements [`VmemPageFaultHandler`], it can handle page faults.
impl<Platform, const ALIGN: usize> VmemManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
    Platform: VmemPageFaultHandler,
    Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
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
            let (r, vma) = vmem
                .overlapping(fault_addr..Platform::TASK_ADDR_MAX)
                .next()
                .ok_or(PageFaultError::AccessError("no mapping"))?;
            (r.start, *vma)
        };
        if fault_addr < start {
            // address is out of range, test if it is next to a stack
            if !vma.flags().contains(VmFlags::VM_GROWSDOWN) {
                return Err(PageFaultError::AccessError("no mapping"));
            }

            if !vmem
                .overlapping(Platform::TASK_ADDR_MIN..fault_addr)
                .next_back()
                .is_none_or(|(prev_range, prev_vma)| {
                    // Enforce gap between stack and other preceding non-stack mappings.
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    // or the previous mapping is far enough from the fault address
                    (prev_vma.flags().contains(VmFlags::VM_GROWSDOWN)
                        && !(prev_vma.flags() & VmFlags::VM_ACCESS_FLAGS).is_empty())
                        || fault_addr - prev_range.end >= Vmem::<Platform, ALIGN>::STACK_GUARD_GAP
                })
            {
                return Err(PageFaultError::AllocationFailed);
            }
            let Some(range) = PageRange::new(fault_addr, start) else {
                unreachable!()
            };
            if let Err(err) = unsafe {
                vmem.insert_mapping(
                    range,
                    vma,
                    false,
                    litebox::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                )
            } {
                unimplemented!("failed to grow stack: {:?}", err)
            }
        }

        if <Platform as VmemPageFaultHandler>::access_error(error_code, vma.flags()) {
            return Err(PageFaultError::AccessError("access error"));
        }

        unsafe {
            vmem.platform
                .handle_page_fault(fault_addr, vma.flags(), error_code)
        }
    }
}

const PAGE_MASK: usize = !(PAGE_SIZE - 1);

impl From<MapFlags> for CreatePagesFlags {
    fn from(flags: MapFlags) -> Self {
        let mut create_flags = Self::empty();
        // MAP_FIXED_NOREPLACE implies MAP_FIXED behavior (exact address, not a hint)
        create_flags.set(
            Self::FIXED_ADDR,
            flags.intersects(MapFlags::MAP_FIXED | MapFlags::MAP_FIXED_NOREPLACE),
        );
        create_flags.set(
            Self::NOREPLACE,
            flags.contains(MapFlags::MAP_FIXED_NOREPLACE),
        );
        create_flags.set(
            Self::POPULATE_PAGES_IMMEDIATELY,
            flags.contains(MapFlags::MAP_POPULATE),
        );
        create_flags.set(Self::MAP_FILE, !flags.contains(MapFlags::MAP_ANONYMOUS));
        create_flags.set(Self::SHARED, flags.contains(MapFlags::MAP_SHARED));
        create_flags
    }
}

impl From<ProtFlags> for MemoryRegionPermissions {
    fn from(prot: ProtFlags) -> Self {
        let mut permissions = Self::empty();
        permissions.set(Self::READ, prot.contains(ProtFlags::PROT_READ));
        permissions.set(Self::WRITE, prot.contains(ProtFlags::PROT_WRITE));
        permissions.set(Self::EXEC, prot.contains(ProtFlags::PROT_EXEC));
        permissions
    }
}

/// Address-selection policy for an mmap operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmapPlacement {
    /// Direction in which to search for free address space.
    pub direction: AllocationDirection,
    /// Whether to reserve additional growth space after the mapping.
    pub ensure_space_after: bool,
}

impl<Platform> VmemManager<Platform, PAGE_SIZE>
where
    Platform: litebox::platform::RawPointerProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::PageManagementProvider<PAGE_SIZE>,
    Platform::Reservations: LinuxReservationStore<Platform, PAGE_SIZE>,
{
    /// Create an mmap-style mapping using the requested placement policy.
    pub fn do_mmap(
        &self,
        suggested_addr: Option<usize>,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
        placement: MmapPlacement,
        op: impl FnOnce(UserPtrMut<u8>) -> Result<usize, MappingError>,
    ) -> Result<UserPtrMut<u8>, MappingError> {
        let op = |p: Platform::RawMutPointer<u8>| op(UserPtrMut::from_platform_ptr::<Platform>(p));
        let mut flags = CreatePagesFlags::from(flags);
        flags.set(
            CreatePagesFlags::ENSURE_SPACE_AFTER,
            placement.ensure_space_after,
        );
        flags.set(
            CreatePagesFlags::TOP_DOWN,
            placement.direction == AllocationDirection::TopDown,
        );
        let suggested_addr = match suggested_addr {
            Some(addr) => Some(NonZeroAddress::new(addr).ok_or(MappingError::UnAligned)?),
            None => None,
        };
        let length = NonZeroPageSize::new(len).ok_or(MappingError::UnAligned)?;
        match prot {
            ProtFlags::PROT_READ_EXEC => unsafe {
                self.create_executable_pages(suggested_addr, length, flags, op)
            },
            ProtFlags::PROT_READ_WRITE => unsafe {
                self.create_writable_pages(suggested_addr, length, flags, op)
            },
            ProtFlags::PROT_READ => unsafe {
                self.create_readable_pages(suggested_addr, length, flags, op)
            },
            ProtFlags::PROT_NONE => unsafe {
                self.create_inaccessible_pages(suggested_addr, length, flags, op)
            },
            _ => {
                litebox_util_log::debug!(prot:? = prot; "unsupported mmap protection");
                Err(VmemProtectError::UnsupportedProtection.into())
            }
        }
        .map(UserPtrMut::from_platform_ptr::<Platform>)
    }

    /// Handle syscall `munmap`.
    pub fn sys_munmap(&self, addr: UserPtrMut<u8>, len: usize) -> Result<(), Errno> {
        if addr.as_usize() & !PAGE_MASK != 0 {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        let aligned_len = len
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        if addr.as_usize().checked_add(aligned_len).is_none() {
            return Err(Errno::EINVAL);
        }

        match unsafe { self.remove_pages(addr.to_platform_ptr::<Platform>(), aligned_len) } {
            Err(VmemUnmapError::UnAligned | VmemUnmapError::InvalidRange(_)) => Err(Errno::EINVAL),
            Err(VmemUnmapError::UnmapError(e)) => match e {
                DeallocationError::Unaligned => Err(Errno::EINVAL),
                // It is not an error if the indicated range does not contain any mapped pages.
                DeallocationError::AlreadyUnallocated => Ok(()),
                _ => unimplemented!(),
            },
            Ok(()) => Ok(()),
        }
    }

    /// Handle syscall `mprotect`.
    pub fn sys_mprotect(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        prot: ProtFlags,
    ) -> Result<(), Errno> {
        if addr.as_usize() & !PAGE_MASK != 0 {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Ok(());
        }

        let addr = addr.to_platform_ptr::<Platform>();
        match prot {
            ProtFlags::PROT_READ_EXEC => unsafe { self.make_pages_executable(addr, len) },
            ProtFlags::PROT_READ_WRITE => unsafe { self.make_pages_writable(addr, len) },
            ProtFlags::PROT_READ => unsafe { self.make_pages_readable(addr, len) },
            ProtFlags::PROT_NONE => unsafe { self.make_pages_inaccessible(addr, len) },
            ProtFlags::PROT_READ_WRITE_EXEC => unsafe { self.make_pages_rwx(addr, len) },
            _ => {
                litebox_util_log::debug!(prot:? = prot; "unsupported mprotect protection");
                Err(VmemProtectError::UnsupportedProtection)
            }
        }
        .map_err(Errno::from)
    }

    /// Handle syscall `mremap`.
    pub fn sys_mremap(
        &self,
        old_addr: UserPtrMut<u8>,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
        _new_addr: usize,
    ) -> Result<UserPtrMut<u8>, Errno> {
        if flags.intersects(
            (MRemapFlags::MREMAP_FIXED
                | MRemapFlags::MREMAP_MAYMOVE
                | MRemapFlags::MREMAP_DONTUNMAP)
                .complement(),
        ) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(MRemapFlags::MREMAP_FIXED) && !flags.contains(MRemapFlags::MREMAP_MAYMOVE)
        {
            return Err(Errno::EINVAL);
        }
        /*
         * MREMAP_DONTUNMAP is always a move and it does not allow resizing
         * in the process.
         */
        if flags.contains(MRemapFlags::MREMAP_DONTUNMAP)
            && (!flags.contains(MRemapFlags::MREMAP_MAYMOVE) || old_size != new_size)
        {
            return Err(Errno::EINVAL);
        }
        if old_addr.as_usize() & !PAGE_MASK != 0 {
            return Err(Errno::EINVAL);
        }

        let old_size = old_size
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        let new_size = new_size
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        if new_size == 0 {
            return Err(Errno::EINVAL);
        }

        if flags.intersects(MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_DONTUNMAP) {
            #[cfg(debug_assertions)]
            todo!("Unsupported flags {:?}", flags);
            #[cfg(not(debug_assertions))]
            return Err(Errno::EINVAL);
        }

        unsafe {
            self.remap_pages(
                old_addr.to_platform_ptr::<Platform>(),
                old_size,
                new_size,
                flags.contains(MRemapFlags::MREMAP_MAYMOVE),
            )
        }
        .map(UserPtrMut::from_platform_ptr::<Platform>)
        .map_err(Errno::from)
    }

    /// Handle syscall `madvise`.
    pub fn sys_madvise(
        &self,
        addr: UserPtrMut<u8>,
        len: usize,
        advice: crate::MadviseBehavior,
    ) -> Result<(), Errno> {
        if addr.as_usize() & !PAGE_MASK != 0 {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Ok(());
        }
        let aligned_len = len
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Errno::EINVAL)?;
        let Some(_end) = addr.as_usize().checked_add(aligned_len) else {
            return Err(Errno::EINVAL);
        };

        let addr = addr.to_platform_ptr::<Platform>();
        match advice {
            crate::MadviseBehavior::Normal
            | crate::MadviseBehavior::DontFork
            | crate::MadviseBehavior::DoFork => {
                // No-op for now, as we don't support fork yet.
                Ok(())
            }
            crate::MadviseBehavior::DontNeed => {
                // After a successful MADV_DONTNEED operation, the semantics of memory access in the specified region are changed:
                // subsequent accesses of pages in the range will succeed, but will result in either repopulating the memory contents
                // from the up-to-date contents of the underlying mapped file (for shared file mappings, shared anonymous mappings,
                // and shmem-based techniques such as System V shared memory segments) or zero-fill-on-demand pages for anonymous private mappings.
                //
                // Note we do not support shared memory yet, so this is just to discard the pages without removing the mapping.
                unsafe { self.reset_pages(addr, aligned_len, false) }.map_err(Errno::from)
            }
            crate::MadviseBehavior::Free => {
                unsafe { self.reset_pages(addr, aligned_len, true) }.map_err(Errno::from)
            }
            _ => unimplemented!("Unsupported madvise behavior {:?}", advice),
        }
    }
}
