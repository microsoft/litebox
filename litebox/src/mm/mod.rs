//! Memory management related functionality

pub mod allocator;
pub mod linux;

#[cfg(test)]
mod tests;

use core::ops::Range;

use alloc::vec::Vec;
use linux::{
    CreatePagesFlags, MappingError, PageFaultError, PageRange, VmFlags, Vmem, VmemPageFaultHandler,
    VmemProtectError, VmemUnmapError,
};

use crate::{
    LiteBox,
    mm::linux::{NonZeroAddress, NonZeroPageSize},
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{MemoryRegionPermissions, RemapError},
    },
    sync::{RawSyncPrimitivesProvider, RwLock},
};

/// A page manager to support `mmap`, `munmap`, and etc.
pub struct PageManager<Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    vmem: RwLock<Platform, Vmem<Platform, ALIGN>>,
}

impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    /// Create a new `PageManager` instance.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let vmem = litebox
            .sync()
            .new_rwlock(linux::Vmem::new(litebox.x.platform));
        Self { vmem }
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
        let mut vmem = self.vmem.write();
        unsafe {
            vmem.create_pages(
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
        let mut vmem = self.vmem.write();
        unsafe { vmem.create_pages(suggested_address, length, flags, perms, perms, op) }
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
        let mut vmem = self.vmem.write();
        unsafe {
            vmem.create_pages(
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
        let mut vmem = self.vmem.write();
        unsafe {
            vmem.create_pages(
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
        let mut vmem = self.vmem.write();
        let flags = CreatePagesFlags::IS_STACK | flags;
        unsafe { vmem.create_pages(suggested_address, length, flags, perms, perms, |_| Ok(0)) }
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
    /// # Safety
    ///
    /// If shrinking the program break, the caller must ensure that the released memory region is no longer used.
    pub unsafe fn brk(&self, brk: usize) -> Result<usize, MappingError> {
        let mut vmem = self.vmem.write();
        if vmem.brk == 0 {
            // If the old brk is not set yet, we set it to the new brk
            // Note the first call should be made by the loader to set the initial brk
            // to the end of the data segment.
            vmem.brk = brk;
            return Ok(brk);
        }
        if brk == 0 {
            // Calling `brk` with 0 can be used to find the current location of the program break.
            return Ok(vmem.brk);
        }

        let old_brk = vmem.brk.next_multiple_of(linux::PAGE_SIZE);
        let new_brk = brk.next_multiple_of(linux::PAGE_SIZE);
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
                    perms,
                    |_| Ok(0),
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
                linux::NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
            )
        } {
            Ok(()) => Ok(old_addr),
            Err(linux::VmemResizeError::RangeOccupied(_)) => {
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
                    Err(linux::VmemMoveError::OutOfMemory) => Err(RemapError::OutOfMemory),
                    Err(linux::VmemMoveError::UnAligned) => Err(RemapError::Unaligned),
                    Err(linux::VmemMoveError::RemapError(err)) => Err(err),
                }
            }
            Err(linux::VmemResizeError::NotExist(_)) => Err(RemapError::AlreadyUnallocated),
            Err(linux::VmemResizeError::InvalidAddr { .. }) => Err(RemapError::AlreadyAllocated),
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

    /// Internal common function used by `make_pages_*` to change page permissions.
    fn change_page_permissions(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len)
            .ok_or(VmemProtectError::InvalidRange(start..start + len))?;
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
}

/// If Backend also implements [`VmemPageFaultHandler`], it can handle page faults.
impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
    Platform: VmemPageFaultHandler,
{
    /// Handle page fault at the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    pub unsafe fn handle_page_fault(
        &mut self,
        fault_addr: usize,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let fault_addr = fault_addr & !(ALIGN - 1);
        if !(Vmem::<Platform, ALIGN>::TASK_ADDR_MIN..Vmem::<Platform, ALIGN>::TASK_ADDR_MAX)
            .contains(&fault_addr)
        {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        let mut vmem = self.vmem.write();
        // Find the range closest to the fault address
        let (start, vma) = {
            let (r, vma) = vmem
                .overlapping(fault_addr..Vmem::<Platform, ALIGN>::TASK_ADDR_MAX)
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
                .overlapping(Vmem::<Platform, ALIGN>::TASK_ADDR_MIN..fault_addr)
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
            unsafe { vmem.insert_mapping(range, vma, false) };
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
