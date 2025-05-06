//! Memory management related functionality

pub mod linux;

#[cfg(test)]
mod tests;

use core::ops::Range;

use alloc::vec::Vec;
use linux::{
    MappingError, PageFaultError, PageRange, VmFlags, Vmem, VmemPageFaultHandler, VmemProtectError,
    VmemUnmapError,
};

use crate::{
    LiteBox,
    platform::{PageManagementProvider, RawConstPointer, page_mgmt::MemoryRegionPermissions},
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
    /// `suggested_addr` is the hint address where to create the pages. Provide `0` to let the kernel
    /// choose an available memory region.
    ///
    /// Set `fixed_addr` to `true` to force the mapping to be created at the given address, resulting in any
    /// existing overlapping mappings being removed.
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
        suggested_addr: usize,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let suggested_range =
            PageRange::new(suggested_addr, suggested_addr + len).ok_or(MappingError::UnAligned)?;
        let mut vmem = self.vmem.write();
        unsafe {
            vmem.create_pages(
                suggested_range,
                fixed_addr,
                false,
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
    /// `suggested_addr` is the hint address where to create the pages. Provide `0` to let the kernel
    /// choose an available memory region.
    ///
    /// Set `fixed_addr` to `true` to force the mapping to be created at the given address, resulting in any
    /// existing overlapping mappings being removed.
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
        suggested_addr: usize,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let flags = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let suggested_range =
            PageRange::new(suggested_addr, suggested_addr + len).ok_or(MappingError::UnAligned)?;
        let mut vmem = self.vmem.write();
        unsafe { vmem.create_pages(suggested_range, fixed_addr, false, flags, flags, op) }
    }

    /// Create read-only pages.
    ///
    /// `suggested_addr` is the hint address where to create the pages. Provide `0` to let the kernel
    /// choose an available memory region.
    ///
    /// Set `fixed_addr` to `true` to force the mapping to be created at the given address, resulting in any
    /// existing overlapping mappings being removed.
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
        suggested_addr: usize,
        len: usize,
        fixed_addr: bool,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let mut vmem = self.vmem.write();
        let suggested_range =
            PageRange::new(suggested_addr, suggested_addr + len).ok_or(MappingError::UnAligned)?;
        unsafe {
            vmem.create_pages(
                suggested_range,
                fixed_addr,
                false,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the data)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE
                MemoryRegionPermissions::READ,
                op,
            )
        }
    }

    /// Create stack pages.
    ///
    /// `suggested_addr` is the hint address where to create the pages. Provide `0` to let the kernel
    /// choose an available memory region.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_stack_pages(
        &self,
        suggested_addr: usize,
        len: usize,
        fixed_addr: bool,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let flags = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let mut vmem = self.vmem.write();
        let suggested_range =
            PageRange::new(suggested_addr, suggested_addr + len).ok_or(MappingError::UnAligned)?;
        unsafe { vmem.create_pages(suggested_range, fixed_addr, true, flags, flags, |_| Ok(0)) }
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

    /// Returns all mappings in a vector.
    pub fn mappings(&self) -> Vec<(Range<usize>, VmFlags)> {
        let mut vmem = self.vmem.read();
        vmem.iter()
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
            unsafe { vmem.insert_mapping(range, vma) };
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
