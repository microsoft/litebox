// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::page_mgmt::MemoryRegionPermissions;
use thiserror::Error;

/// A provider to map and unmap physical pages with virtually contiguous addresses.
///
/// `ALIGN`: The page frame size.
///
/// This provider exists to service `litebox_shim_optee::ptr::PhysMutPtr` and
/// `litebox_shim_optee::ptr::PhysConstPtr`. It can benefit other modules which need
/// Linux kernel's `vmap()` and `vunmap()` functionalities (e.g., HVCI/HEKI, drivers).
pub trait VmapManager<const ALIGN: usize> {
    /// Map the given `PhysPageAddrArray` into virtually contiguous addresses with the given
    /// [`PhysPageMapPermissions`] while returning [`PhysPageMapInfo`].
    ///
    /// This function is analogous to Linux kernel's `vmap()`.
    ///
    /// # Safety
    ///
    /// The caller should ensure that `pages` are not in active use by other entities
    /// (especially, there should be no read/write or write/write conflicts).
    /// Unfortunately, LiteBox itself cannot fully guarantee this and it needs some helps
    /// from the caller, hypervisor, or hardware.
    /// Multiple LiteBox threads might concurrently call this function with overlapping
    /// physical pages, so the implementation should safely handle such cases.
    unsafe fn vmap(
        &self,
        _pages: &PhysPageAddrArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<PhysPageMapInfo<ALIGN>, PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }

    /// Unmap the previously mapped virtually contiguous addresses ([`PhysPageMapInfo`]).
    ///
    /// This function is analogous to Linux kernel's `vunmap()`.
    ///
    /// # Safety
    ///
    /// The caller should ensure that the virtual addresses in `vmap_info` are not in active
    /// use by other entities.
    unsafe fn vunmap(&self, _vmap_info: PhysPageMapInfo<ALIGN>) -> Result<(), PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }

    /// Validate that the given physical pages are not owned by LiteBox.
    ///
    /// Platform is expected to track which physical memory addresses are owned by LiteBox (e.g., VTL1 memory addresses).
    ///
    /// Returns `Ok(())` if the physical pages are not owned by LiteBox. Otherwise, returns `Err(PhysPointerError)`.
    fn validate_unowned(&self, _pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError> {
        Ok(())
    }

    /// Protect the given physical pages to ensure concurrent read or exclusive write access:
    /// - Read protection: prevent others from writing to the pages.
    /// - Read/write protection: prevent others from reading or writing to the pages.
    /// - No protection: allow others to read and write the pages.
    ///
    /// This function can be implemented using EPT/NPT, TZASC, PMP, or some other hardware mechanisms.
    /// If the platform does not support such protection, this function returns `Ok(())` without any action.
    ///
    /// Returns `Ok(())` if it successfully protects the pages. If it fails, returns
    /// `Err(PhysPointerError)`.
    ///
    /// # Safety
    ///
    /// This function relies on hypercalls or other privileged hardware features and assumes those features
    /// are safe to use.
    /// The caller should unprotect the pages when they are no longer needed to access them.
    unsafe fn protect(
        &self,
        _pages: &PhysPageAddrArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError> {
        Ok(())
    }
}

/// Data structure representing a physical address with page alignment.
///
/// Currently, this is an alias to `crate::mm::linux::NonZeroAddress`. This might change if
/// we selectively conduct sanity checks based on whether an address is virtual or physical
/// (e.g., whether a virtual address is canonical, whether a physical address is tagged with
/// a valid key ID, etc.).
pub type PhysPageAddr<const ALIGN: usize> = litebox::mm::linux::NonZeroAddress<ALIGN>;

/// Data structure for an array of physical page addresses which are virtually contiguous.
pub type PhysPageAddrArray<const ALIGN: usize> = [PhysPageAddr<ALIGN>];

/// Data structure to maintain the mapping information returned by `vmap()`.
#[derive(Clone)]
pub struct PhysPageMapInfo<const ALIGN: usize> {
    /// Virtual address of the mapped region which is page aligned.
    pub base: *mut u8,
    /// The size of the mapped region in bytes.
    pub size: usize,
}

bitflags::bitflags! {
    /// Physical page map permissions which is a restricted version of
    /// [`litebox::platform::page_mgmt::MemoryRegionPermissions`].
    ///
    /// This module only supports READ and WRITE permissions. Both EXECUTE and SHARED
    /// permissions are explicitly prohibited.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PhysPageMapPermissions: u8 {
        /// Readable
        const READ = 1 << 0;
        /// Writable
        const WRITE = 1 << 1;
    }
}

impl From<MemoryRegionPermissions> for PhysPageMapPermissions {
    fn from(perms: MemoryRegionPermissions) -> Self {
        let mut phys_perms = PhysPageMapPermissions::empty();
        if perms.contains(MemoryRegionPermissions::READ) {
            phys_perms |= PhysPageMapPermissions::READ;
        }
        if perms.contains(MemoryRegionPermissions::WRITE) {
            phys_perms |= PhysPageMapPermissions::WRITE;
        }
        phys_perms
    }
}

impl From<PhysPageMapPermissions> for MemoryRegionPermissions {
    fn from(perms: PhysPageMapPermissions) -> Self {
        let mut mem_perms = MemoryRegionPermissions::empty();
        if perms.contains(PhysPageMapPermissions::READ) {
            mem_perms |= MemoryRegionPermissions::READ;
        }
        if perms.contains(PhysPageMapPermissions::WRITE) {
            mem_perms |= MemoryRegionPermissions::WRITE;
        }
        mem_perms
    }
}

/// Possible errors for physical pointer access with `VmapManager`
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum PhysPointerError {
    #[error("Physical address {0:#x} is invalid to access")]
    InvalidPhysicalAddress(usize),
    #[error("Physical address {0:#x} is not aligned to {1} bytes")]
    UnalignedPhysicalAddress(usize, usize),
    #[error("Offset {0:#x} is not aligned to {1} bytes")]
    UnalignedOffset(usize, usize),
    #[error("Base offset {0:#x} is greater than or equal to alignment ({1} bytes)")]
    InvalidBaseOffset(usize, usize),
    #[error(
        "The total size of the given pages ({0} bytes) is insufficient for the requested type ({1} bytes)"
    )]
    InsufficientPhysicalPages(usize, usize),
    #[error("Index {0} is out of bounds (count: {1})")]
    IndexOutOfBounds(usize, usize),
    #[error("Physical address {0:#x} is already mapped")]
    AlreadyMapped(usize),
    #[error("Physical address {0:#x} is unmapped")]
    Unmapped(usize),
    #[error("No mapping information available")]
    NoMappingInfo,
    #[error("Overflow occurred during calculation")]
    Overflow,
    #[error("Non-contiguous physical pages in the array")]
    NonContiguousPages,
    #[error("The operation is unsupported on this platform")]
    UnsupportedOperation,
    #[error("Unsupported permissions: {0:#x}")]
    UnsupportedPermissions(u8),
    #[error("Memory copy failed")]
    CopyFailed,
}
