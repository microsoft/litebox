// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::platform::page_mgmt::MemoryRegionPermissions;
use thiserror::Error;

/// A provider to map and unmap physical pages with virtually contiguous addresses.
///
/// `ALIGN`: The page frame size.
///
/// This provider is written to implement `litebox_shim_optee::ptr::PhysMutPtr` and
/// `litebox_shim_optee::ptr::PhysConstPtr`. It can benefit other modules which need
/// Linux kernel's `vmap()` and `vunmap()` functionalities (e.g., HVCI/HEKI, drivers).
pub trait VmapProvider<const ALIGN: usize> {
    /// Data structure for an array of physical page addresses which are virtually contiguous.
    type PhysPageAddrArray;

    /// Data structure to maintain the mapping information returned by `vmap()`.
    type PhysPageMapInfo;

    /// Map the given `PhysPageAddrArray` into virtually contiguous addresses with the given
    /// [`PhysPageMapPermissions`] while returning [`PhysPageMapInfo`]. This function
    /// expects that it can access and update the page table using `&self`.
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
        pages: Self::PhysPageAddrArray,
        perms: PhysPageMapPermissions,
    ) -> Result<Self::PhysPageMapInfo, PhysPointerError>;

    /// Unmap the previously mapped virtually contiguous addresses ([`PhysPageMapInfo`]).
    /// Use `&self` to access and update the page table.
    ///
    /// This function is analogous to Linux kernel's `vunmap()`.
    ///
    /// # Safety
    ///
    /// The caller should ensure that the virtual addresses in `vmap_info` are not in active
    /// use by other entities.
    unsafe fn vunmap(&self, vmap_info: Self::PhysPageMapInfo) -> Result<(), PhysPointerError>;

    /// Validate that the given physical pages do not belong to LiteBox-owned memory.
    /// Use `&self` to get the memory layout of the platform (i.e., the physical memory
    /// range assigned to LiteBox).
    ///
    /// This function is a no-op if there is no other world or VM sharing the physical memory.
    ///
    /// Returns `Ok(())` if valid. If the pages are not valid, returns `Err(PhysPointerError)`.
    fn validate(&self, pages: Self::PhysPageAddrArray) -> Result<(), PhysPointerError>;

    /// Protect the given physical pages to ensure concurrent read or exclusive write access:
    /// - Read protection: prevent others from writing to the pages.
    /// - Read/write protection: prevent others from reading or writing to the pages.
    /// - No protection: allow others to read and write the pages.
    ///
    /// This function can be implemented using EPT/NPT, TZASC, PMP, or some other hardware mechanisms.
    /// It is a no-op if there is no other world or VM sharing the physical memory.
    ///
    /// Returns `Ok(())` if it successfully protects the pages. If it fails, returns
    /// `Err(PhysPointerError)`.
    ///
    /// # Safety
    ///
    /// Since this function is expected to use hypercalls or other privileged hardware features,
    /// the caller must ensure that it is safe to perform such operations at the time of the call.
    /// Also, the caller should unprotect the pages when they are no longer needed to be protected.
    unsafe fn protect(
        &self,
        pages: Self::PhysPageAddrArray,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError>;
}

/// Data structure representing a physical address with page alignment.
///
/// Currently, this is an alias to `crate::mm::linux::NonZeroAddress`. This might change if
/// we selectively conduct sanity checks based on whether an address is virtual or physical
/// (e.g., whether a virtual address is canonical, whether a physical address is tagged with
/// a valid key ID, etc.).
pub type PhysPageAddr<const ALIGN: usize> = crate::mm::linux::NonZeroAddress<ALIGN>;

/// Data structure to maintain the mapping information returned by `vmap()`.
///
/// `base` is the virtual address of the mapped region which is page aligned.
/// `size` is the size of the mapped region in bytes.
#[derive(Clone)]
pub struct PhysPageMapInfo<const ALIGN: usize> {
    pub base: *mut u8,
    pub size: usize,
}

bitflags::bitflags! {
    /// Physical page map permissions which is a restricted version of
    /// [`litebox::platform::page_mgmt::MemoryRegionPermissions`].
    ///
    /// This module only supports READ and WRITE permissions. Both EXECUTE and SHARED
    /// permissions are explicitly prohibited.
    #[non_exhaustive]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PhysPageMapPermissions: u8 {
        /// Readable
        const READ = 1 << 0;
        /// Writable
        const WRITE = 1 << 1;
        const _ = !0;
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

/// Possible errors for physical pointer access with `VmapProvider`
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
}
