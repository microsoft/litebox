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
    /// Data structure for an array of physical pages which are virtually contiguous.
    type PhysPageArray;

    /// Data structure to maintain the mapping information returned by `vmap()`.
    type PhysPageMapInfo;

    /// Map the given [`PhysPageArray`] into virtually contiguous addresses with the given
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
    /// Multiple LiteBox threads might concurrently call this function (and `vunmap()`) with
    /// overlapping physical pages, so the implementation should safely handle such cases.
    unsafe fn vmap(
        &self,
        pages: Self::PhysPageArray,
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
    /// use by other entities. Like `vmap()`, LiteBox itself cannot fully guarantee this and
    /// it needs some helps from other parties.
    /// Multiple LiteBox threads might concurrently call this function (and `vmap()`) with
    /// overlapping physical pages, so the implementation should safely handle such cases.
    unsafe fn vunmap(&self, vmap_info: Self::PhysPageMapInfo) -> Result<(), PhysPointerError>;

    /// Validate that the given physical address (with type) does not belong to LiteBox-managed
    /// memory. Use `&self` to get the memory layout of the platform (i.e., the physical memory
    /// range assigned to LiteBox).
    ///
    /// This function does not use `*const T` or `*mut T` because it deals with a physical address
    /// which should not be dereferenced directly.
    ///
    /// Returns `Ok(pa)` if valid. If the address is not valid, returns `Err(PhysPointerError)`.
    fn validate<T>(&self, pa: usize) -> Result<usize, PhysPointerError>;
}

/// Data structure for an array of physical pages. These physical pages should be virtually contiguous.
#[derive(Clone)]
pub struct PhysPageArray<const ALIGN: usize> {
    inner: alloc::boxed::Box<[usize]>,
}

impl<const ALIGN: usize> PhysPageArray<ALIGN> {
    /// Create a new `PhysPageArray` from the given slice of physical addresses.
    ///
    /// All page addresses should be aligned to `ALIGN`.
    pub fn try_from_slice(addrs: &[usize]) -> Result<Self, PhysPointerError> {
        for addr in addrs {
            if !addr.is_multiple_of(ALIGN) {
                return Err(PhysPointerError::UnalignedPhysicalAddress(*addr, ALIGN));
            }
        }
        // TODO: Remove this check once our platform implementations support virtually
        // contiguous non-contiguous physical page mapping.
        Self::check_contiguity(addrs)?;
        Ok(Self {
            inner: alloc::boxed::Box::from(addrs),
        })
    }

    /// Check if the array is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return the number of physical pages in the array.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return the first physical address in the array if exists.
    pub fn first(&self) -> Option<usize> {
        self.inner.first().copied()
    }

    /// Checks whether the given physical addresses are contiguous with respect to ALIGN.
    ///
    /// Note: This is a temporary check to let this module work with our platform implementations
    /// which map physical pages with a fixed offset (`MemoryProvider::GVA_OFFSET`) such that
    /// do not support non-contiguous physical page mapping with contiguous virtual addresses.
    fn check_contiguity(addrs: &[usize]) -> Result<(), PhysPointerError> {
        for window in addrs.windows(2) {
            let first = window[0];
            let second = window[1];
            if second != first.checked_add(ALIGN).ok_or(PhysPointerError::Overflow)? {
                return Err(PhysPointerError::NonContiguousPages);
            }
        }
        Ok(())
    }
}

impl<const ALIGN: usize> core::iter::Iterator for PhysPageArray<ALIGN> {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        if self.inner.is_empty() {
            None
        } else {
            Some(self.inner[0])
        }
    }
}

impl<const ALIGN: usize> core::ops::Deref for PhysPageArray<ALIGN> {
    type Target = [usize];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

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
}
