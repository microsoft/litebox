// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Physical-page mapping interfaces shared by LiteBox platforms and shims.

use litebox::platform::page_mgmt::MemoryRegionPermissions;
use thiserror::Error;

/// A provider to map and unmap physical pages with virtually contiguous addresses.
///
/// `ALIGN`: The page frame size.
///
/// # Safety
///
/// Implementors must uphold each unsafe method's contract and keep [`Self::MapInfo`] tied to the
/// mapping it identifies.
pub unsafe trait VmapManager<const ALIGN: usize> {
    /// Platform-specific virtual mapping information.
    type MapInfo: PhysPageMapInfo;

    /// Map physical pages into virtually contiguous addresses.
    ///
    /// # Safety
    ///
    /// The returned raw address must not alias LiteBox-owned memory. Any later access must obey
    /// the platform's requirements for shared or foreign physical memory.
    unsafe fn vmap(
        &self,
        _pages: &PhysPageAddrArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }

    /// Map pages while bypassing platform-defined ordinary access checks.
    ///
    /// # Safety
    ///
    /// The caller must independently authorize bypassing the omitted platform checks.
    unsafe fn vmap_privileged(
        &self,
        _pages: &PhysPageAddrArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }

    /// Unmap a mapping returned by this manager.
    ///
    /// # Safety
    ///
    /// The caller must ensure no outstanding accesses remain. After success, the mapping is
    /// invalid and its platform resources have been released or otherwise handled.
    unsafe fn vunmap(
        &self,
        vmap_info: Self::MapInfo,
    ) -> Result<(), (PhysPointerError, Self::MapInfo)> {
        Err((PhysPointerError::UnsupportedOperation, vmap_info))
    }

    /// Validate that the physical pages are not owned by LiteBox.
    fn validate_unowned(&self, pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError>;

    /// Protect physical pages against access by another privilege level.
    ///
    /// # Safety
    ///
    /// This operation relies on privileged platform mechanisms. Callers should restore ordinary
    /// access when protection is no longer needed.
    unsafe fn protect(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError>;
}

/// A non-zero, `ALIGN`-aligned physical page address.
#[derive(Clone, Copy)]
pub struct PhysPageAddr<const ALIGN: usize>(usize);

impl<const ALIGN: usize> PhysPageAddr<ALIGN> {
    /// Create a physical page address if it is non-zero and aligned.
    pub fn new(address: usize) -> Option<Self> {
        if address == 0 || !address.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self(address))
    }

    /// Return the address as a `usize`.
    #[inline]
    pub fn as_usize(self) -> usize {
        self.0
    }
}

/// An array of virtually contiguous physical page addresses.
pub type PhysPageAddrArray<const ALIGN: usize> = [PhysPageAddr<ALIGN>];

/// Mapping information returned by [`VmapManager::vmap`].
pub trait PhysPageMapInfo {
    /// Virtual base address of the mapped region.
    fn base(&self) -> *mut u8;
    /// Size of the mapped region in bytes.
    fn size(&self) -> usize;
}

/// A no-op map-info implementation for platforms without vmap support.
#[derive(Debug)]
pub struct NoopPhysPageMapInfo {
    base: *mut u8,
    size: usize,
}

impl NoopPhysPageMapInfo {
    pub fn new(base: *mut u8, size: usize) -> Self {
        Self { base, size }
    }
}

impl PhysPageMapInfo for NoopPhysPageMapInfo {
    fn base(&self) -> *mut u8 {
        self.base
    }

    fn size(&self) -> usize {
        self.size
    }
}

bitflags::bitflags! {
    /// Permissions supported for physical-page mappings.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PhysPageMapPermissions: u8 {
        /// Readable.
        const READ = 1 << 0;
        /// Writable.
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

/// Errors from physical-pointer access and physical-page mapping.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum PhysPointerError {
    #[error("Physical address {0:#x} is invalid to access")]
    InvalidPhysicalAddress(usize),
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
    #[error("Overflow occurred during calculation")]
    Overflow,
    #[error("The operation is unsupported on this platform")]
    UnsupportedOperation,
    #[error("Unsupported permissions: {0:#x}")]
    UnsupportedPermissions(u8),
    #[error("Memory copy failed")]
    CopyFailed,
    #[error("Duplicate physical page address {0:#x} in the input array")]
    DuplicatePhysicalAddress(usize),
    #[error("Virtual address space exhausted in vmap region")]
    VaSpaceExhausted,
    #[error("Page-table frame allocation failed (out of memory)")]
    FrameAllocationFailed,
    #[error("Rust object allocation failed (out of memory)")]
    AllocError,
}
