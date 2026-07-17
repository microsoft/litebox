// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::page_mgmt::MemoryRegionPermissions;
use thiserror::Error;

/// A provider to map and unmap physical pages with virtually contiguous addresses.
///
/// `ALIGN`: The page frame size.
///
/// This provider exists to service [`crate::physical_pointers::PhysMutPtr`] and
/// [`crate::physical_pointers::PhysConstPtr`]. It can benefit other modules which need
/// Linux kernel's `vmap()` and `vunmap()` functionalities (e.g., HVCI/HEKI, drivers).
///
/// # Safety
///
/// Implementors must uphold each unsafe method's contract and keep [`Self::MapInfo`] tied to the
/// mapping it identifies.
pub unsafe trait VmapManager<const ALIGN: usize> {
    /// Implementors use this to carry the virtual mapping and any platform-specific bookkeeping
    /// needed for unmapping.
    type MapInfo: PhysPageMapInfo;

    /// Map the given `PhysPageAddrArray` into virtually contiguous addresses with the given
    /// [`PhysPageMapPermissions`] while returning [`Self::MapInfo`].
    ///
    /// This function is analogous to Linux kernel's `vmap()`.
    ///
    /// # Safety
    ///
    /// The returned pointer is a raw address; creating or holding it does not access memory or
    /// create a Rust reference. Any later use of that pointer must satisfy the platform's access
    /// requirements for the mapped physical pages. Even when access is logically exclusive, callers
    /// must treat the mapped memory like DMA/shared physical memory rather than ordinary Rust-owned
    /// RAM. Implementors must not return a VA that aliases LiteBox-owned memory; the returned
    /// mapping must live in a platform-defined foreign-memory VA range.
    unsafe fn vmap(
        &self,
        _pages: &PhysPageAddrArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }

    /// Map pages while bypassing platform-defined ordinary access checks. Ordinary [`Self::vmap`]
    /// may delegate here after performing those checks. The default is deny.
    ///
    /// # Safety
    ///
    /// In addition to [`Self::vmap`]'s raw-mapping requirements, the caller must independently
    /// authorize bypassing the omitted platform checks.
    unsafe fn vmap_privileged(
        &self,
        _pages: &PhysPageAddrArray<ALIGN>,
        _perms: PhysPageMapPermissions,
    ) -> Result<Self::MapInfo, PhysPointerError> {
        Err(PhysPointerError::UnsupportedOperation)
    }

    /// Unmap the previously mapped virtually contiguous addresses ([`Self::MapInfo`]).
    ///
    /// This function is analogous to Linux kernel's `vunmap()`.
    ///
    /// On failure, the unchanged `vmap_info` is returned alongside the error so the caller can
    /// retry or otherwise preserve the mapping state. Dropping returned map info is not guaranteed
    /// to release platform resources; each implementation owns the retention policy for resources
    /// that cannot be safely reclaimed after a failed unmap.
    ///
    /// # Safety
    ///
    /// The caller must ensure there are no outstanding raw-pointer uses or Rust references derived
    /// from `PhysPageMapInfo::base()`. After a successful call, the virtual mapping is invalid and
    /// any platform resources tied to the mapping lifetime have been released or otherwise handled
    /// by the implementation.
    unsafe fn vunmap(
        &self,
        vmap_info: Self::MapInfo,
    ) -> Result<(), (PhysPointerError, Self::MapInfo)> {
        Err((PhysPointerError::UnsupportedOperation, vmap_info))
    }

    /// Validate that the given physical pages are not owned by LiteBox.
    ///
    /// Platform is expected to track which physical memory addresses are owned by LiteBox (e.g., VTL1 memory addresses).
    ///
    /// Returns `Ok(())` if the physical pages are not owned by LiteBox. Otherwise, returns `Err(PhysPointerError)`.
    ///
    /// # Invariant
    ///
    /// The implementor must ensure that, whenever this function returns `Ok(())`, none of the
    /// given physical pages may name memory owned by LiteBox/Rust (heap, stack, ...). Callers rely
    /// on a successful return to treat the pages as foreign memory and to map them only through
    /// platform-defined foreign-memory VA ranges, never through LiteBox-owned VA ranges.
    fn validate_unowned(&self, pages: &PhysPageAddrArray<ALIGN>) -> Result<(), PhysPointerError>;

    /// Protect the given physical pages according to `perms`:
    /// - Read protection: prevent others from writing to the pages.
    /// - Read/write protection: prevent others from reading or writing to the pages.
    /// - No protection: allow others to read and write the pages.
    ///
    /// This function can be implemented using EPT/NPT, TZASC, PMP, or some other hardware mechanisms.
    ///
    /// Returns `Ok(())` if it successfully protects the pages. If it fails, returns
    /// `Err(PhysPointerError)`.
    ///
    /// # Safety
    ///
    /// This function relies on hypercalls or other privileged hardware features and assumes those features
    /// are safe to use.
    /// Callers should restore ordinary access when protection is no longer needed.
    unsafe fn protect(
        &self,
        pages: &PhysPageAddrArray<ALIGN>,
        perms: PhysPageMapPermissions,
    ) -> Result<(), PhysPointerError>;
}

/// A type-level handle to a platform-global [`VmapManager`].
///
/// `PhysMutPtr` and `PhysConstPtr` carry their provider as a type parameter
/// (`PhantomData<P>`), so they cannot hold a live `&VmapManager`. This trait
/// is the minimum surface that lets such a `PhantomData`-only carrier reach
/// the live manager: each platform implements this on a small unit struct
/// (e.g., `Vmap`) and points `manager()` at its global
/// platform singleton.
pub trait GlobalVmapManager<const ALIGN: usize>: 'static {
    /// The concrete `VmapManager` this marker resolves to.
    type Manager: VmapManager<ALIGN> + 'static;

    /// Return the global manager instance for this platform.
    fn manager() -> &'static Self::Manager;
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

/// Mapping information returned by `vmap()`.
///
/// Implementors use this value to track the virtual mapping and any platform-specific resources
/// tied to it. Callers must pass it back to the same platform's `vunmap()` to explicitly unmap;
/// drop behavior is implementation-specific.
pub trait PhysPageMapInfo {
    /// Virtual address of the mapped region which is page aligned.
    fn base(&self) -> *mut u8;
    /// The size of the mapped region in bytes.
    fn size(&self) -> usize;
}

/// A no-op [`PhysPageMapInfo`] for platforms that do not support `vmap()`/`vunmap()`.
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
}
