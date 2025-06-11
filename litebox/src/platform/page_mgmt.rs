//! Page-management related types and traits

use super::RawPointerProvider;
use core::ops::Range;
use thiserror::Error;

bitflags::bitflags! {
    /// Permissions for a memory region
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MemoryRegionPermissions: u8 {
        /// Readable
        const READ = 1 << 0;
        /// Writable
        const WRITE = 1 << 1;
        /// Executable
        const EXEC = 1 << 2;
        /// Sharable between processes
        const SHARED = 1 << 3;
    }
}

/// A provider for managing memory pages
///
/// NOTE: Due to insufficient support for associated constants in current Stable Rust, we have
/// `ALIGN` as a parameter. In the future, this may be changed to an associated constant, since each
/// platform has only one canonical alignment.
pub trait PageManagementProvider<const ALIGN: usize>: RawPointerProvider {
    /// Allocate new memory pages at given `range` with `initial_permissions`.
    ///
    /// `can_grow_down` specifies if the region is allowed to grow "downward" (i.e., towards zero),
    /// upon a page fault.
    ///
    /// `populate_pages_immediately` specifies if the pages should be populated immediately or lazily.
    fn allocate_pages(
        &self,
        range: Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>;

    /// De-allocated all pages in the given `range`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that these pages are not in active use.
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError>;

    /// Remap pages from `old_range` to `new_range`.
    ///
    /// ## Returns
    ///
    /// On success it returns a pointer to the new virtual memory area.
    ///
    /// # Safety
    ///
    /// The caller must ensure that it is safe to move the `old_range` (i.e., these pages are not in
    /// active use).
    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
    ) -> Result<Self::RawMutPointer<u8>, RemapError>;

    /// Update the permissions on pages in `range` to `new_permissions`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the permissions do not conflict with any currently active usage
    /// of these pages.
    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError>;

    /// Return reserved pages that are not available for allocation.
    ///
    /// Note that the returned ranges should be `ALIGN`-aligned.
    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>>;
}

/// Possible errors for [`PageManagementProvider::allocate_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AllocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range is already allocated")]
    AlreadyAllocated,
    #[error("out of memory")]
    OutOfMemory,
}

/// Possible errors for [`PageManagementProvider::deallocate_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DeallocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
}

/// Possible errors for [`PageManagementProvider::remap_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum RemapError {
    #[error("at least one of the provided ranges was not page-aligned")]
    Unaligned,
    #[error("provided old range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("provided ranges were overlapping")]
    Overlapping,
    #[error("provided new range is already allocated")]
    AlreadyAllocated,
    #[error("out of memory")]
    OutOfMemory,
}

/// Possible errors for [`PageManagementProvider::update_permissions`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PermissionUpdateError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    Unallocated,
}
