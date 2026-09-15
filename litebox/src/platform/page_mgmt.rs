// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-management related types and traits

use crate::platform::{RawConstPointer as _, RawMutPointer as _};

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

/// The allocation state of a memory region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageState {
    /// The address range is reserved but has no committed pages.
    Reserved,
    /// The address range is reserved and committed with the specified permissions.
    Committed(MemoryRegionPermissions),
}

/// A provider for managing memory pages
///
/// NOTE: Due to insufficient support for associated constants in current Stable Rust, we have
/// `ALIGN` as a parameter. In the future, this may be changed to an associated constant, since each
/// platform has only one canonical alignment.
pub trait PageManagementProvider<const ALIGN: usize>: RawPointerProvider {
    /// The lower bound (inclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MIN: usize;
    /// The upper bound (exclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MAX: usize;

    /// Allocates a new memory region at `suggested_range` with the given `initial_state`.
    ///
    /// # Parameters
    ///
    /// - `suggested_range`: A suggested address range for the allocation.
    /// - `initial_state`: Whether the region is reserved or committed with permissions.
    /// - `can_grow_down`: If `true`, the region is allowed to grow downward (towards zero) upon
    ///   a page fault.
    /// - `populate_pages_immediately`: If `true`, the pages are populated immediately; otherwise,
    ///   they are populated lazily.
    /// - `fixed_address_behavior`: Specifies the required semantics of `suggested_range`.
    ///
    /// # Returns
    ///
    /// On success, returns a raw mutable pointer to the start of the allocated memory region.
    ///
    /// # Errors
    ///
    /// Returns an [`AllocationError`] if the allocation fails.
    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_state: PageState,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>;

    /// De-allocated all pages in the given `range`.
    ///
    /// It does not necessarily release the reservation of the underlying address space,
    /// e.g., it may only decommit the pages if the given range does not match the
    /// originally allocated range returned by [`allocate_pages`](Self::allocate_pages).
    ///
    /// # Safety
    ///
    /// The caller must ensure that these pages are not in active use.
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError>;

    /// Remap pages from `old_range` to `new_range`.
    ///
    /// `new_range` specifies the requested size and a suggested destination address.
    /// The provider may choose a different address; callers must use the returned pointer.
    ///
    /// ## Returns
    ///
    /// On success it returns a pointer to the new virtual memory area.
    ///
    /// # Safety
    ///
    /// The caller must ensure that it is safe to move the `old_range` (i.e., these pages are not in
    /// active use).
    ///
    /// The `new_range` must be at least as large as `old_range`, and must not overlap with it.
    ///
    /// Both ranges must be aligned to `ALIGN`.
    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        state: PageState,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        debug_assert!(old_range.start.is_multiple_of(ALIGN));
        debug_assert!(new_range.start.is_multiple_of(ALIGN));
        debug_assert!(old_range.len().is_multiple_of(ALIGN));
        debug_assert!(new_range.len().is_multiple_of(ALIGN));
        debug_assert!(new_range.len() >= old_range.len());
        debug_assert!(old_range.start.max(new_range.start) >= old_range.end.min(new_range.end));
        // Default implementation: allocate new pages, copy data, deallocate old pages
        let permissions = match state {
            PageState::Reserved => MemoryRegionPermissions::empty(),
            PageState::Committed(permissions) => permissions,
        };
        let temp_state = match state {
            PageState::Reserved => PageState::Reserved,
            PageState::Committed(_) => {
                PageState::Committed(permissions | MemoryRegionPermissions::WRITE)
            }
        };
        let new_ptr = self
            .allocate_pages(
                new_range.clone(),
                temp_state,
                false,
                true,
                FixedAddressBehavior::Hint,
            )
            .map_err(|e| match e {
                AllocationError::OutOfMemory => RemapError::OutOfMemory,
                AllocationError::AddressInUse | AllocationError::AddressInUseByPlatform => {
                    RemapError::AlreadyAllocated
                }
                AllocationError::Unaligned
                | AllocationError::BelowMinAddress
                | AllocationError::AboveMaxAddress
                | AllocationError::AddressPartiallyInUse => unreachable!(),
            })?;

        if let PageState::Committed(permissions) = state {
            // Copy memory from old range to new range
            if !permissions.contains(MemoryRegionPermissions::READ) {
                (unsafe {
                    self.update_permissions(
                        old_range.clone(),
                        permissions | MemoryRegionPermissions::READ,
                    )
                })
                .expect("failed to update permissions on old range for copying");
            }

            // Copy in chunks of ALIGN bytes to handle very large memory regions.
            let total_len = old_range.len();
            let mut offset = 0;
            while offset < total_len {
                let chunk_len = (total_len - offset).min(ALIGN);
                let old_ptr = <Self as RawPointerProvider>::RawConstPointer::from_usize(
                    old_range.start + offset,
                );
                new_ptr
                    .write_slice_at_offset(
                        isize::try_from(offset).unwrap(),
                        &old_ptr.to_owned_slice(chunk_len).unwrap(),
                    )
                    .unwrap();
                offset += ALIGN;
            }
        }

        if temp_state != state {
            let allocated_range = new_ptr.as_usize()..new_ptr.as_usize() + new_range.len();
            // SAFETY: These are the newly allocated committed pages, with no active users.
            (unsafe { self.update_permissions(allocated_range, permissions) })
                .expect("failed to restore permissions on new range");
        }

        (unsafe { self.deallocate_pages(old_range) }).expect("failed to deallocate old range");

        Ok(new_ptr)
    }

    /// Decommit pages while retaining ownership of the address range.
    ///
    /// # Safety
    ///
    /// The caller must own the range through this provider and ensure that the contents
    /// of these pages are no longer in use.
    ///
    /// The default implementation returns [`PageStateUpdateError::UnsupportedByPlatform`].
    ///
    /// It deliberately does not fall back to [`deallocate_pages`](Self::deallocate_pages): that
    /// would relinquish ownership of the address range. Recommit through
    /// [`allocate_pages`](Self::allocate_pages) with `Committed` and `Replace`.
    unsafe fn decommit_pages(&self, _range: Range<usize>) -> Result<(), PageStateUpdateError> {
        Err(PageStateUpdateError::UnsupportedByPlatform)
    }

    /// Update the permissions on committed pages in `range`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the permissions do not conflict with any currently active usage
    /// of these pages.
    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PageStateUpdateError>;

    /// Return reserved pages that are not available for allocation.
    ///
    /// Note that the returned ranges should be `ALIGN`-aligned.
    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>>;

    /// Attempt to allocate pages with copy-on-write semantics backed by static data.
    ///
    /// This method allows platforms that support it to create CoW mappings instead of performing
    /// expensive page-by-page memory copies. This is particularly useful when mapping pre-loaded
    /// file data that was mmap'd by the host.
    ///
    /// The default implementation returns unsupported CoW. Platforms that DO support COW should
    /// override this method to unlock better performance.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
        Err(CowAllocationError::UnsupportedByPlatform)
    }
}

/// Behavior when allocating pages at a fixed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedAddressBehavior {
    /// The address is just a hint, and the platform may choose a different
    /// address if the hint is not available.
    Hint,
    /// Allocate the pages at the specified address, replacing any existing
    /// mappings.
    Replace,
    /// Allocate the pages at the specified address, failing if any part of the
    /// range is already in use.
    NoReplace,
}

/// Possible errors for [`PageManagementProvider::allocate_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AllocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided address is below the minimum allowed address")]
    BelowMinAddress,
    #[error("provided address is above the maximum allowed address")]
    AboveMaxAddress,
    #[error("out of memory")]
    OutOfMemory,
    #[error("provided fixed address range is in use")]
    AddressInUse,
    #[error("provided fixed address range is in use by the platform")]
    AddressInUseByPlatform,
    #[error("provided fixed address range partially overlaps existing mappings")]
    AddressPartiallyInUse,
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

/// Possible errors for page commitment and permission updates.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PageStateUpdateError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    Unallocated,
    #[error("out of memory")]
    OutOfMemory,
    #[error("platform does not support page decommitment")]
    UnsupportedByPlatform,
}

impl From<AllocationError> for PageStateUpdateError {
    fn from(value: AllocationError) -> Self {
        match value {
            AllocationError::Unaligned => Self::Unaligned,
            AllocationError::OutOfMemory => Self::OutOfMemory,
            AllocationError::BelowMinAddress
            | AllocationError::AboveMaxAddress
            | AllocationError::AddressInUse
            | AllocationError::AddressInUseByPlatform
            | AllocationError::AddressPartiallyInUse => Self::Unallocated,
        }
    }
}

/// Possible errors for [`PageManagementProvider::try_allocate_cow_pages`]
///
/// ```text
///  ____________________
/// ( Maybe the grass is )
/// ( greener on the     )
/// ( other side?        )
///  --------------------
///         o   ^__^
///          o  (oo)\_______
///             (__)\       )\/\
///                 ||----w |
///                 ||     ||
/// ```
#[derive(Error, Debug)]
pub enum CowAllocationError {
    #[error("copy-on-write page allocation is not supported for this particular platform")]
    UnsupportedByPlatform,
    #[error("source region is not copy-on-writable")]
    UnsupportedSourceRegion,
    #[error("unaligned request")]
    Unaligned,
    #[error("internal failure in creating CoW pages")]
    InternalFailure,
}
