// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-management related types and traits

use alloc::vec::Vec;

use super::RawPointerProvider;
use core::ops::Range;
use thiserror::Error;

/// Exclusive ownership of a reserved virtual-address extent.
pub trait PageReservation: Into<Range<usize>> {
    /// Return the owned address range.
    fn range(&self) -> Range<usize>;
}

/// Direction used to search for available virtual address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationDirection {
    /// Search from low addresses toward high addresses.
    BottomUp,
    /// Search from high addresses toward low addresses.
    TopDown,
}

/// Placement behavior supported for hint allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintPlacementBehavior {
    /// The platform may relocate a hint without guaranteeing a search direction.
    Unspecified,
    /// The platform always uses the suggested address, so search direction is irrelevant.
    Exact,
    /// The platform can relocate a hint in one direction.
    Directional(AllocationDirection),
    /// The platform can relocate a hint in either direction.
    Bidirectional,
}

impl HintPlacementBehavior {
    /// Return whether this behavior preserves the requested placement direction.
    pub const fn supports(self, direction: AllocationDirection) -> bool {
        match self {
            Self::Unspecified => false,
            Self::Exact | Self::Bidirectional => true,
            Self::Directional(supported) => matches!(
                (supported, direction),
                (AllocationDirection::BottomUp, AllocationDirection::BottomUp)
                    | (AllocationDirection::TopDown, AllocationDirection::TopDown)
            ),
        }
    }
}

/// Storage for reservations indexed by their starting address.
pub trait ReservationStore {
    /// Reservation value retained by the store.
    type Reservation: PageReservation + Into<Self::ReleaseTarget>;
    /// Ownership representation consumed when this store releases pages.
    type ReleaseTarget;

    /// Release every extent represented by this store.
    ///
    /// # Safety
    ///
    /// Every represented extent must belong to `platform` and have no remaining users.
    unsafe fn release_all<Platform, const ALIGN: usize, V>(
        &mut self,
        vmas: &rangemap::RangeMap<usize, V>,
        platform: &Platform,
    ) -> Result<(), DeallocationError>
    where
        Platform: PageManagementProvider<ALIGN, Reservations = Self>;

    /// Insert a reservation at `base`.
    fn insert(&mut self, base: usize, reservation: Self::Reservation) -> Option<Self::Reservation>;

    /// Iterate over reservation bases and values in ascending address order.
    fn iter(&self) -> impl DoubleEndedIterator<Item = (&usize, &Self::Reservation)>;

    /// Iterate over every reservation overlapping `range` in ascending address order.
    fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (usize, &Self::Reservation)>;

    /// Remove and return every reservation overlapping `range` in ascending address order.
    fn take_overlapping(&mut self, range: Range<usize>) -> Vec<Self::Reservation>;
}

/// Native release ownership selected by a page-management provider.
pub type ReleaseTargetOf<Platform, const ALIGN: usize> =
    <<Platform as PageManagementProvider<ALIGN>>::Reservations as ReservationStore>::ReleaseTarget;

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
    /// Reservation storage used by the virtual memory manager.
    type Reservations: ReservationStore + Default;

    /// The lower bound (inclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MIN: usize;
    /// The upper bound (exclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MAX: usize;

    /// Alignment of native reservation base addresses, in bytes.
    ///
    /// This must be a nonzero power of two and a multiple of `ALIGN`.
    const RESERVATION_ALIGNMENT: usize = ALIGN;

    /// Placement behavior supported by [`FixedAddressBehavior::Hint`].
    const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior = HintPlacementBehavior::Unspecified;

    /// Allocates new memory pages at the specified `suggested_range` with the given `initial_permissions`.
    ///
    /// # Parameters
    ///
    /// - `suggested_range`: A suggested address range for the allocation.
    /// - `initial_permissions`: The permissions to apply to the allocated memory region.
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
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>;

    /// Release all pages represented by `target`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that these pages are not in active use.
    unsafe fn release_pages(
        &self,
        target: ReleaseTargetOf<Self, ALIGN>,
    ) -> Result<(), DeallocationError>;

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
    ///
    /// The `new_range` must be larger than `old_range`, and must not overlap with `old_range`.
    ///
    /// Both ranges must be aligned to `ALIGN`.
    #[expect(unused_variables, reason = "default body")]
    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        Err(RemapError::UnsupportedByPlatform)
    }

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
    /// address in the specified direction if the hint is not available.
    Hint(AllocationDirection),
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
    #[error("requested page permissions are denied")]
    PermissionDenied,
    #[error("provided fixed address range is in use")]
    AddressInUse,
    #[error("provided fixed address range is in use by the platform")]
    AddressInUseByPlatform,
    #[error("provided fixed address range partially overlaps existing mappings")]
    AddressPartiallyInUse,
}

/// Possible errors for [`PageManagementProvider::release_pages`]
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
    #[error("native page remapping is not supported by this platform")]
    UnsupportedByPlatform,
    #[error("provided address range is invalid")]
    InvalidRange,
    #[error("at least one of the provided ranges was not page-aligned")]
    Unaligned,
    #[error("provided old range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("provided ranges were overlapping")]
    Overlapping,
    #[error("provided new range is already allocated")]
    AlreadyAllocated,
    #[error("requested page permissions are denied")]
    PermissionDenied,
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
    #[error("requested page permissions are denied")]
    PermissionDenied,
    #[error("out of memory")]
    OutOfMemory,
    #[error("platform failed to update page permissions")]
    PlatformFailure,
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
