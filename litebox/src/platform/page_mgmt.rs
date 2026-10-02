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

    /// Split ownership into the prefix, requested extent, and suffix without changing memory.
    ///
    /// `range` must be nonempty, page-aligned, and contained in the owned extent. The returned
    /// handles must be disjoint and together own exactly the original extent.
    fn split(self, range: Range<usize>) -> (Option<Self>, Self, Option<Self>)
    where
        Self: Sized;
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
    ) -> impl DoubleEndedIterator<Item = &Self::Reservation>;

    /// Remove and return every reservation overlapping `range` in ascending address order.
    fn take_overlapping(&mut self, range: Range<usize>) -> Vec<Self::Reservation>;

    /// Transfer retained reservations within `range`, retaining ownership outside it.
    fn take_replaced(&mut self, range: Range<usize>) -> Vec<Self::Reservation>;
}

/// Native release ownership selected by a page-management provider.
pub type ReleaseTargetOf<Platform, const ALIGN: usize> =
    <<Platform as PageManagementProvider<ALIGN>>::Reservations as ReservationStore>::ReleaseTarget;

/// Native reservation handle selected by a page-management provider.
pub type ReservationOf<Platform, const ALIGN: usize> =
    <<Platform as PageManagementProvider<ALIGN>>::Reservations as ReservationStore>::Reservation;

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

/// A provider for managing memory pages.
///
/// # Page lifecycle
///
/// Reserving acquires virtual address space without making its pages accessible.
/// Platforms that exclusively control their address space, such as the Linux kernel provider,
/// need not allocate or track separate reservations.
///
/// Committing makes pages accessible, with zero-filled contents for pages that were not previously
/// committed; physical pages may be populated lazily. Already committed contents are preserved.
/// [`Self::reserve_and_commit_pages`] combines these steps when supported. [`Self::protect_pages`]
/// changes permissions without discarding contents or changing commitment.
///
/// [`Self::decommit_pages`] discards contents and makes pages inaccessible while retaining the
/// reservation; recommitting decommitted pages yields zeros. [`Self::release_pages`] relinquishes
/// the address space and any remaining backing, without requiring a prior decommit.
///
/// Acquiring an extent returns a [`PageReservation`] with exclusive ownership. The manager may
/// retain reservations in [`Self::Reservations`] or use ranges for release, depending on the
/// provider. Dropping a reservation does not release pages; ownership must be released explicitly
/// once there are no remaining users. Replacement and remapping transfer ownership to the
/// provider as specified by their respective methods.
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

    /// Reserve virtual address space and return its exclusive ownership handle.
    ///
    /// The default calls [`Self::reserve_and_commit_pages`] with empty permissions and lazy
    /// population, which also works for platforms that cannot reserve without creating a mapping.
    /// Platforms that support native reservation operation must override this method.
    ///
    /// # Parameters
    ///
    /// - `replaced_reservations`: On replacement, lazily transfers handles whose extents together
    ///   cover exactly the replaced range, which may be smaller than `suggested_range`;
    ///   handle-free mappings may yield no handles.
    /// - `suggested_range`: A suggested address range for the allocation.
    /// - `can_grow_down`: If `true`, the region is allowed to grow downward (towards zero) upon
    ///   a page fault.
    /// - `fixed_address_behavior`: Specifies the required semantics of `suggested_range`.
    ///
    /// # Errors
    ///
    /// Returns [`AllocationError::UnsupportedByPlatform`] when `suggested_range` starts at zero
    /// and the platform cannot relocate the hint in the requested direction.
    ///
    /// # Safety
    ///
    /// `suggested_range` must be nonempty and lie within
    /// [`Self::TASK_ADDR_MIN`]..[`Self::TASK_ADDR_MAX`] for fixed placement. A relocatable hint may
    /// instead start at zero to specify only the requested length. Its start must be aligned to
    /// [`Self::RESERVATION_ALIGNMENT`], and its end must be aligned to `ALIGN`.
    /// When `fixed_address_behavior` is [`FixedAddressBehavior::Replace`], the caller must ensure
    /// any replaced mappings are not in active use.
    unsafe fn reserve_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        // SAFETY: The caller supplies the range and replacement ownership required by
        // reserve_and_commit_pages; providers using this default leave the range inaccessible.
        unsafe {
            self.reserve_and_commit_pages(
                replaced_reservations,
                suggested_range,
                MemoryRegionPermissions::empty(),
                can_grow_down,
                false,
                fixed_address_behavior,
            )
        }
    }

    /// Commit backing within live reservations.
    ///
    /// Already committed pages retain their contents; `permissions` applies to both newly and
    /// previously committed pages.
    ///
    /// # Parameters
    ///
    /// - `covering_reservations`: Lazily supplies borrowed reservations covering `range`; their
    ///   extents may extend beyond it.
    /// - `range`: The address range to commit.
    /// - `permissions`: The permissions to apply to the committed pages.
    /// - `populate_pages_immediately`: If `true`, populate pages immediately; otherwise,
    ///   populate them lazily.
    ///
    /// # Safety
    ///
    /// The supplied reservations must collectively cover `range`. The caller must exclude
    /// accesses to `range` that could conflict with changes to its backing or permissions.
    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        populate_pages_immediately: bool,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
        ReservationOf<Self, ALIGN>: 'reservation;

    /// Reserve and commit pages in one platform operation.
    ///
    /// # Parameters
    ///
    /// - `suggested_range`: A suggested address range for the allocation.
    /// - `replaced_reservations`: On replacement, lazily transfers handles whose extents together
    ///   cover exactly the replaced range, which may be smaller than `suggested_range`;
    ///   handle-free mappings may yield no handles. Ownership outside the replaced range remains
    ///   with the caller.
    /// - `initial_permissions`: The permissions to apply to the allocated memory region.
    /// - `can_grow_down`: If `true`, the region is allowed to grow downward (towards zero) upon
    ///   a page fault.
    /// - `populate_pages_immediately`: If `true`, the pages are populated immediately; otherwise,
    ///   they are populated lazily.
    /// - `fixed_address_behavior`: Specifies the required semantics of `suggested_range`.
    ///
    /// # Returns
    ///
    /// On success, returns the exclusive reservation handle for the allocated extent.
    ///
    /// # Errors
    ///
    /// Returns [`AllocationError::UnsupportedByPlatform`] when `suggested_range` starts at zero
    /// and the platform cannot relocate the hint in the requested direction.
    ///
    /// # Safety
    ///
    /// `suggested_range` must be nonempty and lie within
    /// [`Self::TASK_ADDR_MIN`]..[`Self::TASK_ADDR_MAX`] for fixed placement. A relocatable hint may
    /// instead start at zero to specify only the requested length. Its start must be aligned to
    /// [`Self::RESERVATION_ALIGNMENT`], and its end must be aligned to `ALIGN`. The caller must
    /// ensure any replaced mappings are not in active use when `fixed_address_behavior` is
    /// [`FixedAddressBehavior::Replace`], and retain the returned reservation as the unique
    /// ownership handle for the allocated extent.
    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>;

    /// Decommit backing within live reservations.
    ///
    /// # Parameters
    ///
    /// - `covering_reservations`: Lazily supplies borrowed reservations covering `range`; their
    ///   extents may extend beyond it.
    /// - `range`: The address range to decommit.
    ///
    /// # Safety
    ///
    /// The reservations must cover `range`, and the caller must exclude all users.
    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
    ) -> Result<(), DeallocationError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
        ReservationOf<Self, ALIGN>: 'reservation;

    /// Update permissions within live reservations.
    ///
    /// # Parameters
    ///
    /// - `covering_reservations`: Lazily supplies borrowed reservations covering `range`; their
    ///   extents may extend beyond it.
    /// - `range`: The address range whose permissions are updated.
    /// - `permissions`: The permissions to apply to the pages in `range`.
    ///
    /// # Safety
    ///
    /// The reservations must cover `range`, and the caller must exclude conflicting accesses.
    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
        ReservationOf<Self, ALIGN>: 'reservation;

    /// Release the reserved address space and any committed backing represented by `target`.
    /// A prior decommit is not required.
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
    /// # Parameters
    ///
    /// - `source_reservations`: Lazily transfers ownership of reservations covering `old_range`.
    /// - `old_range`: The existing address range to remap.
    /// - `new_range`: The requested address range for the remapped pages.
    /// - `permissions`: The permissions to apply to the remapped pages.
    ///
    /// # Returns
    ///
    /// On success it returns the exclusive reservation handle for the new virtual memory area.
    ///
    /// # Safety
    ///
    /// `source_reservations` must yield every retained reservation covering `old_range`,
    /// transferring their ownership to the provider. Handle-free mappings transfer ownership
    /// through `old_range` and may yield no handles. The provider must not invoke the supplier on
    /// recoverable failure. The caller must ensure that the source pages are not in active use.
    ///
    /// The `new_range` must be larger than `old_range`, and must not overlap with `old_range`.
    ///
    /// Both ranges must be aligned to `ALIGN`.
    #[expect(unused_variables, reason = "default body")]
    unsafe fn try_remap_pages<Reservations>(
        &self,
        source_reservations: impl FnOnce() -> Reservations,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<ReservationOf<Self, ALIGN>, RemapError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        Err(RemapError::UnsupportedByPlatform)
    }

    /// Attempt to allocate pages with copy-on-write semantics backed by static data.
    ///
    /// This method allows platforms that support it to create CoW mappings instead of performing
    /// expensive page-by-page memory copies. This is particularly useful when mapping pre-loaded
    /// file data that was mmap'd by the host.
    ///
    /// The default implementation returns unsupported CoW. Platforms that DO support COW should
    /// override this method to unlock better performance.
    /// On success, the returned reservation owns exactly `source_data.len()` bytes. Replacement
    /// consumes every retained overlapping reservation supplied by `replaced_reservations`.
    /// Recoverable failure must leave the supplier uninvoked. Other placement modes must not
    /// invoke it.
    ///
    /// # Parameters
    ///
    /// - `replaced_reservations`: On replacement, lazily transfers ownership of the reservations
    ///   overlapping the requested range.
    /// - `suggested_start`: The suggested starting address for the allocation.
    /// - `source_data`: The static data to use as copy-on-write backing.
    /// - `permissions`: The permissions to apply to the allocated pages.
    /// - `fixed_address_behavior`: Specifies the required placement of `suggested_start`.
    ///
    /// # Errors
    ///
    /// Returns [`CowAllocationError::UnsupportedByPlatform`] when `suggested_start` is zero and
    /// the platform cannot relocate the hint in the requested direction.
    ///
    /// # Safety
    ///
    /// Replacement ownership follows [`Self::reserve_pages`]. The caller must track the returned
    /// reservation directly and must not construct duplicate ownership from its range.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    unsafe fn try_allocate_cow_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, CowAllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
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

/// Possible errors for page reservation and commitment.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AllocationError {
    #[error("page reservation is not supported by this platform")]
    UnsupportedByPlatform,
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

/// Possible errors for [`PageManagementProvider::try_remap_pages`]
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

/// Possible errors for [`PageManagementProvider::protect_pages`]
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
