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

    /// Join ownership with the immediately following extent without changing memory.
    ///
    /// `next` must start exactly where this extent ends. The returned handle owns both extents.
    #[must_use]
    fn merge(self, next: Self) -> Self
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
    }
}

bitflags::bitflags! {
    /// How page allocations back pages, beyond their permissions.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct AllocationOptions: u8 {
        /// The region may grow downward (towards zero) upon a page fault.
        const GROWS_DOWN = 1 << 0;
        /// Populate the pages immediately rather than lazily.
        const POPULATE = 1 << 1;
        /// Back the pages with fresh, zero-filled memory that could be shared
        /// across processes rather than copied, as Linux `MAP_SHARED` memory.
        const SHARED = 1 << 2;
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
    /// The upper bound (exclusive) for addresses that the memory manager chooses itself.
    ///
    /// Mappings at caller-specified fixed addresses may still extend up to
    /// [`Self::TASK_ADDR_MAX`]. Platforms whose host allocates in the upper part of the task
    /// range can lower this to keep self-placed task memory clear of host memory.
    ///
    /// Note it must be aligned to `ALIGN` and greater than [`Self::TASK_ADDR_MIN`].
    const PLACEMENT_ADDR_MAX: usize = Self::TASK_ADDR_MAX;

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
                if can_grow_down {
                    AllocationOptions::GROWS_DOWN
                } else {
                    AllocationOptions::empty()
                },
                fixed_address_behavior,
            )
        }
    }

    /// Reserve virtual address space that can later be joined with adjacent mergeable
    /// reservations by [`Self::merge_reservations`].
    ///
    /// Parameters, errors, and safety requirements match [`Self::reserve_pages`]. Reservations
    /// split from the returned handle remain mergeable. The default forwards to
    /// [`Self::reserve_pages`], which suits platforms whose native operations can already span
    /// adjacent reservations.
    ///
    /// # Safety
    ///
    /// See [`Self::reserve_pages`].
    unsafe fn reserve_mergeable_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        suggested_range: Range<usize>,
        can_grow_down: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        // SAFETY: Forwarded caller contract.
        unsafe {
            self.reserve_pages(
                replaced_reservations,
                suggested_range,
                can_grow_down,
                fixed_address_behavior,
            )
        }
    }

    /// Join adjacent mergeable reservations into one native reservation.
    ///
    /// The default only joins the handles, which suits platforms whose native operations can
    /// already span adjacent reservations.
    ///
    /// # Safety
    ///
    /// `reservations` must be nonempty, in ascending address order, and contiguous. Each must
    /// come from [`Self::reserve_mergeable_pages`] or be split from such a reservation. No page in
    /// them may be committed, and the caller must exclude all users of their extents.
    unsafe fn merge_reservations(
        &self,
        reservations: Vec<ReservationOf<Self, ALIGN>>,
    ) -> ReservationOf<Self, ALIGN> {
        reservations
            .into_iter()
            .reduce(PageReservation::merge)
            .expect("merge_reservations requires at least one reservation")
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
    /// - `options`: How to back newly committed pages; see [`AllocationOptions`].
    ///
    /// # Safety
    ///
    /// The supplied reservations must collectively cover `range`. The caller must exclude
    /// accesses to `range` that could conflict with changes to its backing or permissions.
    /// Shared pages must not be recommitted; use protection to change their permissions.
    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        options: AllocationOptions,
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
    /// - `options`: How to back the pages; see [`AllocationOptions`].
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
        options: AllocationOptions,
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
    /// - `new_range`: The exact address range for the remapped pages.
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

    /// Hints that the caller is about to fill the allocated pages in `range` with data from their
    /// start, possibly stopping short of the end (e.g., at the end of a file copied into them).
    ///
    /// A platform may, for example, back these pages with larger host pages, which take fewer
    /// faults to fill but can leave up to one larger page past the filled part resident.
    ///
    /// The default implementation does nothing.
    #[expect(unused_variables, reason = "default body")]
    fn advise_fill(&self, range: Range<usize>) {}
}

/// A provider for mapping host shared objects that the broker delivers to this process out of
/// band, such as the memfd or section that holds a shared file's contents.
///
/// Every mapping of the same object, in this or any other process, shares its pages, which is
/// how `MAP_SHARED` file mappings stay coherent across processes. A private mapping
/// ([`ObjectSharing::Private`]) shares them too until it writes one, which then becomes its own
/// copy, which is how `MAP_PRIVATE` file mappings avoid copying files. Platforms that cannot map
/// such objects implement this trait with an uninhabited [`Self::SharedObject`], such as
/// [`core::convert::Infallible`], and the other defaults, which report it as unsupported.
///
/// A delivered object is named by a [`SharedObjectToken`] only until
/// [`Self::take_shared_object`] takes it; from then on the platform's own
/// [`Self::SharedObject`] owns it, and dropping that releases it.
pub trait SharedObjectProvider<const ALIGN: usize>: PageManagementProvider<ALIGN> {
    /// A host shared object that the broker delivered to this process, such as a descriptor or
    /// a section handle. Dropping it releases the object; mapping it consumes it.
    type SharedObject: Send;

    /// Returns whether this platform can map host shared objects that the broker hands this
    /// process as `sharing` says, with [`Self::try_map_shared_object`] or
    /// [`Self::commit_shared_object`]. Supporting [`ObjectSharing::Private`] also means
    /// supporting [`Self::discard_private_object_pages`].
    ///
    /// Callers must check this before asking the broker for an object, since asking has lasting
    /// effects, such as moving a file's contents into host shared memory, and the broker delivers
    /// each object only once. The default implementation returns `false`.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn supports_object_mappings(&self, sharing: ObjectSharing) -> bool {
        false
    }

    /// Takes the host shared object that the broker delivered under `token`.
    ///
    /// The default implementation fails with [`AllocationError::UnsupportedByPlatform`].
    ///
    /// # Safety
    ///
    /// `token` must be one the broker delivered to this process that has not been taken yet: on
    /// some platforms it is the object's handle, which the returned object then owns.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    unsafe fn take_shared_object(
        &self,
        token: SharedObjectToken,
    ) -> Result<Self::SharedObject, AllocationError> {
        Err(AllocationError::UnsupportedByPlatform)
    }

    /// Maps the host shared object `object`, starting at its byte `offset`, over exactly `range`
    /// with `permissions`, shared or private as `sharing` says, consuming the object whether or
    /// not the mapping succeeds.
    ///
    /// Platforms whose mappings need no reservation handles implement this; platforms that track
    /// reservations implement [`Self::commit_shared_object`] instead.
    ///
    /// Every mapping of the same object, in this or any other process, shares its pages, and a
    /// native fork child keeps sharing them. A private mapping shares only the pages it has not
    /// written, and never writes the object, even if `object` would allow it; a native fork
    /// child gets its own copies of the pages either writes later.
    ///
    /// `fixed_address_behavior` must be [`FixedAddressBehavior::Replace`] or
    /// [`FixedAddressBehavior::NoReplace`]. On replacement, `replaced_reservations` lazily
    /// transfers ownership of the reservations overlapping `range`; recoverable failure must leave
    /// it uninvoked. On success, the returned reservation owns exactly `range`.
    ///
    /// # Safety
    ///
    /// Replacement ownership follows [`PageManagementProvider::reserve_pages`]. The caller must
    /// track the returned reservation directly and must not construct duplicate ownership from
    /// its range.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors a host mmap of an object"
    )]
    unsafe fn try_map_shared_object<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        object: Self::SharedObject,
        offset: u64,
        sharing: ObjectSharing,
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>,
    {
        Err(AllocationError::UnsupportedByPlatform)
    }

    /// Backs the reserved but unbacked `range`, within live reservations, with the host shared
    /// object `object`, starting at its byte `offset`, with `permissions`, shared or private as
    /// `sharing` says, consuming the object whether or not the mapping succeeds.
    ///
    /// This is [`Self::try_map_shared_object`] for platforms that track reservations, as
    /// [`PageManagementProvider::commit_pages`] is to
    /// [`PageManagementProvider::reserve_and_commit_pages`]. Every mapping of the same
    /// object, in this or any other process, shares its pages, and a native fork child keeps
    /// sharing them. Accessing a page past the end of the object faults.
    ///
    /// On failure, `range` remains reserved and unbacked.
    ///
    /// # Safety
    ///
    /// The supplied reservations must collectively cover `range`, which must have no backing,
    /// and the caller must exclude its users.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    unsafe fn commit_shared_object<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        object: Self::SharedObject,
        offset: u64,
        sharing: ObjectSharing,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), AllocationError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>,
        ReservationOf<Self, ALIGN>: 'reservation,
    {
        Err(AllocationError::UnsupportedByPlatform)
    }

    /// Discards the copies that a private mapping of a host shared object made of the pages in
    /// `range` it wrote, so that they show the object's contents again, as `MADV_DONTNEED` does
    /// to a `MAP_PRIVATE` file mapping on Linux. Pages not written are unchanged.
    ///
    /// The default implementation fails with [`AllocationError::UnsupportedByPlatform`].
    ///
    /// # Safety
    ///
    /// `range` must lie within private mappings of host shared objects that this provider made,
    /// and the caller must ensure that nothing relies on the discarded contents.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    unsafe fn discard_private_object_pages(
        &self,
        range: Range<usize>,
    ) -> Result<(), AllocationError> {
        Err(AllocationError::UnsupportedByPlatform)
    }
}

/// How a host shared object is mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectSharing {
    /// Writes reach the object, and every mapping sees them, as with `MAP_SHARED`.
    Shared,
    /// Writes go to the mapping's own copies of the pages, as with `MAP_PRIVATE`.
    Private,
}

/// Names a host shared object that the broker delivered to this process out of band, such as a
/// memfd or section backing a shared file, until [`SharedObjectProvider::take_shared_object`]
/// takes it, after which it must not be used again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedObjectToken(pub u64);

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
    #[error("provided new range is in use by the platform")]
    AddressInUseByPlatform,
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
