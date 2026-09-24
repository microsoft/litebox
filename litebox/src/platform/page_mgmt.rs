// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-management related types and traits
//!
//! # Explicit backing lifecycle
//!
//! Providers implement reserve, reserve-and-commit, commit, protect, decommit, and range-based
//! release. [`PageManagementProvider::reserve_and_commit_pages`] may report that a combined
//! reservation and commitment is unsupported for a particular request. Native remapping and CoW
//! allocation are also optional. Unsupported operations leave memory and ownership unchanged;
//! allocation errors are distinct from lack of support.
//!
//! Reserve acquires inaccessible, logically uncommitted address space for anonymous memory.
//! Commit supplies zero-filled backing lazily or makes previously reserved backing accessible,
//! preserving already committed contents without acquiring address space. Protection changes
//! permissions of committed pages without changing their contents or commitment.
//! Decommit always discards anonymous contents and makes pages inaccessible while
//! retaining ownership; recommit yields zeros. Release frees any remaining
//! backing and relinquishes address space, like `munmap`; prior decommit is never required.
//!
//! Acquisition returns exclusive handles with exact extents and no hidden padding. Native
//! reservation boundaries must be preserved when splitting ownership. Callers retain unaffected
//! pieces and lazily transfer only replaced ownership; recoverable failure leaves the original
//! handles, contents, and permissions unchanged. State-update errors likewise leave the requested
//! range unchanged. Providers must treat irreversible partial failures as fatal.
//! Commit, protection, and decommit borrow ordered covering handles. Release consumes ordered handles
//! and may span holes that the caller keeps unmapped. Providers may batch native operations or
//! split at reservation boundaries.
//!
//! Reservation may be native or bookkeeping-only when the provider exclusively controls the
//! address space. Kernel providers trust manager-selected free ranges instead of duplicating
//! allocation tracking or searching page tables; only replacement may overlap existing memory.
//! Page alignment and native reservation-base alignment are separate requirements.
//! Grow-down and population are hints where supported. Handles do not release memory on drop;
//! callers must release ownership explicitly after all users have relinquished it.

use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    marker::PhantomData,
    ops::{Index, Range},
};
use rangemap::RangeMap;
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

/// Parameters for creating a reservation-backed mapping.
#[doc(hidden)]
pub struct MmapRequest {
    /// Requested address range.
    pub range: Range<usize>,
    /// Initial page permissions.
    pub permissions: MemoryRegionPermissions,
    /// Whether the mapping may grow downward.
    pub can_grow_down: bool,
    /// Whether pages should be populated immediately.
    pub populate: bool,
    /// Fixed-address placement behavior.
    pub behavior: FixedAddressBehavior,
}

/// Exclusive ownership of a page-aligned address-space extent.
///
/// Provider reservation stores expose an opaque associated handle implementing this trait. Its
/// fields and constructor remain provider-private, so only successful provider operations can
/// create ownership. Dropping a handle does not release memory; the owner must explicitly call
/// [`PageManagementProvider::release_pages`] after all users have relinquished it.
///
/// # Safety
///
/// Implementations must represent unique ownership and must not implement [`Copy`] or [`Clone`].
/// `split` must consume that ownership and return disjoint handles covering exactly the original
/// extent.
pub unsafe trait PageReservation: Sized + Send + Sync + 'static {
    /// Return the complete owned extent.
    fn range(&self) -> Range<usize>;

    /// Split ownership into the prefix, requested extent, and suffix without changing memory.
    ///
    /// All returned handles must belong to the same provider as the original. The requested
    /// range must be nonempty, page-aligned, and contained in the original extent.
    fn split(self, range: Range<usize>) -> (Option<Self>, Self, Option<Self>);
}

/// Define an opaque reservation handle with a private constructor.
///
/// ```compile_fail
/// litebox::define_page_reservation!(ExampleReservation);
///
/// impl<const ALIGN: usize> Clone for ExampleReservation<ALIGN> {
///     fn clone(&self) -> Self {
///         unreachable!()
///     }
/// }
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! define_page_reservation {
    ($name:ident) => {
        #[doc(hidden)]
        // Reservation handles represent unique ownership, so this must remain neither Clone nor Copy.
        #[derive(Debug)]
        pub struct $name<const ALIGN: usize> {
            range: ::core::ops::Range<usize>,
        }

        impl<const ALIGN: usize> $name<ALIGN> {
            unsafe fn new(range: ::core::ops::Range<usize>) -> Self {
                assert!(!range.is_empty());
                assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
                Self { range }
            }
        }

        // SAFETY: Construction is private, the type is neither Clone nor Copy, and split consumes
        // the original handle while returning disjoint handles covering the same extent.
        unsafe impl<const ALIGN: usize> $crate::platform::page_mgmt::PageReservation
            for $name<ALIGN>
        {
            fn range(&self) -> ::core::ops::Range<usize> {
                self.range.clone()
            }

            fn split(self, range: ::core::ops::Range<usize>) -> (Option<Self>, Self, Option<Self>) {
                let extent = self.range;
                assert!(
                    extent.start <= range.start && range.end <= extent.end && !range.is_empty()
                );
                assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
                (
                    (extent.start < range.start).then_some(Self {
                        range: extent.start..range.start,
                    }),
                    Self {
                        range: range.clone(),
                    },
                    (range.end < extent.end).then_some(Self {
                        range: range.end..extent.end,
                    }),
                )
            }
        }

        // A provider owns this generated type and could otherwise add a manual Clone or Copy
        // implementation. Stable Rust has no negative trait bounds, so overlapping candidates
        // make that addition fail through ambiguous trait resolution.
        const _: fn() = || {
            trait AmbiguousIfCloneOrCopy<Marker> {
                fn assert_not_impl() {}
            }
            struct Invalid;
            impl<T: ?Sized> AmbiguousIfCloneOrCopy<()> for T {}
            impl<T: ?Sized + Clone> AmbiguousIfCloneOrCopy<Invalid> for T {}
            impl<T: ?Sized + Copy> AmbiguousIfCloneOrCopy<(Invalid, Invalid)> for T {}

            let _ = <$name<4096> as AmbiguousIfCloneOrCopy<_>>::assert_not_impl;
        };
    };
}

/// Manager-owned reservation handle storage selected by page-manager policy.
#[doc(hidden)]
pub trait ReservationStore:
    Default + Send + Sync + for<'a> Index<&'a usize, Output = Self::Reservation>
{
    /// Opaque ownership handle stored for this provider.
    type Reservation: PageReservation;

    /// Ownership representation consumed when this store releases pages.
    type ReleaseTarget: From<Self::Reservation>;

    /// Check whether a range overlaps committed mappings or, when requested, reserved ownership.
    fn overlaps<V>(
        &self,
        vmas: &RangeMap<usize, V>,
        range: Range<usize>,
        include_reservations: bool,
    ) -> bool;

    /// Transfer ownership of every represented extent overlapping a replacement range.
    ///
    /// Prefixes and suffixes outside `range` remain represented by the store. The returned
    /// reservations are ordered, disjoint, and clipped to `range`.
    ///
    /// # Safety
    ///
    /// `vmas` must accurately represent the provider-owned committed mappings associated with
    /// this store. The caller must be authorized to replace `range`, and the returned ownership
    /// must be consumed by the provider before any conflicting access can occur.
    unsafe fn take_replaced<V>(
        &mut self,
        vmas: &RangeMap<usize, V>,
        range: Range<usize>,
    ) -> Vec<Self::Reservation>;

    /// Attempt to reserve and commit one mapping using the store's ownership representation.
    ///
    /// Retains any explicit reservation handles and returns the actual mapped range for the caller
    /// to publish in `vmas`.
    ///
    /// # Safety
    ///
    /// `vmas` must accurately represent the provider-owned committed mappings associated with
    /// this store. The caller must satisfy [`PageManagementProvider::reserve_and_commit_pages`]
    /// and authorize replacement when `behavior` is [`FixedAddressBehavior::Replace`]. On
    /// success, the caller must immediately publish the returned range without a conflicting
    /// access.
    unsafe fn mmap<Platform, const ALIGN: usize, V: Clone + Eq>(
        &mut self,
        vmas: &mut RangeMap<usize, V>,
        platform: &Platform,
        request: MmapRequest,
    ) -> Result<Range<usize>, AllocationError>
    where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>;

    /// Remove a range from the mapping state and update its provider backing.
    ///
    /// # Safety
    ///
    /// The caller must exclude all users of the removed range and keep unreserved gaps unmapped
    /// until the operation returns.
    unsafe fn unmap<Platform, const ALIGN: usize, V: Clone + Eq>(
        &mut self,
        vmas: &mut RangeMap<usize, V>,
        platform: &Platform,
        range: Range<usize>,
    ) where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>;

    /// Select a native destination, attempt the remap, and update ownership on success.
    ///
    /// # Safety
    ///
    /// The source must be one committed mapping owned by this store, with no active users.
    /// The destination must be larger, disjoint, and suitable for native remapping by this store.
    /// `find_area` selects a VMA-free destination and additionally excludes reservations when
    /// requested by the store.
    unsafe fn remap<Platform, const ALIGN: usize, V: Clone + Eq, FindArea>(
        &mut self,
        vmas: &mut RangeMap<usize, V>,
        platform: &Platform,
        old_range: Range<usize>,
        permissions: MemoryRegionPermissions,
        value: V,
        find_area: FindArea,
    ) -> Result<Range<usize>, RemapError>
    where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>,
        FindArea: FnOnce(&Self, &RangeMap<usize, V>, bool) -> Option<Range<usize>>;

    /// Release all ownership represented by this store.
    ///
    /// Tracked stores release every reservation, independently of current VMAs. Handle-free
    /// stores have no reservation index and therefore release the ranges represented by `vmas`.
    ///
    /// # Safety
    ///
    /// Every represented extent must belong to `platform` and have no remaining users.
    unsafe fn release_all<Platform, const ALIGN: usize, V>(
        &mut self,
        vmas: &RangeMap<usize, V>,
        platform: &Platform,
    ) where
        Platform: PageManagementProvider<ALIGN>,
        Self::ReleaseTarget: Into<ReleaseTargetOf<Platform, ALIGN>>;

    fn insert(&mut self, base: usize, reservation: Self::Reservation) -> Option<Self::Reservation>;
    fn remove(&mut self, base: &usize) -> Option<Self::Reservation>;
    fn get(&self, base: &usize) -> Option<&Self::Reservation>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn values(&self) -> impl DoubleEndedIterator<Item = &Self::Reservation>;
    fn iter(&self) -> impl DoubleEndedIterator<Item = (&usize, &Self::Reservation)>;
    fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (usize, &Self::Reservation)>;
    fn containing(&self, address: usize) -> Option<(usize, &Self::Reservation)>;
    fn take_all(&mut self) -> Vec<Self::Reservation>;
    fn take_overlapping(&mut self, range: Range<usize>) -> Vec<Self::Reservation>;
}

/// Explicit reservation handles indexed by their starting address.
#[doc(hidden)]
pub struct TrackedReservations<Reservation>(BTreeMap<usize, Reservation>);

impl<Reservation> Default for TrackedReservations<Reservation> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<Reservation> Index<&usize> for TrackedReservations<Reservation> {
    type Output = Reservation;

    fn index(&self, index: &usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<Reservation: PageReservation> TrackedReservations<Reservation> {
    /// Take a subrange of the reservation at `base`, retaining its outside pieces.
    pub(crate) fn take_range(&mut self, base: usize, range: Range<usize>) -> Reservation {
        let reservation = self.remove(&base).unwrap();
        self.take_subrange(reservation, range)
    }

    /// Take a subrange of a detached reservation, retaining its outside pieces.
    fn take_subrange(&mut self, reservation: Reservation, range: Range<usize>) -> Reservation {
        let (prefix, removed, suffix) = reservation.split(range);
        for remaining in [prefix, suffix].into_iter().flatten() {
            self.insert(remaining.range().start, remaining);
        }
        removed
    }

    /// Snapshot a range by reservation boundaries; `None` denotes an unreserved gap.
    fn segments(&self, range: Range<usize>) -> Vec<(Range<usize>, Option<usize>)> {
        let mut segments = Vec::new();
        if range.is_empty() {
            return segments;
        }
        let mut cursor = range.start;
        for (base, reservation) in self.overlapping(range.clone()) {
            let extent = reservation.range();
            if cursor < extent.start {
                segments.push((cursor..extent.start, None));
                cursor = extent.start;
            }
            let end = extent.end.min(range.end);
            segments.push((cursor..end, Some(base)));
            cursor = end;
        }
        if cursor < range.end {
            segments.push((cursor..range.end, None));
        }
        segments
    }

    /// Round and reserve one currently unowned gap.
    ///
    /// All missing backing is acquired through this helper with the same native outward
    /// rounding, so rounding another gap cannot partially overlap stored ownership.
    unsafe fn reserve_gap<Platform, const ALIGN: usize>(
        platform: &Platform,
        requested: Range<usize>,
        can_grow_down: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Platform, ALIGN>, AllocationError>
    where
        Platform: PageManagementProvider<ALIGN>,
    {
        let alignment = Platform::RESERVATION_ALIGNMENT;
        let start = requested.start & !(alignment - 1);
        let end = requested
            .end
            .checked_next_multiple_of(alignment)
            .ok_or(AllocationError::OutOfMemory)?;
        let behavior = if requested.start == 0 && behavior == FixedAddressBehavior::Hint {
            FixedAddressBehavior::Hint
        } else {
            FixedAddressBehavior::NoReplace
        };
        // SAFETY: Stored reservations use the same native rounding, so this rounded gap remains unowned.
        let reservation = unsafe {
            platform.reserve_pages(core::iter::empty, start..end, can_grow_down, behavior)
        }?;
        debug_assert_eq!(reservation.range().len(), end - start);
        debug_assert!(
            behavior == FixedAddressBehavior::Hint || reservation.range() == (start..end)
        );
        Ok(reservation)
    }

    /// Reserve every unowned gap and publish the handles in this store.
    unsafe fn reserve_gaps<Platform, const ALIGN: usize>(
        &mut self,
        platform: &Platform,
        requested: Range<usize>,
        can_grow_down: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<Vec<usize>, AllocationError>
    where
        Platform: PageManagementProvider<ALIGN>,
        Self: ReservationStore<Reservation = ReservationOf<Platform, ALIGN>>,
    {
        let mut acquired = Vec::new();
        if requested.start == 0 {
            debug_assert_eq!(behavior, FixedAddressBehavior::Hint);
            // SAFETY: A zero-address hint acquires fresh backing without replacement.
            acquired
                .push(unsafe { Self::reserve_gap(platform, requested, can_grow_down, behavior)? });
        } else {
            for (gap, base) in self.segments(requested) {
                if base.is_some() {
                    continue;
                }
                // SAFETY: The rounded gap is disjoint from existing tracked reservations.
                match unsafe { Self::reserve_gap(platform, gap, can_grow_down, behavior) } {
                    Ok(reservation) => acquired.push(reservation),
                    Err(error) => {
                        for reservation in acquired {
                            // SAFETY: These reservations are unpublished and uncommitted.
                            unsafe {
                                platform.release_pages(reservation.into());
                            };
                        }
                        return Err(error);
                    }
                }
            }
        }

        let mut bases = Vec::new();
        for reservation in acquired {
            let extent = reservation.range();
            debug_assert!(
                extent.start >= Platform::TASK_ADDR_MIN && extent.end <= Platform::TASK_ADDR_MAX
            );
            bases.push(extent.start);
            self.insert(extent.start, reservation);
        }
        Ok(bases)
    }
}

impl<Reservation: PageReservation> ReservationStore for TrackedReservations<Reservation> {
    type Reservation = Reservation;
    type ReleaseTarget = Reservation;

    fn overlaps<V>(
        &self,
        vmas: &RangeMap<usize, V>,
        range: Range<usize>,
        include_reservations: bool,
    ) -> bool {
        if include_reservations {
            self.overlapping(range).next().is_some()
        } else {
            vmas.overlaps(&range)
        }
    }

    unsafe fn take_replaced<V>(
        &mut self,
        _: &RangeMap<usize, V>,
        range: Range<usize>,
    ) -> Vec<Self::Reservation> {
        self.take_overlapping(range.clone())
            .into_iter()
            .map(|reservation| {
                let extent = reservation.range();
                let overlap = extent.start.max(range.start)..extent.end.min(range.end);
                let (prefix, replaced, suffix) = reservation.split(overlap);
                for remaining in [prefix, suffix].into_iter().flatten() {
                    self.insert(remaining.range().start, remaining);
                }
                replaced
            })
            .collect()
    }

    unsafe fn mmap<Platform, const ALIGN: usize, V: Clone + Eq>(
        &mut self,
        vmas: &mut RangeMap<usize, V>,
        platform: &Platform,
        request: MmapRequest,
    ) -> Result<Range<usize>, AllocationError>
    where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>,
    {
        let MmapRequest {
            mut range,
            permissions,
            can_grow_down,
            populate,
            behavior,
        } = request;
        let native_eligible = range.start.is_multiple_of(Platform::RESERVATION_ALIGNMENT)
            && range.end.is_multiple_of(Platform::RESERVATION_ALIGNMENT)
            && (behavior == FixedAddressBehavior::Replace
                || self.overlapping(range.clone()).next().is_none());
        if native_eligible {
            // SAFETY: The caller authorizes replacement and guarantees accurate mapping ownership.
            match unsafe {
                platform.reserve_and_commit_pages(
                    || self.take_replaced(vmas, range.clone()).into_iter(),
                    range.clone(),
                    permissions,
                    can_grow_down,
                    populate,
                    behavior,
                )
            } {
                Ok(reservation) => {
                    let actual = reservation.range();
                    self.insert(actual.start, reservation);
                    return Ok(actual);
                }
                Err(ReserveAndCommitError::UnsupportedByPlatform) => {}
                Err(ReserveAndCommitError::Allocation(error)) => return Err(error),
            }
        }

        // SAFETY: The caller authorizes replacement; existing tracked backing is reused.
        let acquired =
            match unsafe { self.reserve_gaps(platform, range.clone(), can_grow_down, behavior) } {
                Ok(acquired) => acquired,
                Err(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                ) if behavior == FixedAddressBehavior::Hint => {
                    let len = range.len();
                    // SAFETY: Retry acquires fresh backing without replacing mappings.
                    let acquired =
                        unsafe { self.reserve_gaps(platform, 0..len, can_grow_down, behavior)? };
                    debug_assert_eq!(acquired.len(), 1);
                    range = acquired[0]..acquired[0] + len;
                    acquired
                }
                Err(error) => return Err(error),
            };
        let segments = self.segments(range.clone());
        for (segment, base) in &segments {
            let base = base.expect("acquired range must have backing");
            if behavior == FixedAddressBehavior::Replace && !acquired.contains(&base) {
                // SAFETY: The caller excludes users, and this reservation covers the segment.
                unsafe {
                    platform.decommit_pages(|| core::iter::once(&self[&base]), segment.clone())
                }
                .expect("failed to decommit replacement backing");
                vmas.remove(segment.clone());
            }
            debug_assert!(vmas.overlapping(segment.clone()).next().is_none());
            // SAFETY: Placement excluded existing VMAs, or replacement unmapped all overlaps.
            if let Err(error) = unsafe {
                platform.commit_pages(
                    || core::iter::once(&self[&base]),
                    segment.clone(),
                    permissions,
                    populate,
                )
            } {
                let committed_prefix = range.start..segment.start;
                if !committed_prefix.is_empty() {
                    // SAFETY: Earlier segments were committed by this attempt and have no users.
                    unsafe {
                        platform.decommit_pages(
                            || {
                                self.overlapping(committed_prefix.clone())
                                    .map(|(_, reservation)| reservation)
                            },
                            committed_prefix.clone(),
                        )
                    }
                    .expect("failed to roll back backing commitment");
                }
                for base in &acquired {
                    let reservation = self.remove(base).unwrap();
                    // SAFETY: This newly acquired reservation was never published and is uncommitted.
                    unsafe { platform.release_pages(reservation) };
                }
                return Err(match error {
                    PageStateUpdateError::OutOfMemory => AllocationError::OutOfMemory,
                    other => panic!("invalid backing commitment: {other}"),
                });
            }
        }
        Ok(range)
    }

    unsafe fn unmap<Platform, const ALIGN: usize, V: Clone + Eq>(
        &mut self,
        vmas: &mut RangeMap<usize, V>,
        platform: &Platform,
        range: Range<usize>,
    ) where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>,
    {
        let reservations = self.take_overlapping(range.clone());
        let last = reservations.len().saturating_sub(1);
        vmas.remove(range.clone());
        for (index, reservation) in reservations.into_iter().enumerate() {
            if index == 0 || index == last {
                let extent = reservation.range();
                if vmas.overlaps(&extent) {
                    let segment = extent.start.max(range.start)..extent.end.min(range.end);
                    // TODO: Shared and native CoW backing may require a distinct partial-unmap policy.
                    // SAFETY: The removed range is covered by this retained reservation.
                    unsafe { platform.decommit_pages(|| core::iter::once(&reservation), segment) }
                        .expect("failed to decommit owned backing during unmap");
                    self.insert(extent.start, reservation);
                    continue;
                }
            }
            // SAFETY: This owned extent has no remaining users.
            unsafe { platform.release_pages(reservation) }
        }
    }

    unsafe fn remap<Platform, const ALIGN: usize, V: Clone + Eq, FindArea>(
        &mut self,
        _: &mut RangeMap<usize, V>,
        _: &Platform,
        _: Range<usize>,
        _: MemoryRegionPermissions,
        _: V,
        _: FindArea,
    ) -> Result<Range<usize>, RemapError>
    where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>,
        FindArea: FnOnce(&Self, &RangeMap<usize, V>, bool) -> Option<Range<usize>>,
    {
        Err(RemapError::UnsupportedByPlatform)
    }

    unsafe fn release_all<Platform, const ALIGN: usize, V>(
        &mut self,
        _: &RangeMap<usize, V>,
        platform: &Platform,
    ) where
        Platform: PageManagementProvider<ALIGN>,
        Self::ReleaseTarget: Into<ReleaseTargetOf<Platform, ALIGN>>,
    {
        for reservation in self.take_all() {
            // SAFETY: The caller relinquishes this reservation without remaining users.
            unsafe { platform.release_pages(reservation.into()) };
        }
    }

    fn insert(&mut self, base: usize, reservation: Reservation) -> Option<Reservation> {
        let replaced = self.0.insert(base, reservation);
        debug_assert!(
            replaced.is_none(),
            "reservation already exists at base {base:#x}"
        );
        replaced
    }

    fn remove(&mut self, base: &usize) -> Option<Reservation> {
        self.0.remove(base)
    }

    fn get(&self, base: &usize) -> Option<&Reservation> {
        self.0.get(base)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn values(&self) -> impl DoubleEndedIterator<Item = &Reservation> {
        self.0.values()
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = (&usize, &Reservation)> {
        self.0.iter()
    }

    fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (usize, &Reservation)> {
        let first = self
            .0
            .range(..=range.start)
            .next_back()
            .filter(|(_, reservation)| reservation.range().end > range.start)
            .map_or(range.start, |(&base, _)| base);
        self.0
            .range(first..range.end)
            .filter(move |(_, reservation)| {
                !range.is_empty() && reservation.range().end > range.start
            })
            .map(|(&base, reservation)| (base, reservation))
    }

    fn containing(&self, address: usize) -> Option<(usize, &Reservation)> {
        self.0
            .range(..=address)
            .next_back()
            .filter(|(_, reservation)| reservation.range().end > address)
            .map(|(&base, reservation)| (base, reservation))
    }

    fn take_all(&mut self) -> Vec<Reservation> {
        core::mem::take(&mut self.0).into_values().collect()
    }

    fn take_overlapping(&mut self, range: Range<usize>) -> Vec<Reservation> {
        let first = self
            .0
            .range(..=range.start)
            .next_back()
            .filter(|(_, reservation)| reservation.range().end > range.start)
            .map_or(range.start, |(&base, _)| base);
        self.0
            .extract_if(first..range.end, |_, reservation| {
                reservation.range().end > range.start
            })
            .map(|(_, reservation)| reservation)
            .collect()
    }
}

/// Zero-sized storage for managers whose reservation coverage equals their VMA coverage.
///
/// Providers selecting this store must implement
/// [`PageManagementProvider::reserve_and_commit_pages`]. Returning
/// [`ReserveAndCommitError::UnsupportedByPlatform`] from that operation is an invariant violation.
#[doc(hidden)]
pub struct NoReservations<
    const ALIGN: usize,
    Reservation: PageReservation = UntrackedReservation<ALIGN>,
>(PhantomData<Reservation>);

crate::define_page_reservation!(UntrackedReservation);

impl<const ALIGN: usize> From<UntrackedReservation<ALIGN>> for Range<usize> {
    fn from(reservation: UntrackedReservation<ALIGN>) -> Self {
        reservation.range()
    }
}

impl<const ALIGN: usize> NoReservations<ALIGN> {
    /// Represent an exclusively owned range without storing a reservation handle.
    ///
    /// # Safety
    ///
    /// `range` must be exclusively owned, nonempty, and `ALIGN`-aligned.
    pub unsafe fn from_owned_range(range: Range<usize>) -> UntrackedReservation<ALIGN> {
        // SAFETY: The caller establishes the reservation ownership and alignment requirements.
        unsafe { UntrackedReservation::new(range) }
    }
}

impl<const ALIGN: usize, Reservation: PageReservation> Default
    for NoReservations<ALIGN, Reservation>
{
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<const ALIGN: usize, Reservation: PageReservation> Index<&usize>
    for NoReservations<ALIGN, Reservation>
{
    type Output = Reservation;

    fn index(&self, _: &usize) -> &Self::Output {
        unreachable!("provider-managed reservations have no handles")
    }
}

impl<const STORE_ALIGN: usize, Reservation: PageReservation> ReservationStore
    for NoReservations<STORE_ALIGN, Reservation>
where
    Range<usize>: From<Reservation>,
{
    type Reservation = Reservation;
    type ReleaseTarget = Range<usize>;

    fn overlaps<V>(&self, vmas: &RangeMap<usize, V>, range: Range<usize>, _: bool) -> bool {
        vmas.overlaps(&range)
    }

    unsafe fn take_replaced<V>(
        &mut self,
        _: &RangeMap<usize, V>,
        _: Range<usize>,
    ) -> Vec<Self::Reservation> {
        Vec::new()
    }

    unsafe fn mmap<Platform, const ALIGN: usize, V: Clone + Eq>(
        &mut self,
        _: &mut RangeMap<usize, V>,
        platform: &Platform,
        request: MmapRequest,
    ) -> Result<Range<usize>, AllocationError>
    where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>,
    {
        let MmapRequest {
            range,
            permissions,
            can_grow_down,
            populate,
            behavior,
        } = request;
        // SAFETY: The caller authorizes replacement and guarantees accurate mapping ownership.
        let reservation = match unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                range.clone(),
                permissions,
                can_grow_down,
                populate,
                behavior,
            )
        } {
            Ok(reservation) => reservation,
            Err(ReserveAndCommitError::UnsupportedByPlatform) => {
                panic!("providers using NoReservations must implement reserve_and_commit_pages")
            }
            Err(ReserveAndCommitError::Allocation(error)) => return Err(error),
        };
        let range = reservation.range();
        Ok(range)
    }

    unsafe fn unmap<Platform, const ALIGN: usize, V: Clone + Eq>(
        &mut self,
        vmas: &mut RangeMap<usize, V>,
        platform: &Platform,
        range: Range<usize>,
    ) where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>,
    {
        vmas.remove(range.clone());
        // SAFETY: The provider owns this range directly; the caller excludes users and keeps holes unmapped.
        unsafe {
            platform.release_pages(range);
        }
    }

    unsafe fn remap<Platform, const ALIGN: usize, V: Clone + Eq, FindArea>(
        &mut self,
        vmas: &mut RangeMap<usize, V>,
        platform: &Platform,
        old_range: Range<usize>,
        permissions: MemoryRegionPermissions,
        value: V,
        find_area: FindArea,
    ) -> Result<Range<usize>, RemapError>
    where
        Platform: PageManagementProvider<ALIGN>,
        Platform::Reservations:
            ReservationStore<Reservation = Self::Reservation, ReleaseTarget = Self::ReleaseTarget>,
        FindArea: FnOnce(&Self, &RangeMap<usize, V>, bool) -> Option<Range<usize>>,
    {
        let new_range = find_area(self, vmas, false).ok_or(RemapError::OutOfMemory)?;
        // SAFETY: The caller provides an exclusively owned committed source and a free destination.
        let destination_reservation = unsafe {
            platform.try_remap_pages(core::iter::empty, old_range.clone(), new_range, permissions)
        }?;
        let destination = destination_reservation.range();
        drop(destination_reservation);
        vmas.remove(old_range);
        vmas.insert(destination.clone(), value);
        Ok(destination)
    }

    unsafe fn release_all<Platform, const ALIGN: usize, V>(
        &mut self,
        vmas: &RangeMap<usize, V>,
        platform: &Platform,
    ) where
        Platform: PageManagementProvider<ALIGN>,
        Self::ReleaseTarget: Into<ReleaseTargetOf<Platform, ALIGN>>,
    {
        for (range, _) in vmas.iter() {
            // SAFETY: The caller relinquishes this provider-owned range without remaining users.
            unsafe { platform.release_pages(range.clone().into()) };
        }
    }

    fn insert(&mut self, _: usize, _: Self::Reservation) -> Option<Self::Reservation> {
        None
    }
    fn remove(&mut self, _: &usize) -> Option<Self::Reservation> {
        None
    }
    fn get(&self, _: &usize) -> Option<&Self::Reservation> {
        None
    }
    fn len(&self) -> usize {
        0
    }
    fn is_empty(&self) -> bool {
        true
    }
    fn values(&self) -> impl DoubleEndedIterator<Item = &Self::Reservation> {
        core::iter::empty()
    }
    fn iter(&self) -> impl DoubleEndedIterator<Item = (&usize, &Self::Reservation)> {
        core::iter::empty()
    }
    fn overlapping(
        &self,
        _: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (usize, &Self::Reservation)> {
        core::iter::empty()
    }
    fn containing(&self, _: usize) -> Option<(usize, &Self::Reservation)> {
        None
    }
    fn take_all(&mut self) -> Vec<Self::Reservation> {
        Vec::new()
    }
    fn take_overlapping(&mut self, _: Range<usize>) -> Vec<Self::Reservation> {
        Vec::new()
    }
}

/// Reservation handle selected by a page-management provider.
pub type ReservationOf<Platform, const ALIGN: usize> =
    <<Platform as PageManagementProvider<ALIGN>>::Reservations as ReservationStore>::Reservation;

/// Native release ownership selected by a page-management provider.
pub type ReleaseTargetOf<Platform, const ALIGN: usize> =
    <<Platform as PageManagementProvider<ALIGN>>::Reservations as ReservationStore>::ReleaseTarget;

/// A provider for managing memory pages
///
/// `ALIGN` specifies page alignment, including reservation lengths and page-state operations.
/// [`Self::RESERVATION_ALIGNMENT`] separately specifies native reservation-base alignment.
/// `ALIGN` is a const generic so it can be used in page-aligned address and size types on stable Rust.
/// Reserve-and-commit, reserve, commit, protect, decommit, and release are required methods.
/// Other methods provide default compositions or optional platform-specific optimizations.
pub trait PageManagementProvider<const ALIGN: usize>: Sized {
    /// Reservation storage selected by page-manager policy.
    ///
    /// Its [`ReservationStore::Reservation`] is the provider's opaque ownership handle.
    /// Windows-style managers independently store that handle in
    /// [`TrackedReservations`].
    type Reservations: ReservationStore;

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
    /// This must be a nonzero power of two and a multiple of `ALIGN`. Reservation lengths
    /// still only require `ALIGN` alignment. Callers must align reservation bases before
    /// acquisition; providers must not round requests outward.
    const RESERVATION_ALIGNMENT: usize = ALIGN;

    /// Acquire an address-space extent for anonymous memory.
    ///
    /// Success leaves the entire extent logically uncommitted and inaccessible on every
    /// provider. Call [`Self::commit_pages`] before accessing its pages. Providers may use an
    /// inaccessible native mapping to emulate reservation. Native grow-down is a hint where
    /// supported; this operation never commits or populates pages.
    ///
    /// Placement is controlled by `behavior`:
    /// - [`FixedAddressBehavior::Hint`]: if any part of the requested range is already reserved,
    ///   relocate the entire request to an unused extent.
    /// - [`FixedAddressBehavior::NoReplace`]: acquire exactly the requested range, or return an
    ///   error if any part is already reserved, regardless of commitment or permissions.
    /// - [`FixedAddressBehavior::Replace`]: replace every overlapping
    ///   mapping and acquire all unreserved portions within the requested range. The result covers
    ///   the entire range at the requested address; callers need not split mixed reserved and
    ///   unreserved coverage into separate requests.
    ///
    /// Providers may reject occupied `Replace` requests; managers replace existing owned pages through their backing lifecycle
    /// instead. All successful modes preserve the requested length. The range must be nonempty
    /// and page-aligned; fresh reservation bases must also satisfy [`Self::RESERVATION_ALIGNMENT`].
    /// Zero is allowed only as an address hint. Returned extents must lie within task bounds.
    /// Success returns ownership of the actual extent. For replacement, the caller splits
    /// overlapping handles and retains unaffected prefixes and suffixes inside the lazy supplier.
    /// `replaced_reservations` transfers only the replaced pieces, without merging native
    /// reservation boundaries. Failure acquires no new ownership and leaves all original handles,
    /// pages, and permissions unchanged.
    /// Providers must not return a recoverable error after destructive replacement has begun
    /// unless they can uphold this guarantee.
    /// Every recoverable error must leave the supplier uninvoked. Successful replacement must
    /// invoke it after the last recoverable failure point and exhaust the returned iterator.
    /// Consuming these handles only retires replaced ownership; it must not release the new
    /// native mapping. Providers may skip the supplier for `Hint` and `NoReplace`.
    ///
    /// # Safety
    ///
    /// For `Replace`, the caller must own or be authorized to replace every existing mapping
    /// in the requested range and exclude all users of those mappings. Other modes never
    /// replace existing memory. The caller must track and eventually release newly owned pages.
    /// Providers with exclusively managed address spaces, such as kernel providers, may rely
    /// on the caller to supply an in-bounds, nonzero range free of mappings and reservations
    /// for `Hint` and `NoReplace`; they need not search for conflicts or relocate hints.
    /// This obligation covers address-space state managed by the caller. Providers sharing an
    /// address space with external allocators must atomically detect external conflicts themselves:
    /// `Hint` must relocate and `NoReplace` must fail without modifying the conflicting mapping.
    /// The caller is not required to discover untracked external allocations before calling.
    /// The supplier and iterator must not panic or rely on replaced memory retaining its previous
    /// state. For replacement, `replaced_reservations` must yield the intersection of `range`
    /// with every live reservation acquired through this provider; none may be omitted.
    /// The caller must split handles only when the supplier is invoked and retain the outside
    /// pieces. Yielded handles must be nonempty, page-aligned, wholly contained in `range`, and
    /// in ascending, nonoverlapping order. They need not cover the entire range; unreserved gaps
    /// are allowed. Raw mappings without handles may also be replaced when the caller transfers
    /// exclusive ownership of them. For `Hint` and `NoReplace`, the iterator must be empty.
    /// Returned ownership must not be used to construct duplicate handles.
    unsafe fn reserve_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        can_grow_down: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, AllocationError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>;

    /// Commit pages within owned reservations with the requested permissions.
    ///
    /// The range may contain both uncommitted and already committed pages. Success leaves
    /// the entire range committed with the requested permissions, preserving all existing
    /// committed contents. Newly committed anonymous pages are zero-filled, including pages
    /// previously decommitted. Providers may implement this as a permission change,
    /// with zero-filled backing already established by reservation or decommit.
    /// This operation does not acquire address space. Population is a hint.
    /// The range may span multiple reservations. Providers may commit it in one native call
    /// or split it at native reservation boundaries. `covering_reservations` lazily supplies
    /// the covering handles. Providers that commit by range alone should not invoke it.
    ///
    /// On failure, successfully processed prefix segments may remain committed with the requested
    /// permissions. The failing segment and unprocessed suffix must remain unchanged.
    ///
    /// # Safety
    ///
    /// `range` must be nonempty, page-aligned, and covered without gaps by live reservations
    /// owned by the caller and acquired through this provider. The caller must retain their
    /// handles. When invoked, `covering_reservations` must yield those handles in ascending,
    /// nonoverlapping order; each must intersect `range`, and together they must cover it.
    /// Providers selecting a handle-free Linux reservation store receive an empty iterator and
    /// validate ownership from `range` directly.
    /// The caller must exclude accesses conflicting with the requested permissions.
    unsafe fn commit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        populate: bool,
    ) -> Result<(), PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>;

    /// Attempt to acquire a committed extent with a native allocation or replacement operation.
    ///
    /// Success returns ownership of the actual, entirely committed, zero-initialized extent
    /// with the requested permissions and exactly `range.len()` bytes. Placement follows
    /// [`Self::reserve_pages`], including replacement ownership: success exhausts the owned
    /// iterator supplied by `replaced_reservations`; the caller retains unaffected pieces.
    /// Existing contents in the replaced range are discarded, not preserved as in recommit.
    /// Population and grow-down are hints where supported. There is no additional uncommitted
    /// padding in the returned token. Handles must not be merged across native reservations.
    ///
    /// Providers may reject unsupported requests with
    /// [`ReserveAndCommitError::UnsupportedByPlatform`] without mutation. Only this error permits
    /// manager fallback; allocation errors propagate.
    /// Every error leaves the supplier uninvoked, existing contents, permissions, and ownership unchanged and
    /// acquires no new ownership. A destructive replacement failure that cannot uphold this
    /// guarantee must be treated as fatal, as in [`Self::reserve_pages`].
    /// Successful replacement invokes the supplier only after the last recoverable failure point.
    /// Providers may skip the supplier for `Hint` and `NoReplace`, which never modify existing ownership.
    ///
    /// # Safety
    ///
    /// The range, supplier, and owned iterator must satisfy [`Self::reserve_pages`]'s alignment,
    /// placement, supplier, and ownership-transfer requirements. In particular, the caller must
    /// retain outside pieces and yield every replaced piece, without gaps in owned coverage.
    /// As with `reserve_pages`, untracked external allocations are checked by providers that share
    /// their address space with external allocators, not by the caller.
    unsafe fn reserve_and_commit_pages<Reservations>(
        &self,
        replaced_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate: bool,
        behavior: FixedAddressBehavior,
    ) -> Result<ReservationOf<Self, ALIGN>, ReserveAndCommitError>
    where
        Reservations: Iterator<Item = ReservationOf<Self, ALIGN>>;

    /// Discard private anonymous contents and make pages inaccessible, retaining ownership.
    ///
    /// Recommit yields zero-filled pages on every provider. Providers may supply zero-filled backing lazily.
    /// To deny access while preserving contents, use [`Self::protect_pages`] instead.
    ///
    /// Already uncommitted pages are allowed. Recoverable failure must leave commitment,
    /// contents, and permissions unchanged. Failures after irreversible partial updates are fatal.
    /// The range may span multiple reservations. Providers may decommit it in one native call
    /// or split it at native reservation boundaries. `covering_reservations` lazily supplies
    /// the covering handles. Providers that decommit by range alone should not invoke it.
    ///
    /// # Safety
    ///
    /// `range` must be nonempty, page-aligned, and covered without gaps by live reservations
    /// owned by the caller and acquired through this provider. The caller must retain their
    /// handles. When invoked, `covering_reservations` must yield those handles in ascending,
    /// nonoverlapping order; each must intersect `range`, and together they must cover it.
    /// The range must have private anonymous native backing with no active users.
    /// File-backed/CoW and shared native mappings must be released or replaced instead;
    /// decommit does not promise to retain their backing association.
    unsafe fn decommit_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
    ) -> Result<(), PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>;

    /// Change permissions of owned, reserved backing without modifying its contents.
    ///
    /// The whole range must be covered by live reservations and logically committed,
    /// including committed no-access pages. Protection does not commit reserved pages
    /// or allocate backing, even when the provider uses the same native operation for commit.
    ///
    /// The range may span multiple reservations. Providers may update it in one native call
    /// or split it at native reservation boundaries. Failure must leave permissions unchanged;
    /// a provider unable to recover from a partial native update must treat that failure as fatal.
    /// `covering_reservations` lazily supplies the covering handles. Providers that protect by range alone
    /// should not invoke it, avoiding reservation lookup and traversal entirely.
    ///
    /// # Safety
    ///
    /// When invoked, `covering_reservations` must yield live handles acquired through this provider, in
    /// ascending, nonoverlapping order. Each must intersect `range`, and together they must
    /// cover it without gaps. `range` must be nonempty, page-aligned, and entirely committed.
    /// Providers selecting a handle-free Linux reservation store receive an empty iterator and
    /// validate ownership from `range` directly.
    /// The caller must exclude accesses conflicting with the requested permissions.
    unsafe fn protect_pages<'reservation, Reservations>(
        &self,
        covering_reservations: impl FnOnce() -> Reservations,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PageStateUpdateError>
    where
        Reservations: Iterator<Item = &'reservation ReservationOf<Self, ALIGN>>;

    /// Consume one owned range or native reservation.
    ///
    /// Memory, commitment, and ownership outside the target are preserved.
    /// Valid exclusive ownership makes release infallible. Any remaining physical backing is
    /// freed, whether pages are committed, inaccessible, or already decommitted; prior decommit
    /// is not required.
    /// For partial reservation release, split the handle with [`PageReservation::split`] and
    /// retain the outside pieces. Release disjoint reservations with separate calls.
    ///
    /// # Safety
    ///
    /// The target must be nonempty, `ALIGN`-aligned, owned by this provider, and have no remaining
    /// users. A reservation must be live and acquired through this provider or split from such a
    /// handle. For a range, every mapped or reserved page must be owned by the caller, and all
    /// intervening holes must remain unmapped until this call returns. The caller must exclude
    /// mappings and accesses throughout the target.
    unsafe fn release_pages(&self, target: ReleaseTargetOf<Self, ALIGN>);

    /// Attempt to move and expand committed pages using a native remap operation.
    ///
    /// The default returns [`RemapError::UnsupportedByPlatform`] without changing memory or
    /// ownership. `source_reservations` lazily transfers only the pieces inside `old_range`;
    /// the caller splits intersecting handles and retains outside pieces when invoked.
    /// Every recoverable error must leave the supplier uninvoked. Successful remapping must
    /// invoke it after the last recoverable failure point and exhaust the returned iterator.
    /// The suggested destination must not overlap any existing reservation.
    ///
    /// `new_range` specifies the requested size and a suggested destination address.
    /// Placement has [`FixedAddressBehavior::Hint`] semantics only: existing destination
    /// mappings must not be replaced. No fixed-address replacement mode is supported.
    /// The hint and size require only `ALIGN` alignment, not [`Self::RESERVATION_ALIGNMENT`].
    /// The provider handles any native reservation-alignment requirements internally.
    /// The provider may choose a different address; callers must use the returned range.
    /// The actual destination must not overlap existing ownership outside `old_range`, including
    /// prefixes and suffixes retained by the caller.
    /// Providers acquire fresh destination backing or reuse supplied source backing for
    /// in-place growth. Providers that cannot handle a request return
    /// [`RemapError::UnsupportedByPlatform`] without mutation.
    /// Success preserves the source contents and permissions in the committed destination,
    /// and zero-initializes any added pages. Reserved but uncommitted
    /// pages cannot be remapped; committed no-access pages are supported.
    ///
    /// Success leaves pages in `old_range` outside the actual destination decommitted or released.
    /// Every handle yielded by `source_reservations` is consumed on success. The returned handle
    /// represents the contiguous destination ownership; even when it reuses underlying source
    /// backing, it is a new ownership output rather than a surviving source handle. The caller
    /// retains source prefixes and suffixes outside `old_range`, and consumed source handles must
    /// not be used again.
    /// Existing pages and ownership outside `old_range` and the actual destination are preserved.
    /// An error leaves all contents, permissions, and ownership unchanged.
    ///
    /// ## Returns
    ///
    /// On success it returns one handle whose range is the actual committed destination and whose
    /// length is `new_range.len()`. A provider that cannot represent the destination exactly with
    /// one handle must return
    /// [`RemapError::UnsupportedByPlatform`] without mutation.
    /// Providers may return a range starting at `old_range.start` for in-place growth.
    /// Callers must track the returned handles, not construct handles for the returned range.
    ///
    /// # Safety
    ///
    /// When invoked, `source_reservations` must yield live handles in ascending, nonoverlapping
    /// order covering exactly `old_range` without gaps. The caller must split intersecting handles
    /// only when the supplier is invoked and retain outside pieces. Native reservation boundaries
    /// must be preserved. The supplier and iterator must not panic or depend on source memory
    /// retaining its previous contents or mapping.
    /// The caller must exclusively own these handles, ensure the source pages are entirely
    /// committed and not in active use, and relinquish the yielded ownership on success.
    /// `permissions` must describe the current permissions of the entire source range.
    ///
    /// The `new_range` must be strictly larger than `old_range` and must not overlap any
    /// existing reservation, including the supplied source reservations.
    /// Providers with exclusively managed address spaces require the caller to select an
    /// in-bounds, nonzero destination free of mappings and reservations, and keep it free
    /// until this call returns. Providers relying on host allocation must preserve any
    /// conflicting host mappings, relocating or failing instead of replacing them.
    ///
    /// Both ranges must be nonempty and aligned to `ALIGN`.
    #[expect(
        unused_variables,
        reason = "default implementation does not use the parameters"
    )]
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
    /// Success returns a committed reservation of exactly `source_data.len()` bytes and consumes
    /// the replaced pieces supplied by `replaced_reservations`; the caller retains outside pieces.
    /// Every recoverable error leaves the supplier uninvoked and all original handles, contents,
    /// and permissions unchanged. Successful replacement invokes the supplier only after the last
    /// recoverable failure point and exhausts the returned iterator.
    /// Providers must not invoke the supplier for `Hint` or `NoReplace`, which never modify
    /// existing ownership and require no token splitting.
    /// The source length must be nonzero and page-aligned, and the requested address must be
    /// page-aligned. Placement and replacement ownership follow [`Self::reserve_pages`].
    ///
    /// # Safety
    ///
    /// The destination range, supplier, and owned iterator must satisfy [`Self::reserve_pages`]'s
    /// alignment, placement, supplier, and ownership-transfer requirements. The caller must
    /// retain outside pieces and yield every replaced piece, without gaps in owned coverage.
    /// The caller must track the returned ownership directly, without constructing duplicate handles.
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
    /// address if the hint is not available.
    Hint,
    /// Allocate the pages at the specified address, replacing any existing
    /// mappings.
    Replace,
    /// Allocate the pages at the specified address, failing if any part of the
    /// range is already in use.
    NoReplace,
}

/// Possible errors when acquiring address space or creating mappings.
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

/// Possible errors for [`PageManagementProvider::reserve_and_commit_pages`].
#[derive(Error, Debug)]
pub enum ReserveAndCommitError {
    #[error("native combined reservation and commitment is not supported for this request")]
    UnsupportedByPlatform,
    #[error(transparent)]
    Allocation(#[from] AllocationError),
}

/// Possible errors for lower-level page unmapping operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DeallocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
}

/// Possible errors for page-manager remapping and [`PageManagementProvider::try_remap_pages`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum RemapError {
    #[error("native page remapping is not supported by this platform")]
    UnsupportedByPlatform,
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

/// Possible errors for page commitment and permission updates.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PageStateUpdateError {
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
    #[error("platform does not support page decommitment")]
    UnsupportedByPlatform,
}

impl From<AllocationError> for PageStateUpdateError {
    fn from(value: AllocationError) -> Self {
        match value {
            AllocationError::Unaligned => Self::Unaligned,
            AllocationError::OutOfMemory => Self::OutOfMemory,
            AllocationError::PermissionDenied => Self::PermissionDenied,
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::PageReservation as PageReservationTrait;
    use core::ops::Range;

    struct PageReservation<const ALIGN: usize> {
        range: Range<usize>,
    }

    impl<const ALIGN: usize> PageReservation<ALIGN> {
        unsafe fn new(range: Range<usize>) -> Self {
            assert!(!range.is_empty());
            assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
            Self { range }
        }
    }

    unsafe impl<const ALIGN: usize> PageReservationTrait for PageReservation<ALIGN> {
        fn range(&self) -> Range<usize> {
            self.range.clone()
        }

        fn split(self, range: Range<usize>) -> (Option<Self>, Self, Option<Self>) {
            let extent = self.range;
            assert!(extent.start <= range.start && range.end <= extent.end && !range.is_empty());
            assert!(range.start.is_multiple_of(ALIGN) && range.end.is_multiple_of(ALIGN));
            (
                (extent.start < range.start).then_some(Self {
                    range: extent.start..range.start,
                }),
                Self {
                    range: range.clone(),
                },
                (range.end < extent.end).then_some(Self {
                    range: range.end..extent.end,
                }),
            )
        }
    }

    #[test]
    fn test_reservation_release_transfers_extent() {
        use super::{
            AllocationError, FixedAddressBehavior, MemoryRegionPermissions, PageManagementProvider,
            PageStateUpdateError,
        };
        use alloc::vec::Vec;
        use core::cell::RefCell;

        struct ReleaseOnly(RefCell<Vec<Range<usize>>>);

        impl PageManagementProvider<4096> for ReleaseOnly {
            type Reservations = super::TrackedReservations<PageReservation<4096>>;

            const TASK_ADDR_MIN: usize = 0x10000;
            const TASK_ADDR_MAX: usize = 0x100000;

            unsafe fn reserve_pages<Reservations>(
                &self,
                _: impl FnOnce() -> Reservations,
                _: Range<usize>,
                _: bool,
                _: FixedAddressBehavior,
            ) -> Result<PageReservation<4096>, AllocationError>
            where
                Reservations: Iterator<Item = PageReservation<4096>>,
            {
                unreachable!()
            }

            unsafe fn reserve_and_commit_pages<Reservations>(
                &self,
                _: impl FnOnce() -> Reservations,
                _: Range<usize>,
                _: MemoryRegionPermissions,
                _: bool,
                _: bool,
                _: FixedAddressBehavior,
            ) -> Result<PageReservation<4096>, super::ReserveAndCommitError>
            where
                Reservations: Iterator<Item = PageReservation<4096>>,
            {
                Err(super::ReserveAndCommitError::UnsupportedByPlatform)
            }

            unsafe fn commit_pages<'reservation, Reservations>(
                &self,
                _: impl FnOnce() -> Reservations,
                _: Range<usize>,
                _: MemoryRegionPermissions,
                _: bool,
            ) -> Result<(), PageStateUpdateError>
            where
                Reservations: Iterator<Item = &'reservation PageReservation<4096>>,
            {
                unreachable!()
            }

            unsafe fn decommit_pages<'reservation, Reservations>(
                &self,
                _: impl FnOnce() -> Reservations,
                _: Range<usize>,
            ) -> Result<(), PageStateUpdateError>
            where
                Reservations: Iterator<Item = &'reservation PageReservation<4096>>,
            {
                unreachable!()
            }

            unsafe fn protect_pages<'reservation, Reservations>(
                &self,
                _: impl FnOnce() -> Reservations,
                _: Range<usize>,
                _: MemoryRegionPermissions,
            ) -> Result<(), PageStateUpdateError>
            where
                Reservations: Iterator<Item = &'reservation PageReservation<4096>>,
            {
                unreachable!()
            }

            unsafe fn release_pages(&self, reservation: PageReservation<4096>) {
                self.0.borrow_mut().push(reservation.range());
            }
        }

        let provider = ReleaseOnly(RefCell::new(Vec::new()));
        let extents = [0x11000..0x12000, 0x14000..0x15000];
        // SAFETY: These disjoint synthetic extents have no users; all surrounding holes stay unmapped.
        unsafe {
            for range in &extents {
                provider.release_pages(PageReservation::new(range.clone()));
            }
        }
        assert_eq!(*provider.0.borrow(), extents);
    }

    #[test]
    fn test_backing_reservation_split() {
        const PAGE_SIZE: usize = 4096;

        let extent = 0x10000..0x14000;
        for (range, expected_prefix, expected_suffix) in [
            (0x10000..0x14000, None, None),
            (0x10000..0x11000, None, Some(0x11000..0x14000)),
            (0x13000..0x14000, Some(0x10000..0x13000), None),
            (
                0x11000..0x13000,
                Some(0x10000..0x11000),
                Some(0x13000..0x14000),
            ),
        ] {
            // SAFETY: The test exclusively owns this synthetic page-aligned extent.
            let reservation = unsafe { PageReservation::<PAGE_SIZE>::new(extent.clone()) };
            let (prefix, selected, suffix) = reservation.split(range.clone());
            assert_eq!(selected.range(), range);
            assert_eq!(prefix.map(|handle| handle.range()), expected_prefix);
            assert_eq!(suffix.map(|handle| handle.range()), expected_suffix);
        }

        for start in [0x10001, 0x10fff] {
            assert!(
                std::panic::catch_unwind(|| {
                    // SAFETY: This synthetic bookkeeping range is never used for backing operations.
                    let _reservation = unsafe { PageReservation::<PAGE_SIZE>::new(start..0x14000) };
                })
                .is_err()
            );
        }
        assert!(
            std::panic::catch_unwind(|| {
                // SAFETY: This synthetic bookkeeping range is never used for backing operations.
                let _reservation = unsafe { PageReservation::<0x10000>::new(0x11000..0x20000) };
            })
            .is_err()
        );
        for range in [0x11000..0x20000, 0x10000..0x21000] {
            assert!(
                std::panic::catch_unwind(|| {
                    // SAFETY: The fixture exclusively owns this synthetic aligned extent.
                    let reservation = unsafe { PageReservation::<0x10000>::new(0x10000..0x30000) };
                    let _pieces = reservation.split(range);
                })
                .is_err()
            );
        }
        // SAFETY: The fixture exclusively owns this synthetic aligned extent.
        let reservation = unsafe { PageReservation::<0x10000>::new(0x10000..0x30000) };
        let (_, selected, suffix) = reservation.split(0x10000..0x20000);
        assert_eq!(selected.range(), 0x10000..0x20000);
        assert_eq!(suffix.unwrap().range(), 0x20000..0x30000);
    }
}
