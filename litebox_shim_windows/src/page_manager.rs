// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-style explicit reservation, commitment, decommitment, and release.

use alloc::collections::BTreeMap;
use core::ops::Range;

use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox::platform::common_providers::reservations::TrackedReservations;
use litebox::platform::page_mgmt::{
    AllocationDirection, AllocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PageReservation as _, ReleaseTargetOf, ReservationStore as _,
};
use litebox::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use litebox_common_linux::vmem::{
    CreatePagesFlags, MappingError, VmFlags, VmemProtectError, VmemUnmapError,
};
use rangemap::RangeMap;

use crate::PAGE_SIZE;

type Reservations<Platform> = TrackedReservations<<Platform as crate::ShimPlatform>::Reservation>;

/// Initial state of freshly allocated private pages.
#[derive(Clone, Copy)]
pub(crate) enum PrivatePages {
    /// Inaccessible reserved address space.
    Reserved,
    /// Inaccessible reserved address space that [`WindowsVmem::merge_reservations`] can later
    /// join with adjacent mergeable reservations.
    Mergeable,
    /// Address space committed with the given permissions.
    Committed(MemoryRegionPermissions),
}

pub(crate) struct WindowsVmem<Platform>
where
    Platform: crate::ShimPlatform,
{
    platform: &'static Platform,
    reservations: Reservations<Platform>,
    mappings: RangeMap<usize, VmFlags>,
    /// Guest-visible Windows allocations, kept under the same lock as the page state they
    /// describe so no lock ordering is needed between them.
    allocations: BTreeMap<usize, crate::WindowsVirtualAllocation>,
}

impl<Platform> WindowsVmem<Platform>
where
    Platform: crate::ShimPlatform,
{
    fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            reservations: TrackedReservations::<Platform::Reservation>::default(),
            mappings: RangeMap::new(),
            allocations: BTreeMap::new(),
        }
    }

    pub(crate) fn allocations(&self) -> &BTreeMap<usize, crate::WindowsVirtualAllocation> {
        &self.allocations
    }

    pub(crate) fn allocations_mut(
        &mut self,
    ) -> &mut BTreeMap<usize, crate::WindowsVirtualAllocation> {
        &mut self.allocations
    }

    pub(crate) fn is_range_mapped(&self, range: &Range<usize>) -> bool {
        range.start <= range.end && self.mappings.gaps(range).next().is_none()
    }

    unsafe fn create_private_pages(
        &mut self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        address_bounds: Range<usize>,
        length: NonZeroPageSize<PAGE_SIZE>,
        alignment: usize,
        flags: CreatePagesFlags,
        pages: PrivatePages,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        if !alignment.is_power_of_two() || !alignment.is_multiple_of(PAGE_SIZE) {
            return Err(MappingError::UnAligned);
        }
        if flags.intersects(CreatePagesFlags::MAP_FILE | CreatePagesFlags::SHARED) {
            return Err(MappingError::InvalidPermissions);
        }
        let alignment = alignment.max(Platform::RESERVATION_ALIGNMENT);
        let direction = if flags.contains(CreatePagesFlags::TOP_DOWN) {
            AllocationDirection::TopDown
        } else {
            AllocationDirection::BottomUp
        };
        let fixed = flags.contains(CreatePagesFlags::FIXED_ADDR);
        let mut preferred = suggested_address.map_or(0, NonZeroAddress::as_usize);
        if !preferred.is_multiple_of(alignment) {
            return Err(MappingError::UnAligned);
        }
        let mut address_bounds = address_bounds.start.max(Platform::TASK_ADDR_MIN)
            ..address_bounds.end.min(Platform::TASK_ADDR_MAX);
        loop {
            let start = if fixed {
                if preferred < address_bounds.start {
                    return Err(AllocationError::BelowMinAddress.into());
                }
                if preferred
                    .checked_add(length.as_usize())
                    .is_none_or(|end| end > address_bounds.end)
                {
                    return Err(AllocationError::AboveMaxAddress.into());
                }
                preferred
            } else {
                find_reservation_gap::<Platform>(
                    &self.reservations,
                    preferred,
                    length.as_usize(),
                    alignment,
                    &address_bounds,
                    direction,
                )
                .ok_or(MappingError::OutOfMemory)?
            };
            let requested = start..start + length.as_usize();
            // SAFETY: Selection and publication occur while this state is exclusively borrowed;
            // native allocation never replaces mappings.
            match unsafe { self.allocate_private_pages(requested.clone(), flags, pages) } {
                Err(MappingError::MapError(
                    AllocationError::AddressInUse | AllocationError::AddressInUseByPlatform,
                )) if !fixed => {
                    if preferred == start && preferred != 0 {
                        preferred = 0;
                    } else if direction == AllocationDirection::TopDown {
                        preferred = 0;
                        address_bounds.end = requested
                            .end
                            .checked_sub(alignment)
                            .ok_or(MappingError::OutOfMemory)?;
                    } else {
                        preferred = 0;
                        address_bounds.start = start
                            .checked_add(alignment)
                            .ok_or(MappingError::OutOfMemory)?;
                    }
                }
                result => return result,
            }
        }
    }

    /// Reserves `requested` in the initial state described by `pages`.
    unsafe fn allocate_private_pages(
        &mut self,
        requested: Range<usize>,
        flags: CreatePagesFlags,
        pages: PrivatePages,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        if self
            .reservations
            .overlapping(requested.clone())
            .next()
            .is_some()
        {
            return Err(AllocationError::AddressInUse.into());
        }
        let reservation = match pages {
            // SAFETY: Existing reservations were checked above and replacement is disabled.
            PrivatePages::Committed(permissions) => {
                unsafe { self.reserve_and_commit_private(requested.clone(), flags, permissions) }?
            }
            // SAFETY: Existing reservations were checked above and replacement is disabled.
            PrivatePages::Mergeable => unsafe {
                self.platform.reserve_mergeable_pages(
                    core::iter::empty,
                    requested.clone(),
                    false,
                    FixedAddressBehavior::NoReplace,
                )
            }
            .map_err(platform_allocation_error)?,
            // SAFETY: Existing reservations were checked above and replacement is disabled.
            PrivatePages::Reserved => unsafe {
                self.platform.reserve_pages(
                    core::iter::empty,
                    requested.clone(),
                    false,
                    FixedAddressBehavior::NoReplace,
                )
            }
            .map_err(platform_allocation_error)?,
        };
        let range = reservation.range();
        assert_eq!(range, requested);
        let ptr = Platform::RawMutPointer::<u8>::from_usize(range.start);
        if let PrivatePages::Committed(permissions) = pages {
            self.mappings.insert(
                range.clone(),
                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
            );
        }
        assert!(self.reservations.insert(range.start, reservation).is_none());
        Ok(ptr)
    }

    /// Reserves and commits `requested` natively, falling back to a separate reserve and commit
    /// when the platform cannot do both at once.
    ///
    /// # Safety
    /// `requested` must not overlap any owned reservation.
    unsafe fn reserve_and_commit_private(
        &self,
        requested: Range<usize>,
        flags: CreatePagesFlags,
        permissions: MemoryRegionPermissions,
    ) -> Result<Platform::Reservation, MappingError> {
        let populate = flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY);
        // SAFETY: The caller guarantees the range is unowned; replacement is disabled.
        match unsafe {
            self.platform.reserve_and_commit_pages(
                core::iter::empty,
                requested.clone(),
                permissions,
                false,
                populate,
                FixedAddressBehavior::NoReplace,
            )
        } {
            Ok(reservation) => Ok(reservation),
            Err(AllocationError::UnsupportedByPlatform) => {
                // SAFETY: This fresh request cannot replace existing ownership.
                let reservation = unsafe {
                    self.platform.reserve_pages(
                        core::iter::empty,
                        requested,
                        false,
                        FixedAddressBehavior::NoReplace,
                    )
                }
                .map_err(platform_allocation_error)?;
                let actual = reservation.range();
                // SAFETY: The fresh reservation exclusively covers `actual` and is unpublished.
                if let Err(error) = unsafe {
                    self.platform.commit_pages(
                        || core::iter::once(&reservation),
                        actual,
                        permissions,
                        populate,
                    )
                } {
                    // SAFETY: Failed commitment leaves this unpublished reservation unused.
                    let _ = unsafe {
                        self.platform
                            .release_pages(into_release_target::<Platform>(reservation))
                    };
                    return Err(error.into());
                }
                Ok(reservation)
            }
            Err(error) => Err(platform_allocation_error(error).into()),
        }
    }

    pub(crate) unsafe fn commit_pages(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        let Some(reservation) = containing_reservation::<Platform>(&self.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: One retained reservation covers the range, and the caller excludes accesses
        // that conflict with commitment or permission changes.
        unsafe {
            self.platform.commit_pages(
                || core::iter::once(reservation),
                range.clone(),
                permissions,
                false,
            )
        }
        .map_err(|_| VmemProtectError::UnsupportedProtection)?;
        self.mappings.insert(
            range,
            VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
        );
        Ok(())
    }

    pub(crate) unsafe fn decommit_pages(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        let Some(reservation) = containing_reservation::<Platform>(&self.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: The retained reservation covers the range and the caller relinquishes contents.
        unsafe {
            self.platform
                .decommit_pages(|| core::iter::once(reservation), range.clone())
        }
        .map_err(|_| VmemProtectError::InvalidRange(range.clone()))?;
        self.mappings.remove(range);
        Ok(())
    }

    /// Joins the mergeable reservations exactly covering `range` into one reservation, so later
    /// operations within `range` stay inside a single native reservation.
    ///
    /// # Safety
    /// Every reservation overlapping `range` must come from [`Self::allocate_private_pages`]
    /// with [`PrivatePages::Mergeable`], and the caller must exclude all users of `range`.
    pub(crate) unsafe fn merge_reservations(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        if self.mappings.overlapping(range.clone()).next().is_some()
            || self.reservations.gaps(range.clone()).next().is_some()
        {
            return Err(VmemProtectError::InvalidRange(range));
        }
        if containing_reservation::<Platform>(&self.reservations, &range).is_some() {
            return Ok(());
        }
        let pieces = self.reservations.take_replaced(range.clone());
        // SAFETY: The pieces are contiguous, ascending, mergeable per the caller contract, and
        // uncommitted because no mapping overlaps `range`.
        let merged = unsafe { self.platform.merge_reservations(pieces) };
        assert_eq!(merged.range(), range);
        assert!(self.reservations.insert(range.start, merged).is_none());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn reservation_ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.reservations
            .iter()
            .map(|(_, reservation)| reservation.range())
    }

    /// Returns the range of the reservation containing `address`, if any.
    pub(crate) fn reservation_containing(&self, address: usize) -> Option<Range<usize>> {
        let end = address.checked_add(1)?;
        self.reservations
            .overlapping(address..end)
            .next()
            .map(litebox::platform::page_mgmt::PageReservation::range)
    }

    /// Returns the start of the first reservation beginning above `address` and below `limit`.
    pub(crate) fn next_reservation_start(&self, address: usize, limit: usize) -> Option<usize> {
        self.reservations
            .overlapping(address..limit)
            .map(litebox::platform::page_mgmt::PageReservation::range)
            .find(|range| range.start > address)
            .map(|range| range.start)
    }

    pub(crate) fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<PAGE_SIZE>,
        len: NonZeroPageSize<PAGE_SIZE>,
    ) -> Option<MemoryRegionPermissions> {
        let range = ptr.as_usize()..ptr.as_usize().checked_add(len.as_usize())?;
        let mut covered_until = range.start;
        let mut permissions = None;
        for (mapped, flags) in self.mappings.overlapping(range.clone()) {
            if mapped.start > covered_until {
                return None;
            }
            let current = MemoryRegionPermissions::from(*flags);
            if permissions.is_some_and(|permissions| permissions != current) {
                return None;
            }
            permissions = Some(current);
            covered_until = covered_until.max(mapped.end);
            if covered_until >= range.end {
                return permissions;
            }
        }
        None
    }

    pub(crate) unsafe fn protect_pages(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        if !self.is_range_mapped(&range) {
            return Err(VmemProtectError::InvalidRange(range));
        }
        let Some(reservation) = containing_reservation::<Platform>(&self.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: The range is committed and covered by the retained reservation; the caller
        // excludes accesses that conflict with the permission change.
        unsafe {
            self.platform.protect_pages(
                || core::iter::once(reservation),
                range.clone(),
                permissions,
            )
        }?;
        self.mappings.insert(
            range,
            VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
        );
        Ok(())
    }

    pub(crate) unsafe fn remove_pages(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let start = ptr.as_usize();
        let range = page_range(start, len).ok_or(VmemUnmapError::UnAligned)?;
        if containing_reservation::<Platform>(&self.reservations, &range).is_none() {
            return Err(litebox::platform::page_mgmt::DeallocationError::AlreadyUnallocated.into());
        }
        self.mappings.remove(range.clone());
        let reservations = self.reservations.take_replaced(range);
        for reservation in reservations {
            // SAFETY: The caller relinquishes this owned range and excludes remaining users.
            unsafe {
                self.platform
                    .release_pages(into_release_target::<Platform>(reservation))
            }?;
        }
        Ok(())
    }

    pub(crate) fn mappings(&self) -> &RangeMap<usize, VmFlags> {
        &self.mappings
    }

    /// Releases the pages of the allocation recorded at `base` together with its record, so
    /// no other thread can observe one without the other.
    ///
    /// On failure the record is retained.
    ///
    /// # Safety
    /// Same contract as [`Self::remove_pages`].
    pub(crate) unsafe fn release_allocation(
        &mut self,
        base: usize,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        // SAFETY: Forwarded caller contract.
        unsafe { self.remove_pages(Platform::RawMutPointer::<u8>::from_usize(base), len) }?;
        self.allocations.remove(&base);
        Ok(())
    }
}

/// Owns Windows guest reservations independently from their committed page ranges.
pub(crate) struct WindowsPageManager<Platform>
where
    Platform: crate::ShimPlatform,
{
    vmem: RwLock<Platform, WindowsVmem<Platform>>,
}

impl<Platform> WindowsPageManager<Platform>
where
    Platform: crate::ShimPlatform,
{
    pub(crate) fn new(platform: &'static Platform) -> Self {
        Self {
            vmem: RwLock::new(WindowsVmem::new(platform)),
        }
    }

    /// Reserves aligned private address space within exclusive bounds in the initial state
    /// described by `pages`.
    ///
    /// # Safety
    /// The caller must not access uncommitted pages and must exclude accesses conflicting with
    /// the requested permissions.
    pub(crate) unsafe fn create_private_pages(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        address_bounds: Range<usize>,
        length: NonZeroPageSize<PAGE_SIZE>,
        alignment: usize,
        flags: CreatePagesFlags,
        pages: PrivatePages,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let mut vmem = self.vmem.write();
        // SAFETY: The write guard provides exclusive state access and forwards the caller contract.
        unsafe {
            vmem.create_private_pages(
                suggested_address,
                address_bounds,
                length,
                alignment,
                flags,
                pages,
            )
        }
    }

    pub(crate) unsafe fn create_reserved_pages(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        alignment: usize,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        // SAFETY: Forwarded caller contract; the fresh reservation remains inaccessible.
        unsafe {
            self.create_private_pages(
                suggested_address,
                Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX,
                length,
                alignment,
                flags,
                PrivatePages::Reserved,
            )
        }
    }

    pub(crate) unsafe fn create_reserved_and_committed_pages(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        alignment: usize,
        flags: CreatePagesFlags,
        permissions: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        // SAFETY: Forwarded caller contract; initialization is completed before publication.
        unsafe {
            self.create_private_pages(
                suggested_address,
                Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX,
                length,
                alignment,
                flags,
                PrivatePages::Committed(permissions),
            )
        }
    }

    pub(crate) fn create_initialized_pages(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        alignment: usize,
        flags: CreatePagesFlags,
        permissions: MemoryRegionPermissions,
        op: impl FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let writable = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // SAFETY: This acquires fresh private address space without replacement.
        let ptr = unsafe {
            self.create_reserved_and_committed_pages(
                suggested_address,
                length,
                alignment,
                flags,
                writable,
            )
        }?;
        if let Err(error) = op(ptr) {
            // SAFETY: Initialization failed before publication, so the mapping has no users.
            unsafe { self.remove_pages(ptr, length.as_usize()) }
                .expect("failed to release unpublished mapping");
            return Err(error);
        }
        if permissions != writable {
            // SAFETY: The mapping is unpublished and exclusively owned during initialization.
            if unsafe { self.protect_pages(ptr, length.as_usize(), permissions) }.is_err() {
                // SAFETY: Protection failed before publication, so the mapping has no users.
                unsafe { self.remove_pages(ptr, length.as_usize()) }
                    .expect("failed to release unpublished mapping");
                return Err(MappingError::OutOfMemory);
            }
        }
        Ok(ptr)
    }

    pub(crate) fn read_vmem(&self) -> RwLockReadGuard<'_, Platform, WindowsVmem<Platform>> {
        self.vmem.read()
    }

    /// Locks the page state and guest allocations together for a combined update.
    pub(crate) fn write_vmem(&self) -> RwLockWriteGuard<'_, Platform, WindowsVmem<Platform>> {
        self.vmem.write()
    }

    unsafe fn protect_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        // SAFETY: The write guard provides exclusive state access and forwards the caller contract.
        unsafe { vmem.protect_pages(ptr, len, permissions) }
    }

    pub(crate) unsafe fn make_pages_writable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe {
            self.protect_pages(
                ptr,
                len,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )
        }
    }

    pub(crate) unsafe fn remove_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let mut vmem = self.vmem.write();
        // SAFETY: The write guard provides exclusive state access and forwards the caller contract.
        unsafe { vmem.remove_pages(ptr, len) }
    }
}

fn find_reservation_gap<Platform>(
    reservations: &Reservations<Platform>,
    preferred: usize,
    len: usize,
    alignment: usize,
    address_bounds: &Range<usize>,
    direction: AllocationDirection,
) -> Option<usize>
where
    Platform: crate::ShimPlatform,
{
    let is_available = |start: usize| {
        let end = start.checked_add(len)?;
        (start >= address_bounds.start && end <= address_bounds.end)
            .then(|| {
                reservations
                    .overlapping(start..end)
                    .next()
                    .is_none()
                    .then_some(start)
            })
            .flatten()
    };
    if preferred != 0
        && let Some(start) = is_available(preferred)
    {
        return Some(start);
    }

    let low = address_bounds.start.checked_next_multiple_of(alignment)?;
    if address_bounds.end.checked_sub(low)? < len {
        return None;
    }
    if direction == AllocationDirection::TopDown {
        let mut boundary = address_bounds.end;
        for (_, reservation) in reservations.iter().rev() {
            let range = reservation.range();
            if range.start >= boundary {
                continue;
            }
            if range.end <= low {
                break;
            }
            let candidate = boundary.checked_sub(len)? & !(alignment - 1);
            if candidate >= range.end.max(low) {
                return Some(candidate);
            }
            boundary = boundary.min(range.start);
        }
        let candidate = boundary.checked_sub(len)? & !(alignment - 1);
        return (candidate >= low).then_some(candidate);
    }
    let mut candidate = low;
    for (_, reservation) in reservations.iter() {
        let range = reservation.range();
        if range.end <= candidate {
            continue;
        }
        if candidate.checked_add(len)? <= range.start.min(address_bounds.end) {
            return Some(candidate);
        }
        candidate = range.end.checked_next_multiple_of(alignment)?;
        if candidate.checked_add(len)? > address_bounds.end {
            return None;
        }
    }
    is_available(candidate)
}

/// Distinguishes host-side collisions from overlaps with guest-owned reservations.
fn platform_allocation_error(error: AllocationError) -> AllocationError {
    match error {
        AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
        other => other,
    }
}

fn page_range(start: usize, len: usize) -> Option<Range<usize>> {
    let end = start.checked_add(len)?;
    (len != 0 && start.is_multiple_of(PAGE_SIZE) && end.is_multiple_of(PAGE_SIZE))
        .then_some(start..end)
}

/// Returns the single retained reservation containing `range`.
///
/// Every guest allocation lies within one reservation: coalesced placeholders merge their
/// reservations, so native range operations never need to span several of them.
fn containing_reservation<'a, Platform>(
    reservations: &'a Reservations<Platform>,
    range: &Range<usize>,
) -> Option<&'a Platform::Reservation>
where
    Platform: crate::ShimPlatform,
{
    reservations
        .overlapping(range.clone())
        .next()
        .filter(|reservation| {
            let extent = reservation.range();
            extent.start <= range.start && range.end <= extent.end
        })
}

fn into_release_target<Platform>(
    reservation: <Platform::PlatformReservations as litebox::platform::page_mgmt::ReservationStore>::Reservation,
) -> ReleaseTargetOf<Platform, PAGE_SIZE>
where
    Platform: crate::ShimPlatform,
{
    <Platform::PlatformReservations as litebox::platform::page_mgmt::ReservationStore>::ReleaseTarget::from(
        reservation,
    )
}
