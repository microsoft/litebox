// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-style explicit reservation, commitment, decommitment, and release.

use core::ops::Range;

use litebox::mm::page::{NonZeroAddress, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox::platform::common_providers::reservations::TrackedReservations;
use litebox::platform::page_mgmt::{
    AllocationDirection, AllocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PageReservation as _, ReleaseTargetOf, ReservationStore as _,
};
use litebox::sync::{RwLock, RwLockReadGuard};
use litebox_common_linux::vmem::{
    CreatePagesFlags, MappingError, VmFlags, VmemProtectError, VmemUnmapError,
};
use rangemap::RangeMap;

use crate::PAGE_SIZE;

type Reservations<Platform> = TrackedReservations<<Platform as crate::ShimPlatform>::Reservation>;

pub(crate) struct WindowsVmem<Platform>
where
    Platform: crate::ShimPlatform,
{
    platform: &'static Platform,
    reservations: Reservations<Platform>,
    mappings: RangeMap<usize, VmFlags>,
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
        }
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
        permissions: Option<MemoryRegionPermissions>,
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
            match unsafe { self.allocate_private_pages(requested.clone(), flags, permissions) } {
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

    unsafe fn allocate_private_pages(
        &mut self,
        requested: Range<usize>,
        flags: CreatePagesFlags,
        permissions: Option<MemoryRegionPermissions>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        if self
            .reservations
            .overlapping(requested.clone())
            .next()
            .is_some()
        {
            return Err(AllocationError::AddressInUse.into());
        }
        let platform_allocation_error = |error| match error {
            AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
            other => other,
        };

        let reservation = if let Some(permissions) = permissions {
            // SAFETY: Existing reservations were checked above and replacement is disabled.
            match unsafe {
                self.platform.reserve_and_commit_pages(
                    core::iter::empty,
                    requested.clone(),
                    permissions,
                    false,
                    flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                    FixedAddressBehavior::NoReplace,
                )
            } {
                Ok(reservation) => reservation,
                Err(AllocationError::UnsupportedByPlatform) => {
                    // SAFETY: This fresh request cannot replace existing ownership.
                    let reservation = unsafe {
                        self.platform.reserve_pages(
                            core::iter::empty,
                            requested.clone(),
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
                            flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                        )
                    } {
                        // SAFETY: Failed commitment leaves this unpublished reservation unused.
                        let _ = unsafe {
                            self.platform
                                .release_pages(into_release_target::<Platform>(reservation))
                        };
                        return Err(error.into());
                    }
                    reservation
                }
                Err(error) => return Err(platform_allocation_error(error).into()),
            }
        } else {
            // SAFETY: Existing reservations were checked above and replacement is disabled.
            unsafe {
                self.platform.reserve_pages(
                    core::iter::empty,
                    requested.clone(),
                    false,
                    FixedAddressBehavior::NoReplace,
                )
            }
            .map_err(platform_allocation_error)?
        };
        let range = reservation.range();
        assert_eq!(range, requested);
        let ptr = Platform::RawMutPointer::<u8>::from_usize(range.start);
        if let Some(permissions) = permissions {
            self.mappings.insert(
                range.clone(),
                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
            );
        }
        assert!(self.reservations.insert(range.start, reservation).is_none());
        Ok(ptr)
    }

    unsafe fn commit_pages(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        let Some(reservations) = covering_reservations::<Platform>(&self.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: Retained reservations cover the range, and the caller excludes accesses
        // that conflict with commitment or permission changes.
        let committed = unsafe {
            self.platform
                .commit_pages(|| reservations, range.clone(), permissions, false)
        };
        if committed.is_err() {
            // A range spanning several reservations is committed piecewise, so a failure may
            // leave earlier pieces committed. Restore the state recorded in `mappings`.
            self.rollback_failed_commit(&range);
            return Err(VmemProtectError::UnsupportedProtection);
        }
        self.mappings.insert(
            range,
            VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
        );
        Ok(())
    }

    /// Best-effort restoration of `range` to the commitment and permissions recorded in
    /// `mappings` after a partially applied commit.
    fn rollback_failed_commit(&self, range: &Range<usize>) {
        for gap in self.mappings.gaps(range) {
            if let Some(reservations) = covering_reservations::<Platform>(&self.reservations, &gap)
            {
                // SAFETY: The gap was uncommitted before the failed commit, so it holds no
                // guest contents, and the caller's exclusion of conflicting accesses still holds.
                let _ = unsafe { self.platform.decommit_pages(|| reservations, gap.clone()) };
            }
        }
        for (mapped, flags) in self.mappings.overlapping(range.clone()) {
            let restored = mapped.start.max(range.start)..mapped.end.min(range.end);
            if let Some(reservations) =
                covering_reservations::<Platform>(&self.reservations, &restored)
            {
                // SAFETY: The range was committed before the failed commit, which preserved its
                // contents; this only reapplies its previously recorded permissions.
                let _ = unsafe {
                    self.platform.protect_pages(
                        || reservations,
                        restored.clone(),
                        MemoryRegionPermissions::from(*flags),
                    )
                };
            }
        }
    }

    unsafe fn decommit_pages(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        let Some(reservations) = covering_reservations::<Platform>(&self.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: Retained reservations cover the range and the caller relinquishes contents.
        unsafe { self.platform.decommit_pages(|| reservations, range.clone()) }
            .map_err(|_| VmemProtectError::InvalidRange(range.clone()))?;
        self.mappings.remove(range);
        Ok(())
    }

    pub(crate) fn reservation_ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.reservations
            .iter()
            .map(|(_, reservation)| reservation.range())
    }

    fn get_memory_permissions(
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

    unsafe fn protect_pages(
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
        let Some(reservations) = covering_reservations::<Platform>(&self.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: The range is committed and covered by retained reservations; the caller
        // excludes accesses that conflict with the permission change.
        unsafe {
            self.platform
                .protect_pages(|| reservations, range.clone(), permissions)
        }?;
        self.mappings.insert(
            range,
            VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
        );
        Ok(())
    }

    unsafe fn remove_pages(
        &mut self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let start = ptr.as_usize();
        let range = page_range(start, len).ok_or(VmemUnmapError::UnAligned)?;
        if covering_reservations::<Platform>(&self.reservations, &range).is_none() {
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

    /// Reserves aligned private address space within exclusive bounds, optionally committing it.
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
        permissions: Option<MemoryRegionPermissions>,
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
                permissions,
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
                None,
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
                Some(permissions),
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

    pub(crate) unsafe fn commit_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        // SAFETY: The write guard provides exclusive state access and forwards the caller contract.
        unsafe { vmem.commit_pages(ptr, len, permissions) }
    }

    pub(crate) unsafe fn decommit_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        // SAFETY: The write guard provides exclusive state access and forwards the caller contract.
        unsafe { vmem.decommit_pages(ptr, len) }
    }

    pub(crate) fn read_vmem(&self) -> RwLockReadGuard<'_, Platform, WindowsVmem<Platform>> {
        self.vmem.read()
    }

    pub(crate) fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<PAGE_SIZE>,
        len: NonZeroPageSize<PAGE_SIZE>,
    ) -> Option<MemoryRegionPermissions> {
        self.vmem.read().get_memory_permissions(ptr, len)
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

    pub(crate) unsafe fn make_pages_inaccessible(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe { self.protect_pages(ptr, len, MemoryRegionPermissions::empty()) }
    }

    pub(crate) unsafe fn make_pages_readable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe { self.protect_pages(ptr, len, MemoryRegionPermissions::READ) }
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

    pub(crate) unsafe fn make_pages_executable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe {
            self.protect_pages(
                ptr,
                len,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
            )
        }
    }

    pub(crate) unsafe fn make_pages_rwx(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe {
            self.protect_pages(
                ptr,
                len,
                MemoryRegionPermissions::READ
                    | MemoryRegionPermissions::WRITE
                    | MemoryRegionPermissions::EXEC,
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

fn page_range(start: usize, len: usize) -> Option<Range<usize>> {
    let end = start.checked_add(len)?;
    (len != 0 && start.is_multiple_of(PAGE_SIZE) && end.is_multiple_of(PAGE_SIZE))
        .then_some(start..end)
}

/// Returns the reservations overlapping `range` if they contiguously cover it.
///
/// Coverage is validated up front so platform operations never act on a partially covered
/// range; the returned iterator is passed lazily to the platform.
fn covering_reservations<'a, Platform>(
    reservations: &'a Reservations<Platform>,
    range: &Range<usize>,
) -> Option<impl Iterator<Item = &'a Platform::Reservation> + use<'a, Platform>>
where
    Platform: crate::ShimPlatform,
{
    ranges_cover(
        reservations
            .overlapping(range.clone())
            .map(litebox::platform::page_mgmt::PageReservation::range),
        range,
    )
    .then(|| reservations.overlapping(range.clone()))
}

/// Returns whether ascending, non-overlapping `extents` contiguously cover a non-empty `range`.
fn ranges_cover(extents: impl Iterator<Item = Range<usize>>, range: &Range<usize>) -> bool {
    if range.is_empty() {
        return false;
    }
    let mut covered_until = range.start;
    for extent in extents {
        if extent.start > covered_until {
            return false;
        }
        covered_until = covered_until.max(extent.end);
        if covered_until >= range.end {
            return true;
        }
    }
    false
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

#[cfg(test)]
mod tests {
    use super::ranges_cover;

    #[test]
    fn ranges_cover_requires_contiguous_coverage() {
        let range = 0x2000..0x6000;
        assert!(ranges_cover(
            [0x1000..0x3000, 0x3000..0x7000].into_iter(),
            &range
        ));
        assert!(ranges_cover(core::iter::once(0x2000..0x6000), &range));
        assert!(!ranges_cover(
            [0x1000..0x3000, 0x4000..0x7000].into_iter(),
            &range
        ));
        assert!(!ranges_cover(core::iter::once(0x3000..0x7000), &range));
        assert!(!ranges_cover(
            [0x2000..0x3000, 0x3000..0x5000].into_iter(),
            &range
        ));
        assert!(!ranges_cover(core::iter::empty(), &range));
        assert!(!ranges_cover(
            core::iter::once(0x1000..0x7000),
            &(0x2000..0x2000)
        ));
    }
}
