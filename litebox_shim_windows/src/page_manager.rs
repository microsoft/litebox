// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-style explicit reservation, commitment, decommitment, and release.

use alloc::vec::Vec;
use core::ops::Range;

use litebox::platform::RawConstPointer as _;
use litebox::platform::common_providers::reservations::TrackedReservations;
use litebox::platform::page_mgmt::{
    AllocationDirection, AllocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PageReservation as _, ReleaseTargetOf, ReservationStore as _,
};
use litebox::sync::RwLock;
use litebox_common_linux::vmem::{
    CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, VmFlags, VmemProtectError,
    VmemUnmapError,
};
use rangemap::RangeMap;

use crate::PAGE_SIZE;

type Reservations<Platform> = TrackedReservations<<Platform as crate::ShimPlatform>::Reservation>;

struct WindowsVmem<Platform>
where
    Platform: crate::ShimPlatform,
{
    reservations: Reservations<Platform>,
    mappings: RangeMap<usize, VmFlags>,
}

impl<Platform> Default for WindowsVmem<Platform>
where
    Platform: crate::ShimPlatform,
{
    fn default() -> Self {
        Self {
            reservations: TrackedReservations::<Platform::Reservation>::default(),
            mappings: RangeMap::new(),
        }
    }
}

/// Owns Windows guest reservations independently from their committed page ranges.
pub(crate) struct WindowsPageManager<Platform>
where
    Platform: crate::ShimPlatform,
{
    platform: &'static Platform,
    vmem: RwLock<Platform, WindowsVmem<Platform>>,
}

impl<Platform> WindowsPageManager<Platform>
where
    Platform: crate::ShimPlatform,
{
    pub(crate) fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            vmem: RwLock::new(WindowsVmem::default()),
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
        let mut vmem = self.vmem.write();
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
                    &vmem.reservations,
                    preferred,
                    length.as_usize(),
                    alignment,
                    &address_bounds,
                    direction,
                )
                .ok_or(MappingError::OutOfMemory)?
            };
            let requested = start..start + length.as_usize();
            // SAFETY: Selection and publication share the ownership lock; native allocation never
            // replaces mappings, and the caller observes commitment and permission requirements.
            match unsafe {
                self.allocate_private_pages(&mut vmem, requested.clone(), flags, permissions)
            } {
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
        &self,
        vmem: &mut WindowsVmem<Platform>,
        requested: Range<usize>,
        flags: CreatePagesFlags,
        permissions: Option<MemoryRegionPermissions>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        if vmem
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

        let reservation = {
            if let Some(permissions) = permissions {
                // SAFETY: Existing reservations were checked above and Windows allocations never
                // replace ownership. The returned handle remains private until it is tracked.
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
                        // SAFETY: The fresh reservation exclusively covers `actual` and is not
                        // visible to another manager operation yet.
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
            }
        };

        let range = reservation.range();
        assert_eq!(range, requested);
        let ptr = Platform::RawMutPointer::<u8>::from_usize(range.start);
        if let Some(permissions) = permissions {
            vmem.mappings.insert(
                range.clone(),
                VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
            );
        }
        assert!(vmem.reservations.insert(range.start, reservation).is_none());
        Ok(ptr)
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

    pub(crate) unsafe fn commit_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe { self.update_pages(ptr, len, permissions) }
    }

    pub(crate) unsafe fn decommit_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        let mut vmem = self.vmem.write();
        let Some(reservation) = containing_reservation::<Platform>(&vmem.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: The retained reservation covers the range and the caller relinquishes contents.
        unsafe {
            self.platform
                .decommit_pages(|| core::iter::once(reservation), range.clone())
        }
        .map_err(|_| VmemProtectError::InvalidRange(range.clone()))?;
        vmem.mappings.remove(range);
        Ok(())
    }

    pub(crate) fn reservations(&self) -> Vec<Range<usize>> {
        self.vmem
            .read()
            .reservations
            .iter()
            .map(|(_, reservation)| reservation.range())
            .collect()
    }

    pub(crate) fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<PAGE_SIZE>,
        len: NonZeroPageSize<PAGE_SIZE>,
    ) -> Option<MemoryRegionPermissions> {
        let range = ptr.as_usize()..ptr.as_usize().checked_add(len.as_usize())?;
        let vmem = self.vmem.read();
        let mut covered_until = range.start;
        let mut permissions = None;
        for (mapped, flags) in vmem.mappings.overlapping(range.clone()) {
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

    unsafe fn update_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let range = page_range(start, len)
            .ok_or_else(|| VmemProtectError::UnAligned(start..start.saturating_add(len)))?;
        let mut vmem = self.vmem.write();
        let Some(reservation) = containing_reservation::<Platform>(&vmem.reservations, &range)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        if range_is_mapped(&vmem.mappings, &range) {
            // SAFETY: The range is committed and covered by the retained reservation; the caller
            // excludes accesses that conflict with the permission change.
            unsafe {
                self.platform.protect_pages(
                    || core::iter::once(reservation),
                    range.clone(),
                    permissions,
                )
            }?;
        } else {
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
        }
        vmem.mappings.insert(
            range,
            VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
        );
        Ok(())
    }

    pub(crate) unsafe fn make_pages_inaccessible(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe { self.update_pages(ptr, len, MemoryRegionPermissions::empty()) }
    }

    pub(crate) unsafe fn make_pages_readable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe { self.update_pages(ptr, len, MemoryRegionPermissions::READ) }
    }

    pub(crate) unsafe fn make_pages_writable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        // SAFETY: Forwarded caller contract.
        unsafe {
            self.update_pages(
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
            self.update_pages(
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
            self.update_pages(
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
        let start = ptr.as_usize();
        let range = page_range(start, len).ok_or(VmemUnmapError::UnAligned)?;
        let mut vmem = self.vmem.write();
        if containing_reservation::<Platform>(&vmem.reservations, &range).is_none() {
            return Err(litebox::platform::page_mgmt::DeallocationError::AlreadyUnallocated.into());
        }
        vmem.mappings.remove(range.clone());
        let reservations = vmem.reservations.take_replaced(range);
        for reservation in reservations {
            // SAFETY: The caller relinquishes this owned range and excludes remaining users.
            unsafe {
                self.platform
                    .release_pages(into_release_target::<Platform>(reservation))
            }?;
        }
        Ok(())
    }

    pub(crate) fn mappings(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem
            .read()
            .mappings
            .iter()
            .map(|(range, flags)| (range.clone(), *flags))
            .collect()
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

fn range_is_mapped(mappings: &RangeMap<usize, VmFlags>, range: &Range<usize>) -> bool {
    let mut covered_until = range.start;
    for (mapped, _) in mappings.overlapping(range.clone()) {
        if mapped.start > covered_until {
            return false;
        }
        covered_until = covered_until.max(mapped.end);
        if covered_until >= range.end {
            return true;
        }
    }
    range.is_empty()
}

fn containing_reservation<'a, Platform>(
    reservations: &'a Reservations<Platform>,
    range: &Range<usize>,
) -> Option<&'a Platform::Reservation>
where
    Platform: crate::ShimPlatform,
{
    reservations
        .iter()
        .map(|(_, reservation)| reservation)
        .find(|reservation| {
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
