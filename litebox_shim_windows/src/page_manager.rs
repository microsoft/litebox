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

const ALLOCATION_GRANULARITY: usize = 0x1_0000;

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

    unsafe fn create_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        flags: CreatePagesFlags,
        permissions: Option<MemoryRegionPermissions>,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        if flags.intersects(CreatePagesFlags::MAP_FILE | CreatePagesFlags::SHARED) {
            return Err(MappingError::InvalidPermissions);
        }

        let direction = if flags.contains(CreatePagesFlags::TOP_DOWN) {
            AllocationDirection::TopDown
        } else {
            AllocationDirection::BottomUp
        };
        let mut start = suggested_address.map_or(0, NonZeroAddress::as_usize);
        if start != 0 && !start.is_multiple_of(ALLOCATION_GRANULARITY) {
            return Err(MappingError::UnAligned);
        }
        let padding = if flags.contains(CreatePagesFlags::FIXED_ADDR) {
            0
        } else {
            ALLOCATION_GRANULARITY.saturating_sub(PAGE_SIZE)
        };
        let requested_len = length
            .as_usize()
            .checked_add(padding)
            .ok_or(MappingError::OutOfMemory)?;
        let behavior = if flags.contains(CreatePagesFlags::FIXED_ADDR) {
            FixedAddressBehavior::NoReplace
        } else if !Platform::HINT_PLACEMENT_BEHAVIOR.supports(direction)
            && direction == AllocationDirection::BottomUp
        {
            start = find_bottom_up_gap::<Platform>(
                &self.vmem.read().reservations,
                start,
                requested_len,
            )
            .ok_or(MappingError::OutOfMemory)?;
            FixedAddressBehavior::NoReplace
        } else {
            FixedAddressBehavior::Hint(direction)
        };
        let end = start
            .checked_add(requested_len)
            .ok_or(MappingError::OutOfMemory)?;
        let requested = start..end;
        let initial_permissions =
            permissions.map(|_| MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE);

        let reservation = {
            let vmem = self.vmem.write();
            if start != 0
                && vmem
                    .reservations
                    .overlapping(requested.clone())
                    .next()
                    .is_some()
            {
                return Err(AllocationError::AddressInUse.into());
            }

            if let Some(initial_permissions) = initial_permissions {
                // SAFETY: Existing reservations were checked above and Windows allocations never
                // replace ownership. The returned handle remains private until it is tracked.
                match unsafe {
                    self.platform.reserve_and_commit_pages(
                        core::iter::empty,
                        requested.clone(),
                        initial_permissions,
                        false,
                        flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                        behavior,
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
                                behavior,
                            )
                        }?;
                        let actual = reservation.range();
                        // SAFETY: The fresh reservation exclusively covers `actual` and is not
                        // visible to another manager operation yet.
                        if let Err(error) = unsafe {
                            self.platform.commit_pages(
                                || core::iter::once(&reservation),
                                actual,
                                initial_permissions,
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
                    Err(error) => return Err(error.into()),
                }
            } else {
                // SAFETY: Existing reservations were checked above and replacement is disabled.
                unsafe {
                    self.platform
                        .reserve_pages(core::iter::empty, requested, false, behavior)
                }?
            }
        };

        let extent = reservation.range();
        let aligned_start = extent
            .start
            .checked_next_multiple_of(ALLOCATION_GRANULARITY)
            .ok_or(MappingError::OutOfMemory)?;
        let aligned_end = aligned_start
            .checked_add(length.as_usize())
            .ok_or(MappingError::OutOfMemory)?;
        if aligned_end > extent.end {
            // SAFETY: The fresh reservation has not been published.
            let _ = unsafe {
                self.platform
                    .release_pages(into_release_target::<Platform>(reservation))
            };
            return Err(MappingError::OutOfMemory);
        }
        let (prefix, reservation, suffix) = reservation.split(aligned_start..aligned_end);
        for remainder in prefix.into_iter().chain(suffix) {
            // SAFETY: Alignment trimming is unpublished and has no users.
            unsafe {
                self.platform
                    .release_pages(into_release_target::<Platform>(remainder))
            }
            .expect("failed to release unpublished alignment padding");
        }
        let range = reservation.range();
        let ptr = Platform::RawMutPointer::<u8>::from_usize(range.start);
        {
            let mut vmem = self.vmem.write();
            if vmem
                .reservations
                .overlapping(range.clone())
                .next()
                .is_some()
            {
                // SAFETY: The fresh reservation has not been published to the caller.
                let _ = unsafe {
                    self.platform
                        .release_pages(into_release_target::<Platform>(reservation))
                };
                return Err(AllocationError::AddressInUse.into());
            }
            if let Some(initial_permissions) = initial_permissions {
                vmem.mappings.insert(
                    range.clone(),
                    VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(initial_permissions),
                );
            }
            assert!(vmem.reservations.insert(range.start, reservation).is_none());
        }

        if let Err(error) = op(ptr) {
            // SAFETY: The callback failed before publishing the new allocation.
            let _ = unsafe { self.remove_pages(ptr, range.len()) };
            return Err(error);
        }

        if let Some(permissions) = permissions
            && permissions != (MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE)
            && let Err(error) =
                unsafe { self.protect_committed_pages(ptr, range.len(), permissions) }
        {
            // SAFETY: Final protection failed before publishing the allocation.
            let _ = unsafe { self.remove_pages(ptr, range.len()) };
            return Err(MappingError::ProtectError(error));
        }

        Ok(ptr)
    }

    pub(crate) unsafe fn create_reserved_pages(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        alignment: usize,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        if alignment != ALLOCATION_GRANULARITY {
            return Err(MappingError::UnAligned);
        }
        // SAFETY: Forwarded caller contract; the fresh reservation remains inaccessible.
        unsafe { self.create_pages(suggested_address, length, flags, None, |_| Ok(0)) }
    }

    pub(crate) unsafe fn create_reserved_and_committed_pages(
        &self,
        suggested_address: Option<NonZeroAddress<PAGE_SIZE>>,
        length: NonZeroPageSize<PAGE_SIZE>,
        alignment: usize,
        flags: CreatePagesFlags,
        permissions: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        if alignment != ALLOCATION_GRANULARITY {
            return Err(MappingError::UnAligned);
        }
        // SAFETY: Forwarded caller contract; initialization is completed before publication.
        unsafe {
            self.create_pages(suggested_address, length, flags, Some(permissions), |_| {
                Ok(0)
            })
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

    unsafe fn protect_committed_pages(
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
        // SAFETY: The range is committed and covered by the retained reservation; the caller
        // excludes accesses that conflict with the permission change.
        unsafe {
            self.platform.protect_pages(
                || core::iter::once(reservation),
                range.clone(),
                permissions,
            )
        }?;
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

fn find_bottom_up_gap<Platform>(
    reservations: &Reservations<Platform>,
    preferred: usize,
    len: usize,
) -> Option<usize>
where
    Platform: crate::ShimPlatform,
{
    let is_available = |start: usize| {
        let end = start.checked_add(len)?;
        (start >= Platform::TASK_ADDR_MIN && end <= Platform::TASK_ADDR_MAX)
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

    let mut candidate = Platform::TASK_ADDR_MIN.checked_next_multiple_of(ALLOCATION_GRANULARITY)?;
    for (_, reservation) in reservations.iter() {
        let range = reservation.range();
        if range.end <= candidate {
            continue;
        }
        if candidate.checked_add(len)? <= range.start {
            return Some(candidate);
        }
        candidate = range.end.checked_next_multiple_of(ALLOCATION_GRANULARITY)?;
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
