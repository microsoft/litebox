// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-style explicit reservation, commitment, decommitment, and release.

use core::ops::Range;

use super::{
    CreatePagesFlags, MappingError, NonZeroAddress, NonZeroPageSize, PageManager, PageRange,
    VmFlags, VmemProtectError, VmemUnmapError, Windows,
    vmem::{FindAreaRequest, VmArea, Vmem},
};
use crate::{
    platform::{
        PageManagementProvider, RawConstPointer, RawPointerProvider,
        page_mgmt::{
            AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
            PageReservation, PageStateUpdateError, ReservationStore, ReserveAndCommitError,
        },
    },
    sync::RawSyncPrimitivesProvider,
};

impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN, Windows>
where
    Platform: RawSyncPrimitivesProvider + RawPointerProvider + PageManagementProvider<ALIGN>,
{
    /// Reserve a fresh private address range and optionally commit it before publication.
    ///
    /// `None` permits automatic placement within `address_bounds`; a nonzero `suggested_address`
    /// requests that exact rounded address without replacement. `None` permissions leave the
    /// range reserved; `Some` permissions commit zero-initialized pages.
    ///
    /// # Safety
    ///
    /// The caller must not access uncommitted pages and must exclude accesses conflicting with
    /// the requested permissions.
    pub unsafe fn create_private_pages(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        address_bounds: Range<usize>,
        length: NonZeroPageSize<ALIGN>,
        alignment: usize,
        flags: CreatePagesFlags,
        permissions: Option<MemoryRegionPermissions>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let mut vmem = self.vmem.write();
        // SAFETY: The caller observes commitment and permission requirements; ownership changes are locked.
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

    /// Reserve a Windows-style address range without committing pages.
    ///
    /// The reservation has exactly `length` bytes and is absent from [`PageManager::mappings`].
    /// Its base satisfies both `alignment` and
    /// [`PageManagementProvider::RESERVATION_ALIGNMENT`]; lengths only require `ALIGN`
    /// alignment. `alignment` must be a nonzero power of two. Fixed requests never replace an
    /// existing reservation or mapping. Uncommitted ranges remain owned until
    /// [`Self::remove_pages`] releases them or [`PageManager::release_memory`] reclaims the empty
    /// reservation.
    ///
    /// [`CreatePagesFlags::MAP_FILE`] and [`CreatePagesFlags::SHARED`] are invalid for reserved pages.
    /// For fresh reserve-and-commit allocation, use
    /// [`Self::create_reserved_and_committed_pages`].
    /// Neither operation rounds the length to automatic mapping granularity.
    /// Use [`Self::create_private_pages`] with address bounds for bounded placement or explicit
    /// search direction.
    ///
    /// # Safety
    ///
    /// The caller must not access these pages before committing them.
    pub unsafe fn create_reserved_pages(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        alignment: usize,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        // SAFETY: The caller will not access the fresh reservation before commitment.
        unsafe {
            self.create_private_pages(
                suggested_address,
                Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX,
                length,
                alignment,
                flags | CreatePagesFlags::TOP_DOWN,
                None,
            )
        }
    }

    /// Reserve and commit a fresh, zero-initialized Windows-style address range.
    ///
    /// Placement and exact-length ownership follow [`Self::create_reserved_pages`]. The provider's
    /// combined native allocation is tried first; unsupported requests use separate reservation
    /// and commitment. Failure releases any newly acquired backing without publishing a mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure the requested permissions do not conflict with concurrent access.
    pub unsafe fn create_reserved_and_committed_pages(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        alignment: usize,
        flags: CreatePagesFlags,
        permissions: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        // SAFETY: The caller excludes conflicting accesses.
        unsafe {
            self.create_private_pages(
                suggested_address,
                Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX,
                length,
                alignment,
                flags | CreatePagesFlags::TOP_DOWN,
                Some(permissions),
            )
        }
    }

    /// Release pages and their reservation subranges, preserving any surrounding ownership.
    /// The entire range must lie within one owned reservation. Only page alignment is required.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remove_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::from_start_len(start, len).ok_or(VmemUnmapError::UnAligned)?;
        // SAFETY: The caller excludes users from the released range.
        unsafe { vmem.remove_mapping(range) }
    }

    /// Commit already reserved pages without acquiring new address-space ownership.
    /// The entire range must lie within a single owned reservation.
    /// The base and length require only page alignment, not reservation alignment.
    /// Already committed pages receive permission changes without replacing their contents.
    /// One provider call commits the range and updates its permissions.
    /// On failure, commitment, contents, and permissions remain unchanged.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the requested permissions do not conflict with concurrent access.
    pub unsafe fn commit_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::from_start_len(start, len).ok_or(VmemProtectError::InvalidRange(
            start..start.saturating_add(len),
        ))?;
        unsafe { vmem.commit_pages(range, permissions) }
    }

    /// Discard page contents and make pages inaccessible while retaining address-space ownership.
    /// Subsequent commitment yields zero-filled pages on every provider.
    /// The entire range must lie within a single owned reservation.
    /// Already uncommitted pages are allowed. One provider call decommits the whole range;
    /// failure leaves commitment, contents, and VMA metadata unchanged.
    ///
    /// # Safety
    ///
    /// The caller must ensure that its contents are no longer in use.
    pub unsafe fn decommit_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        let mut vmem = self.vmem.write();
        let start = ptr.as_usize();
        let range = PageRange::from_start_len(start, len).ok_or(VmemProtectError::InvalidRange(
            start..start.saturating_add(len),
        ))?;
        unsafe { vmem.decommit_pages(range) }
    }
}

impl<Platform, const ALIGN: usize> Vmem<Platform, ALIGN, Windows>
where
    Platform: PageManagementProvider<ALIGN> + RawPointerProvider + 'static,
{
    /// Commit pages within one owned reservation without acquiring backing or replacing contents.
    /// Submit the entire range once and publish one anonymous VMA only after success.
    ///
    /// # Safety
    ///
    /// The caller must exclude accesses that conflict with the requested permissions.
    pub(super) unsafe fn commit_pages(
        &mut self,
        page_range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let range: Range<usize> = page_range.into();
        let Some((_, reservation)) = self
            .reservations
            .containing(range.start)
            .filter(|(_, reservation)| range.end <= reservation.range().end)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        let flags = VmFlags::from(permissions);
        for (_, vma) in self.vmas.overlapping(range.clone()) {
            if vma.flags.is_empty() {
                return Err(VmemProtectError::InvalidRange(range));
            }
            if (!(vma.flags.bits() >> 4) & flags.bits()) & VmFlags::VM_ACCESS_FLAGS.bits() != 0 {
                return Err(VmemProtectError::NoAccess {
                    old: vma.flags,
                    new: flags,
                });
            }
        }
        // SAFETY: One live reservation covers the range; access limits were validated and the caller excludes conflicting users.
        unsafe {
            self.platform.commit_pages(
                || core::iter::once(reservation),
                range.clone(),
                permissions,
                false,
            )
        }
        .map_err(VmemProtectError::ProtectError)?;
        self.vmas.insert(
            range,
            VmArea::new(VmFlags::VM_MAY_ACCESS_FLAGS | flags, false),
        );
        Ok(())
    }

    /// Decommit pages within one owned reservation, retaining its ownership.
    /// Submit the whole range once and remove VMA metadata only after success.
    ///
    /// # Safety
    ///
    /// The caller must relinquish the contents and exclude concurrent users.
    pub(super) unsafe fn decommit_pages(
        &mut self,
        range: PageRange<ALIGN>,
    ) -> Result<(), VmemProtectError> {
        let range: Range<usize> = range.into();
        let Some((_, reservation)) = self
            .reservations
            .containing(range.start)
            .filter(|(_, reservation)| range.end <= reservation.range().end)
        else {
            return Err(VmemProtectError::InvalidRange(range));
        };
        // SAFETY: One live reservation covers the range and the caller relinquishes its contents.
        unsafe {
            self.platform
                .decommit_pages(|| core::iter::once(reservation), range.clone())
        }
        .map_err(VmemProtectError::ProtectError)?;
        self.vmas.remove(range);
        Ok(())
    }
    /// Release a page-aligned subrange of one owned reservation, preserving its survivors.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    /// The range must not overlap external memory reported by the platform at startup.
    pub(super) unsafe fn remove_mapping(
        &mut self,
        range: PageRange<ALIGN>,
    ) -> Result<(), VmemUnmapError> {
        let range: Range<usize> = range.into();
        let Some((base, _)) = self
            .reservations
            .containing(range.start)
            .filter(|(_, reservation)| range.end <= reservation.range().end)
        else {
            return Err(DeallocationError::AlreadyUnallocated.into());
        };
        self.vmas.remove(range.clone());
        let released = self.reservations.take_range(base, range.clone());
        // SAFETY: The caller relinquishes this owned subrange with no remaining users; survivors remain owned.
        unsafe {
            self.platform.release_pages(released.into());
        }
        Ok(())
    }

    /// Acquire a fresh exact-length reservation using suggested or bounded placement,
    /// optionally committing it before publication.
    ///
    /// # Safety
    ///
    /// The caller must exclude conflicting accesses and not access uncommitted pages.
    pub(super) unsafe fn create_private_pages(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        address_bounds: Range<usize>,
        length: NonZeroPageSize<ALIGN>,
        alignment: usize,
        flags: CreatePagesFlags,
        permissions: Option<MemoryRegionPermissions>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        if !alignment.is_power_of_two() {
            return Err(MappingError::UnAligned);
        }
        if flags.intersects(CreatePagesFlags::SHARED | CreatePagesFlags::MAP_FILE) {
            return Err(MappingError::InvalidFlags);
        }
        let fixed = suggested_address.is_some();
        let top_down = flags.contains(CreatePagesFlags::TOP_DOWN);
        let mut address_bounds = address_bounds.start.max(ALIGN).max(Platform::TASK_ADDR_MIN)
            ..address_bounds.end.min(Platform::TASK_ADDR_MAX);
        let behavior = if suggested_address.is_some() {
            FixedAddressBehavior::NoReplace
        } else if Platform::RESERVATION_ALIGNMENT.is_multiple_of(alignment) {
            FixedAddressBehavior::Hint
        } else {
            FixedAddressBehavior::NoReplace
        };
        let alignment = alignment.max(Platform::RESERVATION_ALIGNMENT);
        if suggested_address.is_some_and(|address| !address.as_usize().is_multiple_of(alignment)) {
            return Err(MappingError::UnAligned);
        }
        let mut address = Self::find_area(
            &self.reservations,
            &self.vmas,
            FindAreaRequest {
                suggested_address,
                length,
                behavior: if fixed {
                    FixedAddressBehavior::NoReplace
                } else {
                    FixedAddressBehavior::Hint
                },
                alignment,
                include_reservations: true,
                address_range: address_bounds.clone(),
                top_down,
            },
        )
        .map_err(MappingError::from)?
        .ok_or(MappingError::OutOfMemory)?;
        loop {
            let range = address..address + length.as_usize();
            // SAFETY: Placement selected fresh address space and the caller excludes conflicting accesses.
            match unsafe {
                self.allocate_private_pages(range.clone(), permissions, behavior, &address_bounds)
            } {
                Err(MappingError::MapError(
                    AllocationError::AddressInUseByPlatform | AllocationError::AddressInUse,
                )) if !fixed => {
                    if top_down {
                        address_bounds.end = range
                            .end
                            .checked_sub(alignment)
                            .ok_or(MappingError::OutOfMemory)?;
                    } else {
                        address_bounds.start = address
                            .checked_add(alignment)
                            .ok_or(MappingError::OutOfMemory)?;
                    }
                    address = Self::find_area(
                        &self.reservations,
                        &self.vmas,
                        FindAreaRequest {
                            suggested_address: None,
                            length,
                            behavior: FixedAddressBehavior::Hint,
                            alignment,
                            include_reservations: true,
                            address_range: address_bounds.clone(),
                            top_down,
                        },
                    )
                    .map_err(MappingError::from)?
                    .ok_or(MappingError::OutOfMemory)?;
                }
                result => return result,
            }
        }
    }

    /// Acquire and optionally commit one validated free range before publishing ownership.
    ///
    /// # Safety
    ///
    /// The range must be aligned, in bounds, and reservation-free, with no conflicting accesses.
    unsafe fn allocate_private_pages(
        &mut self,
        range: Range<usize>,
        permissions: Option<MemoryRegionPermissions>,
        behavior: FixedAddressBehavior,
        address_bounds: &Range<usize>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let native = if let Some(permissions) = permissions {
            // SAFETY: Placement selected fresh address space; neither mode replaces existing pages.
            match unsafe {
                self.platform.reserve_and_commit_pages(
                    core::iter::empty,
                    range.clone(),
                    permissions,
                    false,
                    false,
                    behavior,
                )
            } {
                Ok(backing) => Some(backing),
                Err(ReserveAndCommitError::UnsupportedByPlatform) => None,
                Err(ReserveAndCommitError::Allocation(error)) => return Err(error.into()),
            }
        } else {
            None
        };
        let already_committed = native.is_some();
        let backing = match native {
            Some(backing) => backing,
            // SAFETY: Fresh reservation acquisition never replaces existing native mappings.
            None => unsafe {
                self.platform
                    .reserve_pages(core::iter::empty, range.clone(), false, behavior)
            }?,
        };
        let actual = backing.range();
        assert_eq!(actual.len(), range.len());
        assert!(behavior == FixedAddressBehavior::Hint || actual == range);
        debug_assert!(!self.overlaps(actual.clone(), true));
        if actual.start < address_bounds.start || actual.end > address_bounds.end {
            // SAFETY: This fresh reservation has no published users.
            unsafe {
                self.platform.release_pages(backing.into());
            };
            return Err(AllocationError::AddressInUseByPlatform.into());
        }
        if let Some(permissions) = permissions {
            if !already_committed {
                // SAFETY: This fresh reservation is exclusively owned and not yet published.
                if let Err(error) = unsafe {
                    self.platform.commit_pages(
                        || core::iter::once(&backing),
                        actual.clone(),
                        permissions,
                        false,
                    )
                } {
                    // SAFETY: Failed commitment leaves this unpublished reservation owned and unused.
                    unsafe {
                        self.platform.release_pages(backing.into());
                    };
                    return Err(match error {
                        PageStateUpdateError::OutOfMemory => AllocationError::OutOfMemory.into(),
                        other => panic!("invalid fresh commitment: {other}"),
                    });
                }
            }
            self.vmas.insert(
                actual.clone(),
                VmArea::new(
                    VmFlags::VM_MAY_ACCESS_FLAGS | VmFlags::from(permissions),
                    false,
                ),
            );
        }
        let pointer = Platform::RawMutPointer::from_usize(actual.start);
        self.reservations.insert(actual.start, backing);
        Ok(pointer)
    }
}
