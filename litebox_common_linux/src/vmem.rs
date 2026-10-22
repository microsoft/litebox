// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::num::NonZeroU64;
use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use litebox::mm::page::{NonZeroAddress, NonZeroPageSize, PageRange};
use litebox::platform::PageManagementProvider;
use litebox::platform::RawConstPointer;
use litebox::platform::RawMutPointer;
use litebox::platform::page_mgmt::AllocationDirection;
use litebox::platform::page_mgmt::AllocationError;
use litebox::platform::page_mgmt::AllocationOptions;
use litebox::platform::page_mgmt::FixedAddressBehavior;
use litebox::platform::page_mgmt::HintPlacementBehavior;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::page_mgmt::RemapError;
use litebox::platform::{
    common_providers::reservations::{NoTrackedReservations, TrackedReservations},
    page_mgmt::{DeallocationError, PageReservation, PermissionUpdateError, ReservationStore},
};
use litebox_broker_protocol::shared_futex::{SharedFutexKey, SharedMemoryId};

use crate::PAGE_SIZE;

bitflags::bitflags! {
    /// Flags to describe the properties of a memory region.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmFlags: u32 {
        /// Readable.
        const VM_READ = 1 << 0;
        /// Writable.
        const VM_WRITE = 1 << 1;
        /// Executable.
        const VM_EXEC = 1 << 2;
        /// Shared between processes.
        const VM_SHARED = 1 << 3;

        /* limits for mprotect() etc */
        /// `mprotect` can turn on VM_READ
        const VM_MAYREAD = 1 << 4;
        /// `mprotect` can turn on VM_WRITE
        const VM_MAYWRITE = 1 << 5;
        /// `mprotect` can turn on VM_EXEC
        const VM_MAYEXEC = 1 << 6;
        /// `mprotect` can turn on VM_SHARED
        const VM_MAYSHARE = 1 << 7;

        /// The area can grow downward upon page fault.
        const VM_GROWSDOWN = 1 << 8;
        /// The area may hold data even while it has no access: it is file-backed or had access
        /// at some point. Inaccessible areas without it, such as reservations and guard pages,
        /// hold only zeros.
        const VM_HAS_CONTENTS = 1 << 9;

        const VM_ACCESS_FLAGS = Self::VM_READ.bits()
            | Self::VM_WRITE.bits()
            | Self::VM_EXEC.bits();
        const VM_MAY_ACCESS_FLAGS = Self::VM_MAYREAD.bits()
            | Self::VM_MAYWRITE.bits()
            | Self::VM_MAYEXEC.bits();
    }
}

impl From<CreatePagesFlags> for FixedAddressBehavior {
    fn from(flags: CreatePagesFlags) -> Self {
        if flags.contains(CreatePagesFlags::FIXED_ADDR) {
            if flags.contains(CreatePagesFlags::NOREPLACE) {
                FixedAddressBehavior::NoReplace
            } else {
                FixedAddressBehavior::Replace
            }
        } else {
            FixedAddressBehavior::Hint(if flags.contains(CreatePagesFlags::TOP_DOWN) {
                AllocationDirection::TopDown
            } else {
                AllocationDirection::BottomUp
            })
        }
    }
}

impl VmFlags {
    /// Compute the default `VM_MAY*` and `VM_SHARED` flags for a mapping.
    ///
    /// Write permission (`VM_MAYWRITE`) is restricted only for shared **file-backed**
    /// mappings, because writes cannot be propagated back to the underlying file.
    pub(super) fn may_flags_for_mapping(shared: bool, file_backed: bool) -> Self {
        let restrict_write = shared && file_backed;
        let may = if restrict_write {
            Self::VM_MAY_ACCESS_FLAGS & !Self::VM_MAYWRITE
        } else {
            Self::VM_MAY_ACCESS_FLAGS
        };
        let shared_flag = if shared {
            Self::VM_SHARED
        } else {
            Self::empty()
        };
        may | shared_flag
    }
}

impl From<MemoryRegionPermissions> for VmFlags {
    fn from(value: MemoryRegionPermissions) -> Self {
        let mut flags = VmFlags::empty();
        flags.set(
            VmFlags::VM_READ,
            value.contains(MemoryRegionPermissions::READ),
        );
        flags.set(
            VmFlags::VM_WRITE,
            value.contains(MemoryRegionPermissions::WRITE),
        );
        flags.set(
            VmFlags::VM_EXEC,
            value.contains(MemoryRegionPermissions::EXEC),
        );
        flags
    }
}

impl From<VmFlags> for MemoryRegionPermissions {
    fn from(value: VmFlags) -> Self {
        let mut flags = MemoryRegionPermissions::empty();
        flags.set(
            MemoryRegionPermissions::READ,
            value.contains(VmFlags::VM_READ),
        );
        flags.set(
            MemoryRegionPermissions::WRITE,
            value.contains(VmFlags::VM_WRITE),
        );
        flags.set(
            MemoryRegionPermissions::EXEC,
            value.contains(VmFlags::VM_EXEC),
        );
        flags
    }
}

bitflags::bitflags! {
    /// Options for page creation.
    #[derive(Clone, Copy)]
    pub struct CreatePagesFlags: u8 {
        /// Force the mapping to be created at the given address, resulting in any
        /// existing overlapping mappings being removed.
        const FIXED_ADDR     = 1 << 0;
        /// The mapping is used for stack.
        const IS_STACK       = 1 << 1;
        /// Populate the pages immediately.
        const POPULATE_PAGES_IMMEDIATELY = 1 << 2;
        // This flag indicates that the mapping is backed by a file.
        const MAP_FILE = 1 << 4;
        /// When combined with [`Self::FIXED_ADDR`], fail with [`AllocationError::AddressInUse`]
        /// if any part of the range is already mapped, instead of replacing existing mappings.
        const NOREPLACE = 1 << 5;
        /// The mapping is shared.
        const SHARED = 1 << 6;
        /// Search for free address space from high addresses toward low addresses.
        const TOP_DOWN = 1 << 7;
    }
}

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
    /// Whether this area is backed by a file
    is_file_backed: bool,
    /// Which memory the area maps.
    sharing: Sharing,
}

/// The memory an area maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sharing {
    /// The area's pages are its own.
    None,
    /// Shared anonymous memory that has no name yet. The number tells the pieces of one
    /// `mmap` apart from those of any other, and is never reused within a [`Vmem`].
    Unnamed(NonZeroU64),
    /// Shared anonymous memory once named, which native fork children share.
    Named(SharedMemoryView),
}

/// Where an area maps named shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedMemoryView {
    memory: SharedMemoryId,
    /// Address that offset zero of the memory maps at, which stays the same as the area splits.
    base: usize,
}

impl VmArea {
    /// Get the [flags](`VmFlags`) of this memory area.
    #[inline]
    pub fn flags(&self) -> VmFlags {
        self.flags
    }

    /// Check if this area is backed by a file.
    #[inline]
    pub fn is_file_backed(&self) -> bool {
        self.is_file_backed
    }

    /// Check if this area is shared anonymous memory.
    #[inline]
    pub fn is_shared_anonymous(&self) -> bool {
        self.flags.contains(VmFlags::VM_SHARED) && !self.is_file_backed
    }

    /// Returns the number of the shared anonymous mapping this area is a piece of, if that
    /// mapping has no name yet.
    #[inline]
    pub(super) fn unnamed_shared_mapping(&self) -> Option<NonZeroU64> {
        match self.sharing {
            Sharing::Unnamed(mapping) => Some(mapping),
            _ => None,
        }
    }

    /// Returns whether this area is shared anonymous memory that has no name yet.
    #[inline]
    pub(super) fn needs_shared_memory_id(&self) -> bool {
        self.unnamed_shared_mapping().is_some()
    }

    /// Returns where this area maps named shared memory, if it does.
    #[inline]
    fn shared_memory(&self) -> Option<SharedMemoryView> {
        match self.sharing {
            Sharing::Named(view) => Some(view),
            _ => None,
        }
    }

    /// Returns the key of the futex word at `address` in this area, if the area maps named
    /// shared memory.
    pub(super) fn shared_futex_key(&self, address: usize) -> Option<SharedFutexKey> {
        let view = self.shared_memory()?;
        Some(SharedFutexKey {
            memory: view.memory,
            offset: u64::try_from(address.checked_sub(view.base)?).ok()?,
        })
    }

    /// Create a new [`VmArea`] with the given flags, adding [`VmFlags::VM_HAS_CONTENTS`] if the
    /// area is file-backed or has any access.
    #[inline]
    pub(super) fn new(mut flags: VmFlags, is_file_backed: bool) -> Self {
        if is_file_backed || flags.intersects(VmFlags::VM_ACCESS_FLAGS) {
            flags |= VmFlags::VM_HAS_CONTENTS;
        }
        Self {
            flags,
            is_file_backed,
            sharing: Sharing::None,
        }
    }
}

pub(super) struct FindAreaRequest<const ALIGN: usize> {
    pub(super) suggested_address: Option<NonZeroAddress<ALIGN>>,
    pub(super) length: NonZeroPageSize<ALIGN>,
    pub(super) behavior: FixedAddressBehavior,
    pub(super) alignment: usize,
    pub(super) address_range: Range<usize>,
}

/// Parameters for creating a Linux Vmem mapping.
pub struct MmapRequest {
    /// Requested address range.
    pub range: Range<usize>,
    /// Properties of the new virtual memory area.
    pub vma: VmArea,
    /// Page allocation options.
    pub options: AllocationOptions,
    /// Required fixed-address behavior.
    pub behavior: FixedAddressBehavior,
}

/// Returns the options to create `vma`'s pages with.
fn mapping_options(vma: VmArea, populate_pages_immediately: bool) -> AllocationOptions {
    let mut options = AllocationOptions::empty();
    options.set(
        AllocationOptions::GROWS_DOWN,
        vma.flags.contains(VmFlags::VM_GROWSDOWN),
    );
    options.set(AllocationOptions::POPULATE, populate_pages_immediately);
    // TODO: share the pages of shared file-backed mappings too, which are private copies until
    // then, so that every `VM_SHARED` area is shared.
    options.set(AllocationOptions::SHARED, vma.is_shared_anonymous());
    options
}

fn insert_mapped_vma<Platform: PageManagementProvider<ALIGN>, const ALIGN: usize>(
    vmas: &mut RangeMap<usize, VmArea>,
    start: usize,
    length: usize,
    vma: VmArea,
) {
    let end = start + length;
    debug_assert!(start >= Platform::TASK_ADDR_MIN);
    debug_assert!(end <= Platform::TASK_ADDR_MAX);
    vmas.insert(start..end, vma);
}

/// Linux Vmem operations supported by a reservation store.
pub trait LinuxReservationStore<Platform, const ALIGN: usize>:
    ReservationStore + Send + Sync
where
    Platform: PageManagementProvider<ALIGN, Reservations = Self>,
{
    /// Release all owned reservations and mappings.
    ///
    /// On failure, extents not yet attempted remain available for retry. Tracked stores also
    /// remove mappings for reservations consumed by a failed release.
    ///
    /// # Safety
    ///
    /// The caller must exclude all users of this address space.
    unsafe fn release_all(
        &mut self,
        vmas: &mut RangeMap<usize, VmArea>,
        platform: &Platform,
    ) -> Result<(), DeallocationError>;

    /// Create a platform mapping, update reservation ownership, and insert its VMA.
    ///
    /// # Safety
    ///
    /// Unless `request.behavior` is [`FixedAddressBehavior::Replace`], the requested range must
    /// not overlap any existing VMA.
    /// When `request.behavior` is [`FixedAddressBehavior::Replace`], the caller must ensure that
    /// any replaced mappings are not in active use.
    unsafe fn mmap(
        &mut self,
        platform: &Platform,
        vmas: &mut RangeMap<usize, VmArea>,
        request: MmapRequest,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError>;

    /// Release a range's platform backing, update reservation ownership, and remove its VMAs.
    ///
    /// A failed release that consumes a reservation also removes its VMAs; unattempted
    /// reservations and their VMAs remain tracked.
    ///
    /// # Safety
    ///
    /// The caller must ensure that these pages are not in active use.
    unsafe fn unmap(
        &mut self,
        platform: &Platform,
        vmas: &mut RangeMap<usize, VmArea>,
        range: Range<usize>,
    ) -> Result<(), DeallocationError>;

    /// Remap platform pages and update reservation ownership.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `old_range` is unused and that `new_range` is a valid,
    /// disjoint destination.
    unsafe fn remap(
        &mut self,
        platform: &Platform,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, RemapError>;

    /// Update permissions using this store's reservation ownership.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the range is mapped and excludes conflicting accesses.
    unsafe fn protect(
        &self,
        platform: &Platform,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        // SAFETY: The caller guarantees complete mapping coverage and access exclusion. Tracked
        // stores yield covering handles; handle-free stores yield an empty iterator.
        unsafe {
            platform.protect_pages(
                || self.overlapping(range.clone()),
                range.clone(),
                permissions,
            )
        }
    }
}

impl<Platform, Reservation, const ALIGN: usize> LinuxReservationStore<Platform, ALIGN>
    for NoTrackedReservations<ALIGN, Reservation>
where
    Platform: PageManagementProvider<ALIGN, Reservations = Self>,
    Reservation: PageReservation + Send + Sync,
{
    unsafe fn release_all(
        &mut self,
        vmas: &mut RangeMap<usize, VmArea>,
        platform: &Platform,
    ) -> Result<(), DeallocationError> {
        // Collect contiguous extents from the VMAs to release them with fewer platform calls.
        let mut extents: Vec<Range<usize>> = Vec::new();
        for (range, _) in vmas.iter() {
            match extents.last_mut() {
                Some(last) if last.end == range.start => last.end = range.end,
                _ => extents.push(range.clone()),
            }
        }
        for extent in extents {
            // SAFETY: The caller relinquishes this provider-owned range without remaining users.
            unsafe { platform.release_pages(extent.clone()) }?;
            vmas.remove(extent);
        }
        Ok(())
    }

    unsafe fn mmap(
        &mut self,
        platform: &Platform,
        vmas: &mut RangeMap<usize, VmArea>,
        request: MmapRequest,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let MmapRequest {
            range,
            vma,
            options,
            behavior,
        } = request;
        let length = range.len();
        let permissions = MemoryRegionPermissions::from(vma.flags);
        // SAFETY: The caller authorizes replacement and this handle-free store owns mapping ranges.
        let reservation = unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                range,
                permissions,
                options,
                behavior,
            )
        }?;
        let start = reservation.range().start;
        insert_mapped_vma::<Platform, ALIGN>(vmas, start, length, vma);
        Ok(Platform::RawMutPointer::<u8>::from_usize(start))
    }

    unsafe fn unmap(
        &mut self,
        platform: &Platform,
        vmas: &mut RangeMap<usize, VmArea>,
        range: Range<usize>,
    ) -> Result<(), DeallocationError> {
        // SAFETY: The caller excludes all users of the released range.
        unsafe { platform.release_pages(range.clone()) }?;
        vmas.remove(range);
        Ok(())
    }

    unsafe fn remap(
        &mut self,
        platform: &Platform,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, RemapError> {
        // SAFETY: The caller guarantees that the source is unused and the destination is valid.
        let reservation = unsafe {
            platform.try_remap_pages(core::iter::empty, old_range, new_range, permissions)
        }?;
        Ok(Platform::RawMutPointer::<u8>::from_usize(
            reservation.range().start,
        ))
    }
}

impl<Platform, Reservation, const ALIGN: usize> LinuxReservationStore<Platform, ALIGN>
    for TrackedReservations<Reservation>
where
    Platform: PageManagementProvider<ALIGN, Reservations = Self>,
    Reservation: PageReservation + Send + Sync,
{
    unsafe fn release_all(
        &mut self,
        vmas: &mut RangeMap<usize, VmArea>,
        platform: &Platform,
    ) -> Result<(), DeallocationError> {
        while let Some(reservation) = self.pop_first() {
            let extent = reservation.range();
            // Release consumes reservation ownership even on failure.
            vmas.remove(extent);
            // SAFETY: The caller relinquishes this reservation without remaining users.
            unsafe { platform.release_pages(reservation) }?;
        }
        Ok(())
    }

    unsafe fn mmap(
        &mut self,
        platform: &Platform,
        vmas: &mut RangeMap<usize, VmArea>,
        request: MmapRequest,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let MmapRequest {
            mut range,
            vma,
            options,
            mut behavior,
        } = request;
        let permissions = MemoryRegionPermissions::from(vma.flags);
        let can_grow_down = options.contains(AllocationOptions::GROWS_DOWN);

        // Replacement normally recommits pages in place, which cannot turn private pages into
        // shared ones or shared pages into private ones. Detach such replaced pages first instead,
        // as Linux unmaps replaced pages before mapping new ones.
        if behavior == FixedAddressBehavior::Replace
            && (vma.is_shared_anonymous()
                || vmas
                    .overlapping(range.clone())
                    .any(|(_, replaced)| replaced.is_shared_anonymous()))
        {
            // SAFETY: Replacement covers only mapped, hence reserved, pages, and the caller
            // excludes their users.
            unsafe { platform.decommit_pages(|| self.overlapping(range.clone()), range.clone()) }
                .expect("failed to detach replaced pages");
            vmas.remove(range.clone());
            behavior = FixedAddressBehavior::NoReplace;
        }

        if range.start.is_multiple_of(Platform::RESERVATION_ALIGNMENT)
            && range.end.is_multiple_of(Platform::RESERVATION_ALIGNMENT)
            && self.overlapping(range.clone()).next().is_none()
        {
            // SAFETY: No tracked reservation overlaps this request, and the caller authorizes its
            // placement behavior.
            match unsafe {
                platform.reserve_and_commit_pages(
                    core::iter::empty,
                    range.clone(),
                    permissions,
                    options,
                    behavior,
                )
            } {
                Ok(reservation) => {
                    let extent = reservation.range();
                    let address = extent.start;
                    assert!(self.insert(extent.start, reservation).is_none());
                    insert_mapped_vma::<Platform, ALIGN>(vmas, address, range.len(), vma);
                    return Ok(Platform::RawMutPointer::<u8>::from_usize(address));
                }
                Err(AllocationError::UnsupportedByPlatform) => {}
                Err(error) => return Err(error),
            }
        }

        // SAFETY: NoReplace limits acquisition to unowned gaps in the requested range.
        let acquired = match unsafe {
            self.reserve_gaps(
                platform,
                range.clone(),
                can_grow_down,
                FixedAddressBehavior::NoReplace,
            )
        } {
            Ok(acquired) => acquired,
            Err(
                AllocationError::AddressInUse
                | AllocationError::AddressInUseByPlatform
                | AllocationError::AddressPartiallyInUse,
            ) if matches!(behavior, FixedAddressBehavior::Hint(_)) => {
                // SAFETY: A zero-address hint requests a fresh extent and cannot replace memory.
                let reservation = unsafe {
                    Self::reserve_gap(platform, 0..range.len(), can_grow_down, behavior)
                }?;
                let base = reservation.range().start;
                assert!(self.insert(base, reservation).is_none());
                range = base..base + range.len();
                Vec::from([base])
            }
            Err(error) => return Err(error),
        };

        // SAFETY: Reservations cover the range; new mappings target VMA gaps, and replacement
        // is limited to private backing.
        match unsafe {
            platform.commit_pages(
                || self.overlapping(range.clone()),
                range.clone(),
                permissions,
                options,
            )
        } {
            Ok(pointer) => {
                // Recommitting preserves contents, so zero them in place. Decommitting first would
                // be lazier, but a failed recommit would then lose the replaced contents.
                if behavior == FixedAddressBehavior::Replace {
                    let temporary_permissions = (permissions
                        | MemoryRegionPermissions::READ
                        | MemoryRegionPermissions::WRITE)
                        - MemoryRegionPermissions::EXEC;
                    let zeros = [0; PAGE_SIZE];
                    for (mapped, _) in vmas.overlapping(range.clone()) {
                        let overlap = mapped.start.max(range.start)..mapped.end.min(range.end);
                        if !permissions.contains(MemoryRegionPermissions::WRITE) {
                            // SAFETY: Commitment succeeded and the caller excludes replacement users.
                            unsafe {
                                self.protect(platform, overlap.clone(), temporary_permissions)
                            }
                            .expect("failed to make replacement pages writable");
                        }
                        let mut address = overlap.start;
                        while address < overlap.end {
                            let length = (overlap.end - address).min(zeros.len());
                            pointer
                                .copy_from_slice(address - range.start, &zeros[..length])
                                .expect("failed to zero replacement pages");
                            address += length;
                        }
                        if !permissions.contains(MemoryRegionPermissions::WRITE) {
                            // SAFETY: Zeroing is complete and the caller excludes replacement users.
                            unsafe { self.protect(platform, overlap, permissions) }
                                .expect("failed to protect replacement pages");
                        }
                    }
                }
                insert_mapped_vma::<Platform, ALIGN>(vmas, pointer.as_usize(), range.len(), vma);
                Ok(pointer)
            }
            Err(error) => {
                // The backend commits one reservation at a time, so we need to rollback any changes.
                // First rollback permission changes made to already committed VMAs.
                for (mapped, mapped_vma) in vmas.overlapping(range.clone()) {
                    let original_permissions =
                        MemoryRegionPermissions::from(mapped_vma.flags & VmFlags::VM_ACCESS_FLAGS);
                    if original_permissions != permissions {
                        let overlap = mapped.start.max(range.start)..mapped.end.min(range.end);
                        // SAFETY: Existing mappings remain committed and the caller excludes users.
                        unsafe { self.protect(platform, overlap, original_permissions) }
                            .expect("failed to restore replacement permissions");
                    }
                }
                // Second rollback any partially committed reservations.
                for gap in vmas.gaps(&range) {
                    // SAFETY: These gaps have no published mappings or active users.
                    let _ = unsafe {
                        platform.decommit_pages(|| self.overlapping(gap.clone()), gap.clone())
                    };
                }
                // Lastly release any newly acquired reservations.
                for base in acquired {
                    let reservation = self
                        .take_overlapping(base..base + 1)
                        .pop()
                        .expect("new reservation must remain tracked");
                    // SAFETY: The failed mapping never published this newly acquired reservation.
                    let _ = unsafe { platform.release_pages(reservation) };
                }
                Err(error)
            }
        }
    }

    unsafe fn unmap(
        &mut self,
        platform: &Platform,
        vmas: &mut RangeMap<usize, VmArea>,
        range: Range<usize>,
    ) -> Result<(), DeallocationError> {
        let alignment = Platform::RESERVATION_ALIGNMENT;
        let mut reservations = self.take_overlapping(range.clone()).into_iter();
        while let Some(reservation) = reservations.next() {
            let extent = reservation.range();
            // Only release the reservation if it is fully aligned and has no overlapping mappings outside the range.
            let retained = !extent.start.is_multiple_of(alignment)
                || !extent.end.is_multiple_of(alignment)
                || vmas.overlapping(extent.clone()).any(|(mapped, _)| {
                    mapped.start.max(extent.start) < range.start
                        || mapped.end.min(extent.end) > range.end
                });
            if retained {
                let segment = extent.start.max(range.start)..extent.end.min(range.end);
                // SAFETY: The removed segment has no users and remains inside this reservation.
                unsafe {
                    platform.decommit_pages(|| core::iter::once(&reservation), segment.clone())
                }
                .expect("failed to decommit unmapped reservation backing");
                vmas.remove(segment);
                assert!(self.insert(extent.start, reservation).is_none());
                continue;
            }

            // Release consumes reservation ownership even on failure.
            vmas.remove(extent);
            // SAFETY: This reservation has no surviving users or mappings outside the removed range.
            if let Err(error) = unsafe { platform.release_pages(reservation) } {
                for pending in reservations {
                    assert!(self.insert(pending.range().start, pending).is_none());
                }
                return Err(error);
            }
        }
        vmas.remove(range);
        Ok(())
    }

    unsafe fn remap(
        &mut self,
        _platform: &Platform,
        _old_range: Range<usize>,
        _new_range: Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<Platform::RawMutPointer<u8>, RemapError> {
        Err(RemapError::UnsupportedByPlatform)
    }
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory ranges backed by a memory [backend](PageManagementProvider).
/// Each range needs to be `ALIGN`-aligned.
pub(super) struct Vmem<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> {
    /// Memory backend that provides the actual memory.
    pub(super) platform: &'static Platform,
    /// Virtual memory areas.
    vmas: RangeMap<usize, VmArea>,
    /// Reservations selected and owned by the platform.
    reservations: Platform::Reservations,
    /// The number of shared anonymous mappings created, which numbers each of their areas.
    shared_anonymous_mappings: u64,
}

impl<Platform, const ALIGN: usize> Vmem<Platform, ALIGN>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
{
    pub(super) const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`Vmem`] instance with the given memory [backend](PageManagementProvider).
    pub(super) fn new(platform: &'static Platform) -> Self {
        assert!(Platform::RESERVATION_ALIGNMENT.is_power_of_two());
        assert!(Platform::RESERVATION_ALIGNMENT.is_multiple_of(ALIGN));
        Self {
            platform,
            vmas: RangeMap::new(),
            reservations: Platform::Reservations::default(),
            shared_anonymous_mappings: 0,
        }
    }

    /// Gets an iterator over all pairs of ([`Range<usize>`], [`VmArea`]),
    /// ordered by key range.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
    }

    /// Names every piece of the unnamed shared anonymous mapping numbered `mapping` as
    /// `memory`, with offset zero at the start of its lowest piece.
    pub(super) fn name_shared_mapping(&mut self, mapping: NonZeroU64, memory: SharedMemoryId) {
        let pieces: Vec<(Range<usize>, VmArea)> = self
            .vmas
            .iter()
            .filter(|(_, vma)| vma.unnamed_shared_mapping() == Some(mapping))
            .map(|(range, vma)| (range.clone(), *vma))
            .collect();
        let Some(base) = pieces.first().map(|(range, _)| range.start) else {
            return;
        };
        for (range, vma) in pieces {
            self.vmas.insert(
                range,
                VmArea {
                    sharing: Sharing::Named(SharedMemoryView { memory, base }),
                    ..vma
                },
            );
        }
    }

    /// Gets an iterator over all the stored ranges that are
    /// either partially or completely overlapped by the given range.
    pub(super) fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.overlapping(range)
    }

    /// Remove a range from its virtual address space, if all or any of it was present.
    ///
    /// If the range to be removed _partially_ overlaps any ranges, then those ranges will
    /// be contracted to no longer cover the removed range. An error can leave earlier extents
    /// unmapped.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub(super) unsafe fn remove_mapping(
        &mut self,
        range: PageRange<ALIGN>,
    ) -> Result<(), VmemUnmapError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let range = Range::from(range);
        if range.end > Platform::TASK_ADDR_MAX {
            return Err(VmemUnmapError::InvalidRange(range));
        }
        // SAFETY: The caller excludes all users of the removed range.
        unsafe {
            self.reservations
                .unmap(self.platform, &mut self.vmas, range)
        }
        .map_err(VmemUnmapError::UnmapError)?;
        Ok(())
    }

    /// Release every mapping and reservation owned by this address space.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no mapped memory remains in use.
    pub(super) unsafe fn release_all(&mut self) -> Result<(), DeallocationError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        // SAFETY: The caller relinquishes every owned extent without remaining users.
        unsafe { self.reservations.release_all(&mut self.vmas, self.platform) }?;
        self.vmas.clear();
        Ok(())
    }

    /// Reset pages without removing its mapping (similar to Linux `madvise` with
    /// `MADV_DONTNEED` or `MADV_FREE`).
    ///
    /// If `anonymous_only` is true and any part of the range is non‑anonymous (i.e., file‑backed),
    /// returns `Err(VmemResetError::FileBacked)`.
    ///
    /// The current implementation effectively re-inserts the mapping with the same
    /// `VmArea` properties, which will cause the pages to be unmapped and mapped again.
    /// However, shared anonymous areas are skipped to keep their contents.
    ///
    /// # Panics
    ///
    /// File-backed mapping is not supported yet.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub(super) unsafe fn reset_pages(
        &mut self,
        range: PageRange<ALIGN>,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let range: Range<usize> = range.into();
        // Any unmapped regions in the original range will result in this function returning `DeallocationError::AlreadyUnallocated`
        // while still resetting all of the existing vmas in the range.
        let unmapped_error = self.vmas.gaps(&range).next().is_some();
        let overlapping_ranges: Vec<_> = self
            .overlapping(range.clone())
            .map(|(r, vma)| (r.clone(), *vma))
            .collect();
        for (r, vma) in overlapping_ranges {
            // Like Linux shared memory, shared anonymous pages keep their contents: other
            // processes may still see them, so there is nothing to discard.
            if vma.is_shared_anonymous() {
                continue;
            }
            if vma.is_file_backed() {
                if anonymous_only {
                    return Err(VmemResetError::FileBacked);
                }
                unimplemented!("resetting file-backed mappings is not supported yet");
            }
            let start = r.start.max(range.start);
            let end = r.end.min(range.end);
            let new_range = PageRange::new(start, end).unwrap();
            unsafe { self.insert_mapping(new_range, vma, false, FixedAddressBehavior::Replace) }
                .expect("failed to reset pages");
        }
        if unmapped_error {
            Err(VmemResetError::AlreadyUnallocated)
        } else {
            Ok(())
        }
    }

    /// Insert a range to its virtual address space.
    ///
    /// If the inserted range partially or completely overlaps any
    /// existing range in the map, then the existing range (or ranges) will be
    /// partially or completely replaced by the inserted range.
    ///
    /// If the inserted range either overlaps or is immediately adjacent
    /// any existing range _mapping to the same value_, then the ranges
    /// will be coalesced into a single contiguous range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is not used by any other (i.e., safe
    /// to unmap all overlapping mappings if any).
    pub(super) unsafe fn insert_mapping(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        vma: VmArea,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let (start, end) = (suggested_range.start(), suggested_range.end());
        if start < Platform::TASK_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if end > Platform::TASK_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        let platform_fixed_address_behavior = match fixed_address_behavior {
            FixedAddressBehavior::Hint(direction) => FixedAddressBehavior::Hint(direction),
            FixedAddressBehavior::NoReplace => {
                // Ensure there are no mappings managed by us.
                if self.vmas.overlaps(&(start..end)) {
                    return Err(AllocationError::AddressInUse);
                }
                FixedAddressBehavior::NoReplace
            }
            FixedAddressBehavior::Replace => {
                if self.vmas.overlaps(&(start..end)) {
                    if self.vmas.gaps(&(start..end)).next().is_some() {
                        // The range is partially overlapping with existing
                        // mappings. If we call into the platform with
                        // `Replace`, then it may overwrite external mappings
                        // that are not managed by us.
                        //
                        // FUTURE: support this case, either by splitting this
                        // into multiple allocate calls or by separating VA
                        // allocation from page backing.
                        return Err(AllocationError::AddressPartiallyInUse);
                    }
                    FixedAddressBehavior::Replace
                } else {
                    // There are no mappings managed by us, so just treat this
                    // as NoReplace.
                    FixedAddressBehavior::NoReplace
                }
            }
        };
        // SAFETY: The caller authorizes replacement, and the checks above preserve external gaps.
        // Other requests target VMA gaps selected by the caller.
        unsafe {
            self.reservations.mmap(
                self.platform,
                &mut self.vmas,
                MmapRequest {
                    range: suggested_range.into(),
                    options: mapping_options(vma, populate_pages_immediately),
                    vma,
                    behavior: platform_fixed_address_behavior,
                },
            )
        }
        .map_err(|err| match err {
            AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
            other => other,
        })
    }

    /// Create a new mapping in the virtual address space.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// Return `Some(new_addr)` if the mapping is created successfully.
    /// The returned address is `ALIGN`-aligned.
    ///
    /// # Fixed Address Behavior
    ///
    /// - [`CreatePagesFlags::FIXED_ADDR`] alone: Forces allocation at the exact address, replacing
    ///   any existing overlapping mappings. Caller must ensure overlapping mappings are not in use.
    /// - [`CreatePagesFlags::FIXED_ADDR`] with [`CreatePagesFlags::NOREPLACE`]: Forces allocation at
    ///   the exact address, but fails with [`AllocationError::AddressInUse`] if any part of the
    ///   range is already mapped. This is safe to use without checking for existing mappings first.
    /// - Without [`CreatePagesFlags::FIXED_ADDR`], the address is treated as a hint.
    ///
    /// Note: `NOREPLACE` error responses (`AddressInUse` / `EEXIST`) can be used to probe memory
    /// layout. This matches Linux kernel behavior for `MAP_FIXED_NOREPLACE`.
    ///
    /// # Safety
    ///
    /// When using [`CreatePagesFlags::FIXED_ADDR`] without [`CreatePagesFlags::NOREPLACE`], the
    /// caller must ensure any overlapping mappings are not used by any other code, as they will be
    /// unmapped.
    pub(super) unsafe fn create_mapping(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        vma: VmArea,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        // SAFETY: The caller supplies the same replacement guarantees as this method.
        unsafe { self.create_mapping_in_range(suggested_address, length, vma, flags, None) }
    }

    /// Same as [`Self::create_mapping`], but allows specifying an `allowed_range` for the mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure fixed replacements do not overwrite memory in use.
    pub(super) unsafe fn create_mapping_in_range(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        vma: VmArea,
        flags: CreatePagesFlags,
        allowed_range: Option<Range<usize>>,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let behavior = FixedAddressBehavior::from(flags);
        let direction = match behavior {
            FixedAddressBehavior::Hint(direction) => Some(direction),
            FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => None,
        };
        // A relocated hint may escape the range vmem searched even when the platform preserves
        // its direction, so enforce an exact address when vmem has a stricter upper bound.
        let platform_behavior = match behavior {
            FixedAddressBehavior::Hint(direction)
                if Platform::PLACEMENT_ADDR_MAX < Platform::TASK_ADDR_MAX
                    || allowed_range.is_some()
                    || !Platform::HINT_PLACEMENT_BEHAVIOR.supports(direction) =>
            {
                FixedAddressBehavior::NoReplace
            }
            _ => behavior,
        };
        let mut request = Self::build_unmapped_area_request(
            suggested_address,
            length,
            behavior,
            allowed_range.clone(),
        );
        loop {
            let new_addr = self
                .find_area(&request)?
                .ok_or(AllocationError::OutOfMemory)?;
            // new_addr must be ALIGN aligned
            let new_range = PageRange::new(new_addr, new_addr + length.as_usize()).unwrap();
            let result = unsafe {
                self.insert_mapping(
                    new_range,
                    vma,
                    flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                    platform_behavior,
                )
            };
            match result {
                Err(AllocationError::AddressInUseByPlatform)
                    if direction.is_some()
                        && platform_behavior == FixedAddressBehavior::NoReplace =>
                {
                    // Retry if the requested hint must be placed exactly to preserve its search
                    // direction or vmem's stricter placement bound.
                    let rejected_hint = request
                        .suggested_address
                        .is_some_and(|address| address.as_usize() == new_addr);
                    if rejected_hint {
                        request = Self::build_unmapped_area_request(
                            None,
                            length,
                            behavior,
                            allowed_range.clone(),
                        );
                    } else if direction == Some(AllocationDirection::TopDown) {
                        request.suggested_address = None;
                        request.address_range.end = new_addr;
                    } else {
                        request.suggested_address = None;
                        request.address_range.start = new_addr
                            .checked_add(length.as_usize())
                            .ok_or(AllocationError::OutOfMemory)?;
                    }
                }
                result => return result,
            }
        }
    }

    /// Resize a range in the virtual address space.
    /// Shrink the range if it is larger than `new_size`.
    /// Enlarge the range if it is smaller than `new_size` and will not overlap with
    /// next mapping after the expansion.
    ///
    /// It fails if it resizes more than one mapping or needs to split the current mapping
    /// (due to enlarging). When enlarging, adjacent mappings that differ only in
    /// [`VmFlags::VM_HAS_CONTENTS`] count as one. Shared anonymous mappings can only shrink.
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mremap.c#L886> for reference.
    ///
    /// # Safety
    ///
    /// If it shrinks, the caller must ensure that the unmapped memory region is not used by any other.
    pub(super) unsafe fn resize_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<(), VmemResizeError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let range: Range<usize> = range.into();
        // `cur_range` contains `range.start`
        let cur_range = self
            .vmas
            .get_key_value(&range.start)
            .map(|(cur_range, _)| cur_range.clone())
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range.start.checked_add(new_size.as_usize());
        if let Some(new_end) = new_end
            && new_end <= range.end
        {
            if new_end < range.end {
                // shrink
                let range = PageRange::new(new_end, range.end).unwrap();
                // SAFETY: The caller excludes all users of the removed tail.
                unsafe { self.remove_mapping(range) }.map_err(|_| VmemResizeError::Unsupported)?;
            }
            return Ok(());
        }

        // grow
        let Some(area) = self.merged_area(range.clone()) else {
            // we can't remap across vm area boundaries
            return Err(VmemResizeError::InvalidAddr {
                range: cur_range,
                addr: range.end,
            });
        };
        // TODO: grow shared anonymous areas as Linux does. It grows the area's view of its shared
        // memory, whose size is fixed, so accesses beyond it raise `SIGBUS`, and growing back
        // after shrinking finds the old pages again. That needs the area to know its memory.
        if area.is_shared_anonymous() {
            litebox_util_log::warn!(
                range:? = range, new_size = new_size.as_usize();
                "growing a shared anonymous mapping is unsupported"
            );
            return Err(VmemResizeError::Unsupported);
        }
        let new_end = new_end.ok_or(VmemResizeError::OutOfMemory)?;
        // `last_range` contains the last page of `range`
        let (last_range, last_vma) = self
            .vmas
            .get_key_value(&(range.end - 1))
            .map(|(last_range, last_vma)| (last_range.clone(), *last_vma))
            .unwrap();

        if range.end == last_range.end {
            // expand the last range
            let r = range.end..new_end;
            if self.vmas.overlaps(&r) {
                return Err(VmemResizeError::RangeOccupied(r));
            }
            if last_vma.is_file_backed() {
                unimplemented!("file-backed mapping expansion is not supported yet");
            }
            let range = PageRange::new(range.end, new_end).unwrap();
            // Try to extend the mapping. Although we checked that there are no
            // litebox mappings in this range, this may fail if there are
            // platform mappings in the way.
            match unsafe {
                self.insert_mapping(range, last_vma, false, FixedAddressBehavior::NoReplace)
            } {
                Ok(_) => {}
                Err(AllocationError::PermissionDenied) => {
                    return Err(VmemResizeError::PermissionDenied);
                }
                Err(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse
                    | AllocationError::AboveMaxAddress,
                ) => return Err(VmemResizeError::RangeOccupied(range.into())),
                Err(AllocationError::Unaligned | AllocationError::BelowMinAddress) => {
                    unreachable!()
                }
                Err(_) => return Err(VmemResizeError::OutOfMemory),
            }
            return Ok(());
        }

        // has to split the last range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..last_range.end))
    }

    /// Returns the one area Linux sees over `range`, if areas that differ only in
    /// [`VmFlags::VM_HAS_CONTENTS`] cover it without gaps.
    ///
    /// Such areas, as left by making part of an inaccessible area accessible and back, are one
    /// area to Linux. The returned area may hold data if any of them may.
    fn merged_area(&self, range: Range<usize>) -> Option<VmArea> {
        let (first_range, first) = self.vmas.get_key_value(&range.start)?;
        let mut area = *first;
        let mut end = first_range.end;
        while end < range.end {
            let (next_range, next) = self.vmas.get_key_value(&end)?;
            if next.is_file_backed() != first.is_file_backed()
                || next.sharing != first.sharing
                || !((next.flags() ^ first.flags()) - VmFlags::VM_HAS_CONTENTS).is_empty()
            {
                return None;
            }
            area.flags |= next.flags();
            end = next_range.end;
        }
        Some(area)
    }

    /// Move a range from `old_range` to `suggested_new_range`.
    /// Use it together with [`Vmem::resize_mapping`] to achieve `mremap`.
    ///
    /// The `suggested_new_range.start` is used as a hint for the new address.
    /// If it is zero, kernel will choose a new suitable address freely.
    ///
    /// Returns `Some(new_addr)` if the range is moved successfully
    /// Otherwise, returns `None`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given `range` is safe to be unmapped.
    ///
    /// # Panics
    ///
    /// Panics if the size of `suggested_new_range` is smaller than the size of `old_range`.
    /// Panics if the `old_range` is not covered by exactly one mapping, counting adjacent mappings
    /// that differ only in [`VmFlags::VM_HAS_CONTENTS`] as one.
    pub(super) unsafe fn move_mappings(
        &mut self,
        old_range: PageRange<ALIGN>,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        assert!(new_size.as_usize() >= old_range.len());

        let vma = self
            .merged_area(old_range.into())
            .expect("VMEM: range not covered by one mapping");

        // TODO: move shared anonymous mappings, which needs platforms that share pages with fork
        // children to move them rather than leave copies, which would no longer be shared.
        if vma.is_shared_anonymous() {
            litebox_util_log::warn!(
                range:? = Range::from(old_range), new_size = new_size.as_usize();
                "moving a shared anonymous mapping is unsupported"
            );
            return Err(VmemMoveError::Unsupported);
        }
        if vma.is_file_backed() {
            litebox_util_log::warn!(
                range:? = Range::from(old_range), new_size = new_size.as_usize();
                "moving a file-backed mapping is unsupported"
            );
            return Err(VmemMoveError::Unsupported);
        }
        let mut request = Self::build_unmapped_area_request(
            suggested_new_address,
            new_size,
            FixedAddressBehavior::Hint(AllocationDirection::TopDown),
            None,
        );
        let new_addr = loop {
            let new_addr = self
                .find_area(&request)
                .map_err(|_| VmemMoveError::OutOfMemory)?
                .ok_or(VmemMoveError::OutOfMemory)?;
            let new_range =
                PageRange::<ALIGN>::new(new_addr, new_addr + new_size.as_usize()).unwrap();
            // SAFETY: The caller excludes source users, and find_area found a disjoint guest gap.
            match unsafe {
                self.reservations.remap(
                    self.platform,
                    old_range.into(),
                    new_range.into(),
                    vma.flags.into(),
                )
            } {
                Ok(new_addr) => break new_addr,
                Err(RemapError::AddressInUseByPlatform) => {
                    request.suggested_address = None;
                    request.address_range.end = new_range.start();
                }
                Err(RemapError::AlreadyAllocated)
                    if Platform::HINT_PLACEMENT_BEHAVIOR == HintPlacementBehavior::Exact =>
                {
                    unreachable!("exact-placement platform rejected a free remap destination")
                }
                Err(RemapError::UnsupportedByPlatform) => {
                    // SAFETY: The caller excludes source users, and the copy only places pages
                    // with hints, which never replace existing mappings.
                    return unsafe { self.remap_fallback_with_copy(old_range, new_range, vma) };
                }
                Err(error) => return Err(VmemMoveError::RemapError(error)),
            }
        };

        let new_start = new_addr.as_usize();
        let new_end = new_start + new_size.as_usize();
        self.vmas.insert(new_start..new_end, vma);
        self.vmas.remove(old_range.into());
        Ok(new_addr)
    }

    /// Remap by copying into a newly allocated destination.
    ///
    /// `new_range` provides the destination size and an address hint; the platform may choose a
    /// different one if the given hint is not suitable.
    ///
    /// `vma` is the VMA associated with the source mapping.
    ///
    /// # Safety
    ///
    /// The source must have no active users.
    ///
    /// # Panics
    ///
    /// Failures after destination allocation are fatal because copying or teardown may have begun.
    unsafe fn remap_fallback_with_copy(
        &mut self,
        old_range: PageRange<ALIGN>,
        new_range: PageRange<ALIGN>,
        vma: VmArea,
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        const COPY_CHUNK_SIZE: usize = 1 << 16;

        let permissions = MemoryRegionPermissions::from(vma.flags() & VmFlags::VM_ACCESS_FLAGS);
        let temporary = VmArea::new(
            (vma.flags() | VmFlags::VM_READ | VmFlags::VM_WRITE) - VmFlags::VM_EXEC,
            false,
        );
        let length = NonZeroPageSize::new(new_range.len()).expect("remap destination is empty");
        // SAFETY: Hint placement never replaces existing mappings.
        let destination = unsafe {
            self.create_mapping(
                NonZeroAddress::new(new_range.start()),
                length,
                temporary,
                CreatePagesFlags::TOP_DOWN,
            )
        }
        .map_err(|error| {
            VmemMoveError::RemapError(match error {
                AllocationError::OutOfMemory | AllocationError::AboveMaxAddress => {
                    RemapError::OutOfMemory
                }
                AllocationError::Unaligned | AllocationError::BelowMinAddress => {
                    RemapError::Unaligned
                }
                _ => RemapError::AlreadyAllocated,
            })
        })?;
        let extent = destination.as_usize()..destination.as_usize() + new_range.len();
        if !permissions.contains(MemoryRegionPermissions::READ) {
            // SAFETY: The caller excludes all source users while copying.
            unsafe {
                self.reservations.protect(
                    self.platform,
                    old_range.into(),
                    permissions | MemoryRegionPermissions::READ,
                )
            }
            .expect("failed to make remap source readable");
        }
        let total = old_range.len();
        let mut offset = 0;
        while offset < total {
            let chunk = (total - offset).min(COPY_CHUNK_SIZE);
            let source = Platform::RawConstPointer::<u8>::from_usize(old_range.start() + offset);
            let buffer = source
                .to_owned_slice(chunk)
                .expect("failed to read remap source");
            destination
                .copy_from_slice(offset, &buffer)
                .expect("failed to copy remap source");
            offset += chunk;
        }
        // SAFETY: The destination is mapped, exclusively owned, and copying is complete.
        unsafe {
            self.reservations
                .protect(self.platform, extent.clone(), permissions)
        }
        .expect("failed to restore remap destination permissions");
        self.vmas.insert(extent, vma);
        // SAFETY: Copying is complete and the caller excludes all source users.
        unsafe { self.remove_mapping(old_range) }.expect("failed to unmap remap source");
        Ok(destination)
    }

    /// Change the permissions ([`VmFlags::VM_ACCESS_FLAGS`]) of a range in the virtual address space.
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mprotect.c#L617> for reference.
    ///
    /// # Safety
    ///
    /// The caller must ensure it is safe to change the permissions of the given range, e.g., no more
    /// write access to the range if it is changed to read-only.
    pub(super) unsafe fn protect_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let range: Range<usize> = range.into();
        if self.vmas.gaps(&range).next().is_some() {
            return Err(VmemProtectError::InvalidRange(range));
        }
        // `MemoryRegionPermissions` is a subset of `VmFlags` and we only change the access flags
        let flags =
            VmFlags::from_bits(u32::from(permissions.bits())).unwrap() & VmFlags::VM_ACCESS_FLAGS;
        let mut mappings_to_change = Vec::new();
        for (r, vma) in self.vmas.overlapping(range.clone()) {
            if vma.flags & VmFlags::VM_ACCESS_FLAGS == flags {
                continue;
            }
            // flags >> 4 shift VM_MAY% in place of VM_%
            // turning on VM_% requires VM_MAY%
            if (!(vma.flags.bits() >> 4) & flags.bits()) & VmFlags::VM_ACCESS_FLAGS.bits() != 0 {
                return Err(VmemProtectError::NoAccess {
                    old: vma.flags,
                    new: flags,
                });
            }
            let intersection = range.start.max(r.start)..range.end.min(r.end);
            mappings_to_change.push((intersection, *vma));
        }
        if mappings_to_change.is_empty() {
            return Ok(());
        }

        // SAFETY: The range has complete VMA coverage and the caller excludes conflicting access.
        unsafe { self.reservations.protect(self.platform, range, permissions) }
            .map_err(VmemProtectError::ProtectError)?;
        for (intersection, mut vma) in mappings_to_change {
            let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
            vma.flags = VmArea::new(new_flags, vma.is_file_backed).flags;
            self.vmas.insert(intersection, vma);
        }

        Ok(())
    }

    /// Create a mapping with the given flags.
    ///
    /// `suggested_new_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// `perm` is the permissions to set for the created pages.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    pub(super) unsafe fn create_pages(
        &mut self,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        perms: MemoryRegionPermissions,
        allowed_range: Option<Range<usize>>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        unsafe {
            self.create_pages_with_maximum(
                suggested_new_address,
                length,
                flags,
                perms,
                MemoryRegionPermissions::READ
                    | MemoryRegionPermissions::WRITE
                    | MemoryRegionPermissions::EXEC,
                allowed_range,
            )
        }
    }

    /// Same as [`Self::create_pages`], but the `VM_MAY*` flags are also limited to `maximum`,
    /// so a later [`Self::protect_mapping`] cannot add access beyond it.
    ///
    /// # Safety
    ///
    /// Same as [`Self::create_pages`].
    pub(super) unsafe fn create_pages_with_maximum(
        &mut self,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        perms: MemoryRegionPermissions,
        maximum: MemoryRegionPermissions,
        allowed_range: Option<Range<usize>>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let shared = flags.contains(CreatePagesFlags::SHARED);
        let file_backed = flags.contains(CreatePagesFlags::MAP_FILE);
        // VM_MAY% is VM_% << 4.
        let maximum = VmFlags::from_bits_truncate(
            (VmFlags::from(maximum) & VmFlags::VM_ACCESS_FLAGS).bits() << 4,
        ) | !VmFlags::VM_MAY_ACCESS_FLAGS;
        let mut vma = VmArea::new(
            VmFlags::from(perms)
                | (VmFlags::may_flags_for_mapping(shared, file_backed) & maximum)
                | if flags.contains(CreatePagesFlags::IS_STACK) {
                    VmFlags::VM_GROWSDOWN
                } else {
                    VmFlags::empty()
                },
            file_backed,
        );
        if vma.is_shared_anonymous() {
            self.shared_anonymous_mappings += 1;
            let mapping = NonZeroU64::new(self.shared_anonymous_mappings)
                .expect("a count that only grows from zero is nonzero after an increment");
            vma.sharing = Sharing::Unnamed(mapping);
        }
        // SAFETY: The caller authorizes any replacement `FIXED_ADDR` requests.
        unsafe {
            self.create_mapping_in_range(suggested_new_address, length, vma, flags, allowed_range)
        }
        .map_err(MappingError::MapError)
    }

    /// Get the flags of the single area that covers a given address range.
    ///
    /// `page_range` specifies the range of pages to check.
    /// This function returns `VmFlags` only if the range is valid.
    pub(super) fn get_memory_flags(&self, page_range: PageRange<ALIGN>) -> Option<VmFlags> {
        let (range_start, range_end) = (page_range.start(), page_range.end());
        let range: core::ops::Range<usize> = page_range.into();
        if let Some(iter) = self.overlapping(range).next() {
            if iter.0.start > range_start || iter.0.end < range_end {
                // partial overlap implies that the given range contains unmapped pages or
                // consists of memory pages with different permissions.
                return None;
            }
            Some(iter.1.flags())
        } else {
            None
        }
    }

    /*================================Internal Functions================================ */

    fn build_unmapped_area_request(
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        behavior: FixedAddressBehavior,
        allowed_range: Option<Range<usize>>,
    ) -> FindAreaRequest<ALIGN> {
        // Only fixed-address requests may go above the placement limit; addresses chosen here,
        // including fallbacks for unusable hints, stay below it.
        let (address_range_end, alignment) = match (suggested_address, behavior) {
            (None, _) => (
                // Some platform may allocate more than requested to satisfy alignment requirements,
                // so we restrict the maximum address to avoid exceeding the platform's addressable range.
                Platform::PLACEMENT_ADDR_MAX & !(Platform::RESERVATION_ALIGNMENT - 1),
                // When no specific address is suggested, use the platform's reservation alignment
                // to minimize fragmentation and number of system calls.
                Platform::RESERVATION_ALIGNMENT,
            ),
            (Some(_), FixedAddressBehavior::Hint(_)) => (Platform::PLACEMENT_ADDR_MAX, ALIGN),
            (Some(_), FixedAddressBehavior::NoReplace | FixedAddressBehavior::Replace) => {
                (Platform::TASK_ADDR_MAX, ALIGN)
            }
        };
        let address_range = if let Some(range) = allowed_range {
            Platform::TASK_ADDR_MIN.max(range.start)..address_range_end.min(range.end)
        } else {
            Platform::TASK_ADDR_MIN..address_range_end
        };
        FindAreaRequest {
            suggested_address,
            length,
            behavior,
            alignment,
            address_range,
        }
    }

    /// Search VMA gaps while preserving stack guards.
    pub(super) fn find_area(
        &self,
        request: &FindAreaRequest<ALIGN>,
    ) -> Result<Option<usize>, AllocationError> {
        debug_assert!(
            request
                .suggested_address
                .is_none_or(|address| address.as_usize().is_multiple_of(request.alignment))
        );
        let size = request.length.as_usize();
        if size > Platform::TASK_ADDR_MAX {
            return Ok(None);
        }
        if let Some(suggested_address) = request.suggested_address {
            let suggested_address = suggested_address.as_usize();
            let end = suggested_address.saturating_add(size);
            match request.behavior {
                FixedAddressBehavior::Hint(_) => {
                    if suggested_address >= request.address_range.start
                        && end <= request.address_range.end
                        && !self.vmas.overlaps(&(suggested_address..end))
                    {
                        return Ok(Some(suggested_address));
                    }
                    // fall through if the hint cannot be used
                }
                FixedAddressBehavior::NoReplace | FixedAddressBehavior::Replace => {
                    if suggested_address < request.address_range.start {
                        return Err(AllocationError::BelowMinAddress);
                    }
                    if end > request.address_range.end {
                        return Err(AllocationError::AboveMaxAddress);
                    }
                    if request.behavior == FixedAddressBehavior::Replace
                        || !self.vmas.overlaps(&(suggested_address..end))
                    {
                        return Ok(Some(suggested_address));
                    }
                    return Err(AllocationError::AddressInUse);
                }
            }
        } else if !matches!(request.behavior, FixedAddressBehavior::Hint(_)) {
            return Err(AllocationError::BelowMinAddress);
        }

        Ok(self.find_area_in_range(request))
    }

    fn find_area_in_range(&self, request: &FindAreaRequest<ALIGN>) -> Option<usize> {
        let top_down = matches!(
            request.behavior,
            FixedAddressBehavior::Hint(AllocationDirection::TopDown)
        );
        let size = request.length.as_usize();
        let low_limit = request
            .address_range
            .start
            .max(Platform::TASK_ADDR_MIN)
            .checked_next_multiple_of(request.alignment)?;
        let high_limit = request.address_range.end.min(Platform::TASK_ADDR_MAX);
        if high_limit.checked_sub(low_limit)? < size {
            return None;
        }
        debug_assert_eq!(Platform::TASK_ADDR_MIN % ALIGN, 0);
        debug_assert_eq!(Platform::TASK_ADDR_MAX % ALIGN, 0);
        let find_in_gap = |gap: Range<usize>| {
            let start = if top_down {
                gap.end.checked_sub(size)? & !(request.alignment - 1)
            } else {
                gap.start.checked_next_multiple_of(request.alignment)?
            };
            if start >= gap.start && start.checked_add(size)? <= gap.end {
                Some(start)
            } else {
                None
            }
        };
        // A grow-down mapping also blocks the guard gap below its start.
        let blocked_extent = |(range, vma): (&Range<usize>, &VmArea)| {
            let guard = if vma.flags.contains(VmFlags::VM_GROWSDOWN) {
                Self::STACK_GUARD_GAP << 1
            } else {
                0
            };
            range.start.saturating_sub(guard).min(high_limit)..range.end.max(low_limit)
        };
        // Walk mappings in search order, testing the free gap that precedes each one.
        if top_down {
            let mut boundary = high_limit;
            for blocked in self.vmas.iter().rev().map(blocked_extent) {
                if let Some(start) = find_in_gap(blocked.end..boundary) {
                    return Some(start);
                }
                boundary = blocked.start;
            }
            find_in_gap(low_limit..boundary)
        } else {
            let mut boundary = low_limit;
            for blocked in self.vmas.iter().map(blocked_extent) {
                if let Some(start) = find_in_gap(boundary..blocked.start) {
                    return Some(start);
                }
                boundary = blocked.end;
            }
            find_in_gap(boundary..high_limit)
        }
    }
}

/// Error for removing mappings
#[derive(Error, Debug)]
pub enum VmemUnmapError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("range {0:?} extends outside user address space")]
    InvalidRange(Range<usize>),
    #[error("failed to unmap pages: {0}")]
    UnmapError(#[from] litebox::platform::page_mgmt::DeallocationError),
}

/// Error for resetting pages
#[derive(Error, Debug)]
pub enum VmemResetError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("reset file-backed mapping")]
    FileBacked,
}

/// Error for [`Vmem::resize_mapping`]
#[derive(Error, Debug)]
pub(super) enum VmemResizeError {
    #[error("no mapping containing the address {0:?}")]
    NotExist(usize),
    #[error("invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr { range: Range<usize>, addr: usize },
    #[error("range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<usize>),
    #[error("requested page permissions are denied")]
    PermissionDenied,
    #[error("out of memory")]
    OutOfMemory,
    /// Such as growing a shared anonymous mapping.
    #[error("unsupported")]
    Unsupported,
}

/// Error for moving mappings
#[derive(Error, Debug)]
pub enum VmemMoveError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("out of memory")]
    OutOfMemory,
    /// Such as moving a shared anonymous or file-backed mapping.
    #[error("unsupported")]
    Unsupported,
    #[error("remap failed: {0}")]
    RemapError(#[from] litebox::platform::page_mgmt::RemapError),
}

/// Error for protecting mappings
#[derive(Error, Debug)]
pub enum VmemProtectError {
    #[error("the range {0:?} is not aligned")]
    UnAligned(Range<usize>),
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("unsupported page protection")]
    UnsupportedProtection,
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] litebox::platform::page_mgmt::PermissionUpdateError),
}

/// Error for creating mappings
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("not enough memory")]
    OutOfMemory,
    #[error("mapping memory is inaccessible")]
    MemoryAccess,

    // Errors from mapping a file
    #[error("bad file descriptor: {0}")]
    BadFD(i32),
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for reading")]
    NotForReading,
    #[error("invalid memory permissions")]
    InvalidPermissions,

    #[error("mapping failed: {0}")]
    MapError(#[from] litebox::platform::page_mgmt::AllocationError),
    #[error("failed to apply mapping permissions: {0}")]
    ProtectError(#[from] VmemProtectError),
}

/// Enable [`crate::mm::VmemManager`] to handle page faults if its platform implements this trait.
pub trait VmemPageFaultHandler {
    /// Handle a page fault for the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError>;

    /// Check if it has access to the fault address.
    fn access_error(error_code: u64, flags: VmFlags) -> bool;
}

/// Error for handling page fault
#[derive(Error, Debug)]
pub enum PageFaultError {
    #[error("no access: {0}")]
    AccessError(&'static str),
    #[error("allocation failed")]
    AllocationFailed,
    #[error("given page is part of an already mapped huge page")]
    HugePage,
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use alloc::{boxed::Box, vec, vec::Vec};
    use litebox::platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{
            AllocationDirection, AllocationError, FixedAddressBehavior, HintPlacementBehavior,
            MemoryRegionPermissions,
        },
        trivial_providers::{TransparentConstPtr, TransparentMutPtr},
    };
    use spin::Mutex;
    use zerocopy::{FromBytes, IntoBytes};

    use super::*;

    type AllocationCall = (Range<usize>, FixedAddressBehavior);
    type PermissionUpdate = (Range<usize>, MemoryRegionPermissions);

    litebox::define_page_reservation!(DummyReservation);

    type UntrackedDummyReservations = NoTrackedReservations<PAGE_SIZE, DummyReservation<PAGE_SIZE>>;
    type TrackedDummyReservations = TrackedReservations<DummyReservation<PAGE_SIZE>>;

    /// A configurable dummy page-management backend.
    struct DummyVmemBackend<
        const TOP_DOWN: bool = false,
        Store = UntrackedDummyReservations,
        const LIMITED_PLACEMENT: bool = false,
        const RESERVATION_ALIGN: usize = PAGE_SIZE,
    > {
        rejected_address: Option<usize>,
        rejected_remap_address: Mutex<Option<usize>>,
        remap_unsupported: bool,
        remap_calls: Mutex<Vec<Range<usize>>>,
        rejected_commit: Option<usize>,
        calls: Mutex<Vec<AllocationCall>>,
        decommits: Mutex<Vec<Range<usize>>>,
        shared_allocations: Mutex<Vec<Range<usize>>>,
        rejected_release: Mutex<Option<usize>>,
        releases: Mutex<Vec<Range<usize>>>,
        permission_updates: Mutex<Vec<PermissionUpdate>>,
        store: core::marker::PhantomData<fn() -> Store>,
    }

    impl<const TOP_DOWN: bool, Store, const LIMITED_PLACEMENT: bool, const RESERVATION_ALIGN: usize>
        litebox::platform::RawPointerProvider
        for DummyVmemBackend<TOP_DOWN, Store, LIMITED_PLACEMENT, RESERVATION_ALIGN>
    {
        type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
        type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
    }

    #[expect(unused_variables, reason = "dummy/mock backend")]
    impl<const TOP_DOWN: bool, Store, const LIMITED_PLACEMENT: bool, const RESERVATION_ALIGN: usize>
        PageManagementProvider<PAGE_SIZE>
        for DummyVmemBackend<TOP_DOWN, Store, LIMITED_PLACEMENT, RESERVATION_ALIGN>
    where
        Store: ReservationStore<Reservation = DummyReservation<PAGE_SIZE>> + Default,
        Store::ReleaseTarget: Into<Range<usize>>,
    {
        type Reservations = Store;

        const RESERVATION_ALIGNMENT: usize = RESERVATION_ALIGN;

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        const TASK_ADDR_MIN: usize = 0x1_0000;
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000;
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        const TASK_ADDR_MAX: usize = 0xFFFF_FFFF_F000;
        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        const TASK_ADDR_MAX: usize = 0x7FFF_FFFE_F000;
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        const TASK_ADDR_MIN: usize = 0x1_0000; // Vmem unit-test bound
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        const TASK_ADDR_MAX: usize = 0x7FFF_FE00_0000; // MACH_VM_MAX_ADDRESS
        const PLACEMENT_ADDR_MAX: usize = if LIMITED_PLACEMENT {
            Self::TASK_ADDR_MAX - PAGE_SIZE
        } else {
            Self::TASK_ADDR_MAX
        };
        const HINT_PLACEMENT_BEHAVIOR: HintPlacementBehavior =
            HintPlacementBehavior::Directional(if TOP_DOWN {
                AllocationDirection::TopDown
            } else {
                AllocationDirection::BottomUp
            });

        unsafe fn commit_pages<'reservation, Reservations>(
            &self,
            _covering_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
            _permissions: MemoryRegionPermissions,
            options: AllocationOptions,
        ) -> Result<TransparentMutPtr<u8>, AllocationError>
        where
            Reservations: Iterator<Item = &'reservation DummyReservation<PAGE_SIZE>>,
            DummyReservation<PAGE_SIZE>: 'reservation,
        {
            if self.rejected_commit == Some(range.start) {
                return Err(AllocationError::OutOfMemory);
            }
            if options.contains(AllocationOptions::SHARED) {
                self.shared_allocations.lock().push(range.clone());
            }
            Ok(TransparentMutPtr::from_usize(range.start))
        }

        unsafe fn reserve_and_commit_pages<Reservations>(
            &self,
            _replaced_reservations: impl FnOnce() -> Reservations,
            suggested_range: Range<usize>,
            initial_permissions: MemoryRegionPermissions,
            options: AllocationOptions,
            fixed_address_behavior: FixedAddressBehavior,
        ) -> Result<litebox::platform::page_mgmt::ReservationOf<Self, PAGE_SIZE>, AllocationError>
        where
            Reservations:
                Iterator<Item = litebox::platform::page_mgmt::ReservationOf<Self, PAGE_SIZE>>,
        {
            debug_assert!(!suggested_range.is_empty());
            debug_assert!(
                suggested_range.start >= Self::TASK_ADDR_MIN
                    || (suggested_range.start == 0
                        && matches!(fixed_address_behavior, FixedAddressBehavior::Hint(_)))
            );
            debug_assert!(suggested_range.end <= Self::TASK_ADDR_MAX);
            self.calls
                .lock()
                .push((suggested_range.clone(), fixed_address_behavior));
            if fixed_address_behavior == FixedAddressBehavior::NoReplace
                && self.rejected_address == Some(suggested_range.start)
            {
                return Err(AllocationError::AddressInUse);
            }
            if options.contains(AllocationOptions::SHARED) {
                self.shared_allocations.lock().push(suggested_range.clone());
            }
            // SAFETY: The mock models successful exclusive ownership of this exact range.
            Ok(unsafe { DummyReservation::new(suggested_range) })
        }

        unsafe fn decommit_pages<'reservation, Reservations>(
            &self,
            _covering_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
        ) -> Result<(), litebox::platform::page_mgmt::DeallocationError>
        where
            Reservations: Iterator<Item = &'reservation DummyReservation<PAGE_SIZE>>,
            DummyReservation<PAGE_SIZE>: 'reservation,
        {
            self.decommits.lock().push(range);
            Ok(())
        }

        unsafe fn release_pages(
            &self,
            target: litebox::platform::page_mgmt::ReleaseTargetOf<Self, PAGE_SIZE>,
        ) -> Result<(), DeallocationError> {
            let range = target.into();
            let rejected = *self.rejected_release.lock() == Some(range.start);
            self.releases.lock().push(range);
            if rejected {
                return Err(DeallocationError::AlreadyUnallocated);
            }
            Ok(())
        }

        unsafe fn try_remap_pages<Reservations>(
            &self,
            source_reservations: impl FnOnce() -> Reservations,
            _old_range: Range<usize>,
            new_range: Range<usize>,
            _permissions: MemoryRegionPermissions,
        ) -> Result<
            litebox::platform::page_mgmt::ReservationOf<Self, PAGE_SIZE>,
            litebox::platform::page_mgmt::RemapError,
        >
        where
            Reservations:
                Iterator<Item = litebox::platform::page_mgmt::ReservationOf<Self, PAGE_SIZE>>,
        {
            self.remap_calls.lock().push(new_range.clone());
            if *self.rejected_remap_address.lock() == Some(new_range.start) {
                return Err(litebox::platform::page_mgmt::RemapError::AddressInUseByPlatform);
            }
            if self.remap_unsupported {
                return Err(litebox::platform::page_mgmt::RemapError::UnsupportedByPlatform);
            }
            source_reservations().for_each(drop);
            // SAFETY: The mock models successful transfer to this exact destination.
            Ok(unsafe { DummyReservation::new(new_range) })
        }

        unsafe fn protect_pages<'reservation, Reservations>(
            &self,
            covering_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
            new_permissions: MemoryRegionPermissions,
        ) -> Result<(), PermissionUpdateError>
        where
            Reservations: Iterator<Item = &'reservation DummyReservation<PAGE_SIZE>>,
        {
            let mut reservations = covering_reservations().peekable();
            let mut updates = self.permission_updates.lock();
            if reservations.peek().is_none() {
                updates.push((range, new_permissions));
            } else {
                for reservation in reservations {
                    let extent = reservation.range();
                    updates.push((
                        range.start.max(extent.start)..range.end.min(extent.end),
                        new_permissions,
                    ));
                }
            }
            Ok(())
        }
    }

    fn dummy_backend<const TOP_DOWN: bool>(
        rejected_address: Option<usize>,
    ) -> &'static DummyVmemBackend<TOP_DOWN> {
        new_dummy_backend::<TOP_DOWN, UntrackedDummyReservations, false>(rejected_address, None)
    }

    fn tracked_dummy_backend(
        rejected_commit: Option<usize>,
    ) -> &'static DummyVmemBackend<false, TrackedDummyReservations> {
        new_dummy_backend::<false, TrackedDummyReservations, false>(None, rejected_commit)
    }

    fn new_dummy_backend<const TOP_DOWN: bool, Store: 'static, const LIMITED_PLACEMENT: bool>(
        rejected_address: Option<usize>,
        rejected_commit: Option<usize>,
    ) -> &'static DummyVmemBackend<TOP_DOWN, Store, LIMITED_PLACEMENT> {
        new_dummy_backend_with_alignment::<TOP_DOWN, Store, LIMITED_PLACEMENT, PAGE_SIZE>(
            rejected_address,
            rejected_commit,
        )
    }

    fn new_dummy_backend_with_alignment<
        const TOP_DOWN: bool,
        Store: 'static,
        const LIMITED_PLACEMENT: bool,
        const RESERVATION_ALIGN: usize,
    >(
        rejected_address: Option<usize>,
        rejected_commit: Option<usize>,
    ) -> &'static DummyVmemBackend<TOP_DOWN, Store, LIMITED_PLACEMENT, RESERVATION_ALIGN> {
        Box::leak(Box::new(DummyVmemBackend {
            rejected_address,
            rejected_remap_address: Mutex::new(None),
            remap_unsupported: false,
            remap_calls: Mutex::new(Vec::new()),
            rejected_commit,
            calls: Mutex::new(Vec::new()),
            decommits: Mutex::new(Vec::new()),
            shared_allocations: Mutex::new(Vec::new()),
            rejected_release: Mutex::new(None),
            releases: Mutex::new(Vec::new()),
            permission_updates: Mutex::new(Vec::new()),
            store: core::marker::PhantomData,
        }))
    }

    #[test]
    fn constrained_allocation_retries_without_escaping_range() {
        let low = DummyVmemBackend::<true>::TASK_ADDR_MIN + 8 * PAGE_SIZE;
        for top_down in [false, true] {
            let allowed = low..low + 4 * PAGE_SIZE;
            let rejected = if top_down {
                allowed.end - PAGE_SIZE
            } else {
                allowed.start
            };
            let flags = if top_down {
                CreatePagesFlags::TOP_DOWN
            } else {
                CreatePagesFlags::empty()
            };
            for suggested_address in [None, NonZeroAddress::new(rejected)] {
                let backend = dummy_backend::<true>(Some(rejected));
                let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);
                // SAFETY: The dummy backend owns no live memory and this cannot replace mappings.
                let pointer = unsafe {
                    vmem.create_mapping_in_range(
                        suggested_address,
                        NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                        VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                        flags,
                        Some(allowed.clone()),
                    )
                }
                .unwrap();
                assert_eq!(
                    pointer.as_usize(),
                    if top_down {
                        rejected - PAGE_SIZE
                    } else {
                        rejected + PAGE_SIZE
                    }
                );
                let calls = backend.calls.lock();
                if suggested_address.is_none() {
                    assert_eq!(calls.len(), 2);
                }
                assert!(calls.iter().all(|(range, behavior)| {
                    range.start >= allowed.start
                        && range.end <= allowed.end
                        && *behavior == FixedAddressBehavior::NoReplace
                }));
            }
        }
    }

    #[test]
    fn constrained_allocation_intersects_platform_placement_limits() {
        type Backend = DummyVmemBackend<true, UntrackedDummyReservations, true>;
        let backend = new_dummy_backend::<true, UntrackedDummyReservations, true>(None, None);
        let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);
        // SAFETY: The dummy backend owns no live memory and this cannot replace mappings.
        let pointer = unsafe {
            vmem.create_mapping_in_range(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::TOP_DOWN,
                Some(0..usize::MAX),
            )
        }
        .unwrap();
        assert_eq!(pointer.as_usize(), Backend::PLACEMENT_ADDR_MAX - PAGE_SIZE);
        // SAFETY: The interval is outside placement limits and cannot replace mappings.
        let result = unsafe {
            vmem.create_mapping_in_range(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::TOP_DOWN,
                Some(Backend::PLACEMENT_ADDR_MAX..Backend::TASK_ADDR_MAX),
            )
        };
        assert!(matches!(result, Err(AllocationError::OutOfMemory)));
        assert_eq!(backend.calls.lock().len(), 1);
    }

    #[test]
    fn constrained_allocation_enforces_whole_range_in_both_directions() {
        for top_down in [false, true] {
            let backend = dummy_backend::<true>(None);
            let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);
            let low = DummyVmemBackend::<true>::TASK_ADDR_MIN + 8 * PAGE_SIZE;
            let allowed = low + 1..low + 4 * PAGE_SIZE - 1;
            let flags = if top_down {
                CreatePagesFlags::TOP_DOWN
            } else {
                CreatePagesFlags::empty()
            };
            // SAFETY: The dummy backend owns no live memory and no mappings are replaced.
            let pointer = unsafe {
                vmem.create_mapping_in_range(
                    None,
                    NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                    VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                    flags,
                    Some(allowed.clone()),
                )
            }
            .unwrap();
            assert_eq!(pointer.as_usize(), low + PAGE_SIZE);
            // SAFETY: This request cannot replace mappings; the constrained range is too small.
            let result = unsafe {
                vmem.create_mapping_in_range(
                    None,
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                    flags,
                    Some(allowed),
                )
            };
            assert!(matches!(result, Err(AllocationError::OutOfMemory)));
            assert_eq!(backend.calls.lock().len(), 1);
        }
    }

    #[test]
    fn constrained_allocation_rejects_empty_reversed_and_too_small_ranges() {
        let low = DummyVmemBackend::<true>::TASK_ADDR_MIN;
        let backend = dummy_backend::<true>(None);
        let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);
        for allowed in [low..low, low + PAGE_SIZE..low, low..low + PAGE_SIZE - 1] {
            // SAFETY: These non-replacing requests cannot allocate inside an invalid range.
            let result = unsafe {
                vmem.create_mapping_in_range(
                    None,
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                    CreatePagesFlags::TOP_DOWN,
                    Some(allowed),
                )
            };
            assert!(matches!(result, Err(AllocationError::OutOfMemory)));
        }
        assert!(backend.calls.lock().is_empty());
    }

    #[test]
    fn shared_anonymous_mappings_can_shrink_but_not_grow_or_move() {
        let backend = dummy_backend::<true>(None);
        let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);
        let start = DummyVmemBackend::<true>::TASK_ADDR_MIN;
        let shared = VmArea::new(
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_SHARED,
            false,
        );
        let pages = |start: usize, count: usize| {
            PageRange::<PAGE_SIZE>::new(start, start + count * PAGE_SIZE).unwrap()
        };
        let size = |count: usize| NonZeroPageSize::new(count * PAGE_SIZE).unwrap();
        unsafe {
            vmem.create_mapping(
                NonZeroAddress::new(start),
                size(2),
                shared,
                CreatePagesFlags::FIXED_ADDR,
            )
        }
        .unwrap();

        // An invalid range fails as such first.
        assert!(matches!(
            unsafe { vmem.resize_mapping(pages(start, 3), size(4)) },
            Err(VmemResizeError::InvalidAddr { .. })
        ));
        assert!(matches!(
            unsafe { vmem.resize_mapping(pages(start, 2), size(3)) },
            Err(VmemResizeError::Unsupported)
        ));
        for new_size in [size(2), size(3)] {
            assert!(matches!(
                unsafe { vmem.move_mappings(pages(start, 2), None, new_size) },
                Err(VmemMoveError::Unsupported)
            ));
        }

        unsafe { vmem.resize_mapping(pages(start, 2), size(1)) }.unwrap();
        let (range, area) = vmem
            .overlapping(start..start + 2 * PAGE_SIZE)
            .next()
            .unwrap();
        assert_eq!(*range, start..start + PAGE_SIZE);
        assert!(area.is_shared_anonymous());

        // File-backed mappings cannot move.
        let file = start + 4 * PAGE_SIZE;
        unsafe {
            vmem.create_mapping(
                NonZeroAddress::new(file),
                size(1),
                VmArea::new(VmFlags::VM_READ, true),
                CreatePagesFlags::FIXED_ADDR,
            )
        }
        .unwrap();
        assert!(matches!(
            unsafe { vmem.move_mappings(pages(file, 1), None, size(2)) },
            Err(VmemMoveError::Unsupported)
        ));
        assert!(backend.remap_calls.lock().is_empty());
    }

    #[test]
    fn remap_retries_below_a_platform_collision() {
        let backend = dummy_backend::<true>(None);
        let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);
        let source = DummyVmemBackend::<true>::TASK_ADDR_MIN;
        unsafe {
            vmem.create_mapping(
                NonZeroAddress::new(source),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::FIXED_ADDR,
            )
        }
        .unwrap();
        let rejected = DummyVmemBackend::<true>::TASK_ADDR_MAX - PAGE_SIZE;
        *backend.rejected_remap_address.lock() = Some(rejected);

        let destination = unsafe {
            vmem.move_mappings(
                PageRange::new(source, source + PAGE_SIZE).unwrap(),
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
            )
        }
        .unwrap()
        .as_usize();

        assert_eq!(destination, rejected - PAGE_SIZE);
        assert_eq!(
            *backend.remap_calls.lock(),
            [
                rejected..rejected + PAGE_SIZE,
                destination..destination + PAGE_SIZE,
            ]
        );
    }

    #[test]
    fn bottom_up_hint_does_not_limit_fallback_search() {
        let backend = dummy_backend::<false>(None);
        let mut vmem: Vmem<DummyVmemBackend, PAGE_SIZE> = Vmem::new(backend);
        let suggested_address = DummyVmemBackend::<false>::TASK_ADDR_MIN + PAGE_SIZE;
        unsafe {
            vmem.create_mapping(
                NonZeroAddress::new(suggested_address),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::FIXED_ADDR,
            )
        }
        .unwrap();

        let address = unsafe {
            vmem.create_mapping(
                NonZeroAddress::new(suggested_address),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::empty(),
            )
        }
        .unwrap()
        .as_usize();

        assert_eq!(address, DummyVmemBackend::<false>::TASK_ADDR_MIN);
        assert_eq!(
            *backend.calls.lock(),
            [
                (
                    suggested_address..suggested_address + PAGE_SIZE,
                    FixedAddressBehavior::NoReplace,
                ),
                (
                    address..address + PAGE_SIZE,
                    FixedAddressBehavior::Hint(AllocationDirection::BottomUp),
                ),
            ]
        );
    }

    #[test]
    fn matching_platform_direction_uses_hint() {
        let backend = dummy_backend::<true>(Some(DummyVmemBackend::<true>::TASK_ADDR_MAX));
        let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);

        let address = unsafe {
            vmem.create_mapping(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::TOP_DOWN,
            )
        }
        .unwrap()
        .as_usize();

        assert_eq!(address, DummyVmemBackend::<true>::TASK_ADDR_MAX - PAGE_SIZE);
        assert_eq!(
            *backend.calls.lock(),
            [(
                address..address + PAGE_SIZE,
                FixedAddressBehavior::Hint(AllocationDirection::TopDown),
            )]
        );
    }

    #[test]
    fn limited_placement_range_uses_no_replace() {
        type Backend = DummyVmemBackend<true, UntrackedDummyReservations, true>;
        let backend = new_dummy_backend::<true, UntrackedDummyReservations, true>(None, None);
        let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);

        let address = unsafe {
            vmem.create_mapping(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::TOP_DOWN,
            )
        }
        .unwrap()
        .as_usize();

        assert_eq!(address, Backend::PLACEMENT_ADDR_MAX - PAGE_SIZE);
        assert_eq!(
            *backend.calls.lock(),
            [(
                address..address + PAGE_SIZE,
                FixedAddressBehavior::NoReplace,
            )]
        );
    }

    #[test]
    fn platform_rejected_hint_restarts_full_search() {
        let suggested_address = DummyVmemBackend::<true>::TASK_ADDR_MAX - PAGE_SIZE;
        let backend = dummy_backend::<true>(Some(suggested_address));
        let mut vmem = Vmem::<_, PAGE_SIZE>::new(backend);

        let address = unsafe {
            vmem.create_mapping(
                NonZeroAddress::new(suggested_address),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::empty(),
            )
        }
        .unwrap()
        .as_usize();

        assert_eq!(address, DummyVmemBackend::<true>::TASK_ADDR_MIN);
        assert_eq!(
            *backend.calls.lock(),
            [
                (
                    suggested_address..suggested_address + PAGE_SIZE,
                    FixedAddressBehavior::NoReplace,
                ),
                (
                    address..address + PAGE_SIZE,
                    FixedAddressBehavior::NoReplace,
                ),
            ]
        );
    }

    #[test]
    fn mismatched_platform_direction_retries_with_no_replace() {
        let bottom_up_backend = dummy_backend::<true>(Some(0x1_0000));
        let mut bottom_up_vmem = Vmem::<_, PAGE_SIZE>::new(bottom_up_backend);
        let bottom_up_address = unsafe {
            bottom_up_vmem.create_mapping(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::empty(),
            )
        }
        .unwrap()
        .as_usize();
        assert_eq!(bottom_up_address, 0x1_1000);
        assert_eq!(
            *bottom_up_backend.calls.lock(),
            [
                (0x1_0000..0x1_1000, FixedAddressBehavior::NoReplace),
                (0x1_1000..0x1_2000, FixedAddressBehavior::NoReplace),
            ]
        );

        let rejected_address = DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE;
        let top_down_backend = dummy_backend::<false>(Some(rejected_address));
        let mut top_down_vmem = Vmem::<_, PAGE_SIZE>::new(top_down_backend);
        let top_down_address = unsafe {
            top_down_vmem.create_mapping(
                None,
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::TOP_DOWN,
            )
        }
        .unwrap()
        .as_usize();
        assert_eq!(top_down_address, rejected_address - PAGE_SIZE);
        assert_eq!(
            *top_down_backend.calls.lock(),
            [
                (
                    rejected_address..DummyVmemBackend::<false>::TASK_ADDR_MAX,
                    FixedAddressBehavior::NoReplace,
                ),
                (
                    rejected_address - PAGE_SIZE..rejected_address,
                    FixedAddressBehavior::NoReplace,
                ),
            ]
        );
    }

    fn collect_mappings<Platform: PageManagementProvider<PAGE_SIZE>>(
        vmm: &Vmem<Platform, PAGE_SIZE>,
    ) -> Vec<Range<usize>> {
        vmm.iter().map(|v| v.0.start..v.0.end).collect()
    }

    fn collect_reservations(
        vmm: &Vmem<DummyVmemBackend<false, TrackedDummyReservations>, PAGE_SIZE>,
    ) -> Vec<Range<usize>> {
        vmm.reservations
            .iter()
            .map(|(_, reservation)| reservation.range())
            .collect()
    }

    fn read_write_vma() -> VmArea {
        VmArea::new(
            VmFlags::VM_READ | VmFlags::VM_WRITE | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE,
            false,
        )
    }

    #[test]
    fn reservation_mmap_registers_vma_and_shares_anonymous_pages() {
        fn check<Store>(platform: &'static DummyVmemBackend<false, Store>)
        where
            Store: LinuxReservationStore<DummyVmemBackend<false, Store>, PAGE_SIZE>
                + ReservationStore<Reservation = DummyReservation<PAGE_SIZE>>
                + Default
                + 'static,
            Store::ReleaseTarget: Into<Range<usize>>,
        {
            let base = 0x10_0000;
            let range = base..base + 2 * PAGE_SIZE;
            for (shared, file_backed) in [(false, false), (true, false), (true, true)] {
                platform.shared_allocations.lock().clear();
                let mut vmem = Vmem::<_, PAGE_SIZE>::new(platform);
                let mut flags = VmFlags::VM_READ | VmFlags::VM_MAYREAD | VmFlags::VM_MAYEXEC;
                flags.set(VmFlags::VM_SHARED, shared);
                let vma = VmArea::new(flags, file_backed);
                // SAFETY: The mock records mappings without accessing the simulated addresses.
                let pointer = unsafe {
                    vmem.insert_mapping(
                        PageRange::new(range.start, range.end).unwrap(),
                        vma,
                        false,
                        FixedAddressBehavior::NoReplace,
                    )
                }
                .unwrap();
                assert_eq!(pointer.as_usize(), base);
                assert_eq!(vmem.vmas.iter().collect::<Vec<_>>(), [(&range, &vma)]);
                // Shared file-backed mappings are still private copies.
                let expected: &[Range<usize>] = if shared && !file_backed {
                    core::slice::from_ref(&range)
                } else {
                    &[]
                };
                assert_eq!(*platform.shared_allocations.lock(), expected);
                // SAFETY: The simulated mapping has no users.
                unsafe { vmem.release_all() }.unwrap();
            }
        }

        check(dummy_backend::<false>(None));
        check(tracked_dummy_backend(None));
    }

    #[test]
    fn tracked_release_failure_untracks_consumed_reservations_and_preserves_pending() {
        let base = 0x10_0000;
        let page = |index: usize| base + index * PAGE_SIZE;
        let extents = [page(0)..page(1), page(1)..page(2), page(2)..page(3)];
        for unmap in [false, true] {
            for failed in 0..extents.len() {
                let backend = tracked_dummy_backend(None);
                *backend.rejected_release.lock() = Some(extents[failed].start);
                let mut vmm = Vmem::<_, PAGE_SIZE>::new(backend);
                for extent in &extents {
                    // SAFETY: The mock models disjoint, exclusively owned reservation pieces.
                    let reservation = unsafe { DummyReservation::new(extent.clone()) };
                    vmm.reservations.insert(extent.start, reservation);
                }
                vmm.vmas.insert(page(0)..page(3), read_write_vma());

                let result = if unmap {
                    // SAFETY: These simulated mappings have no active users.
                    unsafe {
                        vmm.reservations
                            .unmap(backend, &mut vmm.vmas, page(0)..page(3))
                    }
                } else {
                    // SAFETY: These simulated mappings have no active users.
                    unsafe { vmm.release_all() }
                };
                assert!(matches!(result, Err(DeallocationError::AlreadyUnallocated)));
                assert_eq!(*backend.releases.lock(), extents[..=failed]);
                assert_eq!(collect_reservations(&vmm), extents[failed + 1..]);
                let pending_range = page(failed + 1)..page(3);
                let pending: &[Range<usize>] = if pending_range.is_empty() {
                    &[]
                } else {
                    core::slice::from_ref(&pending_range)
                };
                assert_eq!(collect_mappings(&vmm), pending);

                *backend.rejected_release.lock() = None;
                // SAFETY: The remaining simulated mappings still have no active users.
                unsafe { vmm.release_all() }.unwrap();
                assert_eq!(*backend.releases.lock(), extents);
                assert_eq!(collect_reservations(&vmm), []);
                assert_eq!(collect_mappings(&vmm), []);
            }
        }
    }

    #[test]
    fn tracked_unmap_retains_unaligned_reservations_until_teardown() {
        let base = 0x10_0000;
        let alignment = 0x1_0000;
        let backend =
            new_dummy_backend_with_alignment::<false, TrackedDummyReservations, false, 0x1_0000>(
                None, None,
            );
        let mut vmm = Vmem::<_, PAGE_SIZE>::new(backend);
        let extents = [
            base..base + PAGE_SIZE,
            base + PAGE_SIZE..base + 3 * PAGE_SIZE,
            base + 3 * PAGE_SIZE..base + alignment,
            base + alignment..base + 2 * alignment,
        ];
        for extent in &extents {
            // SAFETY: The mock models disjoint, exclusively owned native reservation pieces.
            let reservation = unsafe { DummyReservation::new(extent.clone()) };
            vmm.reservations.insert(extent.start, reservation);
        }
        vmm.vmas
            .insert(base..base + 2 * alignment, read_write_vma());
        for extent in &extents {
            // SAFETY: The simulated mappings have no active users.
            unsafe { vmm.remove_mapping(PageRange::new(extent.start, extent.end).unwrap()) }
                .unwrap();
        }
        assert!(vmm.vmas.is_empty());
        assert_eq!(*backend.releases.lock(), [extents[3].clone()]);
        assert_eq!(*backend.decommits.lock(), extents[..3]);
        assert_eq!(
            vmm.reservations
                .iter()
                .map(|(_, reservation)| reservation.range())
                .collect::<Vec<_>>(),
            extents[..3]
        );
        // SAFETY: All simulated pages are unused, including retained unmapped reservations.
        unsafe { vmm.release_all() }.unwrap();
        assert_eq!(
            *backend.releases.lock(),
            [
                extents[3].clone(),
                extents[0].clone(),
                extents[1].clone(),
                extents[2].clone()
            ]
        );
        assert_eq!(vmm.reservations.iter().count(), 0);
    }

    #[test]
    fn tracked_unmap_releases_middle_reservation_of_coalesced_vma() {
        let base = 0x10_0000;
        let page = |index: usize| base + index * PAGE_SIZE;
        for edge_pages in [1, 2] {
            let mut vmm = Vmem::new(tracked_dummy_backend(None));
            for extent in [
                page(0)..page(edge_pages),
                page(edge_pages)..page(edge_pages + 1),
                page(edge_pages + 1)..page(2 * edge_pages + 1),
            ] {
                // SAFETY: The mock models disjoint, exclusively owned reservations.
                let reservation = unsafe { DummyReservation::new(extent.clone()) };
                vmm.reservations.insert(extent.start, reservation);
            }
            vmm.vmas
                .insert(page(0)..page(2 * edge_pages + 1), read_write_vma());
            // SAFETY: No simulated page has active users, including partially unmapped edges.
            unsafe { vmm.remove_mapping(PageRange::new(page(1), page(2 * edge_pages)).unwrap()) }
                .unwrap();
            assert_eq!(
                *vmm.platform.releases.lock(),
                core::slice::from_ref(&(page(edge_pages)..page(edge_pages + 1)))
            );
            assert_eq!(
                collect_reservations(&vmm),
                [
                    page(0)..page(edge_pages),
                    page(edge_pages + 1)..page(2 * edge_pages + 1),
                ]
            );
            assert_eq!(
                collect_mappings(&vmm),
                [
                    page(0)..page(1),
                    page(2 * edge_pages)..page(2 * edge_pages + 1)
                ]
            );
        }
    }

    #[test]
    fn tracked_unmap_decommits_shared_reservations_and_releases_unused_ones() {
        let base = 0x10_0000;
        let mut vmm = Vmem::new(tracked_dummy_backend(None));
        let page = |index: usize| base + index * PAGE_SIZE;

        unsafe {
            vmm.insert_mapping(
                PageRange::new(page(0), page(4)).unwrap(),
                read_write_vma(),
                false,
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();
        unsafe { vmm.remove_mapping(PageRange::new(page(1), page(2)).unwrap()) }.unwrap();
        assert_eq!(*vmm.platform.decommits.lock(), vec![page(1)..page(2)]);
        assert!(vmm.platform.releases.lock().is_empty());
        assert_eq!(collect_reservations(&vmm), vec![page(0)..page(4)]);
        assert_eq!(collect_mappings(&vmm), [page(0)..page(1), page(2)..page(4)]);

        // Remapping the hole commits within the retained reservation without reserving again.
        unsafe {
            vmm.insert_mapping(
                PageRange::new(page(1), page(2)).unwrap(),
                read_write_vma(),
                false,
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();
        assert_eq!(vmm.platform.calls.lock().len(), 1);
        assert_eq!(collect_mappings(&vmm), vec![page(0)..page(4)]);

        unsafe {
            vmm.insert_mapping(
                PageRange::new(page(8), page(9)).unwrap(),
                read_write_vma(),
                false,
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();
        unsafe { vmm.remove_mapping(PageRange::new(page(8), page(9)).unwrap()) }.unwrap();
        assert_eq!(*vmm.platform.releases.lock(), vec![page(8)..page(9)]);

        unsafe { vmm.release_all() }.unwrap();
        assert_eq!(
            *vmm.platform.releases.lock(),
            [page(8)..page(9), page(0)..page(4)]
        );
        assert_eq!(vmm.reservations.iter().count(), 0);
        assert_eq!(vmm.iter().count(), 0);
    }

    #[test]
    fn tracked_commit_failure_rolls_back_new_reservations() {
        let base = 0x10_0000;
        let page = |index: usize| base + index * PAGE_SIZE;
        let mut vmm = Vmem::new(tracked_dummy_backend(Some(page(1))));

        unsafe {
            vmm.insert_mapping(
                PageRange::new(page(0), page(2)).unwrap(),
                read_write_vma(),
                false,
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();
        unsafe { vmm.remove_mapping(PageRange::new(page(1), page(2)).unwrap()) }.unwrap();

        // The request spans the retained hole and a new gap, so it reserves the gap then commits.
        let result = unsafe {
            vmm.insert_mapping(
                PageRange::new(page(1), page(3)).unwrap(),
                read_write_vma(),
                false,
                FixedAddressBehavior::NoReplace,
            )
        };
        assert!(matches!(result, Err(AllocationError::OutOfMemory)));
        assert_eq!(
            vmm.platform.decommits.lock().last(),
            Some(&(page(1)..page(3)))
        );
        assert_eq!(*vmm.platform.releases.lock(), vec![page(2)..page(3)]);
        assert_eq!(collect_reservations(&vmm), vec![page(0)..page(2)]);
        assert_eq!(collect_mappings(&vmm), vec![page(0)..page(1)]);
    }

    #[test]
    fn tracked_replacement_involving_shared_pages_detaches_them_first() {
        let base = 0x10_0000;
        let target = base + PAGE_SIZE..base + 2 * PAGE_SIZE;
        let private = read_write_vma();
        let shared = VmArea::new(private.flags() | VmFlags::VM_SHARED, false);
        for (previous, replacement) in [(private, shared), (shared, private), (shared, shared)] {
            for commit_fails in [false, true] {
                let backend = tracked_dummy_backend(commit_fails.then_some(target.start));
                let mut vmm = Vmem::new(backend);
                // SAFETY: The mock only records mappings; the fixture owns all simulated pages.
                unsafe {
                    vmm.insert_mapping(
                        PageRange::new(base, target.end).unwrap(),
                        previous,
                        false,
                        FixedAddressBehavior::NoReplace,
                    )
                }
                .unwrap();
                let original_calls = backend.calls.lock().clone();
                backend.shared_allocations.lock().clear();
                // SAFETY: The simulated replacement has no active users.
                let result = unsafe {
                    vmm.insert_mapping(
                        PageRange::new(target.start, target.end).unwrap(),
                        replacement,
                        false,
                        FixedAddressBehavior::Replace,
                    )
                };
                // Like Linux, a failed replacement leaves the replaced pages unmapped.
                let mut expected_mappings = RangeMap::new();
                expected_mappings.insert(base..target.start, previous);
                let mut expected_decommits = vec![target.clone()];
                if commit_fails {
                    assert!(matches!(result, Err(AllocationError::OutOfMemory)));
                    expected_decommits.push(target.clone());
                } else {
                    assert_eq!(result.unwrap().as_usize(), target.start);
                    expected_mappings.insert(target.clone(), replacement);
                }
                assert_eq!(vmm.vmas, expected_mappings);
                assert_eq!(*backend.decommits.lock(), expected_decommits);
                let expected_shared: &[Range<usize>] =
                    if replacement.is_shared_anonymous() && !commit_fails {
                        core::slice::from_ref(&target)
                    } else {
                        &[]
                    };
                assert_eq!(*backend.shared_allocations.lock(), expected_shared);
                assert_eq!(*backend.calls.lock(), original_calls);
                assert_eq!(collect_reservations(&vmm), vec![base..target.end]);
                assert!(backend.releases.lock().is_empty());
            }
        }
    }

    #[test]
    fn tracked_replace_zeroes_existing_contents() {
        let layout = core::alloc::Layout::from_size_align(2 * PAGE_SIZE, PAGE_SIZE).unwrap();
        // SAFETY: The layout is nonzero; the buffer models committed pages and is freed below.
        let buffer = unsafe { alloc::alloc::alloc(layout) };
        assert!(!buffer.is_null());
        let base = buffer as usize;
        let mut vmm = Vmem::new(tracked_dummy_backend(None));

        unsafe {
            vmm.insert_mapping(
                PageRange::new(base, base + 2 * PAGE_SIZE).unwrap(),
                read_write_vma(),
                false,
                FixedAddressBehavior::NoReplace,
            )
        }
        .unwrap();
        // SAFETY: The buffer is live, exclusively owned, and spans two pages.
        unsafe { buffer.write_bytes(0xAA, 2 * PAGE_SIZE) };

        unsafe {
            vmm.insert_mapping(
                PageRange::new(base, base + 2 * PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                false,
                FixedAddressBehavior::Replace,
            )
        }
        .unwrap();
        // SAFETY: The buffer is live and no longer written through the mapping.
        let contents = unsafe { core::slice::from_raw_parts(buffer, 2 * PAGE_SIZE) };
        assert!(contents.iter().all(|&byte| byte == 0));
        assert_eq!(vmm.platform.calls.lock().len(), 1);
        assert_eq!(collect_reservations(&vmm), vec![base..base + 2 * PAGE_SIZE]);
        // SAFETY: The buffer was allocated above with this layout and is no longer used.
        unsafe { alloc::alloc::dealloc(buffer, layout) };
    }

    #[test]
    fn test_vmm_mapping() {
        let start_addr = DummyVmemBackend::<false>::TASK_ADDR_MIN;
        let range = PageRange::new(start_addr, start_addr + 12 * PAGE_SIZE).unwrap();
        let mut vmm = Vmem::new(dummy_backend::<false>(None));

        unsafe {
            vmm.insert_mapping(
                range,
                VmArea::new(
                    VmFlags::VM_READ | VmFlags::VM_MAYREAD | VmFlags::VM_MAYWRITE,
                    false,
                ),
                false,
                FixedAddressBehavior::Replace,
            )
        }
        .unwrap();
        assert_eq!(
            collect_mappings(&vmm),
            vec![start_addr..start_addr + 12 * PAGE_SIZE]
        );

        unsafe {
            vmm.remove_mapping(
                PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
            )
        }
        .unwrap();
        {
            let releases = vmm.platform.releases.lock();
            assert_eq!(releases.len(), 1);
            assert_eq!(
                releases[0],
                start_addr + 2 * PAGE_SIZE..start_addr + 4 * PAGE_SIZE
            );
        }
        assert_eq!(
            collect_mappings(&vmm),
            vec![
                start_addr..start_addr + 2 * PAGE_SIZE,
                start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE
            ]
        );

        assert!(matches!(
            unsafe {
                vmm.resize_mapping(
                    PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 3 * PAGE_SIZE).unwrap(),
                    NonZeroPageSize::new(PAGE_SIZE * 2).unwrap(),
                )
            },
            Err(VmemResizeError::NotExist(_))
        ));

        assert!(matches!(
            unsafe {
                vmm.resize_mapping(
                    PageRange::new(start_addr, start_addr + 3 * PAGE_SIZE).unwrap(),
                    NonZeroPageSize::new(PAGE_SIZE * 4).unwrap(),
                )
            },
            Err(VmemResizeError::InvalidAddr { .. })
        ));

        assert!(matches!(
            unsafe {
                vmm.protect_mapping(
                    PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE).unwrap(),
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                )
            },
            Err(VmemProtectError::InvalidRange(_))
        ));

        assert!(
            unsafe {
                vmm.resize_mapping(
                    PageRange::new(start_addr, start_addr + 2 * PAGE_SIZE).unwrap(),
                    NonZeroPageSize::new(PAGE_SIZE * 4).unwrap(),
                )
            }
            .is_ok()
        );
        assert_eq!(
            collect_mappings(&vmm),
            vec![start_addr..start_addr + 12 * PAGE_SIZE]
        );

        assert!(matches!(
            unsafe {
                vmm.protect_mapping(
                    PageRange::new(start_addr, start_addr + 4 * PAGE_SIZE).unwrap(),
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                )
            },
            Err(VmemProtectError::NoAccess { .. })
        ));

        assert!(
            unsafe {
                vmm.protect_mapping(
                    PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap(),
                    MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                )
            }
            .is_ok()
        );
        assert_eq!(
            collect_mappings(&vmm),
            vec![
                start_addr..start_addr + 2 * PAGE_SIZE,
                start_addr + 2 * PAGE_SIZE..start_addr + 4 * PAGE_SIZE,
                start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE
            ]
        );

        let range = PageRange::new(start_addr + 2 * PAGE_SIZE, start_addr + 4 * PAGE_SIZE).unwrap();
        assert!(matches!(
            unsafe { vmm.resize_mapping(range, NonZeroPageSize::new(PAGE_SIZE * 4).unwrap()) },
            Err(VmemResizeError::RangeOccupied(_))
        ));
        assert!(
            unsafe {
                vmm.move_mappings(
                    range,
                    Some(NonZeroAddress::new(start_addr + 12 * PAGE_SIZE).unwrap()),
                    NonZeroPageSize::new(PAGE_SIZE * 4).unwrap(),
                )
            }
            .is_ok_and(|value| value.as_usize() == start_addr + 12 * PAGE_SIZE)
        );
        assert_eq!(
            collect_mappings(&vmm),
            vec![
                start_addr..start_addr + 2 * PAGE_SIZE,
                start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
                start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE
            ]
        );

        assert_eq!(
            unsafe {
                vmm.create_mapping(
                    None,
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                    CreatePagesFlags::TOP_DOWN,
                )
            }
            .unwrap()
            .as_usize(),
            DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE,
        );
        assert_eq!(
            collect_mappings(&vmm),
            vec![
                start_addr..start_addr + 2 * PAGE_SIZE,
                start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
                start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
                DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE
                    ..DummyVmemBackend::<false>::TASK_ADDR_MAX,
            ]
        );

        assert_eq!(
            unsafe {
                vmm.create_mapping(
                    Some(NonZeroAddress::new(start_addr + PAGE_SIZE).unwrap()),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                    CreatePagesFlags::FIXED_ADDR,
                )
            }
            .unwrap()
            .as_usize(),
            start_addr + PAGE_SIZE
        );
        assert_eq!(
            collect_mappings(&vmm),
            vec![
                start_addr..start_addr + PAGE_SIZE,
                start_addr + PAGE_SIZE..start_addr + 2 * PAGE_SIZE,
                start_addr + 4 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
                start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
                DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE
                    ..DummyVmemBackend::<false>::TASK_ADDR_MAX,
            ]
        );

        assert!(
            unsafe {
                vmm.resize_mapping(
                    PageRange::new(start_addr + 4 * PAGE_SIZE, start_addr + 8 * PAGE_SIZE).unwrap(),
                    NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                )
            }
            .is_ok()
        );
        assert_eq!(
            collect_mappings(&vmm),
            vec![
                start_addr..start_addr + PAGE_SIZE,
                start_addr + PAGE_SIZE..start_addr + 2 * PAGE_SIZE,
                start_addr + 4 * PAGE_SIZE..start_addr + 6 * PAGE_SIZE,
                start_addr + 8 * PAGE_SIZE..start_addr + 12 * PAGE_SIZE,
                start_addr + 12 * PAGE_SIZE..start_addr + 16 * PAGE_SIZE,
                DummyVmemBackend::<false>::TASK_ADDR_MAX - PAGE_SIZE
                    ..DummyVmemBackend::<false>::TASK_ADDR_MAX,
            ]
        );
    }

    #[test]
    fn fixed_mappings_respect_task_address_bounds() {
        let mut vmm = Vmem::new(dummy_backend::<false>(None));
        let vma = VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false);

        let below_min = PageRange::new(
            DummyVmemBackend::<false>::TASK_ADDR_MIN - PAGE_SIZE,
            DummyVmemBackend::<false>::TASK_ADDR_MIN,
        )
        .unwrap();
        assert!(matches!(
            unsafe { vmm.insert_mapping(below_min, vma, false, FixedAddressBehavior::NoReplace,) },
            Err(AllocationError::BelowMinAddress)
        ));

        let above_max = PageRange::new(
            DummyVmemBackend::<false>::TASK_ADDR_MAX,
            DummyVmemBackend::<false>::TASK_ADDR_MAX + PAGE_SIZE,
        )
        .unwrap();
        assert!(matches!(
            unsafe { vmm.insert_mapping(above_max, vma, false, FixedAddressBehavior::NoReplace,) },
            Err(AllocationError::AboveMaxAddress)
        ));
    }

    #[test]
    fn maximum_permissions_bound_protection_changes_and_survive_splits() {
        let start = DummyVmemBackend::<false>::TASK_ADDR_MIN;
        let mut vmm = Vmem::new(dummy_backend::<false>(None));
        let read = MemoryRegionPermissions::READ;
        let rw = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        unsafe {
            vmm.create_pages_with_maximum(
                Some(NonZeroAddress::new(start).unwrap()),
                NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                read,
                read,
                None,
            )
        }
        .unwrap();
        let all = PageRange::new(start, start + 3 * PAGE_SIZE).unwrap();
        let middle = PageRange::new(start + PAGE_SIZE, start + 2 * PAGE_SIZE).unwrap();
        let maximum = |vmm: &Vmem<DummyVmemBackend, PAGE_SIZE>| {
            vmm.iter()
                .map(|(range, vma)| (range.clone(), vma.flags() & VmFlags::VM_MAY_ACCESS_FLAGS))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            maximum(&vmm),
            [(start..start + 3 * PAGE_SIZE, VmFlags::VM_MAYREAD)]
        );
        // Within the maximum: lowering and restoring access, which splits the area.
        unsafe { vmm.protect_mapping(middle, MemoryRegionPermissions::empty()) }.unwrap();
        assert_eq!(vmm.iter().count(), 3);
        assert!(
            vmm.iter().all(|(_, vma)| {
                vma.flags() & VmFlags::VM_MAY_ACCESS_FLAGS == VmFlags::VM_MAYREAD
            })
        );
        unsafe { vmm.protect_mapping(middle, read) }.unwrap();
        // Beyond it, on a split piece and on the whole range.
        for range in [middle, all] {
            assert!(matches!(
                unsafe { vmm.protect_mapping(range, rw) },
                Err(VmemProtectError::NoAccess { .. })
            ));
        }
        // Unmapping part of the area leaves the rest bounded.
        unsafe { vmm.remove_mapping(middle) }.unwrap();
        assert_eq!(
            maximum(&vmm),
            [
                (start..start + PAGE_SIZE, VmFlags::VM_MAYREAD),
                (
                    start + 2 * PAGE_SIZE..start + 3 * PAGE_SIZE,
                    VmFlags::VM_MAYREAD
                ),
            ]
        );
        assert!(matches!(
            unsafe { vmm.protect_mapping(PageRange::new(start, start + PAGE_SIZE).unwrap(), rw) },
            Err(VmemProtectError::NoAccess { .. })
        ));
        // A default mapping keeps every VM_MAY* flag.
        unsafe {
            vmm.create_pages(
                NonZeroAddress::new(start + PAGE_SIZE),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                read,
                None,
            )
        }
        .unwrap();
        unsafe { vmm.protect_mapping(middle, rw) }.unwrap();
        assert!(vmm.iter().any(|(range, vma)| *range == Range::from(middle)
            && vma.flags().contains(VmFlags::VM_MAY_ACCESS_FLAGS)));
    }

    #[test]
    fn inaccessible_areas_remember_whether_they_had_access() {
        let start = DummyVmemBackend::<false>::TASK_ADDR_MIN;
        let mut vmm = Vmem::new(dummy_backend::<false>(None));
        unsafe {
            vmm.create_pages(
                Some(NonZeroAddress::new(start).unwrap()),
                NonZeroPageSize::new(3 * PAGE_SIZE).unwrap(),
                CreatePagesFlags::FIXED_ADDR,
                MemoryRegionPermissions::empty(),
                None,
            )
        }
        .unwrap();
        let accessed = PageRange::new(start + PAGE_SIZE, start + 2 * PAGE_SIZE).unwrap();
        for permissions in [
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            MemoryRegionPermissions::empty(),
        ] {
            unsafe { vmm.protect_mapping(accessed, permissions) }.unwrap();
        }
        assert_eq!(
            contents_by_area(&vmm),
            [
                (start..start + PAGE_SIZE, false),
                (start + PAGE_SIZE..start + 2 * PAGE_SIZE, true),
                (start + 2 * PAGE_SIZE..start + 3 * PAGE_SIZE, false),
            ]
        );

        // Growing in place treats areas that differ only in whether they may hold data as one,
        // without merging them.
        unsafe {
            vmm.resize_mapping(
                PageRange::new(start, start + 3 * PAGE_SIZE).unwrap(),
                NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
            )
        }
        .unwrap();
        let blocker = start + 5 * PAGE_SIZE..start + 6 * PAGE_SIZE;
        unsafe {
            vmm.create_mapping(
                NonZeroAddress::new(blocker.start),
                NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                VmArea::new(VmFlags::VM_READ | VmFlags::VM_MAYREAD, false),
                CreatePagesFlags::FIXED_ADDR,
            )
        }
        .unwrap();
        let split = [
            (start..start + PAGE_SIZE, false),
            (start + PAGE_SIZE..start + 2 * PAGE_SIZE, true),
            (start + 2 * PAGE_SIZE..start + 4 * PAGE_SIZE, false),
            (blocker, true),
        ];
        assert_eq!(contents_by_area(&vmm), split);

        // Failed growth and moves leave them apart.
        let grown = PageRange::new(start, start + 4 * PAGE_SIZE).unwrap();
        let huge = NonZeroPageSize::new(usize::MAX & !(PAGE_SIZE - 1)).unwrap();
        assert!(matches!(
            unsafe { vmm.resize_mapping(grown, NonZeroPageSize::new(6 * PAGE_SIZE).unwrap()) },
            Err(VmemResizeError::RangeOccupied(_))
        ));
        assert!(matches!(
            unsafe { vmm.resize_mapping(grown, huge) },
            Err(VmemResizeError::OutOfMemory)
        ));
        assert!(matches!(
            unsafe { vmm.move_mappings(grown, None, huge) },
            Err(VmemMoveError::OutOfMemory)
        ));
        assert_eq!(contents_by_area(&vmm), split);

        // Moving them makes one area that may hold data.
        let moved =
            unsafe { vmm.move_mappings(grown, None, NonZeroPageSize::new(4 * PAGE_SIZE).unwrap()) }
                .unwrap()
                .as_usize();
        let areas = vmm
            .iter()
            .map(|(range, vma)| (range.clone(), vma.flags()))
            .collect::<Vec<_>>();
        assert_eq!(areas.len(), 2);
        assert_eq!(areas[1].0, moved..moved + 4 * PAGE_SIZE);
        assert!(areas[1].1.contains(VmFlags::VM_HAS_CONTENTS));
        assert!(!areas[1].1.intersects(VmFlags::VM_ACCESS_FLAGS));
    }

    #[test]
    fn growing_across_distinct_areas_fails_before_size_overflows() {
        let start = DummyVmemBackend::<false>::TASK_ADDR_MIN;
        let mut vmm = Vmem::new(dummy_backend::<false>(None));
        for (offset, flags) in [
            (0, VmFlags::VM_READ | VmFlags::VM_MAYREAD),
            (PAGE_SIZE, VmFlags::VM_MAYREAD),
        ] {
            unsafe {
                vmm.create_mapping(
                    NonZeroAddress::new(start + offset),
                    NonZeroPageSize::new(PAGE_SIZE).unwrap(),
                    VmArea::new(flags, false),
                    CreatePagesFlags::FIXED_ADDR,
                )
            }
            .unwrap();
        }

        assert!(matches!(
            unsafe {
                vmm.resize_mapping(
                    PageRange::new(start, start + 2 * PAGE_SIZE).unwrap(),
                    NonZeroPageSize::new(usize::MAX & !(PAGE_SIZE - 1)).unwrap(),
                )
            },
            Err(VmemResizeError::InvalidAddr { .. })
        ));
    }

    fn contents_by_area(vmm: &Vmem<DummyVmemBackend, PAGE_SIZE>) -> Vec<(Range<usize>, bool)> {
        vmm.iter()
            .map(|(range, vma)| {
                let contents = vma.flags().contains(VmFlags::VM_HAS_CONTENTS);
                (range.clone(), contents)
            })
            .collect()
    }

    #[test]
    fn copying_remap_passes_only_access_permissions() {
        let backend: &'static DummyVmemBackend = Box::leak(Box::new(DummyVmemBackend {
            rejected_address: None,
            rejected_remap_address: Mutex::new(None),
            remap_unsupported: true,
            remap_calls: Mutex::new(Vec::new()),
            rejected_commit: None,
            calls: Mutex::new(Vec::new()),
            decommits: Mutex::new(Vec::new()),
            shared_allocations: Mutex::new(Vec::new()),
            rejected_release: Mutex::new(None),
            releases: Mutex::new(Vec::new()),
            permission_updates: Mutex::new(Vec::new()),
            store: core::marker::PhantomData,
        }));
        let data = (0..2 * PAGE_SIZE)
            .map(|i| u8::try_from(i % 251).unwrap() + 1)
            .collect::<Vec<_>>();
        // The copy goes through the mapped addresses, so back them with real memory.
        let memory = vec![0u8; 9 * PAGE_SIZE].leak();
        let aligned = memory.as_ptr().align_offset(PAGE_SIZE);
        let pages = &mut memory[aligned..aligned + 8 * PAGE_SIZE];
        pages[..data.len()].copy_from_slice(&data);
        let start = pages.as_mut_ptr() as usize;
        let flags = VmFlags::VM_READ
            | VmFlags::VM_WRITE
            | VmFlags::VM_MAYREAD
            | VmFlags::VM_MAYWRITE
            | VmFlags::VM_MAYSHARE;
        let mut vmm = Vmem::new(backend);
        unsafe {
            vmm.create_mapping(
                NonZeroAddress::new(start),
                NonZeroPageSize::new(2 * PAGE_SIZE).unwrap(),
                VmArea::new(flags, false),
                CreatePagesFlags::FIXED_ADDR,
            )
        }
        .unwrap();

        let destination = unsafe {
            vmm.move_mappings(
                PageRange::new(start, start + 2 * PAGE_SIZE).unwrap(),
                NonZeroAddress::new(start + 4 * PAGE_SIZE),
                NonZeroPageSize::new(4 * PAGE_SIZE).unwrap(),
            )
        }
        .unwrap()
        .as_usize();

        assert_eq!(destination, start + 4 * PAGE_SIZE);
        assert_eq!(
            TransparentConstPtr::<u8>::from_usize(destination)
                .to_owned_slice(data.len())
                .unwrap()[..],
            data[..]
        );
        assert_eq!(
            *backend.permission_updates.lock(),
            [(
                destination..destination + 4 * PAGE_SIZE,
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            )]
        );
        let vmas = vmm
            .iter()
            .map(|(range, vma)| (range.clone(), vma.flags()))
            .collect::<Vec<_>>();
        assert_eq!(
            vmas,
            [(
                destination..destination + 4 * PAGE_SIZE,
                flags | VmFlags::VM_HAS_CONTENTS
            )]
        );
    }
}
