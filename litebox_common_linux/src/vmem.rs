// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use litebox::platform::PageManagementProvider;
use litebox::platform::RawConstPointer;
use litebox::platform::RawMutPointer;
use litebox::platform::page_mgmt::AllocationDirection;
use litebox::platform::page_mgmt::AllocationError;
use litebox::platform::page_mgmt::CowAllocationError;
use litebox::platform::page_mgmt::FixedAddressBehavior;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::platform::page_mgmt::RemapError;
use litebox::platform::{
    common_providers::reservations::{NoTrackedReservations, TrackedReservations},
    page_mgmt::{DeallocationError, PageReservation, PermissionUpdateError, ReservationStore},
};

/// Page size in bytes
pub const PAGE_SIZE: usize = 4096;

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
        if value.contains(MemoryRegionPermissions::SHARED) {
            unimplemented!("SHARED permission is not supported yet");
        }
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
        flags.set(
            MemoryRegionPermissions::SHARED,
            value.contains(VmFlags::VM_SHARED),
        );
        flags
    }
}

pub const DEFAULT_RESERVED_SPACE_SIZE: usize = 0x100_0000; // 16 MiB

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
        /// Ensure there is more space (i.e., `DEFAULT_RESERVED_SPACE_SIZE`) after the
        /// mapping so that user can grow the mapping later.
        const ENSURE_SPACE_AFTER = 1 << 3;
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

/// A non-empty range of page-aligned addresses
#[derive(Clone, Copy)]
pub struct PageRange<const ALIGN: usize> {
    /// Start page of the range.
    pub start: usize,
    /// End page of the range.
    pub end: usize,
}

impl<const ALIGN: usize> From<PageRange<ALIGN>> for Range<usize> {
    fn from(range: PageRange<ALIGN>) -> Self {
        range.start..range.end
    }
}

impl<const ALIGN: usize> IntoIterator for PageRange<ALIGN> {
    type Item = usize;
    type IntoIter = core::iter::StepBy<Range<usize>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.start..self.end).step_by(ALIGN)
    }
}

impl<const ALIGN: usize> PageRange<ALIGN> {
    /// Create a new [`PageRange`].
    ///
    /// Returns `None` if the range is not `ALIGN`-aligned or empty.
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if !start.is_multiple_of(ALIGN) || !end.is_multiple_of(ALIGN) {
            return None;
        }
        if start >= end {
            return None;
        }
        Some(Self { start, end })
    }

    /// Get the size of this `ALIGN`-aligned range
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the range is empty or not
    ///
    /// Note this range is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get the start address and length of this range as a tuple.
    #[allow(
        clippy::missing_panics_doc,
        reason = "This function should not fail as the range is guaranteed to be non-empty and aligned."
    )]
    pub fn start_and_length(&self) -> (NonZeroAddress<ALIGN>, NonZeroPageSize<ALIGN>) {
        (
            NonZeroAddress::new(self.start).unwrap(),
            NonZeroPageSize::new(self.len()).unwrap(),
        )
    }
}

/// A non-zero `ALIGN`-aligned size in bytes.
#[derive(Clone, Copy)]
pub struct NonZeroPageSize<const ALIGN: usize> {
    size: usize,
}

impl<const ALIGN: usize> NonZeroPageSize<ALIGN> {
    /// Create a new non-zero `ALIGN`-aligned size.
    ///
    /// Returns `None` if the size is zero or not `ALIGN`-aligned.
    pub fn new(size: usize) -> Option<Self> {
        if size == 0 || !size.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self { size })
    }

    /// Get the size
    #[inline]
    pub fn as_usize(self) -> usize {
        self.size
    }
}

impl<const ALIGN: usize> core::ops::Add<usize> for NonZeroPageSize<ALIGN> {
    type Output = Option<Self>;

    fn add(self, rhs: usize) -> Self::Output {
        NonZeroPageSize::new(self.size.checked_add(rhs)?)
    }
}

/// A non-zero address that is `ALIGN`-aligned.
#[derive(Clone, Copy)]
pub struct NonZeroAddress<const ALIGN: usize>(usize);

impl<const ALIGN: usize> NonZeroAddress<ALIGN> {
    /// Create a new `NonZeroAddress`, if the address is non-zero and aligned.
    pub fn new(address: usize) -> Option<Self> {
        if address == 0 || !address.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self(address))
    }

    /// Get the address
    #[inline]
    pub fn as_usize(self) -> usize {
        self.0
    }
}

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
    /// Whether this area is backed by a file
    is_file_backed: bool,
}

impl VmArea {
    /// Get the [flags](`VmFlags`) of this memory area.
    #[inline]
    pub(super) fn flags(self) -> VmFlags {
        self.flags
    }

    /// Check if this area is backed by a file.
    #[inline]
    pub(super) fn is_file_backed(self) -> bool {
        self.is_file_backed
    }

    /// Create a new [`VmArea`] with the given flags.
    #[inline]
    pub(super) fn new(flags: VmFlags, is_file_backed: bool) -> Self {
        Self {
            flags,
            is_file_backed,
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
    /// Initial page permissions.
    pub permissions: MemoryRegionPermissions,
    /// Whether the mapping may grow downward.
    pub can_grow_down: bool,
    /// Whether pages should be populated immediately.
    pub populate_pages_immediately: bool,
    /// Required fixed-address behavior.
    pub behavior: FixedAddressBehavior,
}

/// Reservation store required of platforms used by Linux-style shims.
pub type ShimReservations<Reservation> = NoTrackedReservations<PAGE_SIZE, Reservation>;

/// Linux Vmem operations supported by a reservation store.
pub trait LinuxReservationStore<Platform, const ALIGN: usize>:
    ReservationStore + Send + Sync
where
    Platform: PageManagementProvider<ALIGN, Reservations = Self>,
{
    /// Create a platform mapping and update reservation ownership.
    ///
    /// # Safety
    ///
    /// When `request.behavior` is [`FixedAddressBehavior::Replace`], the caller must ensure that
    /// any replaced mappings are not in active use.
    unsafe fn mmap(
        &mut self,
        platform: &Platform,
        request: MmapRequest,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError>;

    /// Release a range's platform backing and update reservation ownership.
    ///
    /// `has_mapping` reports whether a queried range is mapped.
    ///
    /// # Safety
    ///
    /// The caller must ensure that these pages are not in active use.
    unsafe fn unmap(
        &mut self,
        has_mapping: impl Fn(&Range<usize>) -> bool,
        platform: &Platform,
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
                || {
                    self.overlapping(range.clone())
                        .map(|(_, reservation)| reservation)
                },
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
    unsafe fn mmap(
        &mut self,
        platform: &Platform,
        request: MmapRequest,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let MmapRequest {
            range,
            permissions,
            can_grow_down,
            populate_pages_immediately,
            behavior,
        } = request;
        // SAFETY: The caller authorizes replacement and this handle-free store owns mapping ranges.
        let reservation = unsafe {
            platform.reserve_and_commit_pages(
                core::iter::empty,
                range,
                permissions,
                can_grow_down,
                populate_pages_immediately,
                behavior,
            )
        }?;
        Ok(Platform::RawMutPointer::<u8>::from_usize(
            reservation.range().start,
        ))
    }

    unsafe fn unmap(
        &mut self,
        _has_mapping: impl Fn(&Range<usize>) -> bool,
        platform: &Platform,
        range: Range<usize>,
    ) -> Result<(), DeallocationError> {
        // SAFETY: The caller excludes all users of the released range.
        unsafe { platform.release_pages(range) }?;
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
    unsafe fn mmap(
        &mut self,
        platform: &Platform,
        request: MmapRequest,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let MmapRequest {
            mut range,
            permissions,
            can_grow_down,
            populate_pages_immediately,
            behavior,
        } = request;

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
                    can_grow_down,
                    populate_pages_immediately,
                    behavior,
                )
            } {
                Ok(reservation) => {
                    let extent = reservation.range();
                    let address = extent.start;
                    assert!(self.insert(extent.start, reservation).is_none());
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

        if behavior == FixedAddressBehavior::Replace {
            // SAFETY: The caller authorized replacement and excludes users of the old mapping.
            unsafe {
                platform.decommit_pages(
                    || {
                        self.overlapping(range.clone())
                            .map(|(_, reservation)| reservation)
                    },
                    range.clone(),
                )
            }
            .expect("failed to decommit replacement backing");
        }

        // SAFETY: The tracked reservations now completely cover the requested range.
        match unsafe {
            platform.commit_pages(
                || {
                    self.overlapping(range.clone())
                        .map(|(_, reservation)| reservation)
                },
                range.clone(),
                permissions,
                populate_pages_immediately,
            )
        } {
            Ok(pointer) => Ok(pointer),
            Err(error) => {
                // SAFETY: No mapping is published yet, so all commitment from this attempt is unused.
                let _ = unsafe {
                    platform.decommit_pages(
                        || {
                            self.overlapping(range.clone())
                                .map(|(_, reservation)| reservation)
                        },
                        range.clone(),
                    )
                };
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
        has_mapping: impl Fn(&Range<usize>) -> bool,
        platform: &Platform,
        range: Range<usize>,
    ) -> Result<(), DeallocationError> {
        let reservations = self.take_overlapping(range.clone());
        let last = reservations.len().saturating_sub(1);
        for (index, reservation) in reservations.into_iter().enumerate() {
            if index == 0 || index == last {
                let extent = reservation.range();
                if (extent.start < range.start && has_mapping(&(extent.start..range.start)))
                    || (range.end < extent.end && has_mapping(&(range.end..extent.end)))
                {
                    let segment = extent.start.max(range.start)..extent.end.min(range.end);
                    // SAFETY: The removed segment has no users and remains inside this reservation.
                    unsafe { platform.decommit_pages(|| core::iter::once(&reservation), segment) }
                        .expect("failed to decommit unmapped reservation backing");
                    assert!(self.insert(extent.start, reservation).is_none());
                    continue;
                }
            }
            // SAFETY: No VMA uses this reservation after removing the requested range.
            unsafe { platform.release_pages(reservation) }
                .expect("failed to release unmapped reservation");
        }
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
    pub(super) vmas: RangeMap<usize, VmArea>,
    /// Reservations selected and owned by the platform.
    pub(super) reservations: Platform::Reservations,
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
        }
    }

    /// Gets an iterator over all pairs of ([`Range<usize>`], [`VmArea`]),
    /// ordered by key range.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
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
    /// be contracted to no longer cover the removed range.
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
        // SAFETY: The caller excludes all users of the removed range.
        unsafe {
            self.reservations.unmap(
                |candidate| self.vmas.overlaps(candidate),
                self.platform,
                range.clone(),
            )
        }
        .map_err(VmemUnmapError::UnmapError)?;
        self.vmas.remove(range);
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
        let overlapping_ranges: Vec<(Range<usize>, VmArea)> = self
            .overlapping(range.clone())
            .map(|(r, vma)| (r.clone(), *vma))
            .collect();
        for (r, vma) in overlapping_ranges {
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
        let (start, end) = (suggested_range.start, suggested_range.end);
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
        let permissions: u8 = vma
            .flags
            .intersection(VmFlags::VM_ACCESS_FLAGS)
            .bits()
            .try_into()
            .unwrap();
        let max_permissions: u8 = (vma.flags.intersection(VmFlags::VM_MAY_ACCESS_FLAGS).bits()
            >> 4)
            .try_into()
            .unwrap();
        // The `max_permissions` is tracked by `Vmem::protect_mapping` and thus doesn't need to be
        // passed to `allocate_pages`.
        let _ = max_permissions;
        // SAFETY: The caller authorizes replacement, and the checks above preserve external gaps.
        let ret = unsafe {
            self.reservations.mmap(
                self.platform,
                MmapRequest {
                    range: suggested_range.into(),
                    permissions: MemoryRegionPermissions::from_bits(permissions).unwrap(),
                    can_grow_down: vma.flags.contains(VmFlags::VM_GROWSDOWN),
                    populate_pages_immediately,
                    behavior: platform_fixed_address_behavior,
                },
            )
        }
        .map_err(|err| match err {
            AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
            other => other,
        })?;
        let new_start = ret.as_usize();
        let new_end = new_start + suggested_range.len();
        self.vmas.insert(new_start..new_end, vma);
        debug_assert!(new_start >= Platform::TASK_ADDR_MIN);
        debug_assert!(new_end <= Platform::TASK_ADDR_MAX);
        Ok(ret)
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
        let total_length = (length
            + if flags.contains(CreatePagesFlags::ENSURE_SPACE_AFTER) {
                DEFAULT_RESERVED_SPACE_SIZE
            } else {
                0
            })
        .ok_or(AllocationError::OutOfMemory)?;
        let behavior = FixedAddressBehavior::from(flags);
        let direction = match behavior {
            FixedAddressBehavior::Hint(direction) => Some(direction),
            FixedAddressBehavior::Replace | FixedAddressBehavior::NoReplace => None,
        };
        let platform_behavior = match behavior {
            FixedAddressBehavior::Hint(direction)
                if !Platform::HINT_PLACEMENT_BEHAVIOR.supports(direction) =>
            {
                FixedAddressBehavior::NoReplace
            }
            _ => behavior,
        };
        let mut request =
            Self::build_unmapped_area_request(suggested_address, total_length, behavior);
        loop {
            let new_addr = self
                .find_area(&request)?
                .ok_or(AllocationError::OutOfMemory)?;
            // new_addr must be ALIGN aligned
            let new_range = PageRange::new(new_addr, new_addr + length.as_usize()).unwrap();
            match unsafe {
                self.insert_mapping(
                    new_range,
                    vma,
                    flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                    platform_behavior,
                )
            } {
                Err(AllocationError::AddressInUseByPlatform)
                    if direction.is_some()
                        && platform_behavior == FixedAddressBehavior::NoReplace =>
                {
                    // Retry if the requested behavior is `Hint` but the suggested address is already
                    // in use and the platform does not support the required search direction.
                    let rejected_hint = request
                        .suggested_address
                        .is_some_and(|address| address.as_usize() == new_addr);
                    if rejected_hint {
                        request = Self::build_unmapped_area_request(None, total_length, behavior);
                    } else if direction == Some(AllocationDirection::TopDown) {
                        request.suggested_address = None;
                        request.address_range.end = new_addr;
                    } else {
                        request.suggested_address = None;
                        request.address_range.start = new_addr
                            .checked_add(total_length.as_usize())
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
    /// (due to enlarging).
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
        let range = range.start..range.end;
        // `cur_range` contains `range.start`
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range
            .start
            .checked_add(new_size.as_usize())
            .ok_or(VmemResizeError::OutOfMemory)?;
        match new_end.cmp(&range.end) {
            core::cmp::Ordering::Equal => {
                // no change
                return Ok(());
            }
            core::cmp::Ordering::Less => {
                // shrink
                let range = PageRange::new(new_end, range.end).unwrap();
                unsafe { self.remove_mapping(range) }.unwrap();
                return Ok(());
            }
            core::cmp::Ordering::Greater => {}
        }

        // grow
        if range.end > cur_range.end {
            // we can't remap across vm area boundaries
            return Err(VmemResizeError::InvalidAddr {
                range: cur_range.clone(),
                addr: range.end,
            });
        }

        if range.end == cur_range.end {
            // expand the current range
            let r = range.end..new_end;
            if self.vmas.overlaps(&r) {
                return Err(VmemResizeError::RangeOccupied(r));
            }
            if cur_vma.is_file_backed() {
                unimplemented!("file-backed mapping expansion is not supported yet");
            }
            let range = PageRange::new(range.end, new_end).unwrap();
            // Try to extend the mapping. Although we checked that there are no
            // litebox mappings in this range, this may fail if there are
            // platform mappings in the way.
            match unsafe {
                self.insert_mapping(range, *cur_vma, false, FixedAddressBehavior::NoReplace)
            } {
                Ok(_) => {}
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

        // has to split the current range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..cur_range.end))
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
    /// Panics if the `old_range` is not covered by exactly one mapping.
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

        // Check if the given range is covered by exactly one mapping
        let (cur_range, vma) = self
            .vmas
            .get_key_value(&old_range.start)
            .expect("VMEM: range not found");
        assert!(cur_range.contains(&(old_range.end - 1)));
        let vma = *vma;

        if vma.is_file_backed() {
            unimplemented!("file-backed mapping move is not supported yet");
        }
        let new_addr = self
            .get_unmmaped_area(
                suggested_new_address,
                new_size,
                FixedAddressBehavior::Hint(AllocationDirection::TopDown),
            )
            .map_err(|_| VmemMoveError::OutOfMemory)?
            .ok_or(VmemMoveError::OutOfMemory)?;
        let new_range = PageRange::<ALIGN>::new(new_addr, new_addr + new_size.as_usize()).unwrap();
        // SAFETY: The caller excludes source users, and `get_unmmaped_area` found a disjoint gap.
        let new_addr = match unsafe {
            self.reservations.remap(
                self.platform,
                old_range.into(),
                new_range.into(),
                vma.flags.into(),
            )
        } {
            Ok(new_addr) => new_addr,
            Err(RemapError::UnsupportedByPlatform) => {
                // SAFETY: Native remapping left the source unchanged, and the destination is free.
                return unsafe { self.remap_fallback_with_copy(old_range, new_range, vma) };
            }
            Err(error) => return Err(VmemMoveError::RemapError(error)),
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

        let permissions = MemoryRegionPermissions::from(vma.flags());
        let temporary = VmArea::new(vma.flags() | VmFlags::VM_READ | VmFlags::VM_WRITE, false);
        let length = NonZeroPageSize::new(new_range.len()).expect("remap destination is empty");
        // SAFETY: Hint placement never replaces existing mappings.
        let destination = unsafe {
            self.create_mapping(
                NonZeroAddress::new(new_range.start),
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
            let source = Platform::RawConstPointer::<u8>::from_usize(old_range.start + offset);
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
        for (intersection, vma) in mappings_to_change {
            let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
            self.vmas.insert(
                intersection,
                VmArea {
                    flags: new_flags,
                    is_file_backed: vma.is_file_backed,
                },
            );
        }

        Ok(())
    }

    /// Attempt a native CoW mapping and register it in the VMA tracker.
    ///
    /// # Safety
    ///
    /// For replacement, the caller must ensure overlapping mappings are not in use.
    pub(super) unsafe fn try_create_cow_pages(
        &mut self,
        suggested_start: Option<usize>,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, CowAllocationError> {
        let behavior = FixedAddressBehavior::from(flags);
        if source_data.is_empty() || !source_data.len().is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }
        if suggested_start.is_none() && !matches!(behavior, FixedAddressBehavior::Hint(_)) {
            return Err(CowAllocationError::InternalFailure);
        }
        let suggested_start = if let Some(start) = suggested_start {
            if !start.is_multiple_of(ALIGN) {
                return Err(CowAllocationError::Unaligned);
            }
            match start.checked_add(source_data.len()) {
                Some(end) if start >= Platform::TASK_ADDR_MIN && end <= Platform::TASK_ADDR_MAX => {
                    if behavior == FixedAddressBehavior::NoReplace
                        && self.vmas.overlaps(&(start..end))
                    {
                        return Err(CowAllocationError::InternalFailure);
                    }
                    start
                }
                _ if matches!(behavior, FixedAddressBehavior::Hint(_)) => 0,
                _ => return Err(CowAllocationError::InternalFailure),
            }
        } else {
            0
        };
        let requested = suggested_start..suggested_start + source_data.len();

        // SAFETY: The caller authorizes replacement; the supplier transfers overlapping ownership
        // only if the provider successfully performs a replacement.
        let reservation = unsafe {
            self.platform.try_allocate_cow_pages(
                || self.reservations.take_overlapping(requested).into_iter(),
                suggested_start,
                source_data,
                permissions,
                behavior,
            )
        }?;
        let actual = reservation.range();
        let actual_start = actual.start;
        let actual_end = actual.end;
        let ptr = Platform::RawMutPointer::<u8>::from_usize(actual_start);
        assert_eq!(actual.len(), source_data.len());
        debug_assert!(
            matches!(behavior, FixedAddressBehavior::Hint(_)) || suggested_start == actual_start
        );
        debug_assert!(
            actual_start >= Platform::TASK_ADDR_MIN && actual_end <= Platform::TASK_ADDR_MAX
        );

        assert!(
            self.reservations
                .insert(actual_start, reservation)
                .is_none()
        );
        self.vmas.insert(
            actual,
            VmArea::new(
                VmFlags::from(permissions)
                    | VmFlags::may_flags_for_mapping(
                        flags.contains(CreatePagesFlags::SHARED),
                        true,
                    ),
                true,
            ),
        );
        Ok(ptr)
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
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        Platform::Reservations: LinuxReservationStore<Platform, ALIGN>,
    {
        let shared = flags.contains(CreatePagesFlags::SHARED);
        let file_backed = flags.contains(CreatePagesFlags::MAP_FILE);
        unsafe {
            self.create_mapping(
                suggested_new_address,
                length,
                VmArea::new(
                    VmFlags::from(perms)
                        | VmFlags::may_flags_for_mapping(shared, file_backed)
                        | if flags.contains(CreatePagesFlags::IS_STACK) {
                            VmFlags::VM_GROWSDOWN
                        } else {
                            VmFlags::empty()
                        },
                    flags.contains(CreatePagesFlags::MAP_FILE),
                ),
                flags,
            )
        }
        .map_err(MappingError::MapError)
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `page_range` specifies the range of pages to check the memory permissions.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    pub(super) fn get_memory_permissions(
        &self,
        page_range: PageRange<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let (range_start, range_end) = (page_range.start, page_range.end);
        let range: core::ops::Range<usize> = page_range.into();
        if let Some(iter) = self.overlapping(range).next() {
            if iter.0.start > range_start || iter.0.end < range_end {
                // partial overlap implies that the given range contains unmapped pages or
                // consists of memory pages with different permissions.
                return None;
            }
            let vmflags = iter.1.flags();
            Some(vmflags.into())
        } else {
            None
        }
    }

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    /// `suggested_address` and `behavior` are the hint address and placement policy respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if no area was found. Otherwise, returns the start address of an
    /// `ALIGN`-aligned area.
    pub(super) fn get_unmmaped_area(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        behavior: FixedAddressBehavior,
    ) -> Result<Option<usize>, AllocationError> {
        self.find_area(&Self::build_unmapped_area_request(
            suggested_address,
            length,
            behavior,
        ))
    }

    fn build_unmapped_area_request(
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        behavior: FixedAddressBehavior,
    ) -> FindAreaRequest<ALIGN> {
        let (address_range_end, alignment) = if suggested_address.is_none() {
            (
                // Some platform may allocate more than requested to satisfy alignment requirements,
                // so we restrict the maximum address to avoid exceeding the platform's addressable range.
                Platform::TASK_ADDR_MAX & !(Platform::RESERVATION_ALIGNMENT - 1),
                // When no specific address is suggested, use the platform's reservation alignment
                // to minimize fragmentation and number of system calls.
                Platform::RESERVATION_ALIGNMENT,
            )
        } else {
            (Platform::TASK_ADDR_MAX, ALIGN)
        };
        FindAreaRequest {
            suggested_address,
            length,
            behavior,
            alignment,
            address_range: Platform::TASK_ADDR_MIN..address_range_end,
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
                .is_none_or(|address| address.0.is_multiple_of(request.alignment))
        );
        let size = request.length.as_usize();
        if size > Platform::TASK_ADDR_MAX {
            return Ok(None);
        }
        if let Some(suggested_address) = request.suggested_address {
            let end = suggested_address.0.saturating_add(size);
            match request.behavior {
                FixedAddressBehavior::Hint(_) => {
                    if suggested_address.0 >= request.address_range.start
                        && end <= request.address_range.end
                        && !self.vmas.overlaps(&(suggested_address.0..end))
                    {
                        return Ok(Some(suggested_address.0));
                    }
                    // fall through if the hint cannot be used
                }
                FixedAddressBehavior::NoReplace | FixedAddressBehavior::Replace => {
                    if suggested_address.0 < request.address_range.start {
                        return Err(AllocationError::BelowMinAddress);
                    }
                    if end > request.address_range.end {
                        return Err(AllocationError::AboveMaxAddress);
                    }
                    if request.behavior == FixedAddressBehavior::Replace
                        || !self.vmas.overlaps(&(suggested_address.0..end))
                    {
                        return Ok(Some(suggested_address.0));
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
    #[error("out of memory")]
    OutOfMemory,
}

/// Error for moving mappings
#[derive(Error, Debug)]
pub enum VmemMoveError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("out of memory")]
    OutOfMemory,
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

    // Errors from mapping a file
    #[error("bad file descriptor: {0}")]
    BadFD(i32),
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for reading")]
    NotForReading,

    #[error("mapping failed: {0}")]
    MapError(#[from] litebox::platform::page_mgmt::AllocationError),
    #[error("protecting mapping failed: {0}")]
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

    litebox::define_page_reservation!(DummyReservation);

    /// A configurable dummy page-management backend.
    struct DummyVmemBackend<const TOP_DOWN: bool = false> {
        rejected_address: Option<usize>,
        calls: Mutex<Vec<AllocationCall>>,
        releases: Mutex<Vec<Range<usize>>>,
    }

    impl<const TOP_DOWN: bool> litebox::platform::RawPointerProvider for DummyVmemBackend<TOP_DOWN> {
        type RawConstPointer<T: FromBytes> = TransparentConstPtr<T>;
        type RawMutPointer<T: FromBytes + IntoBytes> = TransparentMutPtr<T>;
    }

    #[expect(unused_variables, reason = "dummy/mock backend")]
    impl<const TOP_DOWN: bool> PageManagementProvider<PAGE_SIZE> for DummyVmemBackend<TOP_DOWN> {
        type Reservations =
            litebox::platform::common_providers::reservations::NoTrackedReservations<
                PAGE_SIZE,
                DummyReservation<PAGE_SIZE>,
            >;

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        const TASK_ADDR_MIN: usize = 0x1_0000;
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000;
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        const TASK_ADDR_MAX: usize = 0xFFFF_FFFF_F000;
        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_0000;
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
            _populate_pages_immediately: bool,
        ) -> Result<TransparentMutPtr<u8>, AllocationError>
        where
            Reservations: Iterator<Item = &'reservation DummyReservation<PAGE_SIZE>>,
            DummyReservation<PAGE_SIZE>: 'reservation,
        {
            Ok(TransparentMutPtr::from_usize(range.start))
        }

        unsafe fn reserve_and_commit_pages<Reservations>(
            &self,
            _replaced_reservations: impl FnOnce() -> Reservations,
            suggested_range: Range<usize>,
            initial_permissions: MemoryRegionPermissions,
            can_grow_down: bool,
            populate_pages_immediately: bool,
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
            // SAFETY: The mock models successful exclusive ownership of this exact range.
            Ok(unsafe { DummyReservation::new(suggested_range) })
        }

        unsafe fn decommit_pages<'reservation, Reservations>(
            &self,
            _covering_reservations: impl FnOnce() -> Reservations,
            _range: Range<usize>,
        ) -> Result<(), litebox::platform::page_mgmt::DeallocationError>
        where
            Reservations: Iterator<Item = &'reservation DummyReservation<PAGE_SIZE>>,
            DummyReservation<PAGE_SIZE>: 'reservation,
        {
            Ok(())
        }

        unsafe fn release_pages(
            &self,
            range: Range<usize>,
        ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
            self.releases.lock().push(range);
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
            source_reservations().for_each(drop);
            // SAFETY: The mock models successful transfer to this exact destination.
            Ok(unsafe { DummyReservation::new(new_range) })
        }

        unsafe fn protect_pages<'reservation, Reservations>(
            &self,
            _covering_reservations: impl FnOnce() -> Reservations,
            range: Range<usize>,
            new_permissions: MemoryRegionPermissions,
        ) -> Result<(), PermissionUpdateError>
        where
            Reservations: Iterator<
                Item = &'reservation litebox::platform::page_mgmt::ReservationOf<Self, PAGE_SIZE>,
            >,
            litebox::platform::page_mgmt::ReservationOf<Self, PAGE_SIZE>: 'reservation,
        {
            Ok(())
        }
    }

    fn dummy_backend<const TOP_DOWN: bool>(
        rejected_address: Option<usize>,
    ) -> &'static DummyVmemBackend<TOP_DOWN> {
        Box::leak(Box::new(DummyVmemBackend {
            rejected_address,
            calls: Mutex::new(Vec::new()),
            releases: Mutex::new(Vec::new()),
        }))
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

    fn collect_mappings(vmm: &Vmem<DummyVmemBackend, PAGE_SIZE>) -> Vec<Range<usize>> {
        vmm.iter().map(|v| v.0.start..v.0.end).collect()
    }

    #[test]
    fn test_vmm_mapping() {
        let start_addr: usize = 0x1_0000;
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
}
