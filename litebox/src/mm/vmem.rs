// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.
//!
//! Style-specific implementations live in [`super::linux`] and [`super::windows`].
//! Shared engine internals are accessible only within [`crate::mm`].
//!
//! # Ownership and mapping policy
//!
//! The VMA index tracks committed guest mappings, including committed no-access pages. A separate
//! reservation index covers every VMA. Reservation entries retain native boundaries and never coalesce, even
//! when VMA coalescing or protection changes produce different mapping boundaries.
//!
//! Windows-style acquisition excludes existing ownership regardless of commitment, acquiring
//! exact page-aligned lengths without padding or replacement. Commit and decommit operate within
//! one reservation and publish metadata only after success. Ordinary decommit retains ownership.
//! Linux-style placement may reuse uncommitted backing. When reservation and commitment extents
//! match, the manager first tries native combined allocation, including replacement. Only an
//! unsupported result permits fallback; allocation errors propagate. Otherwise, missing backing
//! is rounded outward to reservation alignment and acquired gap by gap without relocation.
//! Failed hinted acquisition releases new backing and retries the whole mapping with a zero hint.
//! The complete acquired extent is tracked, but only requested pages are committed. Acquisition
//! and CoW allocation return handles directly; VMAs are published after successful state changes.
//! Successful native replacement lazily takes only intersecting pieces; the manager splits
//! ownership and retains outside fragments. Recoverable errors never invoke the supplier.
//!
//! Linux unmap and bulk cleanup retain backing in partially live reservations when reservation
//! alignment exceeds page alignment, decommitting removed subranges so they can be reused.
//! All uncommitted gaps with equal alignments are released. Empty reservations are released in full;
//! bulk cleanup also sweeps previously empty reservations. Every selected VMA is treated as owned.
//! Explicit Windows-style release splits and releases the requested subrange of one reservation,
//! regardless of alignment-based retention policy.
//!
//! Replacement fallback decommits overlaps and commits each reservation segment. Commitment
//! failure rolls back completed commitments and releases unused acquisitions. Discarded contents
//! are not restored; unvisited mappings remain unchanged.
//! Unexpected teardown, replacement decommit, or rollback failures are fatal. Recoverable
//! protection failures preserve the complete requested range.
//!
//! Native remap lazily receives exact source pieces and returns one handle for the destination.
//! The manager retains outside pieces;
//! recoverable failures leave original handles unsplit. Unsupported remaps are emulated by reusing
//! uncommitted destination backing and acquiring only gaps, then committing and copying before
//! unmapping the source. Empty source reservations are released only after publishing destination
//! mappings. Reservations carry no separate reuse policy and are not released on manager drop,
//! since raw guest pointers may remain live.

use core::ops::{Deref, DerefMut, Range};

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use crate::platform::PageManagementProvider;
use crate::platform::page_mgmt::AllocationError;
use crate::platform::page_mgmt::FixedAddressBehavior;
use crate::platform::page_mgmt::MemoryRegionPermissions;
use crate::platform::page_mgmt::PageReservation;
use crate::platform::page_mgmt::ReservationStore;

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
///
/// Construct one through [`PageRange::new`] or [`PageRange::from_start_len`], and access its
/// bounds through [`Self::start`] and [`Self::end`]. Callers modifying the bounds must keep
/// both addresses `ALIGN`-aligned and `start < end`.
///
/// ```
/// let mut range = litebox::mm::PageRange::<4096>::new(0x10000, 0x11000).unwrap();
/// range.end = 0x12000;
/// assert_eq!(range.start, 0x10000);
/// assert_eq!(range.end, 0x12000);
/// ```
#[derive(Clone, Copy)]
#[non_exhaustive]
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

    /// Create a nonempty aligned range, rejecting address overflow.
    pub fn from_start_len(start: usize, len: usize) -> Option<Self> {
        Self::new(start, start.checked_add(len)?)
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
    ///
    /// # Panics
    ///
    /// Panics if the range starts at zero, which cannot be represented by [`NonZeroAddress`].
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
    pub(super) flags: VmFlags,
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

    /// Record native CoW backing, which cannot use anonymous decommit.
    pub(super) fn new_cow(flags: VmFlags) -> Self {
        Self {
            flags,
            is_file_backed: true,
        }
    }
}

/// Virtual Memory Manager
///
/// This struct maintains the virtual memory ranges backed by a memory [backend](PageManagementProvider).
/// Each range needs to be `ALIGN`-aligned. The owning page manager fixes `Style` at construction;
/// automatic mapping operations and explicit reservation operations have separate implementations.
///
/// # Invariants
///
/// The union of VMA ranges is a subset of the union of reservation extents. A VMA may span
/// multiple reservations, and reservations may contain uncommitted
/// holes without VMAs. Thus, gap-free VMA coverage implies gap-free reservation coverage, but
/// not the reverse. Mutation paths must preserve this invariant when publishing their results,
/// even if they temporarily extract reservation handles during an exclusive ownership transfer.
///
/// Linux-style managers with `Platform::RESERVATION_ALIGNMENT == ALIGN` maintain equal VMA
/// and reservation coverage at operation boundaries: allocation commits exact extents, and
/// unmapping releases the removed pages. Their token and VMA boundaries may still differ.
/// Windows-style managers can retain uncommitted reservations regardless of platform alignment.
/// Handle-free Linux reservation stores retain no separate index; their committed ownership is
/// represented directly by VMAs.
pub(super) struct FindAreaRequest<const ALIGN: usize> {
    pub(super) suggested_address: Option<NonZeroAddress<ALIGN>>,
    pub(super) length: NonZeroPageSize<ALIGN>,
    pub(super) behavior: FixedAddressBehavior,
    pub(super) alignment: usize,
    pub(super) include_reservations: bool,
    pub(super) address_range: Range<usize>,
    pub(super) top_down: bool,
}

pub(super) struct MappingState<Store: ReservationStore> {
    /// Committed guest mappings.
    pub(super) vmas: RangeMap<usize, VmArea>,
    /// Disjoint reservation handles covering every VMA.
    pub(super) reservations: Store,
}

impl<Store: ReservationStore + Default> Default for MappingState<Store> {
    fn default() -> Self {
        Self {
            vmas: RangeMap::new(),
            reservations: Store::default(),
        }
    }
}

impl<Store: ReservationStore> MappingState<Store> {
    fn overlaps(&self, range: Range<usize>, include_reservations: bool) -> bool {
        self.reservations
            .overlaps(&self.vmas, range, include_reservations)
    }
}

pub(super) struct Vmem<
    Platform: PageManagementProvider<ALIGN> + 'static,
    const ALIGN: usize,
    Style: super::PageManagerStyleFor<Platform, ALIGN>,
> {
    /// Memory backend that provides the actual memory.
    pub(super) platform: &'static Platform,
    /// Current program break address.
    pub(super) brk: usize,
    /// Committed mappings and their reservation ownership.
    pub(super) mappings: MappingState<Style::Reservations>,
}

impl<Platform, const ALIGN: usize, Style> Deref for Vmem<Platform, ALIGN, Style>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
    Style: super::PageManagerStyleFor<Platform, ALIGN>,
{
    type Target = MappingState<Style::Reservations>;

    fn deref(&self) -> &Self::Target {
        &self.mappings
    }
}

impl<Platform, const ALIGN: usize, Style> DerefMut for Vmem<Platform, ALIGN, Style>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
    Style: super::PageManagerStyleFor<Platform, ALIGN>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mappings
    }
}

impl<Platform, const ALIGN: usize, Style> Vmem<Platform, ALIGN, Style>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
    Style: super::PageManagerStyleFor<Platform, ALIGN>,
{
    pub(super) const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`Vmem`] instance with the given memory [backend](PageManagementProvider).
    pub(super) fn new(platform: &'static Platform) -> Self {
        assert!(Platform::RESERVATION_ALIGNMENT.is_power_of_two());
        assert!(Platform::RESERVATION_ALIGNMENT.is_multiple_of(ALIGN));
        Self {
            mappings: MappingState::default(),
            brk: 0,
            platform,
        }
    }

    /// Gets an iterator over all pairs of ([`Range<usize>`], [`VmArea`]),
    /// ordered by key range.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
    }

    /// Enumerate all tracked reservation ranges.
    pub(super) fn reservations(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        self.reservations.values().map(PageReservation::range)
    }

    /// Check VMA or reservation overlap.
    ///
    /// Tracked reservations cover every VMA, so they are the only tree queried when included.
    /// Otherwise, VMA coverage is checked directly.
    pub(super) fn overlaps(&self, range: Range<usize>, include_reservations: bool) -> bool {
        self.mappings.overlaps(range, include_reservations)
    }

    /// Remove all VMAs, release all owned reservations, and reset the program break.
    ///
    /// # Safety
    ///
    /// All mappings must be owned, valid for provider teardown, and have no users.
    /// The caller relinquishes every reservation, including those already empty.
    pub(super) unsafe fn release_memory(&mut self) {
        // SAFETY: The caller relinquishes all owned extents without remaining users.
        unsafe {
            self.mappings
                .reservations
                .release_all(&self.mappings.vmas, self.platform);
        }
        self.vmas.clear();
        self.brk = 0;
    }

    /// Change the permissions ([`VmFlags::VM_ACCESS_FLAGS`]) of committed mappings in the virtual address space.
    ///
    /// This never commits or decommits pages. Both guest API families use this protection-only path.
    /// The entire range is validated before mutation. The provider can lazily borrow covering handles
    /// and decides whether to batch native protection or split at reservation boundaries.
    /// Gap-free VMA coverage guarantees reservation coverage by the [`Vmem`] invariant.
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
    ) -> Result<(), VmemProtectError> {
        let range: Range<usize> = range.into();
        if self.vmas.gaps(&range).next().is_some() {
            return Err(VmemProtectError::NotCommitted(range));
        }
        let flags = VmFlags::from(permissions);
        let mut mappings = Vec::new();
        for (mapped, vma) in self.vmas.overlapping(range.clone()) {
            if (!(vma.flags.bits() >> 4) & flags.bits()) & VmFlags::VM_ACCESS_FLAGS.bits() != 0 {
                return Err(VmemProtectError::NoAccess {
                    old: vma.flags,
                    new: flags,
                });
            }
            if MemoryRegionPermissions::from(vma.flags) != permissions {
                let overlap = mapped.start.max(range.start)..mapped.end.min(range.end);
                mappings.push((overlap, *vma));
            }
        }
        if mappings.is_empty() {
            return Ok(());
        }
        // SAFETY: Ordered live handles cover this committed range; the caller excludes conflicting accesses.
        unsafe {
            self.platform.protect_pages(
                || {
                    self.reservations
                        .overlapping(range.clone())
                        .map(|(_, reservation)| reservation)
                },
                range.clone(),
                permissions,
            )
        }
        .map_err(VmemProtectError::ProtectError)?;
        for (segment, vma) in mappings {
            let new_vma = VmArea {
                flags: (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags,
                ..vma
            };
            self.vmas.insert(segment, new_vma);
        }
        Ok(())
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
        let mut covered_until = range_start;
        let mut permissions = None;
        for (mapped, vma) in self.vmas.overlapping(range) {
            let current = MemoryRegionPermissions::from(vma.flags());
            if mapped.start > covered_until
                || permissions.is_some_and(|previous| previous != current)
            {
                return None;
            }
            permissions = Some(current);
            covered_until = mapped.end;
        }
        permissions.filter(|_| covered_until >= range_end)
    }

    /*================================Internal Functions================================ */

    /// Search VMA gaps, preserving stack guards while optionally excluding reservations.
    /// Reservation conflicts move candidates downward within a gap without changing its
    /// stack-derived upper bound, including when reservations contain no committed pages.
    pub(super) fn find_area(
        reservations: &Style::Reservations,
        vmas: &RangeMap<usize, VmArea>,
        request: FindAreaRequest<ALIGN>,
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
            let end = suggested_address
                .0
                .checked_add(size)
                .ok_or(AllocationError::AboveMaxAddress)?;
            if suggested_address.0 < request.address_range.start {
                return Err(AllocationError::BelowMinAddress);
            }
            if end > request.address_range.end {
                return Err(AllocationError::AboveMaxAddress);
            }
            if request.behavior == FixedAddressBehavior::Replace
                || !reservations.overlaps(
                    vmas,
                    suggested_address.0..end,
                    request.include_reservations,
                )
            {
                return Ok(Some(suggested_address.0));
            }
            if request.behavior == FixedAddressBehavior::NoReplace {
                return Err(AllocationError::AddressInUse);
            }
        } else if request.behavior != FixedAddressBehavior::Hint {
            return Err(AllocationError::BelowMinAddress);
        }

        Ok(Self::find_area_in_range_with(reservations, vmas, &request))
    }

    /// Find an aligned gap within exclusive address bounds, preserving stack guards.
    /// Each retry skips all current reservation overlaps in the search direction.
    fn find_area_in_range_with(
        reservations: &Style::Reservations,
        vmas: &RangeMap<usize, VmArea>,
        request: &FindAreaRequest<ALIGN>,
    ) -> Option<usize> {
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
            let mut start = if request.top_down {
                gap.end.checked_sub(size)? & !(request.alignment - 1)
            } else {
                gap.start.checked_next_multiple_of(request.alignment)?
            };
            while start >= gap.start && start.checked_add(size)? <= gap.end {
                let conflict = if request.include_reservations {
                    let mut overlaps = reservations.overlapping(start..start + size);
                    if request.top_down {
                        overlaps.next()
                    } else {
                        overlaps.next_back()
                    }
                    .map(|(_, reservation)| reservation.range())
                } else {
                    None
                };
                let Some(conflict) = conflict else {
                    return Some(start);
                };
                start = if request.top_down {
                    conflict.start.checked_sub(size)? & !(request.alignment - 1)
                } else {
                    conflict.end.checked_next_multiple_of(request.alignment)?
                };
            }
            None
        };
        let mut vmas = vmas.iter();
        let mut gap_boundary = if request.top_down {
            high_limit
        } else {
            low_limit
        };
        while let Some((range, vma)) = if request.top_down {
            vmas.next_back()
        } else {
            vmas.next()
        } {
            let guard = if vma.flags.contains(VmFlags::VM_GROWSDOWN) {
                Self::STACK_GUARD_GAP << 1
            } else {
                0
            };
            let guarded_start = range.start.saturating_sub(guard).min(high_limit);
            let gap = if request.top_down {
                range.end.max(low_limit)..gap_boundary
            } else {
                gap_boundary..guarded_start
            };
            if let Some(start) = find_in_gap(gap) {
                return Some(start);
            }
            gap_boundary = if request.top_down {
                guarded_start
            } else {
                range.end.max(low_limit)
            };
        }
        let gap = if request.top_down {
            low_limit..gap_boundary
        } else {
            gap_boundary..high_limit
        };
        find_in_gap(gap)
    }
}

/// Error for removing mappings
#[derive(Error, Debug)]
pub enum VmemUnmapError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("failed to unmap pages: {0}")]
    UnmapError(#[from] crate::platform::page_mgmt::DeallocationError),
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
}

/// Error for moving mappings
#[derive(Error, Debug)]
pub enum VmemMoveError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap failed: {0}")]
    RemapError(#[from] crate::platform::page_mgmt::RemapError),
}

/// Error for protecting mappings
#[derive(Error, Debug)]
pub enum VmemProtectError {
    #[error("the range {0:?} contains uncommitted pages")]
    NotCommitted(Range<usize>),
    #[error("the range {0:?} is not aligned")]
    UnAligned(Range<usize>),
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] crate::platform::page_mgmt::PageStateUpdateError),
}

/// Error for creating mappings
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("invalid page creation flags")]
    InvalidFlags,
    #[error("not enough memory")]
    OutOfMemory,

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
    MapError(#[from] crate::platform::page_mgmt::AllocationError),
    #[error("failed to apply mapping permissions: {0}")]
    ProtectError(#[from] VmemProtectError),
}

/// Enable [`super::PageManager`] to handle page faults if its platform implements this trait
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
