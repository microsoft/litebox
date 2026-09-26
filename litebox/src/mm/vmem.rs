// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::ops::{Deref, DerefMut, Range};

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use crate::platform::PageManagementProvider;
use crate::platform::RawConstPointer;
use crate::platform::page_mgmt::AllocationDirection;
use crate::platform::page_mgmt::AllocationError;
use crate::platform::page_mgmt::CowAllocationError;
use crate::platform::page_mgmt::FixedAddressBehavior;
use crate::platform::page_mgmt::MemoryRegionPermissions;
use crate::platform::page_mgmt::{PageReservation, ReservationStore};

pub use crate::platform::common_providers::reservations::{
    NoTrackedReservation, NoTrackedReservations,
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
        NonZeroPageSize::new(self.size + rhs)
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

/// Committed mappings and their reservation ownership.
pub(super) struct MappingState<Store: ReservationStore> {
    /// Virtual memory areas.
    pub(super) vmas: RangeMap<usize, VmArea>,
    /// Reservation handles associated with the mappings.
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

pub(super) struct FindAreaRequest<const ALIGN: usize> {
    pub(super) suggested_address: Option<NonZeroAddress<ALIGN>>,
    pub(super) length: NonZeroPageSize<ALIGN>,
    pub(super) behavior: FixedAddressBehavior,
    pub(super) alignment: usize,
    pub(super) include_reservations: bool,
    pub(super) address_range: Range<usize>,
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory ranges backed by a memory [backend](PageManagementProvider).
/// Each range needs to be `ALIGN`-aligned.
pub(super) struct Vmem<
    Platform: PageManagementProvider<ALIGN> + 'static,
    const ALIGN: usize,
    Store: ReservationStore = NoTrackedReservations<ALIGN>,
> {
    /// Memory backend that provides the actual memory.
    pub(super) platform: &'static Platform,
    /// Current program break address.
    pub(super) brk: usize,
    /// Committed mappings and their reservation ownership.
    pub(super) mappings: MappingState<Store>,
}

impl<Platform, const ALIGN: usize, Store> Deref for Vmem<Platform, ALIGN, Store>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
    Store: ReservationStore,
{
    type Target = MappingState<Store>;

    fn deref(&self) -> &Self::Target {
        &self.mappings
    }
}

impl<Platform, const ALIGN: usize, Store> DerefMut for Vmem<Platform, ALIGN, Store>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
    Store: ReservationStore,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mappings
    }
}

impl<Platform, const ALIGN: usize, Store> Vmem<Platform, ALIGN, Store>
where
    Platform: PageManagementProvider<ALIGN> + 'static,
    Store: ReservationStore + Default,
{
    pub(super) const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`Vmem`] instance with the given memory [backend](PageManagementProvider).
    pub(super) fn new(platform: &'static Platform) -> Self {
        assert!(Platform::RESERVATION_ALIGNMENT.is_power_of_two());
        assert!(Platform::RESERVATION_ALIGNMENT.is_multiple_of(ALIGN));
        let mut vmem = Self {
            mappings: MappingState::default(),
            brk: 0,
            platform,
        };
        for each in platform.reserved_pages() {
            assert!(
                each.start % ALIGN == 0 && each.end % ALIGN == 0,
                "Vmem: reserved range is not aligned to {ALIGN} bytes"
            );
            vmem.vmas.insert(
                each.start..each.end,
                VmArea {
                    flags: VmFlags::empty(),
                    is_file_backed: false,
                },
            );
        }
        vmem
    }

    /// Gets an iterator over all pairs of ([`Range<usize>`], [`VmArea`]),
    /// ordered by key range.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
    }

    /// Check whether a range overlaps mappings or tracked reservations.
    pub(super) fn overlaps(&self, range: Range<usize>, include_reservations: bool) -> bool {
        self.mappings.overlaps(range, include_reservations)
    }

    /// Insert an already-allocated region (e.g., via CoW) without calling the platform allocator.
    ///
    /// Any existing tracked mappings that overlap `range` are silently removed from tracking
    /// (without calling the platform deallocator) before inserting. Use [`Self::overlapping`] to
    /// check for overlap before running this if needed.
    pub(super) fn register_existing_mapping_overwrite(
        &mut self,
        range: PageRange<ALIGN>,
        vma: VmArea,
    ) {
        self.vmas.insert(range.into(), vma);
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
    ) -> Result<(), VmemUnmapError> {
        unsafe {
            self.platform
                .deallocate_pages(range.into())
                .map_err(VmemUnmapError::UnmapError)?;
        }
        self.vmas.remove(range.into());
        Ok(())
    }

    /// Reset pages without removing its mapping (similar to Linux `madvise` with
    /// `MADV_DONTNEED` or `MADV_FREE`).
    ///
    /// If `anonymous_only` is true and any part of the range is non-anonymous (i.e., file-backed),
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
    ) -> Result<(), VmemResetError> {
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
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
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
        // The `max_permissions` is tracked by `VMem::protect_mapping` and thus doesn't need to be
        // passed to `allocate_pages`.
        let _ = max_permissions;
        let ret = self
            .platform
            .allocate_pages(
                suggested_range.into(),
                MemoryRegionPermissions::from_bits(permissions).unwrap(),
                vma.flags.contains(VmFlags::VM_GROWSDOWN),
                populate_pages_immediately,
                platform_fixed_address_behavior,
            )
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
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let total_length = (length
            + if flags.contains(CreatePagesFlags::ENSURE_SPACE_AFTER) {
                DEFAULT_RESERVED_SPACE_SIZE
            } else {
                0
            })
        .unwrap();
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
            let new_addr = Self::find_area(&self.reservations, &self.vmas, &request)?
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
                    request.suggested_address = None;
                    if direction == Some(AllocationDirection::TopDown) {
                        request.address_range.end = new_addr;
                    } else {
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
    ) -> Result<(), VmemResizeError> {
        let range = range.start..range.end;
        // `cur_range` contains `range.start`
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range.start + new_size.as_usize();
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
                Err(AllocationError::OutOfMemory) => return Err(VmemResizeError::OutOfMemory),
                Err(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                ) => return Err(VmemResizeError::RangeOccupied(range.into())),
                Err(
                    AllocationError::Unaligned
                    | AllocationError::BelowMinAddress
                    | AllocationError::AboveMaxAddress,
                ) => unreachable!(),
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
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError> {
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
        let new_addr = unsafe {
            self.platform
                .remap_pages(old_range.into(), new_range.into(), vma.flags.into())
        }
        .map_err(VmemMoveError::RemapError)?;

        let new_start = new_addr.as_usize();
        let new_end = new_start + new_size.as_usize();
        self.vmas.insert(new_start..new_end, vma);
        self.vmas.remove(old_range.into());
        Ok(new_addr)
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
    ) -> Result<(), VmemProtectError> {
        // `MemoryRegionPermissions` is a subset of `VmFlags` and we only change the access flags
        let flags =
            VmFlags::from_bits(u32::from(permissions.bits())).unwrap() & VmFlags::VM_ACCESS_FLAGS;
        let range = range.start..range.end;
        let mut mappings_to_change = Vec::new();
        for (r, vma) in self.vmas.overlapping(range.clone()) {
            mappings_to_change.push((r.start, r.end, *vma));
        }
        if mappings_to_change.is_empty() {
            return Err(VmemProtectError::InvalidRange(range));
        }

        for (start, end, vma) in mappings_to_change {
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

            self.vmas.remove(start..end);
            let intersection = range.start.max(start)..range.end.min(end);
            // split r into three parts: before, intersection, and after
            let before = start..intersection.start;
            let after = intersection.end..end;

            let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
            // `intersection` is page aligned.
            unsafe {
                self.platform
                    .update_permissions(intersection.clone(), permissions)
            }
            .map_err(|e| {
                // restore the original mapping
                self.vmas.insert(start..end, vma);
                VmemProtectError::ProtectError(e)
            })?;

            self.vmas.insert(
                intersection,
                VmArea {
                    flags: new_flags,
                    is_file_backed: vma.is_file_backed,
                },
            );
            if !before.is_empty() {
                self.vmas.insert(before, vma);
            }
            if !after.is_empty() {
                self.vmas.insert(after, vma);
            }
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
        if let Some(start) = suggested_start {
            let end = start
                .checked_add(source_data.len())
                .ok_or(CowAllocationError::Unaligned)?;
            if start < Platform::TASK_ADDR_MIN || end > Platform::TASK_ADDR_MAX {
                return Err(CowAllocationError::InternalFailure);
            }
            let requested =
                PageRange::<ALIGN>::new(start, end).ok_or(CowAllocationError::Unaligned)?;
            if behavior == FixedAddressBehavior::NoReplace && self.overlaps(requested.into(), true)
            {
                return Err(CowAllocationError::InternalFailure);
            }
        }
        let suggested_start = suggested_start.unwrap_or(0);

        let ptr = self.platform.try_allocate_cow_pages(
            suggested_start,
            source_data,
            permissions,
            behavior,
        )?;
        let actual_start = ptr.as_usize();
        let actual_end = actual_start
            .checked_add(source_data.len())
            .ok_or(CowAllocationError::InternalFailure)?;
        let actual =
            PageRange::new(actual_start, actual_end).ok_or(CowAllocationError::InternalFailure)?;
        debug_assert!(
            matches!(behavior, FixedAddressBehavior::Hint(_)) || suggested_start == actual_start
        );
        debug_assert!(
            actual_start >= Platform::TASK_ADDR_MIN && actual_end <= Platform::TASK_ADDR_MAX
        );

        // TODO: also add the range to reservations once we allow using [`TrackedReservations`]
        // and update [`try_allocate_cow_pages`] to return the reservation handle.
        self.register_existing_mapping_overwrite(
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
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
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
        Self::find_area(
            &self.reservations,
            &self.vmas,
            &Self::build_unmapped_area_request(suggested_address, length, behavior),
        )
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
            include_reservations: false,
            address_range: Platform::TASK_ADDR_MIN..address_range_end,
        }
    }

    /// Search VMA gaps, preserving stack guards while optionally excluding reservations.
    pub(super) fn find_area(
        reservations: &Store,
        vmas: &RangeMap<usize, VmArea>,
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
        } else if !matches!(request.behavior, FixedAddressBehavior::Hint(_)) {
            return Err(AllocationError::BelowMinAddress);
        }

        Ok(Self::find_area_in_range(reservations, vmas, request))
    }

    fn find_area_in_range(
        reservations: &Store,
        vmas: &RangeMap<usize, VmArea>,
        request: &FindAreaRequest<ALIGN>,
    ) -> Option<usize> {
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
            let mut start = if top_down {
                gap.end.checked_sub(size)? & !(request.alignment - 1)
            } else {
                gap.start.checked_next_multiple_of(request.alignment)?
            };
            while start >= gap.start && start.checked_add(size)? <= gap.end {
                let conflict = if request.include_reservations {
                    let mut overlaps = reservations.overlapping(start..start + size);
                    if top_down {
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
                start = if top_down {
                    conflict.start.checked_sub(size)? & !(request.alignment - 1)
                } else {
                    conflict.end.checked_next_multiple_of(request.alignment)?
                };
            }
            None
        };
        let mut vmas = vmas.iter();
        let mut gap_boundary = if top_down { high_limit } else { low_limit };
        while let Some((range, vma)) = if top_down {
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
            let gap = if top_down {
                range.end.max(low_limit)..gap_boundary
            } else {
                gap_boundary..guarded_start
            };
            if let Some(start) = find_in_gap(gap) {
                return Some(start);
            }
            gap_boundary = if top_down {
                guarded_start
            } else {
                range.end.max(low_limit)
            };
        }
        let gap = if top_down {
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
    #[error("the range {0:?} is not aligned")]
    UnAligned(Range<usize>),
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] crate::platform::page_mgmt::PermissionUpdateError),
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
    MapError(#[from] crate::platform::page_mgmt::AllocationError),
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
