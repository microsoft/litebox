//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use crate::platform::PageManagementProvider;
use crate::platform::RawConstPointer;
use crate::platform::page_mgmt::MemoryRegionPermissions;

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

const DEFAULT_RESERVED_SPACE_SIZE: usize = 0x100_0000; // 16 MiB

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
        if start % ALIGN != 0 || end % ALIGN != 0 {
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
        if size == 0 || size % ALIGN != 0 {
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
pub struct NonZeroAddress<const ALIGN: usize>(usize);

impl<const ALIGN: usize> NonZeroAddress<ALIGN> {
    /// Create a new `NonZeroAddress`, if the address is non-zero and aligned.
    pub fn new(address: usize) -> Option<Self> {
        if address == 0 || address % ALIGN != 0 {
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
}

impl VmArea {
    /// Get the [flags](`VmFlags`) of this memory area.
    #[inline]
    pub(super) fn flags(self) -> VmFlags {
        self.flags
    }

    /// Create a new [`VmArea`] with the given flags.
    #[inline]
    pub(super) fn new(flags: VmFlags) -> Self {
        Self { flags }
    }
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory ranges backed by a memory [backend](PageManagementProvider).
/// Each range needs to be `ALIGN`-aligned.
pub(super) struct Vmem<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> {
    /// Memory backend that provides the actual memory.
    pub(super) platform: &'static Platform,
    /// Current program break address.
    pub(super) brk: usize,
    /// Virtual memory areas.
    vmas: RangeMap<usize, VmArea>,
}

impl<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> Vmem<Platform, ALIGN> {
    pub(super) const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    pub(super) const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    #[cfg(target_arch = "x86")]
    pub(super) const TASK_ADDR_MAX: usize = 0xC000_0000; // 3 GiB (see arch/x86/include/asm/page_32_types.h)
    pub(super) const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`Vmem`] instance with the given memory [backend](PageManagementProvider).
    pub(super) fn new(platform: &'static Platform) -> Self {
        let mut vmem = Self {
            vmas: RangeMap::new(),
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
        range: PageRange<ALIGN>,
        vma: VmArea,
        populate_pages_immediately: bool,
    ) -> Option<Platform::RawMutPointer<u8>> {
        let (start, end) = (range.start, range.end);
        if start < Self::TASK_ADDR_MIN || end > Self::TASK_ADDR_MAX {
            return None;
        }
        for (r, _) in self.vmas.overlapping(start..end) {
            let intersection = r.start.max(start)..r.end.min(end);
            unsafe { self.platform.deallocate_pages(intersection) }.ok()?;
        }
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
                range.into(),
                MemoryRegionPermissions::from_bits(permissions).unwrap(),
                vma.flags.contains(VmFlags::VM_GROWSDOWN),
                populate_pages_immediately,
            )
            .ok()?;
        self.vmas.insert(start..end, vma);
        Some(ret)
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
    /// # Safety
    ///
    /// Note that if the suggested address is given and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub(super) unsafe fn create_mapping(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        vma: VmArea,
        flags: CreatePagesFlags,
    ) -> Option<Platform::RawMutPointer<u8>> {
        let total_length = (length
            + if flags.contains(CreatePagesFlags::ENSURE_SPACE_AFTER) {
                DEFAULT_RESERVED_SPACE_SIZE
            } else {
                0
            })
        .unwrap();
        let new_addr = self.get_unmmaped_area(
            suggested_address,
            total_length,
            flags.contains(CreatePagesFlags::FIXED_ADDR),
        )?;
        // new_addr must be ALIGN aligned
        let new_range = PageRange::new(new_addr, new_addr + length.as_usize()).unwrap();
        unsafe {
            self.insert_mapping(
                new_range,
                vma,
                flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
            )
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
            let range = PageRange::new(range.end, new_end).unwrap();
            unsafe { self.insert_mapping(range, *cur_vma, false) };
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

        let new_addr = self
            .get_unmmaped_area(suggested_new_address, new_size, false)
            .ok_or(VmemMoveError::OutOfMemory)?;
        let new_range = PageRange::<ALIGN>::new(new_addr, new_addr + new_size.as_usize()).unwrap();
        let new_addr = unsafe {
            self.platform
                .remap_pages(old_range.into(), new_range.into())
        }
        .map_err(VmemMoveError::RemapError)?;
        assert_eq!(new_addr.as_usize(), new_range.start);
        self.vmas.insert(new_range.into(), *vma);
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

            self.vmas.insert(intersection, VmArea { flags: new_flags });
            if !before.is_empty() {
                self.vmas.insert(before, vma);
            }
            if !after.is_empty() {
                self.vmas.insert(after, vma);
            }
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
    /// `before_perms` and `after_perms` are the permissions to set before and after the call to `op`.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    pub(super) unsafe fn create_pages<F>(
        &mut self,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        before_perms: MemoryRegionPermissions,
        after_perms: MemoryRegionPermissions,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let addr = unsafe {
            self.create_mapping(
                suggested_new_address,
                length,
                VmArea::new(
                    VmFlags::from(before_perms)
                        | VmFlags::VM_MAY_ACCESS_FLAGS
                        | if flags.contains(CreatePagesFlags::IS_STACK) {
                            VmFlags::VM_GROWSDOWN
                        } else {
                            VmFlags::empty()
                        },
                ),
                flags,
            )
        }
        .ok_or(MappingError::OutOfMemory)?;
        // call the user function with the pages
        if let Err(e) = op(addr) {
            // remove the mapping if the user function fails
            unsafe {
                self.remove_mapping(
                    PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize()).unwrap(),
                )
            }
            .unwrap();
            return Err(e);
        }
        if before_perms != after_perms {
            let range =
                PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize()).unwrap();
            // `protect` should succeed, as we just created the mapping.
            unsafe { self.protect_mapping(range, after_perms) }.expect("failed to protect mapping");
        }
        Ok(addr)
    }

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    /// `suggested_range` and `fixed_addr` are the hint address and MAP_FIXED flag respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if no area found. Otherwise, returns the start address of a page-aligned area.
    fn get_unmmaped_area(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        fixed_addr: bool,
    ) -> Option<usize> {
        let size = length.as_usize();
        if size > Self::TASK_ADDR_MAX {
            return None;
        }
        if let Some(suggested_address) = suggested_address {
            if (Self::TASK_ADDR_MAX - size) < suggested_address.0 {
                return None;
            }
            if fixed_addr
                || !self
                    .vmas
                    .overlaps(&(suggested_address.0..(suggested_address.0 + size)))
            {
                return Some(suggested_address.0);
            }
        }

        // top down
        // 1. check [last_end, TASK_SIZE_MAX)
        let (low_limit, high_limit) =
            (Self::TASK_ADDR_MIN, Self::TASK_ADDR_MAX - length.as_usize());
        let last_end = self.vmas.last_range_value().map_or(low_limit, |r| r.0.end);
        if last_end <= high_limit {
            return Some(high_limit);
        }

        // 2. check gaps between ranges
        for (r, flags) in self.vmas.iter().rev() {
            let start = r.start.checked_sub(
                size + if flags.flags.contains(VmFlags::VM_GROWSDOWN) {
                    // If it is a stack, we need to leave enough space for the stack to grow downwards.
                    Self::STACK_GUARD_GAP << 1
                } else {
                    0
                },
            )?;
            if start < low_limit {
                return None;
            }
            if start > high_limit {
                // Note we may have pre-allocated memory that are higher than `TASK_ADDR_MAX`
                // (See [`Vmem::new`]) and thus `start` may be larger than `high_limit`.
                continue;
            }
            if !self.vmas.overlaps(&(start..start + size)) {
                return Some(start);
            }
        }

        None
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

/// Error for [`Vmem::resize_mapping`]
#[derive(Error, Debug)]
pub(super) enum VmemResizeError {
    #[error("no mapping containing the address {0:?}")]
    NotExist(usize),
    #[error("invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr { range: Range<usize>, addr: usize },
    #[error("range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<usize>),
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
