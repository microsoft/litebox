//! Implement [`Vmem`] that manages virtual address space backed by a memory [`VmemBackend`].
//!

use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

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

/// A page range that guarantees the `start` and `end` addresses
/// are page aligned and `start` < `end`.
#[derive(Clone)]
pub struct PageRange<const ALIGN: usize = PAGE_SIZE> {
    /// Start page of the range.
    start: usize,
    /// End page of the range.
    end: usize,
}

impl<const ALIGN: usize> Iterator for PageRange<ALIGN> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let page = self.start;
            self.start += ALIGN;
            Some(page)
        } else {
            None
        }
    }
}

impl<const ALIGN: usize> PageRange<ALIGN> {
    /// Create a new page range.
    ///
    /// # Panics
    ///
    /// Panics if `start` >= `end`.
    pub fn new(start: usize, end: usize) -> Self {
        assert!(start < end);
        assert!((start % ALIGN) == 0);
        assert!((end % ALIGN) == 0);
        Self { start, end }
    }
}

/// A non-zero 4KiB-page-aligned size in bytes.
#[derive(Clone, Copy)]
pub(super) struct NonZeroPageSize<const ALIGN: usize = PAGE_SIZE> {
    size: usize,
}

impl<const ALIGN: usize> NonZeroPageSize<ALIGN> {
    /// Create a new non-zero page-aligned size.
    ///
    /// # Panics
    ///
    /// Panics if `size` is zero or not a multiple of [`PAGE_SIZE`].
    pub fn new(size: usize) -> Self {
        assert!(size != 0);
        assert!(size % ALIGN == 0);
        Self { size }
    }

    #[inline]
    pub fn as_usize(self) -> usize {
        self.size
    }
}

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
}

impl VmArea {
    #[inline]
    pub fn flags(&self) -> VmFlags {
        self.flags
    }

    #[inline]
    pub fn new(flags: VmFlags) -> Self {
        Self { flags }
    }
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory areas of a process.
pub struct Vmem<Backend: VmemBackend> {
    /// Virtual memory areas. The ranges need to be page aligned.
    vmas: RangeMap<usize, VmArea>,
    /// Memory backend that provides the actual memory.
    backend: Backend,
}

pub(super) const PAGE_SIZE: usize = 4096;

impl<Backend: VmemBackend> Vmem<Backend> {
    pub const TASK_ADDR_MIN: usize = PAGE_SIZE;
    pub const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;

    pub const fn new(backend: Backend) -> Self {
        Self {
            vmas: RangeMap::new(),
            backend,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
    }

    pub fn get_backend(&self) -> &Backend {
        &self.backend
    }

    pub fn get_inner_mut(&mut self) -> &mut Backend {
        &mut self.backend
    }

    pub fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.overlapping(range)
    }

    /// Remove a range from its virtual address space, if all or any of it was present.
    ///
    /// If the range to be removed _partially_ overlaps any ranges, then those ranges will
    /// be contracted to no longer cover the removed range.
    pub(super) fn remove_mapping(&mut self, range: PageRange) {
        let (start, end) = (range.start, range.end);
        self.vmas.remove(start..end);
        unsafe {
            self.backend.unmap_pages(start, end - start, true);
        };
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
    /// # Panics
    ///
    /// Panics if the range is beyond the task address space [[`Self::TASK_ADDR_MIN`], [`Self::TASK_ADDR_MAX`]]).
    pub fn insert_mapping(&mut self, range: PageRange, vma: VmArea) {
        let (start, end) = (range.start, range.end);
        assert!(start >= Self::TASK_ADDR_MIN);
        assert!(end <= Self::TASK_ADDR_MAX);
        for (r, _) in self.vmas.overlapping(start..end) {
            let intersection = r.start.max(start)..r.end.min(end);
            unsafe {
                self.backend.unmap_pages(
                    intersection.start,
                    intersection.end - intersection.start,
                    true,
                );
            };
        }
        self.vmas.insert(start..end, vma);
    }

    /// Create a new mapping in the virtual address space.
    /// The mapping will be created at the suggested address. If the start address is zero,
    /// some available range will be choosen by the kernel.
    /// Note that if the suggested address is given and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped.
    pub(super) fn create_mapping(
        &mut self,
        suggested_range: PageRange,
        vma: VmArea,
        fixed_addr: bool,
    ) -> Option<usize> {
        let (suggested_start, suggested_end) = (suggested_range.start, suggested_range.end);
        let len = suggested_end - suggested_start;
        let new_addr =
            self.get_unmmaped_area(suggested_start, NonZeroPageSize::new(len), fixed_addr)?;
        self.vmas.insert(new_addr..new_addr + len, vma);
        Some(new_addr)
    }

    /// Resize a range in the virtual address space.
    /// Split the range and unmap the unused part if it is larger than the new size.
    /// Enlarge the range if it is smaller than the new size and will not overlap with
    /// any existing ranges.
    ///
    /// See https://elixir.bootlin.com/linux/v5.19.17/source/mm/mremap.c#L886 for reference.
    pub(super) fn resize_mapping(
        &mut self,
        range: PageRange,
        new_size: NonZeroPageSize,
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
                self.remove_mapping(PageRange::new(new_end, range.end));
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
            self.vmas.insert(r, *cur_vma);
            return Ok(());
        }

        // has to split the current range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..cur_range.end))
    }

    /// Move a range in the virtual address space.
    ///
    /// Returns `Some(new_addr)` if the range is moved successfully
    ///
    /// Otherwise, returns `None`.
    ///
    /// # Panics
    ///
    /// Panics if `new_size` is smaller than the current size of the range.
    /// Panics if range is not within exact one mapping.
    pub(super) fn move_mappings(
        &mut self,
        range: PageRange,
        new_size: NonZeroPageSize,
        suggested_addr: usize,
    ) -> Result<usize, VmemMoveError> {
        let (start, end) = (range.start, range.end);
        assert!(new_size.as_usize() >= (end - start));

        // Check if the given range is within one mapping
        let (cur_range, vma) = self
            .vmas
            .get_key_value(&start)
            .expect("VMEM: range not found");
        assert!(cur_range.contains(&(end - 1)));

        let new_addr = self
            .get_unmmaped_area(suggested_addr, new_size, false)
            .ok_or(VmemMoveError::OutOfMemory)?;
        self.vmas
            .insert(new_addr..new_addr + new_size.as_usize(), *vma);
        unsafe { self.backend.remap_pages(start, new_addr, end - start) }
            .map_err(VmemMoveError::RemapError)?;
        self.vmas.remove(start..end);
        Ok(new_addr)
    }

    /// Change the permissions ([`VmFlags::VM_ACCESS_FLAG`]) of a range in the virtual address space.
    ///
    /// See https://elixir.bootlin.com/linux/v5.19.17/source/mm/mprotect.c#L617 for reference.
    pub(super) fn protect_mapping(
        &mut self,
        range: PageRange,
        flags: VmFlags,
    ) -> Result<(), VmemProtectError> {
        // only change the access flags
        let flags = flags & VmFlags::VM_ACCESS_FLAGS;
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
                self.backend.mprotect_pages(
                    intersection.start,
                    intersection.end - intersection.start,
                    new_flags,
                )
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

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    /// `suggested_addr` and `fixed_addr` are the hint address and MAP_FIXED flag respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if the area is not found.
    fn get_unmmaped_area(
        &self,
        suggested_addr: usize,
        size: NonZeroPageSize,
        fixed_addr: bool,
    ) -> Option<usize> {
        let size = size.as_usize();
        if size > Self::TASK_ADDR_MAX {
            return None;
        }
        if suggested_addr != 0 {
            debug_assert!(suggested_addr % PAGE_SIZE == 0);
            if (Self::TASK_ADDR_MAX - size) < suggested_addr {
                return None;
            }
            if fixed_addr
                || !self
                    .vmas
                    .overlaps(&(suggested_addr..(suggested_addr + size)))
            {
                return Some(suggested_addr);
            }
        }

        // top down
        // 1. check [last_end, TASK_SIZE_MAX)
        let (low_limit, high_limit) = (Self::TASK_ADDR_MIN, Self::TASK_ADDR_MAX - size);
        let last_end = self.vmas.last_range_value().map_or(low_limit, |r| r.0.end);
        if last_end <= high_limit {
            return Some(last_end);
        }

        // 2. check gaps between ranges
        for (r, _) in self.vmas.iter().rev().skip(1) {
            if !self.vmas.overlaps(&(r.end..r.end + size)) {
                return Some(r.end);
            }
        }

        // 3. check [low_limit, first_start)
        let first_start = self
            .vmas
            .first_range_value()
            .map_or(high_limit, |r| r.0.start);
        if low_limit + size <= first_start {
            return Some(first_start - size);
        }

        None
    }
}

pub trait VmemBackend {
    /// Unmap 4KiB pages
    ///
    /// `free_page` indicates whether the unmapped pages should be freed (This may be helpful
    /// when implementing [`Self::remap_pages`]. If we maintain refcnt for pages, we may not
    /// need this).
    ///
    /// # Safety
    ///
    /// `start` and `len` must be aligned to 4KiB.
    ///
    /// # Panics
    ///
    /// panic if `start` or `len` is misaligned.
    unsafe fn unmap_pages(&mut self, start: usize, len: usize, free_page: bool);

    /// Remap 4KiB pages from `old_addr` to `new_addr`
    ///
    /// # Safety
    ///
    /// The caller must also ensure that the [`new_addr`, `new_addr` + `len`]
    /// is not already mapped, and `old_addr` and `new_addr` do not overlap.
    /// `old_addr`, `new_addr`, and `len` must be aligned to 4KiB.
    unsafe fn remap_pages(
        &mut self,
        old_addr: usize,
        new_addr: usize,
        len: usize,
    ) -> Result<(), RemapError>;

    /// Change the protection for 4KiB pages
    ///
    /// # Safety
    ///
    /// The caller must also ensure that [`start`, `start` + `len`) is okay
    /// to be changed to `new_flags`.
    unsafe fn mprotect_pages(
        &mut self,
        start: usize,
        len: usize,
        new_flags: VmFlags,
    ) -> Result<(), ProtectError>;
}

#[derive(Error, Debug)]
pub(super) enum VmemResizeError {
    #[error("no mapping containing the address {0:?}")]
    NotExist(usize),
    #[error("invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr { range: Range<usize>, addr: usize },
    #[error("range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<usize>),
}

#[derive(Error, Debug)]
pub(super) enum VmemMoveError {
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap failed: {0}")]
    RemapError(#[from] RemapError),
}

#[derive(Error, Debug)]
pub enum RemapError {
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap to huge page")]
    RemapToHugePage,
}

#[derive(Error, Debug)]
pub(super) enum VmemProtectError {
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] ProtectError),
}

#[derive(Error, Debug)]
pub enum ProtectError {
    #[error("protect page that belongs to a huge page")]
    ProtectHugePage,
}
