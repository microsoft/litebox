//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](`VmemBackend`). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

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

/// A non-empty range of page-aligned addresses
#[derive(Clone, Copy)]
pub struct PageRange<const ALIGN: usize> {
    /// Start page of the range.
    start: usize,
    /// End page of the range.
    end: usize,
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
        Some(unsafe { Self::new_unchecked(start, end) })
    }

    /// Create a new [`PageRange`] without checking for alignment or emptiness.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the range is `ALIGN`-aligned and not empty.
    pub unsafe fn new_unchecked(start: usize, end: usize) -> Self {
        Self { start, end }
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
}

/// A non-zero 4KiB-page-aligned size in bytes.
#[derive(Clone, Copy)]
pub(super) struct NonZeroPageSize<const ALIGN: usize> {
    size: usize,
}

impl<const ALIGN: usize> NonZeroPageSize<ALIGN> {
    /// Create a new non-zero `ALIGN`-aligned size.
    ///
    /// Returns `None` if the size is zero or not `ALIGN`-aligned.
    pub(super) fn new(size: usize) -> Option<Self> {
        if size == 0 || size % ALIGN != 0 {
            return None;
        }
        Some(unsafe { Self::new_unchecked(size) })
    }

    /// Create a new non-zero `ALIGN`-aligned size without checking for zero or alignment.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the size is non-zero and `ALIGN`-aligned.
    #[inline]
    pub(super) unsafe fn new_unchecked(size: usize) -> Self {
        Self { size }
    }

    #[inline]
    pub(super) fn as_usize(self) -> usize {
        self.size
    }
}

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
}

impl VmArea {
    #[inline]
    pub(super) fn flags(self) -> VmFlags {
        self.flags
    }

    #[inline]
    pub(super) fn new(flags: VmFlags) -> Self {
        Self { flags }
    }
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory ranges backed by a memory [backend](`VmemBackend`).
/// Each range needs to be `ALIGN`-aligned.
pub(super) struct Vmem<Backend: VmemBackend, const ALIGN: usize> {
    /// Memory backend that provides the actual memory.
    pub(super) backend: Backend,
    /// Virtual memory areas.
    vmas: RangeMap<usize, VmArea>,
}

impl<Backend: VmemBackend, const ALIGN: usize> Vmem<Backend, ALIGN> {
    /// Create a new [`Vmem`] instance with the given memory [backend](`VmemBackend`).
    pub(super) const fn new(backend: Backend) -> Self {
        Self {
            vmas: RangeMap::new(),
            backend,
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
    ) -> Result<(), VmemUnmapError> {
        let (start, end) = (range.start, range.end);
        unsafe {
            self.backend
                .unmap_pages(start, end - start)
                .map_err(VmemUnmapError::UnmapError)?;
        }
        self.vmas.remove(start..end);
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
    ) -> Option<usize> {
        let (start, end) = (range.start, range.end);
        if start < Backend::TASK_ADDR_MIN || end > Backend::TASK_ADDR_MAX {
            return None;
        }
        for (r, _) in self.vmas.overlapping(start..end) {
            let intersection = r.start.max(start)..r.end.min(end);
            unsafe {
                self.backend
                    .unmap_pages(intersection.start, intersection.end - intersection.start)
                    .ok()?;
            }
        }
        unsafe { self.backend.map_pages(start, end - start, vma.flags) }.ok()?;
        self.vmas.insert(start..end, vma);
        Some(start)
    }

    /// Create a new mapping in the virtual address space.
    /// The mapping will be created at the suggested address. If the suggested start address is zero,
    /// some available range will be choosen by the kernel.
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
        suggested_range: PageRange<ALIGN>,
        vma: VmArea,
        fixed_addr: bool,
    ) -> Option<usize> {
        let (suggested_start, suggested_end) = (suggested_range.start, suggested_range.end);
        let len = suggested_end - suggested_start;
        let new_addr = self.get_unmmaped_area(
            suggested_start,
            unsafe { NonZeroPageSize::new_unchecked(len) },
            fixed_addr,
        )?;
        // new_addr must be ALIGN aligned
        unsafe { self.insert_mapping(PageRange::new_unchecked(new_addr, new_addr + len), vma) }
    }

    /// Resize a range in the virtual address space.
    /// Shrinks the range if it is larger than `new_size`.
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
                unsafe { self.remove_mapping(PageRange::new_unchecked(new_end, range.end)) };
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
            unsafe { self.insert_mapping(PageRange::new_unchecked(range.end, new_end), *cur_vma) };
            return Ok(());
        }

        // has to split the current range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..cur_range.end))
    }

    /// Move a range in the virtual address space.
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
    /// Panics if `new_size` is smaller than the current size of the range.
    /// Panics if range is not within exact one mapping.
    pub(super) unsafe fn move_mappings(
        &mut self,
        range: PageRange<ALIGN>,
        new_size: NonZeroPageSize<ALIGN>,
        suggested_new_addr: usize,
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
            .get_unmmaped_area(suggested_new_addr, new_size, false)
            .ok_or(VmemMoveError::OutOfMemory)?;
        unsafe {
            self.backend
                .remap_pages(start, new_addr, end - start, new_size.as_usize())
        }
        .map_err(VmemMoveError::RemapError)?;
        self.vmas
            .insert(new_addr..new_addr + new_size.as_usize(), *vma);
        self.vmas.remove(start..end);
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

    /// Create a mapping with the given flags.
    ///
    /// `suggested_range` is the range of pages to create. If the start address is not given (i.e., zero), some
    /// available memory region will be chosen. Otherwise, the range will be created at the given address if it
    /// is available.
    ///
    /// Set `fixed_addr` to `true` to force the mapping to be created at the given address, resulting in any
    /// existing overlapping mappings being removed.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// `before_flags` and `after_flags` are the flags to set before and after the call to `op`.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    pub(super) unsafe fn create_pages<F, P>(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        fixed_addr: bool,
        before_flags: VmFlags,
        after_flags: VmFlags,
        op: F,
    ) -> Result<usize, MappingError>
    where
        P: crate::platform::RawMutPointer<u8> + From<usize>,
        F: FnOnce(P) -> Result<usize, MappingError>,
    {
        let addr =
            unsafe { self.create_mapping(suggested_range, VmArea::new(before_flags), fixed_addr) }
                .ok_or(MappingError::OutOfMemory)?;
        // call the user function with the pages
        let _ = op(P::from(addr))?;
        if before_flags != after_flags {
            // `protect` should succeed, as we just created the mapping.
            unsafe {
                self.protect_mapping(
                    PageRange::new_unchecked(addr, addr + suggested_range.len()),
                    after_flags,
                )
            }
            .expect("failed to protect mapping");
        }
        Ok(addr)
    }

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    /// `suggested_addr` and `fixed_addr` are the hint address and MAP_FIXED flag respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if no area found. Otherwise, returns the start address of a page-aligned area.
    fn get_unmmaped_area(
        &self,
        suggested_addr: usize,
        size: NonZeroPageSize<ALIGN>,
        fixed_addr: bool,
    ) -> Option<usize> {
        let size = size.as_usize();
        if size > Backend::TASK_ADDR_MAX {
            return None;
        }
        if suggested_addr != 0 {
            debug_assert!(suggested_addr % PAGE_SIZE == 0);
            if (Backend::TASK_ADDR_MAX - size) < suggested_addr {
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
        let (low_limit, high_limit) = (Backend::TASK_ADDR_MIN, Backend::TASK_ADDR_MAX - size);
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

/// A trait for a virtual memory backend
pub trait VmemBackend {
    type InitItem;

    const TASK_ADDR_MIN: usize = PAGE_SIZE;
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`VmemBackend`] instance
    ///
    /// # Safety
    ///
    /// `item` must be a valid initialization item for the backend.
    unsafe fn new(item: Self::InitItem) -> Self;

    /// Map/Allocate pages at the fixed address `start` with `flags`
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is not used by any other.
    unsafe fn map_pages(
        &mut self,
        start: usize,
        len: usize,
        flags: VmFlags,
    ) -> Result<(), MmapError>;

    /// Unmap `ALIGN`-aligned memory region from `start` to `start` + `len`
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is not used by any other.
    unsafe fn unmap_pages(&mut self, start: usize, len: usize) -> Result<(), UnmapError>;

    /// Remap the given memory from `old_addr` to `new_addr`
    ///
    /// # Safety
    ///
    /// The caller must ensure that the [`old_addr`, `old_addr` + `old_len`] is safe to be unmapped,
    /// and [`new_addr`, `new_addr` + `new_len`] is not already mapped.
    /// Also, these two regions can not overlap.
    unsafe fn remap_pages(
        &mut self,
        old_addr: usize,
        new_addr: usize,
        old_len: usize,
        new_len: usize,
    ) -> Result<(), RemapError>;

    /// Change the protection for the given memory from `start` to `start` + `len`
    ///
    /// # Safety
    ///
    /// The caller must ensure that [`start`, `start` + `len`) is okay to be changed to `new_flags`.
    unsafe fn mprotect_pages(
        &mut self,
        start: usize,
        len: usize,
        new_flags: VmFlags,
    ) -> Result<(), ProtectError>;
}

/// Error for [`VmemBackend::map_pages`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MmapError {
    #[error("{0:#x} is not aligned")]
    MisAligned(usize),
}

#[derive(Error, Debug)]
pub enum VmemUnmapError {
    #[error("failed to unmap pages: {0:?}")]
    UnmapError(#[from] UnmapError),
}

/// Error for [`VmemBackend::unmap_pages`]
#[derive(Error, Debug)]
pub enum UnmapError {
    #[error("{0:#x} is not aligned")]
    MisAligned(usize),
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

/// Error for [`Vmem::move_mappings`]
#[derive(Error, Debug)]
pub(super) enum VmemMoveError {
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap failed: {0}")]
    RemapError(#[from] RemapError),
}

/// Error for [`VmemBackend::remap_pages`]
#[derive(Error, Debug)]
pub enum RemapError {
    #[error("{0:#x} is not aligned")]
    MisAligned(usize),
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap to huge page")]
    RemapToHugePage,
}

/// Error for [`Vmem::protect_mapping`]
#[derive(Error, Debug)]
pub(super) enum VmemProtectError {
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] ProtectError),
}

/// Error for [`VmemBackend::mprotect_pages`]
#[derive(Error, Debug)]
pub enum ProtectError {
    #[error("protect page that belongs to a huge page")]
    ProtectHugePage,
}

/// Error for creating mappings
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("not enough memory")]
    OutOfMemory,
    #[error("failed to read from file")]
    ReadError(#[from] crate::fs::errors::ReadError),
}

/// Enable [`super::PageManager`] to handle page faults if its
/// [backend](`crate::platform::PageManagementProvider::Backend`) implements this trait
pub trait VmemPageFaultHandler {
    /// Handle a page fault for the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    unsafe fn handle_page_fault(
        &mut self,
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
