use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use crate::arch::{PAGE_SIZE, Page, PageFaultErrorCode, PageTableFlags, VirtAddr};

use super::pgtable::{PageFaultError, PageTableImpl, PageTableWalkError};

#[cfg(not(test))]
const FLUSH_TLB: bool = true;
#[cfg(test)]
const FLUSH_TLB: bool = false;

bitflags::bitflags! {
    /// Flags to describe the properties of a memory region.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct VmFlags: u32 {
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

impl From<VmFlags> for PageTableFlags {
    fn from(values: VmFlags) -> Self {
        let mut flags = PageTableFlags::empty();
        if values.intersects(VmFlags::VM_READ | VmFlags::VM_WRITE) {
            flags |= PageTableFlags::USER_ACCESSIBLE;
        }
        if values.contains(VmFlags::VM_WRITE) {
            flags |= PageTableFlags::WRITABLE;
        }
        if !values.contains(VmFlags::VM_EXEC) {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        flags
    }
}

/// A page range that guarantees the `start` and `end` addresses
/// are page aligned and `start` < `end`.
#[derive(Clone, Copy)]
pub(super) struct PageRange {
    /// Start page of the range.
    start: Page,
    /// End page of the range.
    end: Page,
}

impl Iterator for PageRange {
    type Item = Page;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let page = self.start;
            self.start += 1;
            Some(page)
        } else {
            None
        }
    }
}

/// A non-zero 4KiB-page-aligned size in bytes.
#[derive(Clone, Copy)]
pub(super) struct NonZeroPageSize {
    size: usize,
}

impl NonZeroPageSize {
    /// Create a new non-zero page-aligned size.
    ///
    /// # Panics
    ///
    /// Panics if `size` is zero or not a multiple of [`PAGE_SIZE`].
    pub(super) fn new(size: usize) -> Self {
        assert!(size != 0);
        assert!(size % PAGE_SIZE == 0);
        Self { size }
    }

    #[inline]
    fn as_u64(&self) -> u64 {
        self.size as u64
    }
}

impl PageRange {
    /// Create a new page range.
    ///
    /// # Panics
    ///
    /// Panics if `start` >= `end`.
    pub(super) fn new(start: Page, end: Page) -> Self {
        assert!(start < end);
        Self { start, end }
    }
}

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
}

/// Virtual Address Space Manager
pub(super) struct Vmem<PT: PageTableImpl> {
    /// Virtual memory areas. The ranges need to be page aligned.
    vmas: RangeMap<VirtAddr, VmArea>,
    pt: PT,
}

impl<PT: PageTableImpl> Vmem<PT> {
    const TASK_ADDR_MIN: VirtAddr = VirtAddr::new(PAGE_SIZE as u64);
    const TASK_ADDR_MAX: VirtAddr = VirtAddr::new(0x7FFF_FFFF_F000); // (1 << 47) - PAGE_SIZE;
    const STACK_GUARD_GAP: u64 = 256u64 << 12;

    pub(super) const fn new(pt: PT) -> Self {
        Self {
            vmas: RangeMap::new(),
            pt,
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<VirtAddr>, &VmArea)> {
        self.vmas.iter()
    }

    pub(super) fn get_pgtable(&self) -> &PT {
        &self.pt
    }

    /// Remove a range from its virtual address space, if all or any of it was present.
    ///
    /// If the range to be removed _partially_ overlaps any ranges, then those ranges will
    /// be contracted to no longer cover the removed range.
    pub(super) fn remove_mapping(&mut self, range: PageRange) {
        let (start, end) = (range.start.start_address(), range.end.start_address());
        self.vmas.remove(start..end);
        unsafe {
            self.pt
                .unmap_pages(start, (end - start) as usize, true, FLUSH_TLB)
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
    pub(super) fn insert_mapping(&mut self, range: PageRange, flags: VmFlags) {
        let (start, end) = (range.start.start_address(), range.end.start_address());
        assert!(start >= Self::TASK_ADDR_MIN);
        assert!(end <= Self::TASK_ADDR_MAX);
        for (r, _) in self.vmas.overlapping(start..end) {
            let intersection = r.start.max(start)..r.end.min(end);
            unsafe {
                self.pt.unmap_pages(
                    intersection.start,
                    (intersection.end - intersection.start).try_into().unwrap(),
                    true,
                    FLUSH_TLB,
                )
            };
        }
        self.vmas.insert(start..end, VmArea { flags })
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
        flags: VmFlags,
        fixed_addr: bool,
    ) -> Option<VirtAddr> {
        let (suggested_start, suggested_end) = (
            suggested_range.start.start_address(),
            suggested_range.end.start_address(),
        );
        let len = suggested_end - suggested_start;
        let new_addr = self.get_unmmaped_area(
            suggested_start,
            NonZeroPageSize::new(len as usize),
            fixed_addr,
        )?;
        self.vmas.insert(new_addr..new_addr + len, VmArea { flags });
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
        let range = range.start.start_address()..range.end.start_address();
        // `cur_range` contains `range.start`
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range.start + new_size.as_u64();
        match new_end.cmp(&range.end) {
            core::cmp::Ordering::Equal => {
                // no change
                return Ok(());
            }
            core::cmp::Ordering::Less => {
                // shrink
                self.remove_mapping(PageRange::new(
                    Page::from_start_address(new_end).unwrap(),
                    Page::from_start_address(range.end).unwrap(),
                ));
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
    /// # Panics
    ///
    /// Panics if `new_size` is smaller than the current size of the range.
    /// Panics if range is not within exact one mapping.
    pub(super) fn move_mappings(
        &mut self,
        range: PageRange,
        new_size: NonZeroPageSize,
        suggested_addr: VirtAddr,
    ) -> Option<VirtAddr> {
        let (start, end) = (range.start.start_address(), range.end.start_address());
        assert!(new_size.as_u64() >= (end - start));

        // Check if the given range is within one mapping
        let (cur_range, vma) = self
            .vmas
            .get_key_value(&start)
            .expect("VMEM: range not found");
        assert!(cur_range.contains(&(end - 1)));

        let new_addr = self.get_unmmaped_area(suggested_addr, new_size, false)?;
        self.vmas
            .insert(new_addr..new_addr + new_size.as_u64(), *vma);
        unsafe {
            self.pt
                .remap_pages(start, new_addr, (end - start) as usize, FLUSH_TLB)
                .ok()
        };
        self.vmas.remove(start..end);
        Some(new_addr)
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
        let range = range.start.start_address()..range.end.start_address();
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
            match unsafe {
                self.pt.mprotect_pages(
                    intersection.start,
                    (intersection.end - intersection.start) as usize,
                    new_flags.into(),
                    FLUSH_TLB,
                )
            } {
                Ok(_) => {}
                Err(PageTableWalkError::MappedToHugePage) => {
                    unreachable!("VMEM: We don't support huge pages")
                }
                Err(PageTableWalkError::AllocationFailed) => {
                    // restore the original mapping
                    self.vmas.insert(start..end, vma);
                    return Err(VmemProtectError::AllocationFailed);
                }
            }

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

    pub(super) fn handle_page_fault(
        &mut self,
        page: Page,
        error_code: PageFaultErrorCode,
    ) -> Result<(), PageFaultError> {
        let fault_addr = page.start_address();
        if fault_addr < Self::TASK_ADDR_MIN || fault_addr >= Self::TASK_ADDR_MAX {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        // Find the range closest to the fault address
        let (start, vma) = {
            let (r, vma) = self
                .vmas
                .overlapping(fault_addr..Self::TASK_ADDR_MAX)
                .next()
                .ok_or(PageFaultError::AccessError("no mapping"))?;
            (r.start, *vma)
        };
        if fault_addr < start {
            // address is out of range, test if it is next to a stack
            if !vma.flags.contains(VmFlags::VM_GROWSDOWN) {
                return Err(PageFaultError::AccessError("no mapping"));
            }

            if !self
                .vmas
                .overlapping(Self::TASK_ADDR_MIN..fault_addr)
                .next_back()
                .is_none_or(|(prev_range, prev_vma)| {
                    // Enforce gap between stack and other preceding non-stack mappings.
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    // or the previous mapping is far enough from the fault address
                    (prev_vma.flags.contains(VmFlags::VM_GROWSDOWN)
                        && !(prev_vma.flags & VmFlags::VM_ACCESS_FLAGS).is_empty())
                        || fault_addr - prev_range.end >= Self::STACK_GUARD_GAP
                })
            {
                return Err(PageFaultError::AllocationFailed);
            }
            self.vmas.insert(fault_addr..start, vma);
        }

        if Self::access_error(error_code, vma.flags) {
            return Err(PageFaultError::AccessError("access error"));
        }

        unsafe {
            self.pt
                .handle_page_fault(page, vma.flags.into(), error_code, FLUSH_TLB)
        }
    }

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    /// `suggested_addr` and `fixed_addr` are the hint address and MAP_FIXED flag respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if the area is not found.
    fn get_unmmaped_area(
        &self,
        suggested_addr: VirtAddr,
        size: NonZeroPageSize,
        fixed_addr: bool,
    ) -> Option<VirtAddr> {
        debug_assert!(suggested_addr.is_aligned(PAGE_SIZE as u64));

        if size.as_u64() > Self::TASK_ADDR_MAX.as_u64() {
            return None;
        }
        if !suggested_addr.is_null() {
            if (Self::TASK_ADDR_MAX - size.as_u64()) < suggested_addr {
                return None;
            }
            if fixed_addr
                || !self
                    .vmas
                    .overlaps(&(suggested_addr..(suggested_addr + size.as_u64())))
            {
                return Some(suggested_addr);
            }
        }

        // top down
        // 1. check [last_end, TASK_SIZE_MAX)
        let (low_limit, high_limit) = (Self::TASK_ADDR_MIN, Self::TASK_ADDR_MAX - size.as_u64());
        let last_end = self
            .vmas
            .last_range_value()
            .map(|r| r.0.end)
            .unwrap_or(low_limit);
        if last_end <= high_limit {
            return Some(last_end);
        }

        // 2. check gaps between ranges
        for (r, _) in self.vmas.iter().rev().skip(1) {
            if !self.vmas.overlaps(&(r.end..r.end + size.as_u64())) {
                return Some(r.end);
            }
        }

        // 3. check [low_limit, first_start)
        let first_start = self
            .vmas
            .first_range_value()
            .map(|r| r.0.start)
            .unwrap_or(high_limit);
        if low_limit + size.as_u64() <= first_start {
            return Some(first_start - size.as_u64());
        }

        None
    }

    /// Check if it has access to the fault address.
    fn access_error(error_code: PageFaultErrorCode, flags: VmFlags) -> bool {
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            return !flags.contains(VmFlags::VM_WRITE);
        }

        // read, present
        if error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
            return true;
        }

        // read, not present
        if (flags & VmFlags::VM_ACCESS_FLAGS).is_empty() {
            return true;
        }

        false
    }
}

#[derive(Error, Debug)]
pub(super) enum VmemResizeError {
    #[error("no mapping containing the address {0:?}")]
    NotExist(VirtAddr),
    #[error("invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr {
        range: Range<VirtAddr>,
        addr: VirtAddr,
    },
    #[error("range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<VirtAddr>),
}

#[derive(Error, Debug)]
pub(super) enum VmemProtectError {
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<VirtAddr>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("allocation failed")]
    AllocationFailed,
}
