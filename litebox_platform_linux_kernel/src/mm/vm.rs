use core::ops::Range;

use alloc::vec::Vec;
use rangemap::RangeMap;
use thiserror::Error;

use crate::arch::{PAGE_SIZE, Page, PageFaultErrorCode, PageRange, PageTableFlags, VirtAddr};

use super::pgtable::{PageFaultError, PageTableImpl, PageTableWalkError};

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

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
}

#[allow(dead_code)]
/// Virtual Address Space Manager
pub struct Vmem<PT: PageTableImpl> {
    /// Virtual memory areas. The ranges need to be page aligned.
    vmas: RangeMap<VirtAddr, VmArea>,
    pt: PT,
}

#[allow(dead_code)]
impl<PT: PageTableImpl> Vmem<PT> {
    const TASK_ADDR_MIN: VirtAddr = VirtAddr::new(PAGE_SIZE as u64);
    const TASK_ADDR_MAX: VirtAddr = VirtAddr::new(0x7FFF_FFFF_F000); // (1 << 47) - PAGE_SIZE;
    const STACK_GUARD_GAP: u64 = 256u64 << 12;

    pub const fn new(pt: PT) -> Self {
        Self {
            vmas: RangeMap::new(),
            pt,
        }
    }

    pub fn iter(&self) -> rangemap::map::Iter<'_, VirtAddr, VmArea> {
        self.vmas.iter()
    }

    pub fn get_pgtable(&self) -> &PT {
        &self.pt
    }

    /// Remove a range from its virtual address space, if all or any of it was present.
    ///
    /// If the range to be removed _partially_ overlaps any ranges, then those ranges will
    /// be contracted to no longer cover the removed range.
    ///
    /// # Panics
    ///
    /// Panics if range `start >= end`.
    pub fn remove_mapping(&mut self, range: PageRange, flush: bool) {
        let (start, end) = (range.start.start_address(), range.end.start_address());
        self.vmas.remove(start..end);
        unsafe {
            self.pt
                .unmap_pages(start, (end - start) as usize, true, flush)
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
    /// Panics if range `start >= end`.
    /// Panics if the range is beyond the task address space [[`Self::TASK_ADDR_MIN`], [`Self::TASK_ADDR_MAX`]]).
    pub fn insert_mapping(&mut self, range: PageRange, flags: VmFlags) {
        let (start, end) = (range.start.start_address(), range.end.start_address());
        assert!(start >= Self::TASK_ADDR_MIN);
        assert!(end <= Self::TASK_ADDR_MAX);
        self.vmas.insert(start..end, VmArea { flags })
    }

    /// Resize a range in the virtual address space.
    /// Split the range and unmap the unused part if it is larger than the new size.
    /// Enlarge the range if it is smaller than the new size and will not overlap with
    /// any existing ranges.
    ///
    /// See https://elixir.bootlin.com/linux/v5.19.17/source/mm/mremap.c#L886 for reference.
    ///
    /// # Panics
    ///
    /// Panics if `new_size` is not a multiple of `PAGE_SIZE` or is zero.
    pub fn resize_mapping(
        &mut self,
        range: PageRange,
        new_size: usize,
        flush: bool,
    ) -> Result<(), VmemResizeError> {
        assert!(new_size != 0);
        assert!(new_size % PAGE_SIZE == 0);

        let range = range.start.start_address()..range.end.start_address();
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range.start + new_size as u64;
        match new_end.cmp(&range.end) {
            core::cmp::Ordering::Equal => {
                // no change
                return Ok(());
            }
            core::cmp::Ordering::Less => {
                // shrink
                self.remove_mapping(
                    Page::range(
                        Page::from_start_address(new_end).unwrap(),
                        Page::from_start_address(range.end).unwrap(),
                    ),
                    flush,
                );
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
    /// Panics if `new_size` is not a multiple of `PAGE_SIZE` or is zero.
    /// Panics if `new_size` is smaller than the current size of the range.
    /// Panics if range `start >= end`.
    /// Panics if range is not within exact one mapping.
    pub fn move_mappings(
        &mut self,
        range: PageRange,
        new_size: usize,
        suggested_addr: VirtAddr,
        flush: bool,
    ) -> Option<VirtAddr> {
        assert!(new_size != 0);
        assert!(new_size % PAGE_SIZE == 0);
        let (start, end) = (range.start.start_address(), range.end.start_address());
        assert!(new_size >= (end - start) as usize);

        let (target_range, vma) = self
            .vmas
            .get_key_value(&start)
            .expect("VMEM: range not found");
        assert!(target_range.contains(&(end - 1)));

        let new_addr = self.get_unmmaped_area(suggested_addr, new_size)?;
        self.vmas.insert(new_addr..new_addr + new_size as u64, *vma);
        unsafe {
            self.pt
                .remap_pages(start, new_addr, (end - start) as usize, flush)
                .ok()
        };
        self.vmas.remove(start..end);
        Some(new_addr)
    }

    /// Change the permissions ([`VmFlags::VM_ACCESS_FLAG`]) of a range in the virtual address space.
    ///
    /// See https://elixir.bootlin.com/linux/v5.19.17/source/mm/mprotect.c#L617 for reference.
    pub fn protect_mapping(
        &mut self,
        range: PageRange,
        flags: VmFlags,
        flush: bool,
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
            unsafe {
                // `intersection` is page aligned.
                match self.pt.mprotect_pages(
                    intersection.start,
                    (intersection.end - intersection.start) as usize,
                    new_flags.into(),
                    flush,
                ) {
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
            };
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

    pub fn handle_page_fault(
        &mut self,
        page: Page,
        error_code: PageFaultErrorCode,
        flush: bool,
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
                    // enforce gap between stack and other preceding non-stack mappings
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    (prev_vma.flags.contains(VmFlags::VM_GROWSDOWN) && !(prev_vma.flags & VmFlags::VM_ACCESS_FLAGS).is_empty())
                    // Or the previous mapping is far enough from the fault address
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
                .handle_page_fault(page, vma.flags.into(), error_code, flush)
        }
    }

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    fn get_unmmaped_area(&self, suggested_addr: VirtAddr, size: usize) -> Option<VirtAddr> {
        debug_assert!(suggested_addr.is_aligned(PAGE_SIZE as u64));
        debug_assert!(size % PAGE_SIZE == 0);

        if size > Self::TASK_ADDR_MAX.as_u64() as usize {
            return None;
        }
        if !suggested_addr.is_null() {
            if (Self::TASK_ADDR_MAX - size as u64) < suggested_addr {
                return None;
            }
            if !self
                .vmas
                .overlaps(&(suggested_addr..(suggested_addr + size as u64)))
            {
                return Some(suggested_addr);
            }
        }

        // top down
        // 1. check [last_end, TASK_SIZE_MAX)
        let (low_limit, high_limit) = (Self::TASK_ADDR_MIN, Self::TASK_ADDR_MAX - size as u64);
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
            if !self.vmas.overlaps(&(r.end..r.end + size as u64)) {
                return Some(r.end);
            }
        }

        // 3. check [low_limit, first_start)
        let first_start = self
            .vmas
            .first_range_value()
            .map(|r| r.0.start)
            .unwrap_or(high_limit);
        if low_limit + size as u64 <= first_start {
            return Some(first_start - size as u64);
        }

        None
    }

    /// Check if it has access to the fault address.
    fn access_error(error_code: PageFaultErrorCode, flags: VmFlags) -> bool {
        if error_code.intersects(PageFaultErrorCode::PROTECTION_KEY | PageFaultErrorCode::SGX) {
            return true;
        }

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
pub enum VmemResizeError {
    #[error("No mapping containing the address {0:?}")]
    NotExist(VirtAddr),
    #[error("Invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr {
        range: Range<VirtAddr>,
        addr: VirtAddr,
    },
    #[error("Range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<VirtAddr>),
}

#[derive(Error, Debug)]
pub enum VmemProtectError {
    #[error("The range {0:?} has no mapping memory")]
    InvalidRange(Range<VirtAddr>),
    #[error("Failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("Allocation failed")]
    AllocationFailed,
}
