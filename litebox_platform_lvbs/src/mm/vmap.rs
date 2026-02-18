// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Vmap region allocator for mapping non-contiguous physical page frames to virtually contiguous addresses.
//!
//! This module provides functionality similar to Linux kernel's `vmap()` and `vunmap()`:
//! - Reserves a virtual address region for vmap mappings
//! - Maintains PA↔VA mappings using HashMap for duplicate detection and cleanup

use alloc::boxed::Box;
use hashbrown::HashMap;
use rangemap::RangeSet;
use spin::Once;
use spin::mutex::SpinMutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::mshv::vtl1_mem_layout::PAGE_SIZE;

/// Start of the vmap virtual address region.
/// This address is chosen to be within the 4-level paging canonical address space
/// and not conflict with VTL1's direct-mapped physical memory.
const VMAP_START: u64 = 0x6000_0000_0000;

/// End of the vmap virtual address region.
/// Provides 1 TiB of virtual address space for vmap allocations.
const VMAP_END: u64 = 0x7000_0000_0000;

/// Number of unmapped guard pages appended after each vmap allocation.
const GUARD_PAGES: usize = 1;

/// Information about a single vmap allocation.
#[derive(Clone, Debug)]
struct VmapAllocation {
    /// Physical frames of the mapped pages (in order).
    frames: Box<[PhysFrame<Size4KiB>]>,
}

/// Inner state for the vmap region allocator.
///
/// Uses a bump allocator with a `RangeSet` free list for virtual addresses
/// and HashMap for maintaining bidirectional mappings between physical and virtual addresses.
struct VmapRegionAllocatorInner {
    /// Next available virtual address for allocation (bump allocator).
    next_va: VirtAddr,
    /// Free set of previously allocated and freed VA ranges (auto-coalescing).
    free_set: RangeSet<VirtAddr>,
    /// Map from physical frame to virtual address.
    pa_to_va_map: HashMap<PhysFrame<Size4KiB>, VirtAddr>,
    /// Map from virtual address to physical frame.
    va_to_pa_map: HashMap<VirtAddr, PhysFrame<Size4KiB>>,
    /// Allocation metadata indexed by starting virtual address.
    allocations: HashMap<VirtAddr, VmapAllocation>,
}

impl VmapRegionAllocatorInner {
    /// Creates a new vmap region allocator inner state.
    fn new() -> Self {
        Self {
            next_va: VirtAddr::new(VMAP_START),
            free_set: RangeSet::new(),
            pa_to_va_map: HashMap::new(),
            va_to_pa_map: HashMap::new(),
            allocations: HashMap::new(),
        }
    }

    /// Allocates a contiguous virtual address range for the given number of pages,
    /// plus [`GUARD_PAGES`] unmapped trailing guard pages.
    ///
    /// The guard pages are reserved in the VA space but never mapped, so an
    /// out-of-bounds access past the allocation triggers a page fault.
    ///
    /// First tries to find a suitable range in the free list, then falls back to
    /// bump allocation.
    ///
    /// Returns `Some(VirtAddr)` with the starting virtual address on success,
    /// or `None` if insufficient virtual address space is available.
    fn allocate_va_range(&mut self, num_pages: usize) -> Option<VirtAddr> {
        if num_pages == 0 {
            return None;
        }

        let total_pages = num_pages.checked_add(GUARD_PAGES)?;
        let size = (total_pages as u64).checked_mul(PAGE_SIZE as u64)?;

        // Try to find a suitable range in the free set (first-fit)
        for range in self.free_set.iter() {
            if range.end - range.start >= size {
                let allocated_start = range.start;
                // Remove the allocated portion from the free set
                self.free_set
                    .remove(allocated_start..allocated_start + size);
                return Some(allocated_start);
            }
        }

        // Fall back to bump allocation.
        // `size` already includes GUARD_PAGES, so `end_va` accounts for both
        // the data pages and the trailing guard pages.
        let end_va = self.next_va + size;
        if end_va > VirtAddr::new(VMAP_END) {
            return None;
        }

        let allocated_va = self.next_va;
        self.next_va = end_va;
        Some(allocated_va)
    }

    /// Returns a VA range to the free set for reuse.
    fn free_va_range(&mut self, start: VirtAddr, num_pages: usize) {
        if num_pages == 0 {
            return;
        }
        let total_pages = num_pages + GUARD_PAGES;
        let end = start + (total_pages as u64) * (PAGE_SIZE as u64);
        self.free_set.insert(start..end);
    }
}

/// Checks if a virtual address is within the vmap region.
pub fn is_vmap_address(va: VirtAddr) -> bool {
    (VMAP_START..VMAP_END).contains(&va.as_u64())
}

/// Vmap region allocator that manages virtual address allocation and PA↔VA mappings.
pub struct VmapRegionAllocator {
    inner: SpinMutex<VmapRegionAllocatorInner>,
}

impl VmapRegionAllocator {
    fn new() -> Self {
        Self {
            inner: SpinMutex::new(VmapRegionAllocatorInner::new()),
        }
    }

    /// Atomically allocates VA range, registers mappings, and records allocation.
    ///
    /// This ensures consistency - either the entire operation succeeds or nothing changes.
    ///
    /// Returns the base VA on success, or None if:
    /// - No VA space available
    /// - Any PA is already mapped (duplicate mapping)
    pub fn allocate_va_and_register_map(&self, frames: &[PhysFrame<Size4KiB>]) -> Option<VirtAddr> {
        if frames.is_empty() {
            return None;
        }

        let mut inner = self.inner.lock();

        // Check for duplicate PA mappings before allocating
        for frame in frames {
            if inner.pa_to_va_map.contains_key(frame) {
                return None;
            }
        }

        let base_va = inner.allocate_va_range(frames.len())?;
        let end_va = base_va + (frames.len() as u64) * (PAGE_SIZE as u64);

        for (va, &frame) in (base_va.as_u64()..end_va.as_u64())
            .step_by(PAGE_SIZE)
            .map(VirtAddr::new)
            .zip(frames.iter())
        {
            inner.pa_to_va_map.insert(frame, va);
            inner.va_to_pa_map.insert(va, frame);
        }

        inner.allocations.insert(
            base_va,
            VmapAllocation {
                frames: frames.into(),
            },
        );

        Some(base_va)
    }

    /// Unregisters all mappings for an allocation starting at the given virtual address
    /// and returns its VA range to the free list.
    ///
    /// This is used both for normal `vunmap` teardown and to roll back a failed
    /// page-table mapping after `allocate_va_and_register_map` succeeds.
    ///
    /// Returns the number of pages that were unmapped, or `None` if no allocation was found.
    pub fn unregister_allocation(&self, base_va: VirtAddr) -> Option<usize> {
        let mut inner = self.inner.lock();
        let allocation = inner.allocations.remove(&base_va)?;
        let end_va = base_va + (allocation.frames.len() as u64) * (PAGE_SIZE as u64);

        for (va, frame) in (base_va.as_u64()..end_va.as_u64())
            .step_by(PAGE_SIZE)
            .map(VirtAddr::new)
            .zip(allocation.frames.iter())
        {
            inner.pa_to_va_map.remove(frame);
            inner.va_to_pa_map.remove(&va);
        }

        inner.free_va_range(base_va, allocation.frames.len());

        Some(allocation.frames.len())
    }
}

/// Returns a reference to the global vmap region allocator.
pub fn vmap_allocator() -> &'static VmapRegionAllocator {
    static ALLOCATOR: Once<VmapRegionAllocator> = Once::new();
    ALLOCATOR.call_once(VmapRegionAllocator::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::PhysAddr;

    #[test]
    fn test_is_vmap_address() {
        assert!(is_vmap_address(VirtAddr::new(VMAP_START)));
        assert!(is_vmap_address(VirtAddr::new(VMAP_START + 0x1000)));
        assert!(is_vmap_address(VirtAddr::new(VMAP_END - 1)));
        assert!(!is_vmap_address(VirtAddr::new(VMAP_START - 1)));
        assert!(!is_vmap_address(VirtAddr::new(VMAP_END)));
    }

    #[test]
    fn test_allocate_va_range() {
        let mut allocator = VmapRegionAllocatorInner::new();

        // Allocate first range (1 data page + 1 guard page = 2 pages consumed)
        let va1 = allocator.allocate_va_range(1);
        assert!(va1.is_some());
        assert_eq!(va1.unwrap().as_u64(), VMAP_START);

        // Second allocation starts after data + guard pages
        let va2 = allocator.allocate_va_range(2);
        assert!(va2.is_some());
        assert_eq!(
            va2.unwrap().as_u64(),
            VMAP_START + (1 + GUARD_PAGES as u64) * PAGE_SIZE as u64
        );

        // Zero pages should return None
        let va3 = allocator.allocate_va_range(0);
        assert!(va3.is_none());
    }

    #[test]
    fn test_va_range_reuse() {
        let mut allocator = VmapRegionAllocatorInner::new();

        // Allocate and free a 2-page range (consumes 2 + guard pages)
        let va1 = allocator.allocate_va_range(2).unwrap();
        allocator.free_va_range(va1, 2);

        // Next allocation of same size should reuse the freed range
        let va2 = allocator.allocate_va_range(2).unwrap();
        assert_eq!(va1, va2);

        // Free the 3-page slot (2 data + 1 guard), then allocate 1 page (needs 1+1=2 pages).
        // The remaining 1 page in the 3-page slot is not enough for another 1+1 allocation.
        allocator.free_va_range(va2, 2);
        let va3 = allocator.allocate_va_range(1).unwrap();
        assert_eq!(va3, va1);
    }

    #[test]
    fn test_allocate_va_and_register_map() {
        let allocator = VmapRegionAllocator::new();

        let frames = alloc::vec![
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x1000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x3000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x5000)),
        ];

        // Allocate and register
        let base_va = allocator.allocate_va_and_register_map(&frames);
        assert!(base_va.is_some());
        let base_va = base_va.unwrap();
        assert_eq!(base_va.as_u64(), VMAP_START);

        // Duplicate PA should fail (proves mappings were recorded)
        let duplicate = allocator
            .allocate_va_and_register_map(&[PhysFrame::containing_address(PhysAddr::new(0x1000))]);
        assert!(duplicate.is_none());

        // Empty input should return None
        assert!(allocator.allocate_va_and_register_map(&[]).is_none());
    }

    #[test]
    fn test_rollback_via_unregister() {
        let allocator = VmapRegionAllocator::new();

        let frames = alloc::vec![
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x1000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x2000)),
        ];

        let base_va = allocator.allocate_va_and_register_map(&frames).unwrap();

        // Simulate rollback by unregistering immediately
        let count = allocator.unregister_allocation(base_va);
        assert_eq!(count, Some(2));

        // Mappings should be gone — re-registering the same PAs must succeed
        let new_va = allocator.allocate_va_and_register_map(&frames).unwrap();
        assert_eq!(new_va, base_va);
    }

    #[test]
    fn test_unregister_allocation() {
        let allocator = VmapRegionAllocator::new();

        let frames = alloc::vec![
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x1000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x3000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x5000)),
        ];

        let base_va = allocator.allocate_va_and_register_map(&frames).unwrap();

        // Unregister
        let num_pages = allocator.unregister_allocation(base_va);
        assert_eq!(num_pages, Some(3));

        // Mappings should be gone — re-registering the same PAs must succeed
        // and reuse the freed VA range
        let new_va = allocator.allocate_va_and_register_map(&frames).unwrap();
        assert_eq!(new_va, base_va);

        // Unregistering an unknown VA returns None
        assert_eq!(
            allocator.unregister_allocation(VirtAddr::new(VMAP_END - 0x1000)),
            None
        );
    }

    #[test]
    fn test_guard_page_gap() {
        let allocator = VmapRegionAllocator::new();

        let frames_a = alloc::vec![PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(
            0x1000
        )),];
        let frames_b = alloc::vec![PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(
            0x2000
        )),];

        let va_a = allocator.allocate_va_and_register_map(&frames_a).unwrap();
        let va_b = allocator.allocate_va_and_register_map(&frames_b).unwrap();

        // Allocations should be separated by at least GUARD_PAGES unmapped pages
        let gap_pages = (va_b.as_u64() - va_a.as_u64()) / PAGE_SIZE as u64;
        assert!(
            gap_pages >= (1 + GUARD_PAGES as u64),
            "expected at least {} pages between allocations, got {}",
            1 + GUARD_PAGES,
            gap_pages
        );
    }
}
