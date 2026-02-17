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
pub const VMAP_START: u64 = 0x6000_0000_0000;

/// End of the vmap virtual address region.
/// Provides 1 TiB of virtual address space for vmap allocations.
pub const VMAP_END: u64 = 0x7000_0000_0000;

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
    pub fn allocate_va_range(&mut self, num_pages: usize) -> Option<VirtAddr> {
        if num_pages == 0 {
            return None;
        }

        let total_pages = num_pages.checked_add(GUARD_PAGES)?;
        let size = (total_pages as u64).checked_mul(PAGE_SIZE as u64)?;

        // Try to find a suitable range in the free set (first-fit)
        for range in self.free_set.iter() {
            let range_size = range.end - range.start;
            if range_size >= size {
                let allocated_start = range.start;
                // Remove the allocated portion from the free set
                self.free_set
                    .remove(allocated_start..allocated_start + size);
                return Some(allocated_start);
            }
        }

        // Fall back to bump allocation
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

    /// Atomically allocates VA range, registers mappings, and records allocation.
    ///
    /// This ensures consistency - either the entire operation succeeds or nothing changes.
    ///
    /// Returns the allocated base VA on success, or None if:
    /// - No VA space available
    /// - Any PA is already mapped (duplicate mapping)
    pub fn allocate_and_register(&mut self, frames: &[PhysFrame<Size4KiB>]) -> Option<VirtAddr> {
        if frames.is_empty() {
            return None;
        }

        // Check for duplicate PA mappings before allocating
        for frame in frames {
            if self.pa_to_va_map.contains_key(frame) {
                return None; // PA already mapped
            }
        }

        let base_va = self.allocate_va_range(frames.len())?;

        for (i, &frame) in frames.iter().enumerate() {
            let va = VirtAddr::new(base_va.as_u64() + (i as u64) * (PAGE_SIZE as u64));
            self.pa_to_va_map.insert(frame, va);
            self.va_to_pa_map.insert(va, frame);
        }

        self.allocations.insert(
            base_va,
            VmapAllocation {
                frames: frames.into(),
            },
        );

        Some(base_va)
    }

    /// Rolls back a failed allocation by removing mappings and freeing VA range.
    ///
    /// Call this if page table mapping fails after `allocate_and_register` succeeds.
    pub fn rollback_allocation(&mut self, base_va: VirtAddr) {
        if let Some(allocation) = self.allocations.remove(&base_va) {
            for (i, frame) in allocation.frames.iter().enumerate() {
                let va = VirtAddr::new(base_va.as_u64() + (i as u64) * (PAGE_SIZE as u64));
                self.pa_to_va_map.remove(frame);
                self.va_to_pa_map.remove(&va);
            }
            self.free_va_range(base_va, allocation.frames.len());
        }
    }

    /// Unregisters all mappings for an allocation starting at the given virtual address.
    ///
    /// Returns the number of pages that were unmapped, or `None` if no allocation was found.
    pub fn unregister_allocation(&mut self, va_start: VirtAddr) -> Option<usize> {
        let allocation = self.allocations.remove(&va_start)?;

        for (i, frame) in allocation.frames.iter().enumerate() {
            let va = VirtAddr::new(va_start.as_u64() + (i as u64) * (PAGE_SIZE as u64));
            self.pa_to_va_map.remove(frame);
            self.va_to_pa_map.remove(&va);
        }

        self.free_va_range(va_start, allocation.frames.len());

        Some(allocation.frames.len())
    }

    /// Checks if a virtual address is within the vmap region.
    fn is_vmap_address(va: VirtAddr) -> bool {
        (VMAP_START..VMAP_END).contains(&va.as_u64())
    }
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

    /// Atomically allocates VA range and registers all mappings.
    ///
    /// Returns the base VA on success, or None if allocation fails or any PA is already mapped.
    pub fn allocate_and_register(&self, frames: &[PhysFrame<Size4KiB>]) -> Option<VirtAddr> {
        self.inner.lock().allocate_and_register(frames)
    }

    /// Rolls back a failed allocation by removing mappings and freeing VA range.
    pub fn rollback_allocation(&self, base_va: VirtAddr) {
        self.inner.lock().rollback_allocation(base_va);
    }

    /// Unregisters all mappings for an allocation starting at the given virtual address.
    pub fn unregister_allocation(&self, va_start: VirtAddr) -> Option<usize> {
        self.inner.lock().unregister_allocation(va_start)
    }

    /// Checks if a virtual address is within the vmap region.
    pub fn is_vmap_address(va: VirtAddr) -> bool {
        VmapRegionAllocatorInner::is_vmap_address(va)
    }
}

/// Returns a reference to the global vmap region allocator.
pub fn vmap_allocator() -> &'static VmapRegionAllocator {
    static ALLOCATOR: Once<VmapRegionAllocator> = Once::new();
    ALLOCATOR.call_once(VmapRegionAllocator::new)
}

/// Checks if a virtual address is within the vmap region.
pub fn is_vmap_address(va: VirtAddr) -> bool {
    VmapRegionAllocator::is_vmap_address(va)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::PhysAddr;

    #[test]
    fn test_is_vmap_address() {
        assert!(VmapRegionAllocatorInner::is_vmap_address(VirtAddr::new(
            VMAP_START
        )));
        assert!(VmapRegionAllocatorInner::is_vmap_address(VirtAddr::new(
            VMAP_START + 0x1000
        )));
        assert!(VmapRegionAllocatorInner::is_vmap_address(VirtAddr::new(
            VMAP_END - 1
        )));
        assert!(!VmapRegionAllocatorInner::is_vmap_address(VirtAddr::new(
            VMAP_START - 1
        )));
        assert!(!VmapRegionAllocatorInner::is_vmap_address(VirtAddr::new(
            VMAP_END
        )));
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
    fn test_allocate_and_register() {
        let mut allocator = VmapRegionAllocatorInner::new();

        let frames = alloc::vec![
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x1000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x3000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x5000)),
        ];

        // Allocate and register
        let base_va = allocator.allocate_and_register(&frames);
        assert!(base_va.is_some());
        let base_va = base_va.unwrap();
        assert_eq!(base_va.as_u64(), VMAP_START);

        // Duplicate PA should fail (proves mappings were recorded)
        let duplicate = allocator
            .allocate_and_register(&[PhysFrame::containing_address(PhysAddr::new(0x1000))]);
        assert!(duplicate.is_none());

        // Empty input should return None
        assert!(allocator.allocate_and_register(&[]).is_none());
    }

    #[test]
    fn test_rollback_allocation() {
        let mut allocator = VmapRegionAllocatorInner::new();

        let frames = alloc::vec![
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x1000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x2000)),
        ];

        let base_va = allocator.allocate_and_register(&frames).unwrap();

        // Rollback
        allocator.rollback_allocation(base_va);

        // Mappings should be gone — re-registering the same PAs must succeed
        let new_va = allocator.allocate_and_register(&frames).unwrap();
        assert_eq!(new_va, base_va);
    }

    #[test]
    fn test_unregister_allocation() {
        let mut allocator = VmapRegionAllocatorInner::new();

        let frames = alloc::vec![
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x1000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x3000)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(0x5000)),
        ];

        let base_va = allocator.allocate_and_register(&frames).unwrap();

        // Unregister
        let num_pages = allocator.unregister_allocation(base_va);
        assert_eq!(num_pages, Some(3));

        // Mappings should be gone — re-registering the same PAs must succeed
        // and reuse the freed VA range
        let new_va = allocator.allocate_and_register(&frames).unwrap();
        assert_eq!(new_va, base_va);

        // Unregistering an unknown VA returns None
        assert_eq!(
            allocator.unregister_allocation(VirtAddr::new(VMAP_END - 0x1000)),
            None
        );
    }

    #[test]
    fn test_guard_page_gap() {
        let mut allocator = VmapRegionAllocatorInner::new();

        let frames_a = alloc::vec![PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(
            0x1000
        )),];
        let frames_b = alloc::vec![PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(
            0x2000
        )),];

        let va_a = allocator.allocate_and_register(&frames_a).unwrap();
        let va_b = allocator.allocate_and_register(&frames_b).unwrap();

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
