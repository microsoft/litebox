// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Vmap region allocator for mapping non-contiguous physical page frames to virtually contiguous addresses.
//!
//! This module provides functionality similar to Linux kernel's `vmap()` and `vunmap()`:
//! - Reserves a virtual address region for vmap mappings
//! - Maintains PA→VA mappings using HashMap for duplicate detection and cleanup

use alloc::boxed::Box;
use hashbrown::HashMap;
use litebox::utils::TruncateExt;
use rangemap::RangeSet;
use spin::Once;
use spin::mutex::SpinMutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::mshv::vtl1_mem_layout::PAGE_SIZE;

/// Errors of `VmapRegionAllocator`
#[derive(Debug, thiserror::Error)]
pub enum VmapAllocError {
    /// The input frame slice was empty.
    #[error("empty frame slice")]
    EmptyInput,
    /// At least one physical frame is already mapped.
    #[error("physical frame already mapped")]
    DuplicateMapping,
    /// The vmap virtual address region has no contiguous range large enough.
    #[error("vmap virtual address space exhausted")]
    VaSpaceExhausted,
}

/// Start of the vmap virtual address region.
/// This address is chosen to be within the 4-level paging canonical address space
/// and not conflict with VTL1's direct-mapped physical memory.
pub(crate) const VMAP_START: usize = 0x6000_0000_0000;

/// End of the vmap virtual address region.
/// Provides 1 TiB of virtual address space for vmap allocations.
const VMAP_END: usize = 0x6FFF_FFFF_F000;

/// Virtual page numbers corresponding to `VMAP_START` and `VMAP_END`.
const VMAP_START_VPN: usize = VMAP_START / PAGE_SIZE;
const VMAP_END_VPN: usize = VMAP_END / PAGE_SIZE;

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
/// Uses a bump allocator with a `RangeSet` free list for virtual page numbers
/// and HashMap for maintaining mappings between physical and virtual addresses.
struct VmapRegionAllocatorInner {
    /// Next available virtual page number for allocation (bump allocator).
    next_vpn: usize,
    /// Free set of previously allocated and freed VPN ranges (auto-coalescing).
    free_set: RangeSet<usize>,
    /// Map from physical frame to virtual address.
    pa_to_va_map: HashMap<PhysFrame<Size4KiB>, VirtAddr>,
    /// Allocation metadata indexed by starting virtual address.
    allocations: HashMap<VirtAddr, VmapAllocation>,
}

impl VmapRegionAllocatorInner {
    /// Creates a new vmap region allocator inner state.
    fn new() -> Self {
        Self {
            next_vpn: VMAP_START_VPN,
            free_set: RangeSet::new(),
            pa_to_va_map: HashMap::new(),
            allocations: HashMap::new(),
        }
    }

    /// Converts a virtual page number to a `VirtAddr`.
    fn vpn_to_va(vpn: usize) -> VirtAddr {
        VirtAddr::new((vpn * PAGE_SIZE) as u64)
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

        // Try to find a suitable range in the free set (first-fit)
        for range in self.free_set.iter() {
            if range.end - range.start >= total_pages {
                let start_vpn = range.start;
                self.free_set.remove(start_vpn..start_vpn + total_pages);
                return Some(Self::vpn_to_va(start_vpn));
            }
        }

        // Fall back to bump allocation.
        let end_vpn = self.next_vpn.checked_add(total_pages)?;
        if end_vpn > VMAP_END_VPN {
            return None;
        }

        let allocated_vpn = self.next_vpn;
        self.next_vpn = end_vpn;
        Some(Self::vpn_to_va(allocated_vpn))
    }

    /// Returns a VA range to the free set for reuse.
    fn free_va_range(&mut self, start: VirtAddr, num_pages: usize) {
        if num_pages == 0 {
            return;
        }
        let start_vpn =
            <u64 as litebox::utils::TruncateExt<usize>>::truncate(start.as_u64()) / PAGE_SIZE;
        let total_pages = num_pages + GUARD_PAGES;
        self.free_set.insert(start_vpn..start_vpn + total_pages);
    }
}

/// Checks if a virtual address is within the vmap region.
pub fn is_vmap_address(va: VirtAddr) -> bool {
    (VMAP_START..VMAP_END).contains(&va.as_u64().truncate())
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
    /// This ensures consistency: either the entire operation succeeds or nothing changes.
    ///
    /// # Errors
    ///
    /// - [`VmapAllocError::EmptyInput`] — `frames` is empty.
    /// - [`VmapAllocError::DuplicateMapping`] — a physical frame is already mapped.
    /// - [`VmapAllocError::VaSpaceExhausted`] — no contiguous VA range is available.
    pub fn allocate_va_and_register_map(
        &self,
        frames: &[PhysFrame<Size4KiB>],
    ) -> Result<VirtAddr, VmapAllocError> {
        if frames.is_empty() {
            return Err(VmapAllocError::EmptyInput);
        }

        let mut inner = self.inner.lock();

        // Check for duplicate PA mappings before allocating
        for frame in frames {
            if inner.pa_to_va_map.contains_key(frame) {
                return Err(VmapAllocError::DuplicateMapping);
            }
        }

        let base_va = inner
            .allocate_va_range(frames.len())
            .ok_or(VmapAllocError::VaSpaceExhausted)?;
        let end_va = base_va + (frames.len() as u64) * (PAGE_SIZE as u64);

        for (va, &frame) in (base_va.as_u64()..end_va.as_u64())
            .step_by(PAGE_SIZE)
            .map(VirtAddr::new)
            .zip(frames.iter())
        {
            inner.pa_to_va_map.insert(frame, va);
        }

        inner.allocations.insert(
            base_va,
            VmapAllocation {
                frames: frames.into(),
            },
        );

        Ok(base_va)
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
        for frame in &allocation.frames {
            inner.pa_to_va_map.remove(frame);
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
    fn test_allocate_va_range() {
        let mut allocator = VmapRegionAllocatorInner::new();

        // Allocate first range (1 data page + 1 guard page = 2 pages consumed)
        let va1 = allocator.allocate_va_range(1);
        assert!(va1.is_some());
        assert_eq!(va1.unwrap().as_u64(), VMAP_START as u64);

        // Second allocation starts after data + guard pages
        let va2 = allocator.allocate_va_range(2);
        assert!(va2.is_some());
        assert_eq!(
            va2.unwrap().as_u64(),
            VMAP_START as u64 + (1 + GUARD_PAGES as u64) * PAGE_SIZE as u64
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
        assert!(base_va.is_ok());
        let base_va = base_va.unwrap();
        assert_eq!(base_va.as_u64(), VMAP_START as u64);

        // Duplicate PA should fail with DuplicateMapping
        let duplicate = allocator
            .allocate_va_and_register_map(&[PhysFrame::containing_address(PhysAddr::new(0x1000))]);
        assert!(matches!(duplicate, Err(VmapAllocError::DuplicateMapping)));

        // Empty input should fail with EmptyInput
        assert!(matches!(
            allocator.allocate_va_and_register_map(&[]),
            Err(VmapAllocError::EmptyInput)
        ));
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
            allocator.unregister_allocation(VirtAddr::new(VMAP_END as u64 - 0x1000)),
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
