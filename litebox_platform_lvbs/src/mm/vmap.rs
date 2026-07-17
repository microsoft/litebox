// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Vmap region allocator for mapping non-contiguous physical page frames to virtually contiguous addresses.
//!
//! This module provides functionality similar to Linux kernel's `vmap()` and `vunmap()`:
//! - Reserves a virtual address region for vmap mappings
//! - Tracks allocations by base virtual address for cleanup
//!
//! The same physical frame may be mapped at multiple virtual addresses simultaneously, so no
//! PA→VA uniqueness is enforced: each mapping is a private, transient window.

use litebox::utils::TruncateExt;
use rangemap::RangeSet;
use spin::Once;
use spin::mutex::SpinMutex;
use x86_64::VirtAddr;

use crate::mshv::vtl1_mem_layout::PAGE_SIZE;

/// Errors of `VmapRegionAllocator`
#[derive(Debug, thiserror::Error)]
pub enum VmapAllocError {
    /// The input frame slice was empty.
    #[error("empty frame slice")]
    EmptyInput,
    /// The vmap virtual address region has no contiguous range large enough.
    #[error("vmap virtual address space exhausted")]
    VaSpaceExhausted,
}

use crate::{VMAP_END, VMAP_START};

/// Virtual page numbers corresponding to [`crate::VMAP_START`] and [`crate::VMAP_END`].
const VMAP_START_VPN: usize = VMAP_START / PAGE_SIZE;
const VMAP_END_VPN: usize = VMAP_END / PAGE_SIZE;

/// Number of unmapped guard pages appended after each vmap allocation.
const GUARD_PAGES: usize = 1;

/// Inner state for the vmap region allocator.
///
/// Uses a bump allocator with a `RangeSet` free list for virtual page numbers.
///
/// The same physical frame may be mapped at multiple virtual addresses simultaneously: each
/// mapping is a private, transient window (used only to copy data in/out). The allocator only
/// tracks free VA ranges; the caller owns the page count for each live mapping (it is recoverable
/// from the mapping info) and passes it back on teardown.
struct VmapRegionAllocatorInner {
    /// Next available virtual page number for allocation (bump allocator).
    next_vpn: usize,
    /// Free set of previously allocated and freed VPN ranges (auto-coalescing).
    free_set: RangeSet<usize>,
}

impl VmapRegionAllocatorInner {
    /// Creates a new vmap region allocator inner state.
    fn new() -> Self {
        Self {
            next_vpn: VMAP_START_VPN,
            free_set: RangeSet::new(),
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
            <u64 as litebox::utils::TruncateExt<usize>>::trunc(start.as_u64()) / PAGE_SIZE;
        let total_pages = num_pages + GUARD_PAGES;
        self.free_set.insert(start_vpn..start_vpn + total_pages);
    }
}

/// Checks if a virtual address is within the vmap region.
pub fn is_vmap_address(va: VirtAddr) -> bool {
    (VMAP_START..VMAP_END).contains(&va.as_u64().trunc())
}

/// Vmap region allocator that manages virtual address allocation for transient physical mappings.
pub struct VmapRegionAllocator {
    inner: SpinMutex<VmapRegionAllocatorInner>,
}

impl VmapRegionAllocator {
    fn new() -> Self {
        Self {
            inner: SpinMutex::new(VmapRegionAllocatorInner::new()),
        }
    }

    /// Allocates a fresh VA range covering `num_pages` mapped pages (plus trailing guard pages).
    ///
    /// # Errors
    ///
    /// - [`VmapAllocError::EmptyInput`] — `num_pages` is zero.
    /// - [`VmapAllocError::VaSpaceExhausted`] — no contiguous VA range is available.
    pub fn allocate_va(&self, num_pages: usize) -> Result<VirtAddr, VmapAllocError> {
        if num_pages == 0 {
            return Err(VmapAllocError::EmptyInput);
        }

        self.inner
            .lock()
            .allocate_va_range(num_pages)
            .ok_or(VmapAllocError::VaSpaceExhausted)
    }

    /// Returns a `num_pages`-page VA range starting at `base_va` to the free list.
    ///
    /// This is used both for normal `vunmap` teardown and to roll back a failed page-table mapping
    /// after [`Self::allocate_va`] succeeds. `base_va`/`num_pages` must match a value pair from a
    /// prior `allocate_va`; mapping-info move semantics guarantee each range is freed at most once.
    pub fn free_va(&self, base_va: VirtAddr, num_pages: usize) {
        self.inner.lock().free_va_range(base_va, num_pages);
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
    fn test_allocate_va() {
        let allocator = VmapRegionAllocator::new();

        // Allocate a 3-page range
        let base_va = allocator.allocate_va(3);
        assert!(base_va.is_ok());
        assert_eq!(base_va.unwrap().as_u64(), VMAP_START as u64);

        // Zero pages should fail with EmptyInput
        assert!(matches!(
            allocator.allocate_va(0),
            Err(VmapAllocError::EmptyInput)
        ));
    }

    #[test]
    fn test_rollback_via_free() {
        let allocator = VmapRegionAllocator::new();

        let base_va = allocator.allocate_va(2).unwrap();

        // Simulate rollback by freeing immediately
        allocator.free_va(base_va, 2);

        // The VA range should be gone — re-allocating must succeed and reuse it
        let new_va = allocator.allocate_va(2).unwrap();
        assert_eq!(new_va, base_va);
    }

    #[test]
    fn test_free_va() {
        let allocator = VmapRegionAllocator::new();

        let base_va = allocator.allocate_va(3).unwrap();

        // Free, then re-allocating the same size must reuse the freed VA range
        allocator.free_va(base_va, 3);
        let new_va = allocator.allocate_va(3).unwrap();
        assert_eq!(new_va, base_va);
    }

    #[test]
    fn test_guard_page_gap() {
        let allocator = VmapRegionAllocator::new();

        let va_a = allocator.allocate_va(1).unwrap();
        let va_b = allocator.allocate_va(1).unwrap();

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
