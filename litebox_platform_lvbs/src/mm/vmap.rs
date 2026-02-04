// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Vmap region allocator for mapping non-contiguous physical pages to virtually contiguous addresses.
//!
//! This module provides functionality similar to Linux kernel's `vmap()` and `vunmap()`:
//! - Reserves a virtual address region for vmap mappings
//! - Maintains PA↔VA mappings using HashMap for efficient lookups
//! - Supports `pa_to_va` and `va_to_pa` operations within the vmap region

use alloc::vec::Vec;
use hashbrown::HashMap;
use spin::mutex::SpinMutex;
use x86_64::{PhysAddr, VirtAddr};

use super::MemoryProvider;
use crate::mshv::vtl1_mem_layout::PAGE_SIZE;

/// Start of the vmap virtual address region.
/// This address is chosen to be within the 4-level paging canonical address space
/// and not conflict with VTL1's direct-mapped physical memory.
pub const VMAP_START: u64 = 0x6000_0000_0000;

/// End of the vmap virtual address region.
/// Provides 1 TiB of virtual address space for vmap allocations.
pub const VMAP_END: u64 = 0x7000_0000_0000;

/// Size of the vmap region in bytes.
pub const VMAP_SIZE: u64 = VMAP_END - VMAP_START;

/// Information about a single vmap allocation.
#[derive(Clone, Debug)]
struct VmapAllocation {
    /// Number of pages in the allocation.
    num_pages: usize,
    /// Physical addresses of the mapped pages (in order).
    phys_addrs: Vec<PhysAddr>,
}

/// A freed VA range available for reuse.
#[derive(Clone, Debug)]
struct FreeRange {
    /// Starting virtual address.
    start: VirtAddr,
    /// Number of pages in this free range.
    num_pages: usize,
}

/// Vmap region allocator that manages virtual address allocation and PA↔VA mappings.
///
/// This allocator uses a bump allocator with a free list for virtual addresses and HashMap
/// for maintaining bidirectional mappings between physical and virtual addresses.
pub struct VmapRegionAllocator {
    /// Next available virtual address for allocation (bump allocator).
    next_va: VirtAddr,
    /// Free list of previously allocated and freed VA ranges.
    free_list: Vec<FreeRange>,
    /// Map from physical address to virtual address.
    pa_to_va_map: HashMap<u64, u64>,
    /// Map from virtual address to physical address.
    va_to_pa_map: HashMap<u64, u64>,
    /// Allocation metadata indexed by starting virtual address.
    allocations: HashMap<u64, VmapAllocation>,
}

impl VmapRegionAllocator {
    /// Creates a new vmap region allocator.
    pub fn new() -> Self {
        Self {
            next_va: VirtAddr::new_truncate(VMAP_START),
            free_list: Vec::new(),
            pa_to_va_map: HashMap::new(),
            va_to_pa_map: HashMap::new(),
            allocations: HashMap::new(),
        }
    }

    /// Allocates a contiguous virtual address range for the given number of pages.
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

        // First, try to find a suitable range in the free list (first-fit)
        if let Some(idx) = self.free_list.iter().position(|r| r.num_pages >= num_pages) {
            let range = self.free_list.remove(idx);
            if range.num_pages > num_pages {
                // Split: put remainder back in free list
                let remainder_start = VirtAddr::new_truncate(
                    range.start.as_u64() + (num_pages as u64) * (PAGE_SIZE as u64),
                );
                self.free_list.push(FreeRange {
                    start: remainder_start,
                    num_pages: range.num_pages - num_pages,
                });
            }
            return Some(range.start);
        }

        // Fall back to bump allocation
        let size = (num_pages as u64).checked_mul(PAGE_SIZE as u64)?;
        let end_va = self.next_va.as_u64().checked_add(size)?;

        if end_va > VMAP_END {
            return None;
        }

        let allocated_va = self.next_va;
        self.next_va = VirtAddr::new_truncate(end_va);
        Some(allocated_va)
    }

    /// Returns a VA range to the free list for reuse.
    fn free_va_range(&mut self, start: VirtAddr, num_pages: usize) {
        if num_pages == 0 {
            return;
        }
        // Simple approach: just add to free list
        // A more sophisticated implementation could coalesce adjacent ranges
        self.free_list.push(FreeRange { start, num_pages });
    }

    /// Atomically allocates VA range, registers mappings, and records allocation.
    ///
    /// This ensures consistency - either the entire operation succeeds or nothing changes.
    ///
    /// Returns the allocated base VA on success, or None if:
    /// - No VA space available
    /// - Any PA is already mapped (duplicate mapping)
    pub fn allocate_and_register(&mut self, phys_addrs: &[PhysAddr]) -> Option<VirtAddr> {
        if phys_addrs.is_empty() {
            return None;
        }

        // Check for duplicate PA mappings before allocating
        for pa in phys_addrs {
            if self.pa_to_va_map.contains_key(&pa.as_u64()) {
                return None; // PA already mapped
            }
        }

        // Allocate VA range
        let base_va = self.allocate_va_range(phys_addrs.len())?;

        // Register all mappings
        for (i, &pa) in phys_addrs.iter().enumerate() {
            let va = VirtAddr::new_truncate(base_va.as_u64() + (i as u64) * (PAGE_SIZE as u64));
            self.pa_to_va_map.insert(pa.as_u64(), va.as_u64());
            self.va_to_pa_map.insert(va.as_u64(), pa.as_u64());
        }

        // Record allocation metadata
        self.allocations.insert(
            base_va.as_u64(),
            VmapAllocation {
                num_pages: phys_addrs.len(),
                phys_addrs: phys_addrs.to_vec(),
            },
        );

        Some(base_va)
    }

    /// Rolls back a failed allocation by removing mappings and freeing VA range.
    ///
    /// Call this if page table mapping fails after `allocate_and_register` succeeds.
    pub fn rollback_allocation(&mut self, base_va: VirtAddr) {
        if let Some(allocation) = self.allocations.remove(&base_va.as_u64()) {
            // Remove all individual page mappings
            for (i, pa) in allocation.phys_addrs.iter().enumerate() {
                let va = VirtAddr::new_truncate(base_va.as_u64() + (i as u64) * (PAGE_SIZE as u64));
                self.pa_to_va_map.remove(&pa.as_u64());
                self.va_to_pa_map.remove(&va.as_u64());
            }
            // Return VA range to free list
            self.free_va_range(base_va, allocation.num_pages);
        }
    }

    /// Unregisters all mappings for an allocation starting at the given virtual address.
    ///
    /// Returns the number of pages that were unmapped, or `None` if no allocation was found.
    pub fn unregister_allocation(&mut self, va_start: VirtAddr) -> Option<usize> {
        let allocation = self.allocations.remove(&va_start.as_u64())?;

        // Remove all individual page mappings
        for (i, pa) in allocation.phys_addrs.iter().enumerate() {
            let va = VirtAddr::new_truncate(va_start.as_u64() + (i as u64) * (PAGE_SIZE as u64));
            self.pa_to_va_map.remove(&pa.as_u64());
            self.va_to_pa_map.remove(&va.as_u64());
        }

        // Return VA range to free list for reuse
        self.free_va_range(va_start, allocation.num_pages);

        Some(allocation.num_pages)
    }

    /// Translates a physical address to its mapped virtual address.
    ///
    /// Returns `Some(VirtAddr)` if the physical address is mapped in the vmap region,
    /// or `None` if not found.
    pub fn pa_to_va(&self, pa: PhysAddr) -> Option<VirtAddr> {
        self.pa_to_va_map
            .get(&pa.as_u64())
            .map(|&va| VirtAddr::new_truncate(va))
    }

    /// Translates a virtual address to its corresponding physical address.
    ///
    /// Returns `Some(PhysAddr)` if the virtual address is in the vmap region and mapped,
    /// or `None` if not found.
    pub fn va_to_pa(&self, va: VirtAddr) -> Option<PhysAddr> {
        self.va_to_pa_map
            .get(&va.as_u64())
            .map(|&pa| PhysAddr::new_truncate(pa))
    }

    /// Checks if a virtual address is within the vmap region.
    pub fn is_vmap_address(va: VirtAddr) -> bool {
        (VMAP_START..VMAP_END).contains(&va.as_u64())
    }
}

impl Default for VmapRegionAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Global vmap region allocator instance.
static VMAP_ALLOCATOR: SpinMutex<Option<VmapRegionAllocator>> = SpinMutex::new(None);

/// Initializes the global vmap allocator if not already initialized.
fn ensure_initialized() -> spin::mutex::SpinMutexGuard<'static, Option<VmapRegionAllocator>> {
    let mut guard = VMAP_ALLOCATOR.lock();
    if guard.is_none() {
        *guard = Some(VmapRegionAllocator::new());
    }
    guard
}

/// Atomically allocates VA range and registers all mappings.
///
/// Returns the base VA on success, or None if allocation fails or any PA is already mapped.
pub fn allocate_and_register_vmap(phys_addrs: &[PhysAddr]) -> Option<VirtAddr> {
    let mut guard = ensure_initialized();
    guard
        .as_mut()
        .and_then(|alloc| alloc.allocate_and_register(phys_addrs))
}

/// Rolls back a vmap allocation after page table mapping failure.
pub fn rollback_vmap_allocation(base_va: VirtAddr) {
    let mut guard = ensure_initialized();
    if let Some(alloc) = guard.as_mut() {
        alloc.rollback_allocation(base_va);
    }
}

/// Unregisters an allocation from the global vmap allocator.
pub fn unregister_vmap_allocation(va_start: VirtAddr) -> Option<usize> {
    let mut guard = ensure_initialized();
    guard
        .as_mut()
        .and_then(|alloc| alloc.unregister_allocation(va_start))
}

/// Translates a physical address to virtual address in the vmap region.
pub fn vmap_pa_to_va(pa: PhysAddr) -> Option<VirtAddr> {
    let guard = VMAP_ALLOCATOR.lock();
    guard.as_ref().and_then(|alloc| alloc.pa_to_va(pa))
}

/// Translates a virtual address to physical address in the vmap region.
pub fn vmap_va_to_pa(va: VirtAddr) -> Option<PhysAddr> {
    let guard = VMAP_ALLOCATOR.lock();
    guard.as_ref().and_then(|alloc| alloc.va_to_pa(va))
}

/// Checks if a virtual address is within the vmap region.
pub fn is_vmap_address(va: VirtAddr) -> bool {
    VmapRegionAllocator::is_vmap_address(va)
}

/// Extended memory provider trait that adds vmap-aware address translation.
///
/// This trait extends the base `MemoryProvider` with methods to handle
/// both direct-mapped and vmap regions.
pub trait VmapAwareMemoryProvider: MemoryProvider {
    /// Translates a virtual address to physical address, checking both
    /// direct-mapped and vmap regions.
    fn va_to_pa_vmap_aware(va: VirtAddr) -> Option<PhysAddr> {
        if is_vmap_address(va) {
            vmap_va_to_pa(va)
        } else {
            // Use the direct mapping translation from MemoryProvider
            Some(Self::va_to_pa(va))
        }
    }

    /// Translates a physical address to virtual address.
    ///
    /// First checks if the PA is mapped in the vmap region, otherwise
    /// falls back to direct mapping.
    fn pa_to_va_vmap_aware(pa: PhysAddr) -> VirtAddr {
        // First check if it's in the vmap region
        if let Some(va) = vmap_pa_to_va(pa) {
            return va;
        }
        // Fall back to direct mapping
        Self::pa_to_va(pa)
    }
}

// Blanket implementation for all types that implement MemoryProvider
impl<T: MemoryProvider> VmapAwareMemoryProvider for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmap_region_bounds() {
        const { assert!(VMAP_START < VMAP_END) };
        assert_eq!(VMAP_SIZE, VMAP_END - VMAP_START);
    }

    #[test]
    fn test_is_vmap_address() {
        assert!(VmapRegionAllocator::is_vmap_address(
            VirtAddr::new_truncate(VMAP_START)
        ));
        assert!(VmapRegionAllocator::is_vmap_address(
            VirtAddr::new_truncate(VMAP_START + 0x1000)
        ));
        assert!(VmapRegionAllocator::is_vmap_address(
            VirtAddr::new_truncate(VMAP_END - 1)
        ));
        assert!(!VmapRegionAllocator::is_vmap_address(
            VirtAddr::new_truncate(VMAP_START - 1)
        ));
        assert!(!VmapRegionAllocator::is_vmap_address(
            VirtAddr::new_truncate(VMAP_END)
        ));
    }

    #[test]
    fn test_allocate_va_range() {
        let mut allocator = VmapRegionAllocator::new();

        // Allocate first range
        let va1 = allocator.allocate_va_range(1);
        assert!(va1.is_some());
        assert_eq!(va1.unwrap().as_u64(), VMAP_START);

        // Allocate second range
        let va2 = allocator.allocate_va_range(2);
        assert!(va2.is_some());
        assert_eq!(va2.unwrap().as_u64(), VMAP_START + PAGE_SIZE as u64);

        // Zero pages should return None
        let va3 = allocator.allocate_va_range(0);
        assert!(va3.is_none());
    }

    #[test]
    fn test_va_range_reuse() {
        let mut allocator = VmapRegionAllocator::new();

        // Allocate and free a range
        let va1 = allocator.allocate_va_range(2).unwrap();
        allocator.free_va_range(va1, 2);

        // Next allocation should reuse the freed range
        let va2 = allocator.allocate_va_range(2).unwrap();
        assert_eq!(va1, va2);

        // Allocate smaller than freed - should split
        allocator.free_va_range(va2, 2);
        let va3 = allocator.allocate_va_range(1).unwrap();
        assert_eq!(va3, va1);

        // Remainder should be in free list
        let va4 = allocator.allocate_va_range(1).unwrap();
        assert_eq!(va4.as_u64(), va1.as_u64() + PAGE_SIZE as u64);
    }

    #[test]
    fn test_allocate_and_register() {
        let mut allocator = VmapRegionAllocator::new();

        let phys_addrs = alloc::vec![
            PhysAddr::new(0x1000),
            PhysAddr::new(0x3000),
            PhysAddr::new(0x5000),
        ];

        // Allocate and register
        let base_va = allocator.allocate_and_register(&phys_addrs);
        assert!(base_va.is_some());
        let base_va = base_va.unwrap();

        // Verify mappings exist
        for (i, &pa) in phys_addrs.iter().enumerate() {
            let expected_va =
                VirtAddr::new_truncate(base_va.as_u64() + (i as u64) * (PAGE_SIZE as u64));
            assert_eq!(allocator.pa_to_va(pa), Some(expected_va));
            assert_eq!(allocator.va_to_pa(expected_va), Some(pa));
        }

        // Duplicate PA should fail
        let duplicate = allocator.allocate_and_register(&[PhysAddr::new(0x1000)]);
        assert!(duplicate.is_none());
    }

    #[test]
    fn test_rollback_allocation() {
        let mut allocator = VmapRegionAllocator::new();

        let phys_addrs = alloc::vec![PhysAddr::new(0x1000), PhysAddr::new(0x2000)];

        let base_va = allocator.allocate_and_register(&phys_addrs).unwrap();

        // Rollback
        allocator.rollback_allocation(base_va);

        // Mappings should be gone
        assert_eq!(allocator.pa_to_va(PhysAddr::new(0x1000)), None);
        assert_eq!(allocator.pa_to_va(PhysAddr::new(0x2000)), None);

        // VA should be reusable
        let new_va = allocator.allocate_va_range(2).unwrap();
        assert_eq!(new_va, base_va);
    }

    #[test]
    fn test_unregister_allocation() {
        let mut allocator = VmapRegionAllocator::new();

        let phys_addrs = alloc::vec![
            PhysAddr::new(0x1000),
            PhysAddr::new(0x3000),
            PhysAddr::new(0x5000),
        ];

        let base_va = allocator.allocate_and_register(&phys_addrs).unwrap();

        // Unregister
        let num_pages = allocator.unregister_allocation(base_va);
        assert_eq!(num_pages, Some(3));

        // Verify mappings are gone
        for pa in &phys_addrs {
            assert_eq!(allocator.pa_to_va(*pa), None);
        }

        // VA should be reusable
        let new_va = allocator.allocate_va_range(3).unwrap();
        assert_eq!(new_va, base_va);
    }
}
