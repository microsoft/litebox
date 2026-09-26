// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LVBS memory resources, explicitly bound to the runner-owned allocator.
//! No global allocator is installed by the platform library.

use super::HostLvbsInterface;
use crate::{HostInterface, mm::MemoryProvider};
use litebox::mm::allocator::SafeZoneAllocator;
use spin::Once;

/// Preserve LVBS's existing buddy order and slab allocator. The runner owns
/// the instance and its `#[global_allocator]` annotation.
pub type LvbsAllocator = SafeZoneAllocator<'static, 25, HostLvbsInterface>;

/// Static resources selected by HostLvbsInterface for every LVBS page table.
pub struct LvbsMemory;

#[derive(Debug, PartialEq, Eq)]
pub struct AllocatorAlreadyInstalled;

struct AllocatorSlot(Once<&'static LvbsAllocator>);

impl AllocatorSlot {
    const fn new() -> Self {
        Self(Once::new())
    }

    fn install(&self, allocator: &'static LvbsAllocator) -> Result<(), AllocatorAlreadyInstalled> {
        let mut installed_here = false;
        self.0.call_once(|| {
            installed_here = true;
            allocator
        });
        if installed_here {
            Ok(())
        } else {
            Err(AllocatorAlreadyInstalled)
        }
    }

    fn get(&self) -> &'static LvbsAllocator {
        self.0
            .get()
            .expect("LVBS allocator not installed by the runner")
    }
}

static ALLOCATOR: AllocatorSlot = AllocatorSlot::new();

/// Bind the same allocator the runner uses for Rust allocations. Call once
/// after final relocation, before seeding memory or allocating per-CPU state.
/// The reference is published to all CPUs and cannot be replaced while frames
/// or page tables still refer to it. Registration does not allocate memory.
pub fn install_allocator(
    allocator: &'static LvbsAllocator,
) -> Result<(), AllocatorAlreadyInstalled> {
    ALLOCATOR.install(allocator)
}

// Preserve the existing LVBS heap-exhaustion policy (HostInterface::alloc
// panics: dynamically obtaining more physical memory is not supported).
impl litebox::mm::allocator::MemoryProvider for HostLvbsInterface {
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        <Self as HostInterface>::alloc(layout)
    }
    unsafe fn free(addr: usize) {
        unsafe { <Self as HostInterface>::free(addr) };
    }
}

impl MemoryProvider for LvbsMemory {
    #[cfg(not(test))]
    type Tlb = super::tlb::LvbsTlb;
    #[cfg(test)]
    type Tlb = crate::host::mock::MockTlb;

    const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        ALLOCATOR.get().allocate_pages(order)
    }

    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        unsafe { ALLOCATOR.get().free_pages(ptr, order) };
    }

    unsafe fn mem_fill_pages(start: usize, size: usize) {
        unsafe { ALLOCATOR.get().fill_pages(start, size) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static FIRST: LvbsAllocator = LvbsAllocator::new();
    static SECOND: LvbsAllocator = LvbsAllocator::new();

    #[test]
    fn binding_preserves_instance_identity_and_cannot_be_replaced() {
        let slot = AllocatorSlot::new();
        assert_eq!(slot.install(&FIRST), Ok(()));
        assert!(core::ptr::eq(slot.get(), &raw const FIRST));
        assert_eq!(slot.install(&SECOND), Err(AllocatorAlreadyInstalled));
        assert_eq!(slot.install(&FIRST), Err(AllocatorAlreadyInstalled));
        assert!(core::ptr::eq(slot.get(), &raw const FIRST));
    }

    #[test]
    fn rust_objects_and_platform_pages_use_the_runner_owned_heap() {
        use core::alloc::{GlobalAlloc, Layout};
        static RUNNER_HEAP: LvbsAllocator = LvbsAllocator::new();
        // This is the only test installing the module-wide binding. Other
        // registry tests use local slots. Backing storage is intentionally kept
        // for the static allocator's lifetime, like runner-provided guest RAM.
        const SIZE: usize = 8 * 1024 * 1024;
        let layout = Layout::from_size_align(SIZE, 2 * 1024 * 1024).unwrap();
        let backing = unsafe { alloc::alloc::alloc_zeroed(layout) };
        assert!(!backing.is_null());
        install_allocator(&RUNNER_HEAP).unwrap();
        unsafe {
            LvbsMemory::mem_fill_pages(backing as usize, SIZE);
        }
        let object_layout = Layout::from_size_align(32, 8).unwrap();
        let object = unsafe { RUNNER_HEAP.alloc(object_layout) };
        let page = LvbsMemory::mem_allocate_pages(0).unwrap();
        for ptr in [object, page] {
            assert!((backing as usize..backing as usize + SIZE).contains(&(ptr as usize)));
        }
        assert_ne!(object, page);
        assert_eq!(page as usize % 4096, 0);
        unsafe {
            RUNNER_HEAP.dealloc(object, object_layout);
            LvbsMemory::mem_free_pages(page, 0);
        }
    }

    #[test]
    #[should_panic(expected = "LVBS allocator not installed by the runner")]
    fn missing_binding_fails_before_accessing_an_allocator() {
        AllocatorSlot::new().get();
    }
}
