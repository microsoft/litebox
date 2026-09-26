// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Concrete LVBS heap. Page allocation and Rust allocation use one instance
//! directly, without a global registration slot or initialization back-reference.
//! This allocator is compiled only with the `lvbs` feature; independent VM
//! runners disable that feature and own their own memory providers/allocators.

use super::HostLvbsInterface;
use crate::{HostInterface, mm::MemoryProvider};
use litebox::mm::allocator::SafeZoneAllocator;

#[cfg(not(test))]
#[global_allocator]
static HEAP: SafeZoneAllocator<'static, 25, HostLvbsInterface> = SafeZoneAllocator::new();

pub struct LvbsMemory;

impl litebox::mm::allocator::MemoryProvider for HostLvbsInterface {
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        <Self as HostInterface>::alloc(layout)
    }
    unsafe fn free(addr: usize) {
        unsafe { <Self as HostInterface>::free(addr) };
    }
}

#[cfg(not(test))]
impl MemoryProvider for LvbsMemory {
    type Tlb = super::tlb::LvbsTlb;
    const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn print(args: core::fmt::Arguments<'_>) {
        super::console::print(args);
    }
    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        HEAP.allocate_pages(order)
    }
    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        unsafe { HEAP.free_pages(ptr, order) };
    }
    unsafe fn mem_fill_pages(start: usize, size: usize) {
        unsafe { HEAP.fill_pages(start, size) };
    }
}

// Host unit tests never boot a VTL or install its heap. A concrete LVBS memory
// request here is a setup error, not an implicit fallback to the test allocator.
#[cfg(test)]
impl MemoryProvider for LvbsMemory {
    type Tlb = crate::host::mock::MockTlb;
    const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
    const PRIVATE_PTE_MASK: u64 = 0;
    fn print(_args: core::fmt::Arguments<'_>) {
        panic!("LVBS diagnostics in host test");
    }
    fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
        panic!("LVBS heap is not booted");
    }
    unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
        panic!("LVBS heap is not booted");
    }
    unsafe fn mem_fill_pages(_start: usize, _size: usize) {
        panic!("LVBS heap is not booted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::alloc::Layout;

    #[test]
    fn caller_owned_heap_serves_and_reuses_pages() {
        // Page allocation needs no &'static allocator; use a local fixture.
        // Returning its only page leaves no live slab metadata in backing RAM.
        let heap = SafeZoneAllocator::<25, HostLvbsInterface>::new();
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        let backing = unsafe { alloc::alloc::alloc_zeroed(layout) };
        assert!(!backing.is_null());
        unsafe {
            heap.fill_pages(backing as usize, 4096);
        }
        let page = heap.allocate_pages(0).unwrap();
        assert_eq!(page, backing);
        unsafe {
            heap.free_pages(page, 0);
        }
        let reused = heap.allocate_pages(0).unwrap();
        assert_eq!(reused, backing);
        unsafe {
            heap.free_pages(reused, 0);
        }
        // No allocations remain; SafeZoneAllocator has no destructor and is
        // not used after releasing this fixture's backing page.
        unsafe {
            alloc::alloc::dealloc(backing, layout);
        }
    }
}
