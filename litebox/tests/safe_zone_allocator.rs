// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Exercises [`SafeZoneAllocator`] as the global allocator, so that fallible collection APIs
//! (e.g., [`Vec::try_reserve`]) go through it.

use core::alloc::Layout;

use litebox::mm::allocator::{MemoryProvider, SafeZoneAllocator};

/// Maximum order of the buddy allocator, i.e., the largest block it can serve is
/// `1 << (ORDER - 1)` bytes (4 MiB).
const ORDER: usize = 23;

/// Memory provider backed by the system allocator.
struct SystemMemory;

impl MemoryProvider for SystemMemory {
    fn alloc(layout: &Layout) -> Option<(usize, usize)> {
        // SAFETY: the allocator only requests non-zero, power-of-two sized layouts. The memory
        // is handed over to the buddy allocator and intentionally never returned.
        let ptr = unsafe { std::alloc::GlobalAlloc::alloc(&std::alloc::System, *layout) };
        if ptr.is_null() {
            None
        } else {
            Some((ptr as usize, layout.size()))
        }
    }

    unsafe fn free(_addr: usize) {
        unreachable!("SafeZoneAllocator never returns memory to the provider")
    }
}

#[global_allocator]
static ALLOCATOR: SafeZoneAllocator<'static, ORDER, SystemMemory> = SafeZoneAllocator::new();

#[test]
fn try_reserve_beyond_max_order_fails_gracefully() {
    let mut v: Vec<u8> = Vec::new();
    assert!(v.try_reserve_exact(1 << ORDER).is_err());
    assert!(v.try_reserve_exact(1 << (ORDER + 1)).is_err());

    // Allocations that fit in the buddy allocator keep working afterwards.
    v.try_reserve_exact(1 << (ORDER - 1))
        .expect("the largest supported block should be allocatable");
    v.resize(1 << (ORDER - 1), 0xa5);
    assert!(v.iter().all(|&b| b == 0xa5));
}
