// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Heap and page-table allocations share the RAM supplied by `seed_heap`.

use core::alloc::{GlobalAlloc, Layout};
use litebox_platform_vm_kernel::preempt::NoPreempt;

/// Largest single allocation: `1 << (HEAP_ORDER - 1)` bytes (16 MiB).
const HEAP_ORDER: usize = 25;

type Allocator = litebox::mm::allocator::SafeZoneAllocator<'static, HEAP_ORDER, NoHost>;

/// Its locks are the kernel's, which broker work, running with interrupts
/// enabled, shares: every allocation and free takes them with interrupts
/// disabled (see [`NoPreempt`]), as does [`KernelPages`].
#[global_allocator]
static KERNEL_ALLOCATOR: KernelAllocator = KernelAllocator(Allocator::new());

struct KernelAllocator(Allocator);

// Safety: forwards to the allocator, with interrupts disabled.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _no_preempt = NoPreempt::new();
        // Safety: forwarded to the caller.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _no_preempt = NoPreempt::new();
        // Safety: forwarded to the caller.
        unsafe { self.0.dealloc(ptr, layout) }
    }
}

struct NoHost;

impl litebox::mm::allocator::MemoryProvider for NoHost {
    /// Must not log: fallible allocations end up here too.
    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        None
    }

    unsafe fn free(_addr: usize) {
        unreachable!("the kernel heap never obtains memory from a host");
    }
}

/// Transfers the range permanently to the heap.
///
/// # Safety
///
/// The range must be mapped, writable, and unused by anything else.
pub unsafe fn add_memory(start: usize, size: usize) {
    // Safety: forwarded to the caller.
    unsafe { KERNEL_ALLOCATOR.0.fill_pages(start, size) }
}

pub struct KernelPages;

// Safety: the heap hands out disjoint, page-aligned buddy blocks (live ones
// are never reused) carved only from RAM that `seed_heap` adds, which is inside
// `BootConfig::ram` and mapped at `PA + KERNEL_OFFSET`.
unsafe impl litebox_platform_vm_kernel::mm::PageAllocator for KernelPages {
    fn allocate_pages(&self, order: u32) -> Option<*mut u8> {
        let _no_preempt = NoPreempt::new();
        KERNEL_ALLOCATOR.0.allocate_pages(order)
    }

    unsafe fn free_pages(&self, ptr: *mut u8, order: u32) {
        let _no_preempt = NoPreempt::new();
        // Safety: forwarded to the caller.
        unsafe { KERNEL_ALLOCATOR.0.free_pages(ptr, order) }
    }
}
