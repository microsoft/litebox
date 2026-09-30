// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Heap and page-table allocations share the RAM supplied by `seed_heap`.

/// Largest single allocation: `1 << (HEAP_ORDER - 1)` bytes (16 MiB).
const HEAP_ORDER: usize = 25;

#[global_allocator]
static KERNEL_ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<'static, HEAP_ORDER, NoHost> =
    litebox::mm::allocator::SafeZoneAllocator::new();

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
    unsafe { KERNEL_ALLOCATOR.fill_pages(start, size) }
}

pub struct KernelPages;

// Safety: the heap hands out disjoint, page-aligned buddy blocks (live ones
// are never reused) carved only from RAM that `seed_heap` adds, which is inside
// the RAM passed to `VmKernel::new` and mapped at `PA + KERNEL_OFFSET`.
unsafe impl litebox_platform_vm_kernel::mm::PageAllocator for KernelPages {
    fn allocate_pages(&self, order: u32) -> Option<*mut u8> {
        KERNEL_ALLOCATOR.allocate_pages(order)
    }

    unsafe fn free_pages(&self, ptr: *mut u8, order: u32) {
        // Safety: forwarded to the caller.
        unsafe { KERNEL_ALLOCATOR.free_pages(ptr, order) }
    }
}
