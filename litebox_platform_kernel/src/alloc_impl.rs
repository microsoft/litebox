#[cfg(not(test))]
mod alloc {
    const HEAP_ORDER: usize = 25;

    #[global_allocator]
    static ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<
        'static,
        HEAP_ORDER,
        crate::LiteBoxKernel,
    > = litebox::mm::allocator::SafeZoneAllocator::new();

    // TODO: these alloc and free functions are for dynamic memory management which are
    // often meaningless if there is no host. In that sense, we might want to remove these from
    // `SafeZoneAllocator`.
    impl litebox::mm::allocator::MemoryProvider for crate::LiteBoxKernel {
        fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
            // For a (virtual) machine, this might be memory ballooning or hotplugging.
            unimplemented!()
        }

        unsafe fn free(_addr: usize) {
            unimplemented!()
        }
    }

    impl crate::mm::MemoryProvider for crate::LiteBoxKernel {
        // TODO: this offset should be configurable
        const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(0x18000000000);
        // TODO: this mask should be configurable
        const PRIVATE_PTE_MASK: u64 = 0;

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe {
                ALLOCATOR.free_pages(ptr, order);
            }
        }

        unsafe fn mem_fill_pages(start: usize, size: usize) {
            unsafe { ALLOCATOR.fill_pages(start, size) };
        }
    }
}
