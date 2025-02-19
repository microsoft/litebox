use core::alloc::{GlobalAlloc, Layout};

use crate::{host::mock::MockHostInterface, mm::MemoryProvider, HostInterface, LinuxKernel};

use super::slab::LockedSlabAllocator;

const MAX_ORDER: usize = 23;
type MockKernel = LinuxKernel<MockHostInterface>;

#[global_allocator]
pub static ALLOCATOR: LockedSlabAllocator<'static, MAX_ORDER, MockKernel> =
    LockedSlabAllocator::new();

impl super::MemoryProvider for MockKernel {
    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::error::Errno> {
        MockHostInterface::alloc(layout)
    }

    fn mem_allocate_pages(order: usize) -> Option<*mut u8> {
        ALLOCATOR.allocate_pages(order)
    }

    unsafe fn mem_free_pages(ptr: *mut u8, order: usize) {
        ALLOCATOR.free_pages(ptr, order)
    }
}

#[test]
fn test_buddy() {
    let ptr = MockKernel::mem_allocate_pages(1);
    assert!(ptr.is_some_and(|p| p as usize != 0));
    unsafe {
        MockKernel::mem_free_pages(ptr.unwrap(), 1);
    }
}

#[test]
fn test_slab() {
    unsafe {
        assert!(ALLOCATOR.alloc(Layout::from_size_align(0x1000, 0x1000).unwrap()) as usize != 0);
        assert!(ALLOCATOR.alloc(Layout::from_size_align(0x10, 0x10).unwrap()) as usize != 0);
    }
}
