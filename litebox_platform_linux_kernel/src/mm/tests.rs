use core::alloc::{GlobalAlloc, Layout};

use crate::{host::mock::MockHostInterface, LinuxKernel};

use super::{buddy::LockedHeapWithRescue, slab::LockedSlabAllocator};

lazy_static::lazy_static!(
    static ref PLATFORM: LinuxKernel<MockHostInterface> = LinuxKernel::new();
    static ref SYNC: litebox::sync::Synchronization<'static, LinuxKernel<MockHostInterface>>  = litebox::sync::Synchronization::new(&PLATFORM);
);

const MAX_ORDER: usize = 23;

#[test]
fn test_heap_oom_rescue() {
    let allocator = LockedHeapWithRescue::<'_, MAX_ORDER, _>::new(&SYNC);
    unsafe {
        assert!(allocator.alloc(Layout::from_size_align(0x1000, 1).unwrap()) as usize != 0);
    }
}

#[test]
fn test_slab() {
    let allocator = LockedSlabAllocator::<'_, MAX_ORDER, _>::new(&SYNC);

    unsafe {
        assert!(allocator.alloc(Layout::from_size_align(0x1000, 0x1000).unwrap()) as usize != 0);
        assert!(allocator.alloc(Layout::from_size_align(0x10, 0x10).unwrap()) as usize != 0);
    }
}
