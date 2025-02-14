use core::alloc::{GlobalAlloc, Layout};

use crate::{
    host::mock::{MockHostInterface, MockTask},
    LinuxKernel,
};

use super::{buddy::LockedHeapWithRescue, slab::LockedSlabAllocator};

lazy_static::lazy_static!(
    static ref PLATFORM: LinuxKernel<MockHostInterface, MockTask> = LinuxKernel::new();
    static ref SYNC: litebox::sync::Synchronization<'static, LinuxKernel<MockHostInterface, MockTask>>  = litebox::sync::Synchronization::new(&PLATFORM);
);

#[test]
fn test_heap_oom_rescue() {
    let allocator = LockedHeapWithRescue::<'_, 23, _>::new(&SYNC);
    unsafe {
        assert!(allocator.alloc(Layout::from_size_align(0x1000, 1).unwrap()) as usize != 0);
    }
}

#[test]
fn test_slab() {
    let allocator = LockedSlabAllocator::<'_, 23, _>::new(&SYNC);

    unsafe {
        assert!(allocator.alloc(Layout::from_size_align(0x1000, 0x1000).unwrap()) as usize != 0);
        assert!(allocator.alloc(Layout::from_size_align(0x10, 0x10).unwrap()) as usize != 0);
    }
}
