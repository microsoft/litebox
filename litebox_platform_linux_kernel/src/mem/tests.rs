use core::alloc::{GlobalAlloc, Layout};

use litebox::sync::Synchronization;

use crate::{
    host::mock::{MockHostInterface, MockTask},
    LinuxKernel,
};

use super::buddy::LockedHeapWithRescue;

#[test]
fn test_heap_oom_rescue() {
    let platform = LinuxKernel::<MockHostInterface, MockTask>::new(0x1000);
    let sync = Synchronization::new(&platform);
    let allocator = LockedHeapWithRescue::<'_, 23, _>::new(&sync);

    unsafe {
        assert!(allocator.alloc(Layout::from_size_align(0x1000, 1).unwrap()) as usize != 0);
    }
}
