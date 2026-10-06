// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The runner's heap: [`StartupInfo::heap`](litebox_common_vm_abi::StartupInfo).

use litebox_common_vm_abi::UserRange;

/// Largest single allocation: `1 << (HEAP_ORDER - 1)` bytes (16 MiB).
const HEAP_ORDER: usize = 25;

#[global_allocator]
static ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<'static, HEAP_ORDER, NoHost> =
    litebox::mm::allocator::SafeZoneAllocator::new();

struct NoHost;

impl litebox::mm::allocator::MemoryProvider for NoHost {
    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        None
    }

    unsafe fn free(_addr: usize) {
        unreachable!("the heap never obtains memory from a host");
    }
}

/// # Safety
///
/// `region` must be mapped writable, stay mapped, and be otherwise unused.
pub unsafe fn init(region: UserRange) {
    let start = usize::try_from(region.start).expect("heap address fits usize");
    let len = usize::try_from(region.len).expect("heap length fits usize");
    // Safety: forwarded to the caller.
    unsafe { ALLOCATOR.fill_pages(start, len) };
}
