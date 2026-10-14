// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Allocator that uses buddy allocator for pages and slab allocator for small objects.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
};

use buddy_system_allocator::LockedHeapWithRescue;
use slabmalloc::{AllocationError, Allocator, LargeObjectPage, ObjectPage, ZoneAllocator};
use spin::mutex::SpinMutex;

/// Memory provider trait for global allocator.
///
/// TODO: consider taking a `&mut self` to allow for more flexibility in the future.
pub trait MemoryProvider {
    /// For page allocation from host.
    ///
    /// Note this is only called when the allocator is out of memory.
    /// To add memory to the allocator at any time (e.g., initialize the allocator with
    /// pre-allocated fixed-size memory), use [`SafeZoneAllocator::fill_pages`].
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &Layout) -> Option<(usize, usize)>;

    /// Returns the memory back to host.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `addr` is valid and was allocated by [`Self::alloc`].
    unsafe fn free(addr: usize);
}

/// Allocator that uses buddy allocator for pages and slab allocator for small objects.
///
/// `ORDER` is the maximum order of the buddy allocator, specifying the maximum size of the
/// allocation that can be done using the buddy allocator -- i.e., 1 << (ORDER - 1). Larger
/// allocation requests fail (i.e., [`GlobalAlloc::alloc`] returns null) instead of panicking.
pub struct SafeZoneAllocator<'a, const ORDER: usize, M: MemoryProvider> {
    buddy_allocator: LockedHeapWithRescue<ORDER>,
    slab_allocator: SpinMutex<ZoneAllocator<'a>>,
    memory_provider: core::marker::PhantomData<M>,
}

impl<const ORDER: usize, M: MemoryProvider> Default for SafeZoneAllocator<'_, ORDER, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const ORDER: usize, M: MemoryProvider> SafeZoneAllocator<'_, ORDER, M> {
    const PAGE_SIZE: usize = 4096;
    /// 4 KiB
    const BASE_PAGE_SIZE: usize = 4096;
    /// 2 MiB
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
    const BASE_PAGE_SIZE_ORDER: u32 = (Self::BASE_PAGE_SIZE / Self::PAGE_SIZE).trailing_zeros();
    const LARGE_PAGE_SIZE_ORDER: u32 = (Self::LARGE_PAGE_SIZE / Self::PAGE_SIZE).trailing_zeros();

    pub const fn new() -> Self {
        Self {
            buddy_allocator: LockedHeapWithRescue::new(|heap, layout| {
                let page_aligned_size = layout.size().next_power_of_two();
                if page_aligned_size.trailing_zeros() as usize >= ORDER {
                    // The buddy allocator cannot serve a block of this order no matter how much
                    // memory we add, so do not ask the memory provider for more. Returning here
                    // makes the retry in `LockedHeapWithRescue::alloc` fail and return null, which
                    // lets fallible APIs (e.g., `Vec::try_reserve`) report the failure.
                    return;
                }
                let Ok(layout) = Layout::from_size_align(page_aligned_size, page_aligned_size)
                else {
                    unreachable!();
                };
                if let Some((start, size)) = M::alloc(&layout) {
                    // the returned size might be larger than requested (i.e., layout.size())
                    unsafe { heap.add_to_heap(start, start + size) };
                }
            }),
            slab_allocator: SpinMutex::new(ZoneAllocator::new()),
            memory_provider: core::marker::PhantomData,
        }
    }

    /// Adds a range of memory to allow it to be controlled by the buddy allocator.
    /// Morally, the buddy allocator takes ownership of this range of memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory range is valid and not used by any others.
    pub unsafe fn fill_pages(&self, addr: usize, size: usize) {
        unsafe { self.buddy_allocator.lock().add_to_heap(addr, addr + size) };
    }

    /// Allocates a new [`ObjectPage`] from the System.
    fn alloc_page(&self) -> Option<&'static mut ObjectPage<'static>> {
        self.allocate_pages(Self::BASE_PAGE_SIZE_ORDER).map(|r| {
            if (r as usize).is_multiple_of(core::mem::align_of::<ObjectPage<'static>>()) {
                unsafe { &mut *r.cast() }
            } else {
                unreachable!()
            }
        })
    }

    /// Allocates a new [`LargeObjectPage`] from the system.
    fn alloc_large_page(&self) -> Option<&'static mut LargeObjectPage<'static>> {
        self.allocate_pages(Self::LARGE_PAGE_SIZE_ORDER).map(|r| {
            if (r as usize).is_multiple_of(core::mem::align_of::<LargeObjectPage<'static>>()) {
                unsafe { &mut *r.cast() }
            } else {
                unreachable!()
            }
        })
    }

    /// Allocate (1 << `order`) virtually contiguous pages using buddy allocator.
    pub fn allocate_pages(&self, order: u32) -> Option<*mut u8> {
        let ptr = unsafe {
            self.buddy_allocator.alloc(
                Layout::from_size_align(
                    Self::BASE_PAGE_SIZE << order,
                    Self::BASE_PAGE_SIZE << order,
                )
                .ok()?,
            )
        };
        if ptr.is_null() { None } else { Some(ptr) }
    }

    /// De-allocates virtually contiguous pages returned from [`SafeZoneAllocator::allocate_pages`].
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    ///
    /// * `ptr` is a block of memory currently allocated via this allocator and,
    ///
    /// * `order` is the same that was used to allocate that block of memory.
    ///
    /// # Panics
    ///
    /// Panics if `order` is greater than `ORDER`.
    pub unsafe fn free_pages(&self, ptr: *mut u8, order: u32) {
        assert!(order as usize <= ORDER);
        unsafe {
            self.buddy_allocator.dealloc(
                ptr,
                Layout::from_size_align(
                    Self::BASE_PAGE_SIZE << order,
                    Self::BASE_PAGE_SIZE << order,
                )
                .unwrap(),
            );
        };
    }
}

unsafe impl<const ORDER: usize, M: MemoryProvider> GlobalAlloc
    for SafeZoneAllocator<'static, ORDER, M>
{
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        match layout.size() {
            Self::BASE_PAGE_SIZE => {
                // Best to use the underlying backend directly to allocate pages
                // to avoid fragmentation
                let Some(ptr) = self.allocate_pages(Self::BASE_PAGE_SIZE_ORDER) else {
                    return core::ptr::null_mut();
                };
                ptr
            }
            Self::LARGE_PAGE_SIZE => {
                // Best to use the underlying backend directly to allocate large pages
                // to avoid fragmentation
                let Some(ptr) = self.allocate_pages(Self::LARGE_PAGE_SIZE_ORDER) else {
                    return core::ptr::null_mut();
                };
                ptr
            }
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                let mut zone_allocator = self.slab_allocator.lock();
                match zone_allocator.allocate(layout) {
                    Ok(ptr) => ptr.as_ptr(),
                    Err(AllocationError::OutOfMemory) => {
                        if layout.size() <= ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                            self.alloc_page().map_or(core::ptr::null_mut(), |page| {
                                unsafe {
                                    zone_allocator
                                        .refill(layout, page)
                                        .expect("Could not refill?");
                                }
                                zone_allocator
                                    .allocate(layout)
                                    .expect("Should succeed after refill")
                                    .as_ptr()
                            })
                        } else {
                            self.alloc_large_page()
                                .map_or(core::ptr::null_mut(), |large_page| {
                                    unsafe {
                                        zone_allocator
                                            .refill_large(layout, large_page)
                                            .expect("Could not refill?");
                                    }
                                    zone_allocator
                                        .allocate(layout)
                                        .expect("Should succeed after refill")
                                        .as_ptr()
                                })
                        }
                    }
                    Err(AllocationError::InvalidLayout) => {
                        panic!("Invalid layout: {layout:?}");
                    }
                }
            }
            _ => unsafe { self.buddy_allocator.alloc(layout) },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        match layout.size() {
            Self::BASE_PAGE_SIZE | Self::LARGE_PAGE_SIZE => unsafe {
                self.buddy_allocator.dealloc(ptr, layout);
            },
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                if let Some(ptr) = NonNull::new(ptr) {
                    self.slab_allocator
                        .lock()
                        .deallocate(ptr, layout)
                        .expect("Failed to deallocate");
                }

                // TODO: An proper reclamation strategy could be implemented here
                // to release empty pages back from the ZoneAllocator to the buddy allocator.
            }
            _ => unsafe {
                self.buddy_allocator.dealloc(ptr, layout);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{MemoryProvider, SafeZoneAllocator};

    /// Maximum order of the buddy allocators under test, i.e., the largest block they can serve
    /// is `1 << (ORDER - 1)` bytes (4 MiB).
    const ORDER: usize = 23;

    /// Number of times each [`SystemMemory`] instance has been asked for memory.
    static SYSTEM_MEMORY_CALLS: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

    /// Memory provider backed by the host's allocator. `ID` keeps the call counters of
    /// concurrently running tests apart.
    struct SystemMemory<const ID: usize>;

    impl<const ID: usize> MemoryProvider for SystemMemory<ID> {
        fn alloc(layout: &Layout) -> Option<(usize, usize)> {
            SYSTEM_MEMORY_CALLS[ID].fetch_add(1, Ordering::SeqCst);
            // SAFETY: the allocator only requests non-zero, power-of-two sized layouts. The memory
            // is handed over to the buddy allocator and intentionally never returned.
            let ptr = unsafe { std::alloc::alloc(*layout) };
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

    /// Memory provider that never has memory available.
    struct NoMemory;

    impl MemoryProvider for NoMemory {
        fn alloc(_layout: &Layout) -> Option<(usize, usize)> {
            None
        }

        unsafe fn free(_addr: usize) {
            unreachable!("NoMemory never hands out memory")
        }
    }

    #[test]
    fn over_max_order_allocation_returns_null() {
        static ALLOCATOR: SafeZoneAllocator<'static, ORDER, SystemMemory<0>> =
            SafeZoneAllocator::new();

        for size in [1 << ORDER, (1 << ORDER) + 1, 1 << (ORDER + 4)] {
            let layout = Layout::from_size_align(size, 8).unwrap();
            // SAFETY: `layout` has a non-zero size.
            let ptr = unsafe { ALLOCATOR.alloc(layout) };
            assert!(ptr.is_null(), "allocation of {size:#x} bytes should fail");
        }
        // Requests that the buddy allocator can never serve must not grow the heap.
        assert_eq!(SYSTEM_MEMORY_CALLS[0].load(Ordering::SeqCst), 0);
    }

    #[test]
    fn allocations_within_max_order_grow_the_heap() {
        static ALLOCATOR: SafeZoneAllocator<'static, ORDER, SystemMemory<1>> =
            SafeZoneAllocator::new();

        // Small (slab), base page, large page, and the largest block the buddy allocator supports.
        for size in [64, 4096, 2 * 1024 * 1024, 1 << (ORDER - 1)] {
            let layout = Layout::from_size_align(size, 8).unwrap();
            // SAFETY: `layout` has a non-zero size.
            let ptr = unsafe { ALLOCATOR.alloc(layout) };
            assert!(
                !ptr.is_null(),
                "allocation of {size:#x} bytes should succeed"
            );
            // SAFETY: `ptr` points to `size` freshly allocated bytes.
            unsafe { ptr.write_bytes(0xa5, size) };
            // SAFETY: `ptr` was allocated above by `ALLOCATOR` with `layout`.
            unsafe { ALLOCATOR.dealloc(ptr, layout) };
        }
        assert!(SYSTEM_MEMORY_CALLS[1].load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn unavailable_memory_returns_null() {
        static ALLOCATOR: SafeZoneAllocator<'static, ORDER, NoMemory> = SafeZoneAllocator::new();

        for size in [64, 4096, 2 * 1024 * 1024, 1 << (ORDER - 1)] {
            let layout = Layout::from_size_align(size, 8).unwrap();
            // SAFETY: `layout` has a non-zero size.
            let ptr = unsafe { ALLOCATOR.alloc(layout) };
            assert!(ptr.is_null(), "allocation of {size:#x} bytes should fail");
        }
    }
}
