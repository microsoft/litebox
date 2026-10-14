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
/// allocation that can be done using the buddy allocator -- i.e., 1 << (ORDER - 1).
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
                // On failure, add nothing so the retry fails and `alloc` returns null.
                let Some(page_aligned_size) = layout.size().checked_next_power_of_two() else {
                    return;
                };
                if page_aligned_size.trailing_zeros() as usize >= ORDER {
                    return;
                }
                let Ok(layout) = Layout::from_size_align(page_aligned_size, page_aligned_size)
                else {
                    return;
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
        // Pad to alignment so the slab size class is >= `align`. Must match `dealloc`.
        let layout = layout.pad_to_align();
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
                        // Refill and retry; report any failure as null.
                        let refilled = if layout.size() <= ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                            self.alloc_page().is_some_and(|page| {
                                let raw = core::ptr::from_mut(page).cast::<u8>();
                                let ok = unsafe { zone_allocator.refill(layout, page) }.is_ok();
                                if !ok {
                                    unsafe { self.free_pages(raw, Self::BASE_PAGE_SIZE_ORDER) };
                                }
                                ok
                            })
                        } else {
                            self.alloc_large_page().is_some_and(|large_page| {
                                let raw = core::ptr::from_mut(large_page).cast::<u8>();
                                let ok = unsafe { zone_allocator.refill_large(layout, large_page) }
                                    .is_ok();
                                if !ok {
                                    unsafe { self.free_pages(raw, Self::LARGE_PAGE_SIZE_ORDER) };
                                }
                                ok
                            })
                        };
                        if !refilled {
                            return core::ptr::null_mut();
                        }
                        zone_allocator
                            .allocate(layout)
                            .map_or(core::ptr::null_mut(), NonNull::as_ptr)
                    }
                    // Unreachable: sizes are bounded by `MAX_ALLOC_SIZE`.
                    Err(AllocationError::InvalidLayout) => core::ptr::null_mut(),
                }
            }
            _ => unsafe { self.buddy_allocator.alloc(layout) },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        // Must match `alloc`.
        let layout = layout.pad_to_align();
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
