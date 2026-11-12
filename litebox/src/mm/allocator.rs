// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Allocator that uses buddy allocator for pages and slab allocator for small objects.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
};

use buddy_system_allocator::LockedHeapWithRescue;
use buddy_system_allocator::linked_list::LinkedList;
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
    /// Single pages freed, kept for the next single-page allocations, in a list through the pages
    /// themselves (the buddy allocator's own list type), as the allocator cannot allocate to track
    /// them.
    ///
    /// Note: this works around `buddy_system_allocator`, whose free looks for a block's buddy by
    /// walking a free list, so that freeing many pages one at a time (e.g., an address space's)
    /// takes time that grows with the list: hundreds of milliseconds for thousands of pages, with
    /// interrupts disabled in a kernel. The cache only defers that cost to when an allocation
    /// fails without the cached pages, which then go back to the buddy allocator, merged. Fixing
    /// the buddy allocator (e.g., finding buddies with a bitmap) or using a better allocator
    /// would remove the need for it.
    page_cache: SpinMutex<LinkedList>,
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
            page_cache: SpinMutex::new(LinkedList::new()),
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

    /// Runs `f` with the allocator locked, its locks taken in the order allocations take them,
    /// e.g., so that a copy of the process made in `f` has a copy of the allocator that no other
    /// thread was changing. `f` must not allocate or free, which would deadlock.
    pub fn with_locked<R>(&self, f: impl FnOnce() -> R) -> R {
        let _slab = self.slab_allocator.lock();
        let _cache = self.page_cache.lock();
        let _buddy = self.buddy_allocator.lock();
        f()
    }

    /// The buddy allocator's block for `layout`, after returning the cached pages to it if it
    /// has none, and only then asking the memory provider for more; null if it has none still.
    ///
    /// # Safety
    ///
    /// `layout` must be one the buddy allocator takes (nonzero size).
    unsafe fn buddy_alloc(&self, layout: Layout) -> *mut u8 {
        // Not the rescuing allocation: the host is asked only once the cached pages do not do.
        if let Ok(ptr) = self.buddy_allocator.lock().alloc(layout) {
            return ptr.as_ptr();
        }
        {
            let mut cache = self.page_cache.lock();
            if !cache.is_empty() {
                // The heap is locked before the pages leave the cache, in `with_locked`'s order, so
                // that a copy made under `with_locked` finds each of them in one or the other.
                let mut heap = self.buddy_allocator.lock();
                let mut cached = core::mem::replace(&mut *cache, LinkedList::new());
                drop(cache);
                let page = Layout::from_size_align(Self::BASE_PAGE_SIZE, Self::BASE_PAGE_SIZE)
                    .expect("a page's layout");
                while let Some(free) = cached.pop() {
                    // A cached page is a free page of the buddy allocator's.
                    heap.dealloc(
                        NonNull::new(free.cast()).expect("cached pages are not null"),
                        page,
                    );
                }
                if let Ok(ptr) = heap.alloc(layout) {
                    return ptr.as_ptr();
                }
            }
        }
        // SAFETY: forwarded to the caller.
        unsafe { self.buddy_allocator.alloc(layout) }
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
        if order == Self::BASE_PAGE_SIZE_ORDER
            && let Some(page) = self.page_cache.lock().pop()
        {
            return Some(page.cast());
        }
        let layout =
            Layout::from_size_align(Self::BASE_PAGE_SIZE << order, Self::BASE_PAGE_SIZE << order)
                .ok()?;
        // SAFETY: a nonzero size.
        let ptr = unsafe { self.buddy_alloc(layout) };
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
        if order == Self::BASE_PAGE_SIZE_ORDER {
            #[expect(clippy::cast_ptr_alignment, reason = "pages are page-aligned")]
            let page = ptr.cast::<usize>();
            // SAFETY: the caller frees an allocated page, which the cache owns until it pops it.
            unsafe { self.page_cache.lock().push(page) };
            return;
        }
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
            _ => unsafe { self.buddy_alloc(layout) },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        // Must match `alloc`.
        let layout = layout.pad_to_align();
        match layout.size() {
            Self::BASE_PAGE_SIZE => unsafe { self.free_pages(ptr, Self::BASE_PAGE_SIZE_ORDER) },
            Self::LARGE_PAGE_SIZE => unsafe {
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

    use super::*;

    /// A host that has memory, but must not be asked for it.
    struct UnaskedHost;

    impl MemoryProvider for UnaskedHost {
        fn alloc(layout: &Layout) -> Option<(usize, usize)> {
            panic!("the host was asked for {layout:?}");
        }

        unsafe fn free(_addr: usize) {
            unreachable!("nothing is allocated from the host");
        }
    }

    const PAGE: usize = 4096;
    const PAGES: usize = 16;

    /// An allocator of `PAGES` pages, one block of the buddy allocator.
    fn allocator<M: MemoryProvider>() -> SafeZoneAllocator<'static, 20, M> {
        let layout = Layout::from_size_align(PAGES * PAGE, PAGES * PAGE).unwrap();
        // SAFETY: a nonzero size; leaked, so the allocator owns it for good.
        let region = unsafe { std::alloc::alloc(layout) };
        assert!(!region.is_null());
        let allocator = SafeZoneAllocator::new();
        // SAFETY: the region is the allocator's alone.
        unsafe { allocator.fill_pages(region as usize, PAGES * PAGE) };
        allocator
    }

    #[test]
    fn freed_pages_are_reused_first() {
        let allocator = allocator::<UnaskedHost>();
        let page = allocator.allocate_pages(0).unwrap();
        let other = allocator.allocate_pages(0).unwrap();
        // SAFETY: allocated above, and no longer used.
        unsafe { allocator.free_pages(page, 0) };
        assert_eq!(allocator.allocate_pages(0), Some(page));
        // SAFETY: as above.
        unsafe {
            allocator.free_pages(page, 0);
            allocator.free_pages(other, 0);
        }
    }

    #[test]
    fn freed_pages_merge_back_before_the_host_is_asked() {
        let allocator = allocator::<UnaskedHost>();
        let pages: std::vec::Vec<*mut u8> = (0..PAGES)
            .map(|_| allocator.allocate_pages(0).unwrap())
            .collect();
        for page in pages {
            // SAFETY: allocated above, and no longer used.
            unsafe { allocator.free_pages(page, 0) };
        }
        let order = PAGES.trailing_zeros();
        let block = allocator
            .allocate_pages(order)
            .expect("the cached pages, merged");
        // SAFETY: allocated above, and no longer used.
        unsafe { allocator.free_pages(block, order) };
    }
}
