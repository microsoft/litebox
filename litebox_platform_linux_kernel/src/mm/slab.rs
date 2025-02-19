//! Allocator that uses buddy allocator for pages and slab allocator for small objects.

use core::{
    alloc::{GlobalAlloc, Layout},
    mem::transmute,
    ptr::NonNull,
};

use slabmalloc::{AllocationError, LargeObjectPage, ObjectPage};

use super::{buddy::LockedHeapWithRescue, MemoryProvider};

/// Allocator that uses buddy allocator for pages and slab allocator for small objects.
pub struct LockedSlabAllocator<'a, const ORDER: usize, Platform: MemoryProvider> {
    buddy_allocator: LockedHeapWithRescue<ORDER, Platform>,
    slab_allocator: super::zone::ZoneAllocator<'a>,
}

impl<const ORDER: usize, Platform: MemoryProvider> Default
    for LockedSlabAllocator<'_, ORDER, Platform>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const ORDER: usize, Platform: MemoryProvider> LockedSlabAllocator<'_, ORDER, Platform> {
    const BASE_PAGE_SIZE: usize = 4096;
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    pub const fn new() -> Self {
        LockedSlabAllocator {
            buddy_allocator: LockedHeapWithRescue::new(),
            slab_allocator: super::zone::ZoneAllocator::new(),
        }
    }

    /// Allocates a new [`ObjectPage`] from the System.
    fn alloc_page(&self) -> Option<&'static mut ObjectPage<'static>> {
        self.buddy_allocator
            .alloc_pages(
                Layout::from_size_align(Self::BASE_PAGE_SIZE, Self::BASE_PAGE_SIZE).unwrap(),
            )
            .map(|r| unsafe { transmute(r as usize) })
    }

    /// Allocates a new [`LargeObjectPage`] from the system.
    fn alloc_large_page(&self) -> Option<&'static mut LargeObjectPage<'static>> {
        self.buddy_allocator
            .alloc_pages(
                Layout::from_size_align(Self::LARGE_PAGE_SIZE, Self::LARGE_PAGE_SIZE).unwrap(),
            )
            .map(|r| unsafe { transmute(r as usize) })
    }

    #[allow(dead_code)]
    /// Allocate (1 << `order`) virtually and physically contiguous pages using buddy allocator.
    pub(crate) fn allocate_pages(&self, order: usize) -> Option<*mut u8> {
        self.buddy_allocator.alloc_pages(
            Layout::from_size_align(Self::BASE_PAGE_SIZE << order, Self::BASE_PAGE_SIZE << order)
                .unwrap(),
        )
    }

    #[allow(dead_code)]
    /// De-allocates physically contiguous pages returned from [`LockedSlabAllocator::allocate_pages`].
    pub(crate) unsafe fn free_pages(&self, ptr: *mut u8, order: usize) {
        self.buddy_allocator.dealloc(
            ptr,
            Layout::from_size_align(Self::BASE_PAGE_SIZE << order, Self::BASE_PAGE_SIZE << order)
                .unwrap(),
        );
    }
}

unsafe impl<const ORDER: usize, Platform: MemoryProvider> GlobalAlloc
    for LockedSlabAllocator<'static, ORDER, Platform>
{
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        match layout.size() {
            Self::BASE_PAGE_SIZE => self
                .buddy_allocator
                .alloc_pages(
                    Layout::from_size_align(Self::BASE_PAGE_SIZE, Self::BASE_PAGE_SIZE).unwrap(),
                )
                .expect("allocate page"),
            Self::LARGE_PAGE_SIZE => self
                .buddy_allocator
                .alloc_pages(
                    Layout::from_size_align(Self::LARGE_PAGE_SIZE, Self::LARGE_PAGE_SIZE).unwrap(),
                )
                .expect("allocate large page"),
            0..=super::zone::ZoneAllocator::MAX_ALLOC_SIZE => {
                match self.slab_allocator.allocate(layout) {
                    Ok(ptr) => ptr.as_ptr(),
                    Err(AllocationError::OutOfMemory) => {
                        if layout.size() <= super::zone::ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                            self.alloc_page().map_or(core::ptr::null_mut(), |page| {
                                self.slab_allocator
                                    .refill_and_allocate(layout, page)
                                    .expect("Failed to refill or allocate")
                                    .as_ptr()
                            })
                        } else {
                            self.alloc_large_page()
                                .map_or(core::ptr::null_mut(), |large_page| {
                                    self.slab_allocator
                                        .refill_large_and_allocate(layout, large_page)
                                        .expect("Failed to refill large page or allocate")
                                        .as_ptr()
                                })
                        }
                    }
                    Err(AllocationError::InvalidLayout) => {
                        panic!("Invalid layout: {:?}", layout);
                    }
                }
            }
            _ => self
                .buddy_allocator
                .alloc_pages(layout)
                .expect("allocate page"),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        match layout.size() {
            Self::BASE_PAGE_SIZE => self.buddy_allocator.dealloc(ptr, layout),
            Self::LARGE_PAGE_SIZE => self.buddy_allocator.dealloc(ptr, layout),
            0..=super::zone::ZoneAllocator::MAX_ALLOC_SIZE => {
                if let Some(ptr) = NonNull::new(ptr) {
                    self.slab_allocator
                        .deallocate(ptr, layout)
                        .expect("Failed to deallocate");
                }

                // TODO: An proper reclamation strategy could be implemented here
                // to release empty pages back from the ZoneAllocator to the buddy allocator.
            }
            _ => {
                self.buddy_allocator.dealloc(ptr, layout);
            }
        }
    }
}
