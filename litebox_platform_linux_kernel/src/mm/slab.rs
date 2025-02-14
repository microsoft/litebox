//! Allocator that uses buddy allocator for pages and slab allocator for small objects.

use core::{alloc::GlobalAlloc, mem::transmute, ptr::NonNull};

use litebox::{
    platform::RawMutexProvider,
    sync::{Mutex, Synchronization},
};
use slabmalloc::{AllocationError, Allocator, LargeObjectPage, ObjectPage, ZoneAllocator};

use super::{buddy::LockedHeapWithRescue, MemoryProvider};

/// Allocator that uses buddy allocator for pages and slab allocator for small objects.
///
/// Note this is not very scalable since we use a single big lock around the slab allocator.
pub struct LockedSlabAllocator<'a, const ORDER: usize, Platform: RawMutexProvider + MemoryProvider>
{
    buddy_allocator: LockedHeapWithRescue<'a, ORDER, Platform>,
    slab_allocator: Mutex<'a, Platform, ZoneAllocator<'static>>,
}

impl<'a, const ORDER: usize, Platform: RawMutexProvider + MemoryProvider>
    LockedSlabAllocator<'a, ORDER, Platform>
{
    const BASE_PAGE_SIZE: usize = 4096;
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    pub fn new(sync: &'a Synchronization<'_, Platform>) -> Self {
        LockedSlabAllocator {
            buddy_allocator: LockedHeapWithRescue::new(sync),
            slab_allocator: sync.new_mutex(ZoneAllocator::new()),
        }
    }

    /// Allocates a new [`ObjectPage`] from the System.
    pub fn alloc_page(&self) -> Option<&'static mut ObjectPage<'static>> {
        self.buddy_allocator
            .alloc_pages(Self::BASE_PAGE_SIZE)
            .map(|r| unsafe { transmute(r as usize) })
    }

    /// Allocates a new [`LargeObjectPage`] from the system.
    pub fn alloc_large_page(&self) -> Option<&'static mut LargeObjectPage<'static>> {
        self.buddy_allocator
            .alloc_pages(Self::LARGE_PAGE_SIZE)
            .map(|r| unsafe { transmute(r as usize) })
    }
}

unsafe impl<const ORDER: usize, Platform: RawMutexProvider + MemoryProvider> GlobalAlloc
    for LockedSlabAllocator<'_, ORDER, Platform>
{
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        match layout.size() {
            Self::BASE_PAGE_SIZE => self
                .buddy_allocator
                .alloc_pages(Self::BASE_PAGE_SIZE)
                .expect("allocate page"),
            Self::LARGE_PAGE_SIZE => self
                .buddy_allocator
                .alloc_pages(Self::LARGE_PAGE_SIZE)
                .expect("allocate large page"),
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                let mut allocator = self.slab_allocator.lock();
                match allocator.allocate(layout) {
                    Ok(ptr) => ptr.as_ptr(),
                    Err(AllocationError::OutOfMemory) => {
                        if layout.size() <= ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                            let page = self.alloc_page().expect("allocate page");
                            allocator.refill(layout, page).expect("Failed to refill");
                            allocator
                                .allocate(layout)
                                .expect("Should succeed after refill")
                                .as_ptr()
                        } else {
                            let large_page = self.alloc_large_page().expect("allocate large page");
                            allocator
                                .refill_large(layout, large_page)
                                .expect("Failed to refill large page");
                            allocator
                                .allocate(layout)
                                .expect("Should succeed after refill")
                                .as_ptr()
                        }
                    }
                    Err(AllocationError::InvalidLayout) => {
                        panic!("Invalid layout: {:?}", layout);
                    }
                }
            }
            _ => self
                .buddy_allocator
                .alloc_pages(layout.size())
                .expect("allocate page"),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        match layout.size() {
            Self::BASE_PAGE_SIZE => self.buddy_allocator.dealloc(ptr, layout),
            Self::LARGE_PAGE_SIZE => self.buddy_allocator.dealloc(ptr, layout),
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                if let Some(ptr) = NonNull::new(ptr) {
                    let mut allocator = self.slab_allocator.lock();
                    allocator
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
