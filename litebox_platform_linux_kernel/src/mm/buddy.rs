//! Page Allocator using buddy allocator

use core::{
    alloc::{GlobalAlloc, Layout},
    ops::Deref,
    ptr::NonNull,
};

use buddy_system_allocator::Heap;
use litebox::{
    platform::RawMutexProvider,
    sync::{Mutex, Synchronization},
};

use super::MemoryProvider;

/// A locked version of `Heap` with rescue before oom
///
/// # Usage
///
/// Create a locked heap:
/// ```
/// let heap = LockedHeapWithRescue::new(|heap: &mut Heap<33>, layout: &core::alloc::Layout| {});
/// ```
///
/// Before oom, the allocator will try to call rescue function and try for one more time.
/// Note we use [`spin::mutex::SpinMutex`] instead of our own Mutex because SpinMutex does not require
/// an allocator, which breaks the circular dependency.
pub struct LockedHeapWithRescue<const ORDER: usize, Platform: MemoryProvider> {
    inner: SpinMutex<Heap<ORDER>>,
    platform: core::marker::PhantomData<Platform>,
}

impl<'a, const ORDER: usize, Platform: RawMutexProvider> LockedHeapWithRescue<'a, ORDER, Platform> {
    /// Creates an empty heap
    pub fn new(sync: &'a Synchronization<'_, Platform>) -> Self {
        LockedHeapWithRescue {
            inner: sync.new_mutex(Heap::<ORDER>::new()),
        }
    }
}

impl<'a, const ORDER: usize, Platform: RawMutexProvider> Deref
    for LockedHeapWithRescue<'a, ORDER, Platform>
{
    type Target = Mutex<'a, Platform, Heap<ORDER>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const ORDER: usize, Platform: RawMutexProvider + MemoryProvider>
    LockedHeapWithRescue<'_, ORDER, Platform>
{
    /// Allocates pages (page_size >= 4096)
    pub(super) fn alloc_pages(&self, layout: Layout) -> Option<*mut u8> {
        let ptr = unsafe { self.alloc(layout) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }
}

unsafe impl<const ORDER: usize, Platform: RawMutexProvider + MemoryProvider> GlobalAlloc
    for LockedHeapWithRescue<'_, ORDER, Platform>
{
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut inner = self.inner.lock();
        match inner.alloc(layout) {
            Ok(allocation) => allocation.as_ptr(),
            Err(_) => {
                Platform::rescue_heap(&mut inner, &layout);
                inner
                    .alloc(layout)
                    .ok()
                    .map_or(core::ptr::null_mut(), |allocation| allocation.as_ptr())
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner
            .lock()
            .dealloc(NonNull::new_unchecked(ptr), layout)
    }
}
