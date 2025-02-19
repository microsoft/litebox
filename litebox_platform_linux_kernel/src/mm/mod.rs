//! Memory management module including:
//! - Buddy and Slab allocator

use buddy_system_allocator::Heap;

pub mod buddy;
pub mod slab;
pub mod zone;

#[cfg(test)]
pub mod tests;

/// Memory provider trait for global allocator.
pub trait MemoryProvider {
    /// For page allocation.
    ///
    /// Note this is only called by [`Self::rescue_heap`] when the buddy allocator is out of memory.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::error::Errno>;

    /// Called to refill the buddy allocator when OOM occurs.
    fn rescue_heap<const ORDER: usize>(heap: &mut Heap<ORDER>, layout: &core::alloc::Layout) {
        match Self::alloc(layout) {
            Ok((start, size)) => {
                // TODO: init reference count for allocated pages
                unsafe { heap.add_to_heap(start, start + size) };
            }
            Err(_) => {
                panic!("OOM");
            }
        }
    }

    /// Allocate (1 << `order`) virtually and physically contiguous pages using buddy allocator.
    fn mem_allocate_pages(order: usize) -> Option<*mut u8>;

    /// De-allocates physically consecutive pages returned from [`Self::mem_allocate_pages`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `ptr` is valid and was allocated by this allocator.
    ///
    /// `order` must be the same as the one used during allocation.
    unsafe fn mem_free_pages(ptr: *mut u8, order: usize);
}
