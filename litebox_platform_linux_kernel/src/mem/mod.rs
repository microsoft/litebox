//! Memory management module including:
//! - Memory provider
//! - Page table management

use buddy_system_allocator::Heap;

pub mod buddy;
#[cfg(test)]
pub mod tests;

pub trait MemoryProvider {
    /// For page allocation.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::error::Errno>;

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
}
