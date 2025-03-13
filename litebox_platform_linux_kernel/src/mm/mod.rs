//! Memory management module including:
//! - Buddy and Slab allocator
//! - Page table management

use buddy_system_allocator::Heap;

use crate::arch::{PhysAddr, VirtAddr};

pub(crate) mod alloc;
#[cfg(test)]
pub(crate) mod pgtable;
#[cfg(test)]
pub(crate) mod vm;

#[cfg(test)]
pub mod tests;

/// Memory provider trait for global allocator.
pub trait MemoryProvider {
    /// Global virtual address offset for one-to-one mapping of physical memory
    /// to kernel virtual memory.
    const GVA_OFFSET: VirtAddr;
    /// Mask for private page table entry (e.g., SNP encryption bit).
    /// For simplicity, we assume the mask is constant.
    const PRIVATE_PTE_MASK: u64;

    /// For page allocation from host.
    ///
    /// Note this is only called by [`Self::rescue_heap`] when the buddy allocator is out of memory.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::Errno>;

    /// Returns the memory back to host.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `addr` is valid and was allocated by [`Self::alloc`].
    unsafe fn free(addr: usize);

    /// Called to refill the buddy allocator when OOM occurs.
    fn rescue_heap<const ORDER: usize>(heap: &mut Heap<ORDER>, layout: &core::alloc::Layout) {
        match Self::alloc(layout) {
            Ok((start, size)) => {
                // the returned size might be larger than requested (i.e., layout.size())
                // TODO: init reference count for allocated pages
                unsafe { heap.add_to_heap(start, start + size) };
            }
            Err(e) => {
                panic!("OOM: {e}");
            }
        }
    }

    /// Allocate (1 << `order`) virtually and physically contiguous pages from global allocator.
    fn mem_allocate_pages(order: u32) -> Option<*mut u8>;

    /// De-allocates virtually and physically contiguous pages returned from [`Self::mem_allocate_pages`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `ptr` is valid and was allocated by this allocator.
    ///
    /// `order` must be the same as the one used during allocation.
    unsafe fn mem_free_pages(ptr: *mut u8, order: u32);

    /// Obtain physical address (PA) of a page given its VA
    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        PhysAddr::new_truncate(va - Self::GVA_OFFSET)
    }

    /// Obtain virtual address (VA) of a page given its PA
    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        let pa = pa.as_u64() & !Self::PRIVATE_PTE_MASK;
        VirtAddr::new_truncate(pa + Self::GVA_OFFSET.as_u64())
    }

    /// Set physical address as private via mask.
    fn make_pa_private(pa: PhysAddr) -> PhysAddr {
        PhysAddr::new_truncate(pa.as_u64() | Self::PRIVATE_PTE_MASK)
    }
}
