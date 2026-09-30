// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management

use crate::arch::{PhysAddr, VirtAddr};

pub(crate) mod pgtable;

#[cfg(test)]
mod tests;

/// Kernel-supplied page source for [`crate::VmKernel::new`].
///
/// # Safety
///
/// Successful allocations must provide `1 << order` contiguous, page-aligned,
/// readable/writable pages, exclusively owned until freed. They must lie in
/// `VmKernel::new`'s RAM and remain accessible at `VA = PA + KERNEL_OFFSET`.
pub unsafe trait PageAllocator: Sync {
    /// Allocate `1 << order` pages, or `None` when out of memory.
    fn allocate_pages(&self, order: u32) -> Option<*mut u8>;

    /// # Safety
    ///
    /// `ptr` must come from [`Self::allocate_pages`] with the same `order`.
    unsafe fn free_pages(&self, ptr: *mut u8, order: u32);
}

static PAGE_ALLOCATOR: spin::Once<&'static dyn PageAllocator> = spin::Once::new();

/// # Panics
///
/// Panics if a page allocator is already set.
pub(crate) fn set_page_allocator(allocator: &'static dyn PageAllocator) {
    let mut installed = false;
    PAGE_ALLOCATOR.call_once(|| {
        installed = true;
        allocator
    });
    assert!(installed, "the page allocator is already set");
}

fn page_allocator() -> &'static dyn PageAllocator {
    *PAGE_ALLOCATOR
        .get()
        .expect("page allocation before VmKernel::new")
}

/// Physical memory for page tables and the VA/PA translation of the kernel
/// mapping (`VA = PA + KERNEL_OFFSET`).
pub trait MemoryProvider {
    /// Allocate `1 << order` virtually and physically contiguous pages.
    fn mem_allocate_pages(order: u32) -> Option<*mut u8>;

    /// # Safety
    ///
    /// `ptr` must come from [`Self::mem_allocate_pages`] with the same `order`.
    unsafe fn mem_free_pages(ptr: *mut u8, order: u32);

    /// Only valid for addresses in the kernel mapping.
    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        PhysAddr::new_truncate(va.as_u64() - crate::KERNEL_OFFSET)
    }

    /// Only valid for physical addresses in the kernel mapping.
    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        VirtAddr::new_truncate(pa.as_u64() + crate::KERNEL_OFFSET)
    }
}

impl MemoryProvider for crate::VmKernel {
    fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
        page_allocator().allocate_pages(order)
    }

    unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
        // Safety: forwarded to the caller.
        unsafe { page_allocator().free_pages(ptr, order) }
    }
}

pub(crate) type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::VmKernel, ALIGN>;
