//! Memory management module

use crate::arch::{PhysAddr, VirtAddr};

pub(crate) mod pgtable;

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

#[cfg(all(target_arch = "x86_64", not(test)))]
pub type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::host::snp::SnpLinuxKenrel, ALIGN>;
#[cfg(all(target_arch = "x86_64", test))]
pub type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::host::mock::MockKernel, ALIGN>;
