// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management module

use crate::arch::{PhysAddr, VirtAddr};

pub(crate) mod pgtable;
#[cfg(feature = "optee_syscall")]
pub(crate) mod vmap;

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

    /// Add a range of memory to global allocator.
    /// Morally, the global allocator takes ownership of this range of memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory range is valid and not used by any others.
    unsafe fn mem_fill_pages(start: usize, size: usize);

    /// Obtain physical address (PA) of a page given its direct-map VA.
    ///
    /// The direct map covers all physical memory via `VA = PA + GVA_OFFSET`.
    /// Use this for VTL0 / external physical memory.
    fn va_to_pa_direct(va: VirtAddr) -> PhysAddr {
        PhysAddr::new_truncate(va - Self::GVA_OFFSET)
    }

    /// Obtain the direct-map virtual address (VA) of a page given its PA.
    ///
    /// The direct map covers all physical memory via `VA = PA + GVA_OFFSET`.
    /// Use this for VTL0 / external physical memory.
    fn pa_to_va_direct(pa: PhysAddr) -> VirtAddr {
        let pa = pa.as_u64() & !Self::PRIVATE_PTE_MASK;
        let va = VirtAddr::new_truncate(pa + Self::GVA_OFFSET.as_u64());
        #[cfg(feature = "optee_syscall")]
        assert!(
            va.as_u64() < crate::VMAP_START as u64,
            "VA {va:#x} is out of range for direct mapping"
        );
        va
    }

    /// Obtain physical address (PA) of a page given its kernel VA.
    ///
    /// The VTL1 kernel region maps kernel memory via `VA = PA + KERNEL_OFFSET`.
    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        PhysAddr::new_truncate(va.as_u64() - crate::KERNEL_OFFSET)
    }

    /// Obtain the kernel virtual address (VA) of a page given its PA.
    ///
    /// The VTL1 kernel region maps kernel memory via `VA = PA + KERNEL_OFFSET`.
    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        VirtAddr::new_truncate(pa.as_u64() + crate::KERNEL_OFFSET)
    }

    /// Set physical address as private via mask.
    fn make_pa_private(pa: PhysAddr) -> PhysAddr {
        PhysAddr::new_truncate(pa.as_u64() | Self::PRIVATE_PTE_MASK)
    }
}

#[cfg(all(target_arch = "x86_64", not(test)))]
pub type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::host::LvbsLinuxKernel, ALIGN>;
#[cfg(all(target_arch = "x86_64", test))]
pub type PageTable<const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, crate::host::mock::MockKernel, ALIGN>;
