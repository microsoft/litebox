// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management module

use crate::arch::{PhysAddr, VirtAddr};

pub(crate) mod active;
pub(crate) mod pgtable;
pub mod tlb;
// The foreign-memory VA allocator currently serves only LVBS. Keep its
// software tests available without enabling the concrete platform.
#[cfg(any(feature = "lvbs", test))]
pub(crate) mod vmap;

#[cfg(test)]
pub mod tests;

/// Memory and translation-coherence resources used by the kernel page tables.
///
/// A provider type identifies one stable allocation/translation domain. All
/// tables using it must return frames to the same allocator that supplied them;
/// changing an allocator or address translation while frames are live is invalid.
/// Providers are independent of the kernel object so allocation works during
/// early boot, before a kernel has been constructed.
pub trait MemoryProvider: Send + Sync + 'static {
    /// Platform-selected synchronous invalidation. No implicit local-only
    /// default: a backend must account for every CPU that can use its mappings.
    type Tlb: tlb::TlbInvalidation;

    /// Diagnostic output selected alongside the memory backend. No global
    /// registration is required for allocation or page-table fault diagnostics.
    fn print(args: core::fmt::Arguments<'_>);

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

/// Architecture page table using the memory resources selected by its owner.
/// Tests and production use the same type; there is no crate-wide backend alias.
pub type PageTable<M, const ALIGN: usize> =
    crate::arch::mm::paging::X64PageTable<'static, M, ALIGN>;
