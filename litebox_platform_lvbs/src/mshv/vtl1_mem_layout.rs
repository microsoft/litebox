// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL1 physical memory layout (LVBS-specific)

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;
pub const PTES_PER_PAGE: usize = 512;

pub const VSM_PMD_SIZE: usize = PAGE_SIZE * PTES_PER_PAGE;
pub const VSM_SK_INITIAL_MAP_SIZE: usize = 16 * 1024 * 1024;
pub const VSM_SK_PTE_PAGES_COUNT: usize = VSM_SK_INITIAL_MAP_SIZE / VSM_PMD_SIZE;

pub const VTL1_PRE_POPULATED_MEMORY_SIZE: usize = VSM_SK_INITIAL_MAP_SIZE;

// physical page frames specified by VTL0 kernel
pub const VTL1_GDT_PAGE: usize = 0;
pub const VTL1_TSS_PAGE: usize = 1;
pub const VTL1_PML4E_PAGE: usize = 2;
pub const VTL1_PDPE_PAGE: usize = 3;
pub const VTL1_PDE_PAGE: usize = 4;
pub const VTL1_PTE_0_PAGE: usize = 5;

// use this stack only for per-core VTL startup
pub const VTL1_KERNEL_STACK_PAGE: usize = VTL1_PTE_0_PAGE + VSM_SK_PTE_PAGES_COUNT;

/// PDPT page for the Phase 1 high-canonical PML4 entry. Placed after the
/// VTL0-reserved special pages (GDT, TSS, PT pages, and stack) so that all 8
/// VTL0 PTE pages remain available for the high-canonical mapping. This page
/// is within the VTL0 identity-mapped 16 MiB region but is otherwise unused
/// memory.
pub const VTL1_REMAP_PDPT_PAGE: usize = VTL1_KERNEL_STACK_PAGE + 1;

/// PDE page for the Phase 1 high-canonical mapping. PDE entries point to
/// all 8 VTL0 PTE pages (pages 5–12) to establish 4KB-granularity mappings
/// covering the full 16 MiB of VTL1 pre-populated memory.
pub const VTL1_REMAP_PDE_PAGE: usize = VTL1_REMAP_PDPT_PAGE + 1;

/// Vault backing pages in the unused boot gap, excluded from the normal mapping
/// and allocator. PRK, dispatch page, then the private stack.
pub const VTL1_VAULT_START_PAGE: usize = VTL1_REMAP_PDE_PAGE + 1;
// The current KDF needs ~18 KiB in debug and ~1.3 KiB in release.
pub const VTL1_VAULT_STACK_PAGES: usize = if cfg!(debug_assertions) { 8 } else { 2 };
pub const VTL1_VAULT_PAGES: usize = 2 + VTL1_VAULT_STACK_PAGES;
const _: () = assert!(VTL1_VAULT_START_PAGE + VTL1_VAULT_PAGES <= VTL1_INIT_HEAP_START_PAGE);

pub(crate) fn vault_frame_range(
    memory_start: x86_64::PhysAddr,
) -> x86_64::structures::paging::frame::PhysFrameRange {
    use x86_64::structures::paging::PhysFrame;
    let start =
        PhysFrame::containing_address(memory_start) + u64::try_from(VTL1_VAULT_START_PAGE).unwrap();
    PhysFrame::range(start, start + u64::try_from(VTL1_VAULT_PAGES).unwrap())
}

/// Number of VTL0 PTE pages available for the Phase 1 high-canonical mapping.
/// All 8 PTE pages are used, covering 8 * 2 MiB = 16 MiB.
///
/// This must fit in a single PDE page (≤ 512 entries) because Phase 1
/// allocates only one PDE page for the high-canonical mapping.
pub const VTL1_REMAP_PTE_COUNT: usize = VSM_SK_PTE_PAGES_COUNT;
const _: () = assert!(
    VTL1_REMAP_PTE_COUNT <= PTES_PER_PAGE,
    "Phase 1 remap assumes all PTE pages fit in a single PDE page"
);

// initial heap to add the entire VTL1 physical memory to the kernel page table
// We need ~256 KiB to cover the entire VTL1 physical memory (128 MiB)
pub const VTL1_INIT_HEAP_START_PAGE: usize = 256;
pub const VTL1_INIT_HEAP_SIZE: usize = 1024 * 1024;

unsafe extern "C" {
    static _memory_base: u8;
    static _heap_start: u8;
    static _text_start: u8;
    static _text_end: u8;
    static _rodata_start: u8;
    static _rodata_end: u8;
    static _hvcall_page_start: u8;
    static _rela_start: u8;
    static _rela_end: u8;
}

#[inline]
pub fn get_memory_base_address() -> u64 {
    &raw const _memory_base as u64
}

#[inline]
pub fn get_heap_start_address() -> u64 {
    &raw const _heap_start as u64
}

#[inline]
pub fn get_address_of_special_page(page: usize) -> u64 {
    get_memory_base_address() + (page as u64) * PAGE_SIZE as u64
}

/// Returns the start address of the VTL1 kernel text (code) section.
#[inline]
pub fn get_text_start_address() -> u64 {
    &raw const _text_start as u64
}

/// Returns the end address (exclusive) of the VTL1 kernel text (code) section.
#[inline]
pub fn get_text_end_address() -> u64 {
    &raw const _text_end as u64
}

/// Returns the start address of the VTL1 kernel `.rodata` section.
#[inline]
pub fn get_rodata_start_address() -> u64 {
    &raw const _rodata_start as u64
}

/// Returns the end address (exclusive) of the VTL1 kernel `.rodata` section.
#[inline]
pub fn get_rodata_end_address() -> u64 {
    &raw const _rodata_end as u64
}

/// Returns the start address of the Hyper-V hypercall code page.
#[inline]
pub fn get_hvcall_page_start_address() -> u64 {
    &raw const _hvcall_page_start as u64
}

/// Returns the start address of the `.rela.dyn` section.
#[inline]
pub fn get_rela_start_address() -> u64 {
    &raw const _rela_start as u64
}

/// Returns the end address (exclusive) of the `.rela.dyn` section.
#[inline]
pub fn get_rela_end_address() -> u64 {
    &raw const _rela_end as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_reservation_fits_between_boot_tables_and_heap() {
        let base = x86_64::PhysAddr::new(0x0800_0000);
        let range = vault_frame_range(base);
        assert_eq!(
            range.start.start_address(),
            base + (VTL1_VAULT_START_PAGE * PAGE_SIZE) as u64
        );
        assert_eq!(range.end - range.start, VTL1_VAULT_PAGES as u64);
        assert!(
            range.start.start_address() >= base + ((VTL1_REMAP_PDE_PAGE + 1) * PAGE_SIZE) as u64
        );
        assert!(range.end.start_address() <= base + (VTL1_INIT_HEAP_START_PAGE * PAGE_SIZE) as u64);
    }
}
