pub const PAGE_SIZE: usize = 4096;
pub const PTES_PER_PAGE: usize = 512;

pub const VSM_PMD_SIZE: usize = PAGE_SIZE * PTES_PER_PAGE;
pub const VSM_SK_INITIAL_MAP_SIZE: usize = 16 * 1024 * 1024;
pub const VSM_SK_PTE_PAGES_COUNT: usize = VSM_SK_INITIAL_MAP_SIZE / VSM_PMD_SIZE;

pub const VTL1_TOTAL_MEMORY_SIZE: usize = 128 * 1024 * 1024;
pub const VTL1_PRE_POPULATED_MEMORY_SIZE: usize = VSM_SK_INITIAL_MAP_SIZE;

// physical page frames specified by VTL0 kernel
pub const VTL1_GDT_PAGE: usize = 0;
pub const VTL1_TSS_PAGE: usize = 1;
pub const VTL1_PML4E_PAGE: usize = 2;
pub const VTL1_PDPE_PAGE: usize = 3;
pub const VTL1_PDE_PAGE: usize = 4;
pub const VTL1_PTE_0_PAGE: usize = 5;
// pub const VTL1_PTE_63_PAGE: usize = 68;
// use this stack only for per-core VTL startup
pub const VTL1_KERNEL_STACK_PAGE: usize = VTL1_PTE_0_PAGE + VSM_SK_PTE_PAGES_COUNT;

// TODO: get addresses from VTL call params rather than use these static indexes
pub const VTL1_BOOT_PARAMS_PAGE: usize = VTL1_KERNEL_STACK_PAGE + 1;
pub const VTL1_CMDLINE_PAGE: usize = VTL1_BOOT_PARAMS_PAGE + 1;

unsafe extern "C" {
    static _memory_base: u8;
}

// TODO: should be removed in the future
#[inline]
pub fn get_memory_base_address() -> u64 {
    &raw const _memory_base as u64
}

#[inline]
pub fn get_address_of_special_page(page: usize) -> u64 {
    get_memory_base_address() + (page as u64) * PAGE_SIZE as u64
}

// repurpose page frames pre-allocated for VTL1 kernel
// TODO: use heap or embed this info in the binary
// pub const VTL1_HEAP_START_PAGE: usize = 3092;
// pub const VTL1_HEAP_END_PAGE: usize = 4091;
// pub const VTL1_TEMP_PTE_PAGE: usize = 4092;
// pub const VTL1_EXT_PTE_BASE: usize = 4096;

// special user pages
// TODO: use heap
// pub const DL_PHDR_INFO_PAGE: u64 = 0x1f_f000;
// pub const KERNEL_USER_SHARED_PAGE: u64 = 0x1f_e000;
// pub const USER_STACK_TOP: u64 = 0x1f_e000;
// pub const USER_CODE_BASE: u64 = 0x1000;
