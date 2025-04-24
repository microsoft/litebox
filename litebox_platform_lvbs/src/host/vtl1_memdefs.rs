pub const PAGE_SIZE: usize = 4096;
pub const PTES_PER_PAGE: usize = 512;

pub const VSM_PMD_SIZE: usize = PAGE_SIZE * PTES_PER_PAGE;
pub const VSM_SK_INITIAL_MAP_SIZE: usize = 16 * 1024 * 1024;
pub const VSM_SK_PTE_PAGES_COUNT: usize = VSM_SK_INITIAL_MAP_SIZE / VSM_PMD_SIZE;

pub const VTL1_TOTAL_MEMORY_SIZE: usize = 128 * 1024 * 1024;
pub const VTL1_PRE_POPULATED_MEMORY_SIZE: usize = VSM_SK_INITIAL_MAP_SIZE;

// physical page frames specified by VTL0 kernel
pub const VTL1_GDT_PAGE: u32 = 0;
pub const VTL1_TSS_PAGE: u32 = 1;
pub const VTL1_PML4E_PAGE: u32 = 2;
pub const VTL1_PDPE_PAGE: u32 = 3;
pub const VTL1_PDE_PAGE: u32 = 4;
pub const VTL1_PTE_0_PAGE: u32 = 5;
pub const VTL1_KERNEL_STACK_PAGE: u32 = VTL1_PTE_0_PAGE + VSM_SK_PTE_PAGES_COUNT as u32;

// TODO: get addresses from VTL call params rather than use these static indexes
pub const VTL1_BOOT_PARAMS_PAGE: u32 = VTL1_KERNEL_STACK_PAGE + 1;
pub const VTL1_CMDLINE_PAGE: u32 = VTL1_BOOT_PARAMS_PAGE + 1;

// repurpose page frames pre-allocated for VTL1 kernel
// TODO: use heap or embed this info in the binary
pub const VTL1_HEAP_START_PAGE: u32 = 3092;
pub const VTL1_HEAP_END_PAGE: u32 = 4091;
pub const VTL1_TEMP_PTE_PAGE: u32 = 4092;
pub const VTL1_VP_ASSIST_PAGE: u32 = 4093;
pub const VTL1_HYPERCALL_PAGE: u32 = 4094;
pub const VTL1_HV_SIMP_PAGE: u32 = 4095;
pub const VTL1_EXT_PTE_BASE: u32 = 4096;

// special user pages
// TODO: use heap
pub const DL_PHDR_INFO_PAGE: u64 = 0x1f_f000;
pub const KERNEL_USER_SHARED_PAGE: u64 = 0x1f_e000;
pub const USER_STACK_TOP: u64 = 0x1f_e000;
pub const USER_CODE_BASE: u64 = 0x1000;
