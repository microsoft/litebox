// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL1 physical memory layout (LVBS-specific)

use thiserror::Error;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;
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

// use this stack only for per-core VTL startup
pub const VTL1_KERNEL_STACK_PAGE: usize = VTL1_PTE_0_PAGE + VSM_SK_PTE_PAGES_COUNT;

// TODO: get addresses from VTL call params rather than use these static indexes
pub const VTL1_BOOT_PARAMS_PAGE: usize = VTL1_KERNEL_STACK_PAGE + 1;
pub const VTL1_CMDLINE_PAGE: usize = VTL1_BOOT_PARAMS_PAGE + 1;

// initial heap to add the entire VTL1 physical memory to the kernel page table
// We need ~256 KiB to cover the entire VTL1 physical memory (128 MiB)
pub const VTL1_INIT_HEAP_START_PAGE: usize = 256;
pub const VTL1_INIT_HEAP_SIZE: usize = 1024 * 1024;

unsafe extern "C" {
    static _memory_base: u8;
    static _heap_start: u8;
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

/// Errors for VTL memory operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum VtlMemoryError {
    #[error("invalid boot parameters")]
    InvalidBootParams,
    #[error("invalid command line")]
    InvalidCmdLine,
}
