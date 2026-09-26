// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Link the platform as a runner would, with a caller-owned global allocator.
//! A global allocator accidentally reintroduced in the shared platform makes
//! this test binary fail to build. Run with `--no-default-features`: no concrete
//! LVBS code, boot registration, or VTL linker symbols belong to this runner.

#![cfg(not(feature = "lvbs"))]

#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

use litebox_platform_lvbs::mm::{MemoryProvider, PageTable, tlb::TlbInvalidation};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{Page, Size4KiB},
};

struct RunnerMemory;
struct SoftwareOnlyTlb;

// SAFETY: this fixture is never loaded into CR3 and has no hardware translations.
unsafe impl TlbInvalidation for SoftwareOnlyTlb {
    fn invalidate(_start: Page<Size4KiB>, _page_count: usize) {}
}

impl MemoryProvider for RunnerMemory {
    type Tlb = SoftwareOnlyTlb;
    const GVA_OFFSET: VirtAddr = VirtAddr::zero();
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
        None
    }
    unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
        panic!("no frames allocated");
    }
    unsafe fn mem_fill_pages(_start: usize, _size: usize) {
        panic!("no boot memory provided");
    }
    fn va_to_pa(va: VirtAddr) -> PhysAddr {
        PhysAddr::new(va.as_u64())
    }
    fn pa_to_va(pa: PhysAddr) -> VirtAddr {
        VirtAddr::new(pa.as_u64())
    }
}

#[test]
fn runner_can_prepare_common_per_cpu_storage_without_lvbs() {
    use litebox_platform_lvbs::per_cpu_variables::PerCpuVariables;
    let mut storage = Box::<PerCpuVariables>::new_uninit();
    // SAFETY: this is aligned, writable, uninitialized storage owned by the
    // caller. No GSBASE change or privileged instructions are involved.
    let cpu = unsafe {
        PerCpuVariables::initialize_at(storage.as_mut_ptr());
        storage.assume_init()
    };
    cpu.init_stacks();
    // A real runner configures XCR0 before using these buffers. Allocation
    // alone is ordinary memory access and is safe in this software-only test.
    cpu.allocate_xsave_areas();
}

#[test]
fn runner_can_select_allocator_and_name_its_own_page_table_type() {
    assert!(std::mem::size_of::<PageTable<RunnerMemory, 4096>>() > 0);
    // Force an actual allocation through the runner's System allocator.
    let mut values = Vec::new();
    values.extend(0..std::hint::black_box(64));
    assert_eq!(values.iter().sum::<u32>(), 2016);
}
