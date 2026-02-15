// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]

extern crate alloc;

use core::{ops::Neg, panic::PanicInfo};
use litebox::{
    mm::linux::PAGE_SIZE,
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::errno::Errno;
use litebox_common_lvbs::{NUM_VTLCALL_PARAMS, VsmFunction};
use litebox_platform_lvbs::{
    arch::{gdt, get_core_id, instrs::hlt_loop, interrupts},
    debug_serial_println,
    host::{bootparam::get_vtl1_memory_info, per_cpu_variables::allocate_per_cpu_variables},
    mm::MemoryProvider,
    mshv::{
        hvcall,
        vsm_intercept::raise_vtl0_gp_fault,
        vtl_switch::vtl_switch,
        vtl1_mem_layout::{
            VTL1_INIT_HEAP_SIZE, VTL1_INIT_HEAP_START_PAGE, VTL1_PML4E_PAGE,
            VTL1_PRE_POPULATED_MEMORY_SIZE, get_heap_start_address,
        },
    },
    serial_println,
};
use litebox_platform_multiplex::Platform;

mod mem_integrity;
mod optee_smc;
mod ringbuffer;
mod vsm;

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn init() -> Option<&'static Platform> {
    let mut ret: Option<&'static Platform> = None;

    if get_core_id() == 0 {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            let vtl1_start = x86_64::PhysAddr::new(start);
            let vtl1_end = x86_64::PhysAddr::new(start + size);

            // Add a small range of mapped memory to the global allocator for populating the base page table.
            // `VTL1_INIT_HEAP_START_PAGE` and `VTL1_INIT_HEP_SIZE` specify a physical address range which is
            // not used by the VTL1 kernel.
            let mem_fill_start =
                TruncateExt::<usize>::truncate(Platform::pa_to_va(vtl1_start).as_u64())
                    + VTL1_INIT_HEAP_START_PAGE * PAGE_SIZE;
            let mem_fill_size = VTL1_INIT_HEAP_SIZE;
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "adding a range of memory to the global allocator: start = {:#x}, size = {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            // Add remaining mapped but non-used memory pages (between `get_heap_start_address()` and
            // `vtl1_start + VTL1_PRE_POPULATED_MEMORY_SIZE`) to the global allocator.
            let mem_fill_start: usize = get_heap_start_address().truncate();
            let mem_fill_size = VTL1_PRE_POPULATED_MEMORY_SIZE
                - TruncateExt::<usize>::truncate(get_heap_start_address() - start);
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "adding a range of memory to the global allocator: start = {:#x}, size = {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            let pml4_table_addr = vtl1_start + (PAGE_SIZE * VTL1_PML4E_PAGE) as u64;
            let platform = Platform::new(pml4_table_addr, vtl1_start, vtl1_end);
            ret = Some(platform);
            litebox_platform_multiplex::set_platform(platform);

            // Add the rest of the VTL1 memory to the global allocator once they are mapped to the base page table.
            let mem_fill_start = mem_fill_start + mem_fill_size;
            let mem_fill_size = TruncateExt::<usize>::truncate(
                size - (mem_fill_start as u64 - Platform::pa_to_va(vtl1_start).as_u64()),
            );
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "adding a range of memory to the global allocator: start = {:#x}, size = {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            allocate_per_cpu_variables();
        } else {
            panic!("Failed to get memory info");
        }
    }

    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
    vsm::init();
    gdt::init();
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();
    Platform::enable_syscall_support();

    ret
}

pub fn run(_platform: Option<&'static Platform>) -> ! {
    let mut return_value: Option<i64> = None;
    loop {
        let params = vtl_switch(return_value);
        return_value = Some(vtlcall_dispatch(&params));
    }
}

/// Dispatch VTL call based on the function ID in params[0] and return the result.
///
/// VTL call is with up to four u64 parameters and returns an i64 result.
/// The first parameter (params[0]) is the VSM function ID to identify the requested service.
/// The remaining parameters (params[1] to params[3]) are function-specific arguments.
///
/// TODO: Consider unified interface signature and naming
/// VTL call is Hyper-V specific. However, in general, there is no fundamental difference
/// between VTL call and TrustZone SMC call, TDX TDCALL, etc.
fn vtlcall_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    let func_id: u32 = params[0].truncate();
    let Ok(func_id) = VsmFunction::try_from(func_id) else {
        return Errno::EINVAL.as_neg().into();
    };
    match func_id {
        VsmFunction::OpteeMessage => {
            let smc_args_pfn = params[1];
            optee_smc::optee_smc_handler_entry(smc_args_pfn)
        }
        _ => vsm::vsm_dispatch(func_id, &params[1..]),
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    match raise_vtl0_gp_fault() {
        Ok(result) => vtl_switch(Some(result.reinterpret_as_signed())),
        Err(err) => vtl_switch(Some((err as u32).reinterpret_as_signed().neg().into())),
    };
    // We assume that once this VTL1 kernel panics, we don't try to resume its execution.
    // This is because, after the panic, the kernel is in an undefined state.
    // Switch back to VTL0, do crash dump, and reboot the machine.
    hlt_loop()
}
