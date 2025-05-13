#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::{
    arch::{gdt, instrs::hlt_loop, interrupts},
    host::{bootparam::get_vtl1_memory_info, lvbs_impl::init_heap_mem_block},
    kernel_context::get_core_id,
    mm::MemoryProvider,
    mshv::{
        hvcall,
        vtl1_mem_layout::{PAGE_SIZE, VTL1_HEAP_SIZE, VTL1_HEAP_START, VTL1_PML4E_PAGE},
    },
    serial_println,
};
use litebox_platform_multiplex::{Platform, set_platform};

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn per_core_init() {
    gdt::init();
    interrupts::init_idt();
    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }

    if get_core_id() != 0 {
        return;
    }

    if let Ok((start, size)) = get_vtl1_memory_info() {
        let vtl1_start = x86_64::PhysAddr::new(start);
        let vtl1_end = x86_64::PhysAddr::new(start + size);

        if init_heap_mem_block(
            <Platform as MemoryProvider>::pa_to_va(vtl1_start)
                + VTL1_HEAP_START.try_into().unwrap(),
            <Platform as MemoryProvider>::pa_to_va(vtl1_start)
                + (VTL1_HEAP_START + VTL1_HEAP_SIZE).try_into().unwrap(),
        )
        .is_err()
        {
            serial_println!("Failed to initialize heap memory block");
        }

        let pml4_table_addr = vtl1_start + u64::try_from(PAGE_SIZE * VTL1_PML4E_PAGE).unwrap();
        set_platform(Platform::new(pml4_table_addr, vtl1_start, vtl1_end));
    } else {
        panic!("Failed to get memory info");
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
