#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::{
    arch::{gdt, instrs::hlt_loop, interrupts},
    host::bootparam::get_vtl1_memory_info,
    kernel_context::get_core_id,
    mm::MemoryProvider,
    mshv::{
        hvcall,
        vtl1_mem_layout::{
            PAGE_SIZE, VTL1_INIT_HEAP_SIZE, VTL1_INIT_HEAP_START_PAGE, VTL1_PML4E_PAGE,
            get_heap_start_address,
        },
    },
    serial_println, set_platform_low,
};
use litebox_platform_multiplex::{Platform, set_platform};

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn init() {
    gdt::init();

    // TODO: IDTs are ignored when VTL1 is enabled. We should implement SynIC.
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();

    if get_core_id() == 0 {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            let vtl1_start = x86_64::PhysAddr::new(start);
            let vtl1_end = x86_64::PhysAddr::new(start + size);

            // Add a small range of mapped memory to the global allocator (to populate the kernel page table).
            unsafe {
                Platform::mem_fill_pages(
                    usize::try_from(Platform::pa_to_va(vtl1_start).as_u64()).unwrap()
                        + VTL1_INIT_HEAP_START_PAGE * PAGE_SIZE,
                    VTL1_INIT_HEAP_SIZE,
                );
            }

            let pml4_table_addr = vtl1_start + u64::try_from(PAGE_SIZE * VTL1_PML4E_PAGE).unwrap();
            let platform = Platform::new(pml4_table_addr, vtl1_start, vtl1_end);
            set_platform(platform);
            set_platform_low(platform); // TODO: this is a temporary solution to allow LVBS functions to access the platform (i.e., kernel page table).

            // Add the rest of the VTL1 memory to the global allocator once they are mapped to the kernel page table.
            unsafe {
                Platform::mem_fill_pages(
                    usize::try_from(get_heap_start_address()).unwrap(),
                    usize::try_from(
                        size - (get_heap_start_address() - Platform::pa_to_va(vtl1_start).as_u64()),
                    )
                    .unwrap(),
                );
            }
        } else {
            panic!("Failed to get memory info");
        }
    }

    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
