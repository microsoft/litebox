#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::{
    arch::{gdt, instrs::hlt_loop, interrupts},
    mshv::hvcall,
    serial_println,
};

#[cfg(debug_assertions)]
use litebox_platform_lvbs::mshv::vtl1_mem_layout::{
    VTL1_BOOT_PARAMS_PAGE, get_address_of_special_page,
};

#[cfg(debug_assertions)]
use litebox_platform_lvbs::host::bootparam::BootParams;

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn per_core_init() {
    gdt::init();
    interrupts::init_idt();
    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
}

#[cfg(debug_assertions)]
pub fn print_boot_params() {
    let boot_params = get_address_of_special_page(VTL1_BOOT_PARAMS_PAGE) as *const BootParams;
    unsafe {
        (*boot_params).dump();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
