#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::{
    arch::{gdt, instrs::hlt_loop},
    mshv::hvcall,
    serial_println,
};

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn per_core_init() {
    gdt::init();
    litebox_platform_lvbs_isr::init_idt();
    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
