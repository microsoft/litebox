#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::{
    arch::{gdt, instrs::hlt_loop, interrupts},
    mshv::hvcall,
    mshv::hvcall_vp,
    serial_println,
};

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

/// # Panics
///
/// Panics if it failed to enable VTL on online cores (except core 0)
pub fn secondary_init(online_cores: u32) {
    if let Err(e) = hvcall_vp::init_vtl_aps(online_cores) {
        panic!("Err: {:?}", e);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
