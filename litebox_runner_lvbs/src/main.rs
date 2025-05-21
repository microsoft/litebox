#![no_std]
#![no_main]

use core::arch::asm;
use litebox_platform_lvbs::{
    arch::instrs::hlt_loop,
    kernel_context::{get_core_id, get_per_core_kernel_context},
    serial_println,
};

#[cfg(debug_assertions)]
use litebox_platform_lvbs::host::bootparam::{dump_boot_params, dump_cmdline};

#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    let kernel_context = get_per_core_kernel_context();
    let stack_top = kernel_context.kernel_stack_top();

    unsafe {
        asm!(
            "mov rsp, rax",
            "and rsp, -16",
            "push rax",
            "call {kernel_main}",
            in("rax") stack_top, kernel_main = sym kernel_main
        );
    }

    hlt_loop()
}

pub fn kernel_main() -> ! {
    let core_id = get_core_id();
    if core_id == 0 {
        serial_println!("==============================");
        serial_println!(" Hello from LiteBox for LVBS! ");
        serial_println!("==============================");

        #[cfg(debug_assertions)]
        dump_boot_params();

        #[cfg(debug_assertions)]
        dump_cmdline();
    }

    let platform = litebox_runner_lvbs::init();
    litebox_runner_lvbs::run(platform)
}
