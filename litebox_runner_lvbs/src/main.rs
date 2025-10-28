#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]

use core::arch::asm;
use litebox_platform_lvbs::{
    arch::{enable_extended_states, enable_fsgsbase, get_core_id, instrs::hlt_loop},
    host::{bootparam::parse_boot_info, per_cpu_variables::with_per_cpu_variables},
    serial_println,
};

#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    enable_fsgsbase();
    enable_extended_states();
    let stack_top = with_per_cpu_variables(
        litebox_platform_lvbs::host::per_cpu_variables::PerCpuVariables::kernel_stack_top,
    );

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

        parse_boot_info();
    }

    let platform = litebox_runner_lvbs::init();
    litebox_runner_lvbs::run(platform)
}
