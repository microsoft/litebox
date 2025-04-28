#![no_std]
#![no_main]

use core::arch::asm;
use litebox_platform_lvbs::{
    arch::instrs::hlt_loop,
    kernel_context::{get_core_id, get_per_core_kernel_context},
    mshv::vtl_switch::vtl_return,
    serial_println,
};

// shared? per-core?
// lazy_static! {
//     static ref PLATFORM: Mutex<&'static LvbsLinuxKernel> = Mutex::new(LvbsLinuxKernel::new(
//         PhysAddr::new(get_memory_base_address())
//     ));
// }

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
        serial_println!("Hello from LiteBox for LVBS!");
    }

    // TODO: BSP init (e.g., heap, ...)

    litebox_runner_lvbs::per_core_init();
    vtl_return(0);

    if core_id == 0 {
        // TODO: get this info through VTL call (cpumask)
        let online_cores = 6;
        litebox_runner_lvbs::secondary_init(online_cores);
        vtl_return(0);
    }

    // TODO: event loop
    loop {
        let result: u64 = 0;
        vtl_return(result);
    }
}
