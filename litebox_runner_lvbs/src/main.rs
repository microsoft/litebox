#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};
use litebox_runner_lvbs::hlt_loop;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    unsafe {
        asm!(
            "push rax",
            "call {kernel_main}",
            kernel_main = sym kernel_main
        );
    }

    hlt_loop()
}

pub fn kernel_main() -> ! {
    // let kernel = litebox_platform_lvbs::LinuxKernel::new(x86_64::PhysAddr::new(0));

    // set up VTL1 environment
    unsafe {
        asm!("vmcall", in("rax") 0x0, in("rcx") 0x12, in("r8") 0);
    }
    // kernel.switch(0);

    // Event loop for VTL Calls which never terminates
    loop {
        // let vtl_call_param = kernel.switch(result);

        // invoke a vtl call handler based on entry reason and params

        let result: u64 = 0;
        unsafe {
            asm!("vmcall", in("rax") 0x0, in("rcx") 0x12, in("r8") result);
        }
        // kernel.switch(result);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    hlt_loop()
}
