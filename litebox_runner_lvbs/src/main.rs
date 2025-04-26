#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};
use lazy_static::lazy_static;
use litebox_platform_lvbs::{
    arch::{gdt, interrupts},
    host::LvbsLinuxKernel,
    kernel_context::{KERNEL_STACK_SIZE, get_per_core_kernel_context},
    mshv::{hvcall, vtl1_mem_layout::get_memory_base_address},
    port_println,
};
use litebox_runner_lvbs::hlt_loop;
use spin::Mutex;
use x86_64::addr::PhysAddr;

lazy_static! {
    static ref PLATFORM: Mutex<&'static LvbsLinuxKernel> = Mutex::new(LvbsLinuxKernel::new(
        PhysAddr::new(get_memory_base_address())
    ));
}

#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    let kernel_context = get_per_core_kernel_context();
    let stack_top = &raw const kernel_context.kernel_stack as u64 + (KERNEL_STACK_SIZE - 1) as u64;

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
    port_println!("Hello from LiteBox for LVBS!");

    gdt::init();
    interrupts::init_idt();
    hvcall::per_core_init();

    // port_println!("LiteBox VTL1 Runner");

    // set up VTL1 environment
    unsafe {
        asm!(
            "vmcall",
             in("rax") 0x0, in("rcx") 0x12, in("r8") 0
        );
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
