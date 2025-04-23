#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    unsafe {
        asm!(
            "push rax",
            "call {kernel_main}",
            kernel_main = sym kernel_main
        );
    }

    loop {}
}

pub fn kernel_main() -> ! {
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
