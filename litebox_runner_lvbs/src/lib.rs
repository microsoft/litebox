#![no_std]

use core::arch::asm;

#[inline(always)]
pub fn hlt_loop() -> ! {
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}
