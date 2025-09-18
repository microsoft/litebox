//! Some Assembly instructions

use core::arch::asm;

#[expect(clippy::inline_always)]
#[inline(always)]
pub fn hlt_loop() -> ! {
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}

#[expect(clippy::inline_always)]
#[inline(always)]
pub fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;

    unsafe {
        asm!(
            "rdmsr",
            in("rcx") msr, out("rax") low, out("rdx") high,
            options(nostack)
        );
    }

    (u64::from(high) << 32) | u64::from(low)
}

#[expect(clippy::inline_always)]
#[inline(always)]
pub fn wrmsr(msr: u32, value: u64) {
    let low = (value & 0xffff_ffff) as u32;
    let high = (value >> 32) as u32;

    unsafe {
        asm!(
            "wrmsr",
            in("rcx") msr, in("rax") low, in("rdx") high,
            options(nostack)
        );
    }
}

#[expect(clippy::inline_always)]
#[inline(always)]
pub fn rdgsbase() -> u64 {
    let gsbase: u64;
    unsafe {
        asm!("rdgsbase {}", out(reg) gsbase, options(nostack, preserves_flags));
    }
    gsbase
}

#[expect(clippy::inline_always)]
#[inline(always)]
pub fn wrgsbase(gsbase: u64) {
    unsafe { asm!("wrgsbase {}", in(reg) gsbase, options(nostack, preserves_flags)) }
}
