// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! DEBUG (ubuntu-26.04 CI SIGILL): a program without glibc, which writes a
//! line and exits, to tell glibc's startup from the shim's.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

const SYS_WRITE: usize = 1;
const SYS_EXIT_GROUP: usize = 231;

#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor ebp, ebp",
        "and rsp, -16",
        "call {main}",
        "ud2",
        main = sym main,
    );
}

extern "C" fn main() -> ! {
    let line = b"hello, nostd\n";
    // SAFETY: writes from a valid buffer, then exits.
    unsafe {
        syscall3(SYS_WRITE, 1, line.as_ptr() as usize, line.len());
        syscall3(SYS_EXIT_GROUP, 0, 0, 0);
    }
    loop {}
}

/// # Safety
///
/// The syscall's requirements.
unsafe fn syscall3(nr: usize, a: usize, b: usize, c: usize) -> isize {
    let ret: isize;
    // SAFETY: forwarded to the caller; `syscall` clobbers only rcx and r11.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // SAFETY: exits.
    unsafe {
        syscall3(SYS_EXIT_GROUP, 101, 0, 0);
    }
    loop {}
}
