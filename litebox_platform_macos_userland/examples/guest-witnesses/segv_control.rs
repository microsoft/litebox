// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Control witness for `HvfBackend`'s lazy write-xor-execute toggle: a fault
//! on a page the toggle was never asked to manage must still reach the guest
//! as a real SIGSEGV. This program maps one ordinary read-only page and writes
//! to it; reaching the line after the write is the failure, and the runner's
//! exit status must be 11 (the delivered signal number).
//!
//! Same no_std / static-PIE shape as `wx_toggle.rs`; see that file's header.
#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { syscall1(93, 111) };
    loop {}
}

#[inline(always)]
unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret,
             out("x1") _, out("x2") _, out("x3") _, out("x4") _, out("x5") _,
             options(nostack));
    }
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, in("x1") a1, in("x2") a2,
             out("x3") _, out("x4") _, out("x5") _,
             options(nostack));
    }
    ret
}

#[inline(always)]
unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, in("x1") a1, in("x2") a2,
             in("x3") a3, in("x4") a4, in("x5") a5,
             options(nostack));
    }
    ret
}

unsafe fn write_str(s: &[u8]) {
    unsafe { syscall3(64, 1, s.as_ptr() as u64, s.len() as u64) };
}

const PAGE: u64 = 16 * 1024;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        write_str(b"segvtest: start\n");
        // An ordinary read-only mapping, never registered with the toggle.
        let addr = syscall6(222, 0, PAGE, 0x1, 0x22, u64::MAX, 0);
        if addr < 0 {
            write_str(b"segvtest: mmap FAIL\n");
            syscall1(93, 1);
        }
        write_str(b"segvtest: mmap(PROT_READ) ok, about to write (should SIGSEGV)\n");
        let p = addr as *mut u8;
        core::ptr::write_volatile(p, 0xAA);
        // Must not reach here.
        write_str(b"segvtest: BUG -- write to read-only page did not fault\n");
        syscall1(93, 2);
    }
    loop {}
}
