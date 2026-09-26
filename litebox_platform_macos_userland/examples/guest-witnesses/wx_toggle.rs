// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Live witness for `HvfBackend`'s lazy write-xor-execute toggle (see
//! `WxToggle` in `hvf_backend.rs`). A guest asks for one region as RWX,
//! writes machine code into two separate pages, executes both, then rewrites
//! page 0 *after* it has already been flipped to read+execute and executes it
//! again: both flip directions, on independent pages, with the new code
//! actually running rather than a stale cached copy. Prints `wxtest: ALL PASS`
//! and exits 0; any mismatch exits with a distinct nonzero code.
//!
//! no_std / no_main / crt-free static-PIE: see project memory
//! `litebox-guest-test-binary-recipe` for why (musl startup is not needed and
//! would only add moving parts to a witness of the page-permission machinery).
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

unsafe fn write_num(mut n: i64) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        unsafe { *buf.get_unchecked_mut(i) = b'0' };
    } else {
        let neg = n < 0;
        if neg {
            n = -n;
        }
        while n > 0 {
            i -= 1;
            unsafe { *buf.get_unchecked_mut(i) = b'0' + (n % 10) as u8 };
            n /= 10;
        }
        if neg {
            i -= 1;
            unsafe { *buf.get_unchecked_mut(i) = b'-' };
        }
    }
    unsafe { write_str(buf.get_unchecked(i..)) };
}

/// Host page size under `--hvf` on Apple Silicon.
const PAGE: u64 = 16 * 1024;

/// `movz x0, #imm16 ; ret`
fn make_fn(imm: u16, out: &mut [u8; 8]) {
    let instr: u32 = 0xD280_0000 | ((imm as u32) << 5);
    out[0..4].copy_from_slice(&instr.to_le_bytes());
    out[4..8].copy_from_slice(&0xD65F_03C0u32.to_le_bytes());
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        write_str(b"wxtest: start\n");

        let len = PAGE * 2;
        // mmap(NULL, 2 pages, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        let addr = syscall6(222, 0, len, 0, 0x22, u64::MAX, 0);
        if addr < 0 {
            write_str(b"wxtest: mmap FAIL\n");
            syscall1(93, 1);
        }
        write_str(b"wxtest: mmap ok addr=");
        write_num(addr);
        write_str(b"\n");
        let base = addr as u64;

        // mprotect(base, len, PROT_READ|PROT_WRITE|PROT_EXEC) -- the call the
        // toggle exists for; before it, this returned ENOMEM.
        let rc = syscall3(226, base, len, 0x7);
        if rc != 0 {
            write_str(b"wxtest: mprotect(RWX) FAIL rc=");
            write_num(rc);
            write_str(b"\n");
            syscall1(93, 2);
        }
        write_str(b"wxtest: mprotect(RWX) ok\n");

        let mut fa = [0u8; 8];
        make_fn(42, &mut fa);
        let p0 = base as *mut u8;
        core::ptr::copy_nonoverlapping(fa.as_ptr(), p0, 8);
        write_str(b"wxtest: wrote fn A to page0\n");

        let mut fb = [0u8; 8];
        make_fn(99, &mut fb);
        let p1 = (base + PAGE) as *mut u8;
        core::ptr::copy_nonoverlapping(fb.as_ptr(), p1, 8);
        write_str(b"wxtest: wrote fn B to page1\n");

        // First execute of page 0: RW -> RX flip.
        let f0: extern "C" fn() -> i64 = core::mem::transmute(p0);
        let r0 = f0();
        write_str(b"wxtest: call page0 -> ");
        write_num(r0);
        write_str(b"\n");
        if r0 != 42 {
            write_str(b"wxtest: MISMATCH page0\n");
            syscall1(93, 3);
        }

        // Page 1 flips independently of page 0.
        let f1: extern "C" fn() -> i64 = core::mem::transmute(p1);
        let r1 = f1();
        write_str(b"wxtest: call page1 -> ");
        write_num(r1);
        write_str(b"\n");
        if r1 != 99 {
            write_str(b"wxtest: MISMATCH page1\n");
            syscall1(93, 4);
        }

        // Page 0 is RX now; writing again must flip it back (RX -> RW).
        let mut fc = [0u8; 8];
        make_fn(7, &mut fc);
        core::ptr::copy_nonoverlapping(fc.as_ptr(), p0, 8);
        write_str(b"wxtest: rewrote page0 (RX->RW->write)\n");

        // ...and executing it must run the NEW code (RW -> RX again).
        let r2 = f0();
        write_str(b"wxtest: call page0 again -> ");
        write_num(r2);
        write_str(b"\n");
        if r2 != 7 {
            write_str(b"wxtest: MISMATCH page0-v2\n");
            syscall1(93, 5);
        }

        // Page 1 was untouched by all of that.
        let r3 = f1();
        write_str(b"wxtest: call page1 again -> ");
        write_num(r3);
        write_str(b"\n");
        if r3 != 99 {
            write_str(b"wxtest: MISMATCH page1-v2\n");
            syscall1(93, 6);
        }

        write_str(b"wxtest: ALL PASS\n");
        syscall1(93, 0);
    }
    loop {}
}
