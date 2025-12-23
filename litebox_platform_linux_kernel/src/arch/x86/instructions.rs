// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::arch::asm;

/// Read MSR
#[inline]
pub fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;

    unsafe {
        asm!("rdmsr",
             in("rcx") msr, out("rax") lo, out("rdx") hi,
             options(nostack));
    }

    (u64::from(hi) << 32) | u64::from(lo)
}

/// Write to MSR a given value
#[inline]
pub fn wrmsr(msr: u32, value: u64) {
    #[expect(clippy::cast_possible_truncation)]
    let lo: u32 = value as u32;
    let hi: u32 = (value >> 32) as u32;

    unsafe {
        asm!("wrmsr",
             in("rcx") msr, in("rax") lo, in("rdx") hi,
             options(nostack));
    }
}

#[inline]
pub fn vc_vmgexit() {
    unsafe {
        asm!("rep vmmcall", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn cr3() -> u64 {
    let value: u64;
    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub fn cr2() -> u64 {
    let value: u64;

    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }

    value
}
