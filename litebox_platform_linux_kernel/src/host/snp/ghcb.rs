use core::arch::asm;

const GHCB_MSR: u32 = 0xc0010130;
const GHCB_HV_DEBUG: u64 = 0xf03;

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

pub fn str2u64(s: &str, start: usize, size: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf[0..size].copy_from_slice(&s.as_bytes()[start..(start + size)]);
    u64::from_le_bytes(buf)
}

pub fn ghcb_prints(s: &str) {
    let mut index = 0;
    let n = s.len();
    let orig_val: u64 = rdmsr(GHCB_MSR);
    while index < n {
        let len = 6.min(n - index);
        let mut val = GHCB_HV_DEBUG;
        val |= str2u64(s, index, len) << 16;
        wrmsr(GHCB_MSR, val);
        vc_vmgexit();
        index += len;
    }
    // restore ghcb msr val
    wrmsr(GHCB_MSR, orig_val);
}
