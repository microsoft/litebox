use litebox::utils::TruncateExt as _;

use crate::arch::instructions::{rdmsr, vc_vmgexit, wrmsr};

// GHCB MSR
const GHCB_MSR: u32 = 0xc0010130;
// GHCB Protocols
const GHCB_HV_DEBUG: u64 = 0xf03;

fn str2u64(s: &str, start: usize, size: usize) -> u64 {
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

fn num_to_char(n: u8) -> u8 {
    if n < 10 { n + b'0' } else { n - 10 + b'a' }
}

pub fn num_to_buf(buf: &mut [u8; 40], mut n: u64, base: u64) -> usize {
    let mut i = 0;
    if n == 0 {
        buf[i] = num_to_char(0);
        i += 1;
    }
    while n > 0 {
        buf[i] = num_to_char((n % base).truncate());
        n /= base;
        i += 1;
    }
    i
}

#[macro_export]
macro_rules! print_int {
    ($num: expr, $base: expr) => {{
        let mut _buf = [0u8; 40];
        let i = $crate::host::snp::ghcb::num_to_buf(&mut _buf, $num, $base);
        let slice = &mut _buf[..i];
        slice.reverse();
        let s = core::str::from_utf8(&*slice).unwrap();
        $crate::host::snp::ghcb::ghcb_prints(s);
    }};
}

#[macro_export]
macro_rules! print_str_and_int {
    ($str: expr, $num: expr, $base: expr) => {{
        $crate::host::snp::ghcb::ghcb_prints($str);
        $crate::print_int!($num, $base);
        $crate::host::snp::ghcb::ghcb_prints("\n");
    }};
}
