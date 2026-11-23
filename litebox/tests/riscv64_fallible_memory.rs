// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(target_arch = "riscv64")]

use litebox::mm::exception_table::*;
use zerocopy::IntoBytes as _;

#[test]
fn scalar_accesses_preserve_width_at_any_alignment() {
    let mut storage = [0u64; 2];
    let bytes = storage.as_mut_bytes();
    macro_rules! check {
        ($read:ident, $write:ident, $value:expr) => {{
            let value = $value;
            for offset in 0..size_of_val(&value) {
                bytes.fill(0x55);
                let dst = bytes.as_mut_ptr().wrapping_add(offset).cast();
                // SAFETY: dst covers one value inside storage; no reference to it is in use.
                unsafe { $write(dst, value).unwrap() };
                let end = offset + size_of_val(&value);
                assert_eq!(&bytes[offset..end], value.to_ne_bytes());
                assert!(
                    bytes[..offset]
                        .iter()
                        .chain(&bytes[end..])
                        .all(|&b| b == 0x55)
                );
                // SAFETY: Same initialized range, reborrowed after checking the bytes.
                assert_eq!(
                    unsafe { $read(bytes.as_ptr().wrapping_add(offset).cast()) }.unwrap(),
                    value
                );
            }
        }};
    }
    check!(read_u8_fallible, write_u8_fallible, 0xadu8);
    check!(read_u16_fallible, write_u16_fallible, 0xab07u16);
    check!(read_u32_fallible, write_u32_fallible, 0x890a_bcdeu32);
    check!(
        read_u64_fallible,
        write_u64_fallible,
        0x8123_4567_89ab_cdefu64
    );
}

#[test]
fn aligned_copy_includes_byte_tail() {
    let src = [0x1122_3344_5566_7788u64; 3];
    let mut dst = [0u64; 3];
    // SAFETY: These disjoint, aligned buffers each hold 24 bytes.
    unsafe { memcpy_fallible(dst.as_mut_ptr().cast(), src.as_ptr().cast(), 17) }.unwrap();
    assert_eq!(&dst.as_bytes()[..17], &src.as_bytes()[..17]);
    assert_eq!(&dst.as_bytes()[17..], &[0; 7]);
}
