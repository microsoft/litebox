// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kernel image layout from `x86_64_qemu.ld`. The addresses are only valid
//! after relocation.

unsafe extern "C" {
    static _heap_start: u8;
    static _text_start: u8;
    static _text_end: u8;
    static _rodata_start: u8;
    static _rodata_end: u8;
}

/// First address the heap may use: above the image and the boot scratch.
#[inline]
pub fn heap_start_address() -> u64 {
    &raw const _heap_start as u64
}

#[inline]
pub fn text_start_address() -> u64 {
    &raw const _text_start as u64
}

#[inline]
pub fn text_end_address() -> u64 {
    &raw const _text_end as u64
}

pub fn rodata_start_address() -> u64 {
    &raw const _rodata_start as u64
}

pub fn rodata_end_address() -> u64 {
    &raw const _rodata_end as u64
}
