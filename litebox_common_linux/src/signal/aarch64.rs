// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Definitions for aarch64 signal context structures.

use crate::AARCH64_GENERAL_REGISTER_COUNT;
use zerocopy::{FromBytes, IntoBytes};

/// sigcontext for aarch64.
/// See: <https://elixir.bootlin.com/linux/v5.19.17/source/arch/arm64/include/uapi/asm/sigcontext.h>
///
/// The kernel declares `__u8 __reserved[4096] __attribute__((__aligned__(16)))`,
/// which forces both the struct's alignment to 16 and `__reserved` to a 16-byte
/// boundary. The natural offset of `__reserved` is 280 (8-aligned), so the kernel
/// inserts 8 bytes of padding to place it at offset 288 (size 4384). We reproduce
/// this with an explicit padding field and `align(16)` so the layout matches
/// exactly (explicit padding also keeps `IntoBytes` valid, unlike implicit padding).
#[repr(C, align(16))]
#[derive(Clone, FromBytes, IntoBytes)]
#[allow(clippy::pub_underscore_fields)]
pub struct Sigcontext {
    pub fault_address: u64,
    pub regs: [u64; AARCH64_GENERAL_REGISTER_COUNT],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    /// Padding to align `__reserved` to a 16-byte boundary (matches the kernel's
    /// `__attribute__((__aligned__(16)))` on this field).
    pub __reserved_pad: [u8; 8],
    /// 4K reserved for FP/SIMD state and future extensions.
    pub __reserved: [u8; 4096],
}
