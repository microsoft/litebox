// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64-specific helpers independent of host operating systems and guest ABIs.

/// Inclusive lower bound for user instruction and stack pointers, excluding the null guard.
pub const USER_ADDR_MIN: usize = 0x0000_0000_0001_0000;
/// Exclusive upper bound for user addresses, reserving the final low-userspace page as a guard.
pub const USER_ADDR_END: usize = 0x0000_ffff_ffff_f000;

/// Number of AArch64 general-purpose registers (`x0` through `x30`).
pub const GENERAL_REGISTER_COUNT: usize = 31;

/// PSTATE condition flags (N, Z, C, V).
pub const PSR_NZCV_MASK: u64 = 0b1111 << 28;
/// Speculative Store Bypass Safe bit.
pub const PSR_SSBS_BIT: u64 = 1 << 12;
/// Data Independent Timing bit.
pub const PSR_DIT_BIT: u64 = 1 << 24;
