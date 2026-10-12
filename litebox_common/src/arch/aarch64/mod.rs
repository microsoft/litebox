// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! AArch64-specific helpers independent of host operating systems and guest ABIs.

/// Number of AArch64 general-purpose registers (`x0` through `x30`).
pub const GENERAL_REGISTER_COUNT: usize = 31;

/// PSTATE condition flags (N, Z, C, V).
pub const PSR_NZCV_MASK: u64 = 0b1111 << 28;
/// Speculative Store Bypass Safe bit.
pub const PSR_SSBS_BIT: u64 = 1 << 12;
/// Data Independent Timing bit.
pub const PSR_DIT_BIT: u64 = 1 << 24;
