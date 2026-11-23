// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RISC-V guest address bounds.

/// Inclusive lower bound, excluding the null guard.
pub const USER_ADDR_MIN: usize = 0x1_0000;
/// Exclusive upper bound. LiteBox uses the low Sv39 user range even on hosts
/// with wider virtual addresses, and reserves its final page as a guard.
pub const USER_ADDR_END: usize = (1 << 38) - 4096;
