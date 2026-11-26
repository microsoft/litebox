// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RISC-V guest address bounds.

/// Inclusive lower bound for user instruction and stack pointers, excluding the null guard.
pub const USER_ADDR_MIN: usize = 0x1_0000;
/// Exclusive upper bound for user addresses: the Sv39 user range less a final
/// guard page. LiteBox uses it even on hosts with wider virtual addresses.
pub const USER_ADDR_END: usize = (1 << 38) - 4096;
