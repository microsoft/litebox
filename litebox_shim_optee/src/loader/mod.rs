// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module contains the loader for the LiteBox shim.

pub(crate) mod elf;
pub(crate) mod ta_stack;

/// The magic number used to identify the LiteBox rewriter and where we should
/// update the syscall callback pointer.
pub const REWRITER_MAGIC_NUMBER: u64 = u64::from_le_bytes(*b"LITE BOX");
pub const REWRITER_VERSION_NUMBER: u64 = u64::from_le_bytes(*b"LITEBOX0");

pub(crate) const DEFAULT_STACK_SIZE: usize = 1024 * 1024; // 1 MB

/// Default low address for loading TA binaries.
///
/// This must be >= `USER_ADDR_MIN` defined in the platform because user memory is
/// mapped in the range [`USER_ADDR_MIN`, `USER_ADDR_MAX`) for easy identification
/// during cleanup. The binary grows upwards from this address.
pub const DEFAULT_LOW_ADDR: usize = 0x6FFF_FFFF_F000;
