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

// Re-export from litebox_common_optee for convenience
pub(crate) use litebox_common_optee::TA_DEFAULT_LOW_ADDR as DEFAULT_LOW_ADDR;
