// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module contains the loader for the LiteBox shim.

#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub mod auxv;
pub mod elf;
mod stack;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Offset from a partition's base at which PIE binaries are loaded.
///
/// This keeps the low portion of each partition unmapped, mirroring Linux's
/// behaviour where addresses below `mmap_min_addr` are reserved for
/// NULL-pointer dereference detection.
pub(crate) const PIE_LOAD_OFFSET: usize = 0x1000_0000; // 256 MiB
