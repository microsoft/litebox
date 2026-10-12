// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host- and guest-ABI-neutral implementations shared by LiteBox platforms and shims.

#![no_std]

extern crate alloc;

/// Size of a 4 KiB page in bytes.
pub const PAGE_SIZE: usize = 4096;

pub mod arch;
pub mod page;
pub mod physical_pointers;
pub mod user_pointers;
pub mod vmap;
