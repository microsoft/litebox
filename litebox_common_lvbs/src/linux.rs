// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux kernel ABI types shared between platform and runner crates.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// `list_head` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/types.h#L190)
/// Pointer fields stored as u64 since we don't dereference them.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ListHead {
    pub next: u64,
    pub prev: u64,
}
