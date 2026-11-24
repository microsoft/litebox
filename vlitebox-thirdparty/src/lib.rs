// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]
#![cfg_attr(verus_keep_ghost, feature(allocator_api))]

#[cfg(verus_keep_ghost)]
extern crate alloc;

pub mod spin_spec;

#[cfg(verus_keep_ghost)]
pub mod alloc_spec;
