// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared platform capabilities and portable primitives used by LiteBox cores.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod buffer;
pub mod peer_memory;
pub mod sync;
pub mod time;
