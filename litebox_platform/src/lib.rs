// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared platform capabilities and portable primitives used by LiteBox cores.

#![no_std]

#[cfg(feature = "lock_tracing")]
extern crate alloc;

pub mod sync;
pub mod time;
