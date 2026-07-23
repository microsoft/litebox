// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg_attr(not(feature = "std"), no_std)]

//! Broker transport implementations.
//!
//! Transports own hosted or platform-specific framing and I/O. Portable broker
//! protocol messages, local-side adapters, host-side request handling, and core
//! authority state live in separate crates.

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod control_ring;

#[cfg(all(feature = "linux-userland", target_os = "linux"))]
pub mod shared_memory;

#[cfg(all(feature = "linux-userland", target_os = "linux"))]
pub mod unix_socket;

#[cfg(all(feature = "linux-userland", target_os = "linux"))]
mod unix_io;
