// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg_attr(not(feature = "std"), no_std)]

//! Broker transport implementations.
//!
//! Transports own hosted or platform-specific framing and I/O. Portable broker
//! protocol messages, local-side adapters, host-side request handling, and core
//! authority state live in separate crates.
//!
//! This crate owns the portable control-ring primitives, the Linux-userland
//! shared memory that backs them, and the concrete *local* (guest-side) Unix
//! endpoints. The matching *host* (broker-side) Unix endpoints live in the
//! platform binding crate `litebox_broker_platform_linux_userland`, which
//! builds on the shared surface in [`platform_support`].

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod control_ring;

#[cfg(all(feature = "linux-userland", target_os = "linux"))]
pub mod platform_support;

#[cfg(all(feature = "linux-userland", target_os = "linux"))]
pub mod shared_memory;

#[cfg(all(feature = "linux-userland", target_os = "linux"))]
pub mod unix_socket;

#[cfg(all(feature = "linux-userland", target_os = "linux"))]
mod unix_io;
