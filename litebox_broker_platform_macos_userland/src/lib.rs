// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland implementations of trusted broker platform capabilities.
//!
//! Association transport belongs to `litebox_broker_transport_macos_userland`.
//! This crate instead owns broker-side operating-system resources that must
//! never cross into the local process.

#![cfg(target_os = "macos")]

mod sync;

pub use sync::MacosSyncPrimitivesProvider;
