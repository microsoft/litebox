// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-userland implementations of trusted broker platform capabilities.
//!
//! Association transport belongs to `litebox_broker_transport_windows_userland`.
//! This crate instead owns broker-side operating-system resources that must
//! never cross into the local process.

#![cfg(windows)]

mod sync;

pub use sync::WindowsSyncPrimitivesProvider;
