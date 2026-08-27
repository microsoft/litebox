// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux-userland implementations of trusted broker platform capabilities.
//!
//! Association transport belongs to `litebox_broker_transport_linux_userland`.
//! This crate instead owns broker-side operating-system resources that must
//! never cross into the local process.

#![cfg(target_os = "linux")]

mod socket;

pub use socket::{DnsARecord, LinuxSocketProvider};
