// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable support for hosting a broker in userland.
//!
//! This crate owns the shared parts of userland broker deployments: a
//! structured builder that selects operating-system providers and constructs a
//! [`litebox_broker_core::BrokerCore`] ([`builder`]), the generic association
//! runtime that serves one association from setup through
//! teardown ([`runtime`]), and threaded readiness publication
//! ([`readiness`]). On hosts with network support, the `socket` module
//! provides broker-owned sockets on the host's network stack. On supported
//! out-of-process hosts, the `runner` module owns
//! one runner and its platform-specific transport endpoint. The
//! `litebox-broker-userland` binary composes these with CLI parsing, broker
//! policy, shared services, and the explicitly non-secure in-process runner
//! mode.

pub mod builder;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub mod fs;
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
pub mod mapped_file;
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod process_launcher;
pub mod readiness;
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
pub mod runner;
pub mod runtime;
#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
pub mod socket;

pub mod random;
pub mod stdio;
mod terminal;
mod timer;
