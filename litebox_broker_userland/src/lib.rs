// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable support for hosting a broker in userland.
//!
//! This crate owns the shared parts of userland broker deployments: a
//! structured builder that selects operating-system providers and constructs a
//! [`litebox_broker_core::BrokerCore`] ([`builder`]), the generic hosted
//! association runtime that serves one association from setup through
//! teardown ([`runtime`]), and threaded readiness publication
//! ([`readiness`]). The `litebox-broker-userland` binary composes these with
//! CLI parsing, runner process lifecycle, and the platform-specific transport
//! endpoints from `litebox_broker_transport_linux_userland` and
//! `litebox_broker_transport_windows_userland`; an in-process caller can use
//! the same builder and runtime directly instead.

pub mod builder;
pub mod readiness;
pub mod runtime;

mod random;
mod stdio;

const WORKER_COUNT: usize = 8;
