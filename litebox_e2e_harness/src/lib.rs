// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! # LiteBox E2E Test Harness
//!
//! This implements a pure-Rust shim + platform + runner combined into a single
//! crate. It can be used to perform end-to-end tests on the [`litebox`] core
//! crate, without relying on anything outside of the Rust Abstract Machine
//! (like ISA-specific assembly). This allows writing, e.g., Miri tests that
//! check for soundness bugs or memory leaks.
//!
//! This shim moves regular Rust types (structs and enums) between the shim and
//! platform through the core. It's threads are native boxed Rust closures,
//! which are run on Rust's standard library threads. This is sufficiently
//! expressive to model the behavior of real-world shims and find, e.g.,
//! concurrency-related soundness issues.

pub mod context;
pub mod kernel;
pub mod platform;
pub mod runner;
pub mod shim;

pub use context::{ExecutionContext, GuestAction, GuestApi};
pub use platform::HarnessPlatform;
pub use runner::HarnessRunner;
pub use shim::{HarnessInitThread, HarnessShim};
