// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-userland broker association transport.
//!
//! Portable protocol and control-ring state live in `litebox_broker_transport`.
//! This crate supplies Windows file-mapping and IPC bindings for hosted deployments.

#![cfg(all(windows, target_arch = "x86_64"))]

pub mod broker;
pub mod control_ring;
mod host;
mod local;
pub mod named_pipe;
mod pending_calls;
mod setup;
pub mod shared_memory;
