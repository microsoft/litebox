// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-facing file operations and local descriptor integration.
//!
//! Filesystem resolution and backend implementations live in `litebox_broker_core`. This module
//! retains caller context and local descriptors. Shared file values are defined in
//! [`litebox_broker_protocol::fs`].

pub mod errors;
mod file;

pub use file::{BrokerFile, Context, FileFd};

#[cfg(test)]
mod tests;
