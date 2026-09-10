// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-facing file operations and local descriptor integration.
//!
//! Filesystem resolution and backend implementations live in `litebox_broker_core`. This module
//! retains caller context and local descriptors, plus the 9P transport traits that deployments
//! implement. Shared file values are defined in [`litebox_broker_protocol::fs`].

pub mod errors;
mod file;

pub use file::{Context, File, FileFd, OFlags, ResolvedPath};

#[doc(hidden)]
pub mod nine_p {
    pub use litebox_broker_core::fs::nine_p::*;
}

#[cfg(test)]
mod tests;
