// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-facing file operations.
//!
//! Filesystem resolution and backend implementations live in `litebox_broker_core`. This module
//! retains caller context and references to broker-owned open files. Shared file values are
//! defined in [`litebox_broker_protocol::fs`].

pub mod errors;
mod file;

pub use file::{Caller, Context, File, ResolvedPath, SharedFileObject};

/// File security metadata to update together; omitted fields retain their current values.
pub type SecurityUpdate = litebox_broker_protocol::fs::FileSecurityUpdate;
