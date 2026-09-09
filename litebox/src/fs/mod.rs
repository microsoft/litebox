// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest-facing file values and operations.
//!
//! Filesystem resolution and backend implementations live in `litebox_broker_core`. This module
//! retains LiteBox's guest values and descriptor integration, plus the 9P transport traits that
//! deployments implement.

pub mod errors;
mod file;

pub use file::{
    Context, DirEntry, File, FileFd, FileStatus, FileType, Mode, NodeInfo, OFlags, ResolvedPath,
    SeekWhence, UserInfo,
};

#[doc(hidden)]
pub mod nine_p {
    pub use litebox_broker_core::fs::nine_p::*;
}

#[cfg(test)]
mod tests;
