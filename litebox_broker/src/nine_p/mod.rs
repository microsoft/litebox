// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P2000.L protocol implementation for the broker.
//!
//! This module contains the protocol message types and transport abstractions
//! needed by the broker's 9P server. It is adapted from the guest-side
//! implementation in `litebox/src/fs/nine_p/`.

pub mod fcall;
pub mod fs_compat;
pub mod server;
pub mod transport;

/// Error type for 9P operations
#[derive(Debug)]
pub enum Error {
    Io,
    InvalidResponse,
}
