// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-provided cryptographic randomness.

use crate::shared_buffer::SharedBufferDescriptor;

/// Maximum number of random bytes transferred by one broker operation.
pub const MAX_RANDOM_TRANSFER_SIZE: u32 = 256;

/// Fills a shared buffer with cryptographically secure random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillRandomRequest {
    /// Shared output buffer to fill completely.
    pub buffer: SharedBufferDescriptor,
}
