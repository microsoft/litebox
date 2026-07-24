// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ObjectHandle;
use crate::shared_memory::SharedBufferDescriptor;

/// Maximum pipe bytes transferred by one broker request.
///
/// Each association shared-buffer slot has this size. Larger blocking writes
/// are split across requests, while reads may return at most this amount.
pub const MAX_PIPE_TRANSFER_SIZE: u32 = 32 * 1024;

/// Request to create a broker-owned byte pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatePipeRequest {
    /// Maximum number of buffered bytes.
    pub capacity: u64,
    /// Maximum write size that must be accepted atomically.
    pub atomic_write_size: u64,
}

/// Response to a pipe create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatePipeResponse {
    /// Handle for the read endpoint.
    pub read_handle: ObjectHandle,
    /// Handle for the write endpoint.
    pub write_handle: ObjectHandle,
}

/// Request to read bytes from a pipe endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPipeRequest {
    /// Read endpoint handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer region to receive the bytes.
    pub buffer: SharedBufferDescriptor,
}

/// Response describing bytes read into shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPipeResponse {
    /// Number of bytes placed in the read region.
    pub read: u32,
}

/// Request to write bytes staged in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritePipeRequest {
    /// Write endpoint handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer region containing the staged bytes.
    pub buffer: SharedBufferDescriptor,
}

/// Response describing a completed pipe write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritePipeResponse {
    /// Number of bytes appended to the pipe.
    pub written: u32,
}
