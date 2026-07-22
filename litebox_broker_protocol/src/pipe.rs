// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ObjectHandle;

/// Maximum pipe transfer described by one control-path request or response.
///
/// This leaves room for the broker envelope and operation metadata within the
/// smallest currently supported transport frame.
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
    /// Maximum number of bytes to return.
    pub length: u32,
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
    /// Number of staged bytes to write.
    pub length: u32,
}

/// Response describing a completed pipe write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritePipeResponse {
    /// Number of bytes appended to the pipe.
    pub written: u32,
}
