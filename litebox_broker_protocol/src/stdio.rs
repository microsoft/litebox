// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferDescriptor};

/// Maximum standard-I/O bytes transferred by one broker request.
pub const MAX_STDIO_TRANSFER_SIZE: u32 = 32 * 1024;

const _: () = assert!(MAX_STDIO_TRANSFER_SIZE <= SHARED_BUFFER_SLOT_SIZE);

/// Standard stream selected by a capability query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioStream {
    /// Process standard input.
    Stdin,
    /// Process standard output.
    Stdout,
    /// Process standard error.
    Stderr,
}

/// Standard output stream selected by a write request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioOutputStream {
    /// Process standard output.
    Stdout,
    /// Process standard error.
    Stderr,
}

/// Request to read standard input into a leased shared-buffer region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadStdioRequest {
    /// Leased shared-buffer region that receives the input bytes.
    pub buffer: SharedBufferDescriptor,
}

/// Response describing a completed standard-input read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadStdioResponse {
    /// Number of bytes read, or zero if standard input reached end-of-file.
    pub read: u32,
}

/// Request to write bytes staged in shared memory to a standard output stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteStdioRequest {
    /// Destination standard output stream.
    pub stream: StdioOutputStream,
    /// Leased shared-buffer region containing the staged bytes.
    pub buffer: SharedBufferDescriptor,
}

/// Response describing a completed standard output write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteStdioResponse {
    /// Number of bytes written to the selected stream.
    pub written: u32,
}

/// Request to determine whether a standard stream is connected to a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsTerminalStdioRequest {
    /// Standard stream to query.
    pub stream: StdioStream,
}

/// Response describing whether a standard stream is connected to a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsTerminalStdioResponse {
    /// Whether the selected stream is connected to a terminal.
    pub is_terminal: bool,
}
