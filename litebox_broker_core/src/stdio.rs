// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host standard streams behind the `/dev` stdio devices.

use thiserror::Error;

/// Standard stream selected by a terminal query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioStream {
    /// Process standard input.
    Stdin,
    /// Process standard output.
    Stdout,
    /// Process standard error.
    Stderr,
}

/// Standard output stream selected by a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioOutputStream {
    /// Process standard output.
    Stdout,
    /// Process standard error.
    Stderr,
}

/// Failure reported by a trusted standard-I/O provider.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StdioProviderError {
    /// The selected standard stream is closed.
    #[error("standard stream is closed")]
    Closed,
    /// The host standard-I/O operation failed internally.
    #[error("trusted standard-I/O provider failed")]
    Failed,
    /// This broker deployment does not provide standard I/O.
    #[error("standard I/O is unsupported")]
    Unsupported,
}

/// Trusted provider of standard-I/O operations.
pub trait StdioProvider: Send + Sync {
    /// Blocks until bytes can be read from standard input, returning zero at
    /// end-of-file.
    fn read(&self, output: &mut [u8]) -> core::result::Result<usize, StdioProviderError>;

    /// Writes bytes to the selected standard output stream.
    fn write(
        &self,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError>;

    /// Determines whether the selected standard stream is connected to a
    /// terminal.
    fn is_terminal(&self, stream: StdioStream) -> bool;
}

/// Standard-I/O provider for deployments that do not expose standard streams.
pub struct UnsupportedStdioProvider;

impl StdioProvider for UnsupportedStdioProvider {
    fn read(&self, _output: &mut [u8]) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn write(
        &self,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn is_terminal(&self, _stream: StdioStream) -> bool {
        false
    }
}
