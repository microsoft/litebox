// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative standard I/O.

use litebox_broker_protocol::stdio::{MAX_STDIO_TRANSFER_SIZE, StdioOutputStream, StdioStream};
use thiserror::Error;

use crate::{AssociationCancellation, BrokerError, BrokerSession, Result};

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

impl From<StdioProviderError> for BrokerError {
    fn from(error: StdioProviderError) -> Self {
        match error {
            StdioProviderError::Closed => Self::PeerClosed,
            StdioProviderError::Failed => Self::Internal,
            StdioProviderError::Unsupported => Self::UnsupportedOperation,
        }
    }
}

/// Trusted provider of standard-I/O operations.
pub trait StdioProvider: Send + Sync {
    /// Blocks until bytes can be read from standard input, returning zero at
    /// end-of-file.
    ///
    /// Blocking implementations must periodically check `cancellation` and
    /// return promptly when it becomes cancelled.
    fn read(
        &self,
        cancellation: &AssociationCancellation,
        output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError>;

    /// Writes bytes to the selected standard output stream.
    ///
    /// Blocking implementations must periodically check `cancellation` and
    /// return promptly when it becomes cancelled.
    fn write(
        &self,
        cancellation: &AssociationCancellation,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError>;

    /// Determines whether the selected standard stream is connected to a
    /// terminal.
    fn is_terminal(&self, stream: StdioStream) -> core::result::Result<bool, StdioProviderError>;
}

/// Standard-I/O provider for deployments that do not expose standard streams.
pub struct UnsupportedStdioProvider;

impl StdioProvider for UnsupportedStdioProvider {
    fn read(
        &self,
        _cancellation: &AssociationCancellation,
        _output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn write(
        &self,
        _cancellation: &AssociationCancellation,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn is_terminal(&self, _stream: StdioStream) -> core::result::Result<bool, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }
}

/// Reads standard input through the provider configured for this broker.
pub fn read(session: &BrokerSession, output: &mut [u8]) -> Result<usize> {
    if output.len() > MAX_STDIO_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    if output.is_empty() {
        return Ok(0);
    }
    let read = session
        .core
        .stdio_provider
        .read(&session.cancellation, output)?;
    if read > output.len() {
        return Err(BrokerError::Internal);
    }
    Ok(read)
}

/// Writes `input` through the standard-I/O provider configured for this broker.
pub fn write(session: &BrokerSession, stream: StdioOutputStream, input: &[u8]) -> Result<usize> {
    if input.len() > MAX_STDIO_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    if input.is_empty() {
        return Ok(0);
    }
    let written = session
        .core
        .stdio_provider
        .write(&session.cancellation, stream, input)?;
    if written > input.len() {
        return Err(BrokerError::Internal);
    }
    Ok(written)
}

/// Determines whether a standard stream is connected to a terminal.
pub fn is_terminal(session: &BrokerSession, stream: StdioStream) -> Result<bool> {
    session
        .core
        .stdio_provider
        .is_terminal(stream)
        .map_err(Into::into)
}
