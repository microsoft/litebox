// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative standard I/O.

use core::sync::atomic::{AtomicBool, Ordering};

use litebox_broker_protocol::stdio::{MAX_STDIO_TRANSFER_SIZE, StdioOutputStream};
use thiserror::Error;

use crate::{BrokerError, BrokerSession, Result};

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

/// Per-session cancellation state for standard-input reads.
#[derive(Debug, Default)]
pub struct StdioReadCancellation {
    cancelled: AtomicBool,
}

impl StdioReadCancellation {
    /// Returns whether the broker session is ending.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
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
        cancellation: &StdioReadCancellation,
        output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        let _ = cancellation;
        let _ = output;
        Err(StdioProviderError::Unsupported)
    }

    /// Writes bytes to the selected standard output stream.
    fn write(
        &self,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError>;
}

/// Standard-I/O provider for deployments that do not expose standard streams.
pub struct UnsupportedStdioProvider;

impl StdioProvider for UnsupportedStdioProvider {
    fn read(
        &self,
        _cancellation: &StdioReadCancellation,
        _output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }

    fn write(
        &self,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
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
        .read(&session.stdio_read_cancellation, output)
        .map_err(map_provider_error)?;
    if read > output.len() {
        return Err(BrokerError::Internal);
    }
    Ok(read)
}

/// Cancels standard-input reads that are still pending for an ending
/// association.
pub fn cancel_pending_reads(session: &BrokerSession) {
    session.stdio_read_cancellation.cancel();
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
        .write(stream, input)
        .map_err(map_provider_error)?;
    if written > input.len() {
        return Err(BrokerError::Internal);
    }
    Ok(written)
}

fn map_provider_error(error: StdioProviderError) -> BrokerError {
    match error {
        StdioProviderError::Closed => BrokerError::PeerClosed,
        StdioProviderError::Failed => BrokerError::Internal,
        StdioProviderError::Unsupported => BrokerError::UnsupportedOperation,
    }
}
