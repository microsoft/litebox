// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative standard I/O.

use litebox_broker_protocol::stdio::{MAX_STDIO_TRANSFER_SIZE, StdioOutputStream};
use thiserror::Error;

use crate::{BrokerError, BrokerSession, Result};

/// Failure reported by a trusted standard-I/O provider.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StdioProviderError {
    /// The selected output stream is closed.
    #[error("standard output stream is closed")]
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
    fn write(
        &self,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Err(StdioProviderError::Unsupported)
    }
}

#[cfg(test)]
pub(crate) struct TestStdioProvider;

#[cfg(test)]
impl StdioProvider for TestStdioProvider {
    fn write(
        &self,
        _stream: StdioOutputStream,
        input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        Ok(input.len())
    }
}

/// Writes `input` through the standard-I/O provider configured for this broker.
pub fn write(session: &BrokerSession, stream: StdioOutputStream, input: &[u8]) -> Result<usize> {
    write_with_provider(session.core.stdio_provider.as_ref(), stream, input)
}

fn write_with_provider(
    provider: &dyn StdioProvider,
    stream: StdioOutputStream,
    input: &[u8],
) -> Result<usize> {
    if input.len() > MAX_STDIO_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    if input.is_empty() {
        return Ok(0);
    }
    let written = provider.write(stream, input).map_err(|error| match error {
        StdioProviderError::Closed => BrokerError::PeerClosed,
        StdioProviderError::Failed => BrokerError::Internal,
        StdioProviderError::Unsupported => BrokerError::UnsupportedOperation,
    })?;
    if written > input.len() {
        return Err(BrokerError::Internal);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct FixedResultProvider(core::result::Result<usize, StdioProviderError>);

    impl StdioProvider for FixedResultProvider {
        fn write(
            &self,
            _stream: StdioOutputStream,
            _input: &[u8],
        ) -> core::result::Result<usize, StdioProviderError> {
            self.0
        }
    }

    #[test]
    fn write_accepts_empty_and_partial_results() {
        assert_eq!(
            write_with_provider(
                &FixedResultProvider(Err(StdioProviderError::Failed)),
                StdioOutputStream::Stdout,
                &[],
            ),
            Ok(0)
        );
        assert_eq!(
            write_with_provider(
                &FixedResultProvider(Ok(2)),
                StdioOutputStream::Stdout,
                b"output",
            ),
            Ok(2)
        );
    }

    #[test]
    fn write_rejects_invalid_lengths() {
        assert_eq!(
            write_with_provider(
                &FixedResultProvider(Ok(7)),
                StdioOutputStream::Stdout,
                b"output",
            ),
            Err(BrokerError::Internal)
        );

        let oversized = vec![0; MAX_STDIO_TRANSFER_SIZE as usize + 1];
        assert_eq!(
            write_with_provider(
                &FixedResultProvider(Ok(oversized.len())),
                StdioOutputStream::Stdout,
                &oversized,
            ),
            Err(BrokerError::ResourceExhausted)
        );
    }

    #[test]
    fn write_maps_provider_errors() {
        for (provider_error, broker_error) in [
            (StdioProviderError::Closed, BrokerError::PeerClosed),
            (StdioProviderError::Failed, BrokerError::Internal),
            (
                StdioProviderError::Unsupported,
                BrokerError::UnsupportedOperation,
            ),
        ] {
            assert_eq!(
                write_with_provider(
                    &FixedResultProvider(Err(provider_error)),
                    StdioOutputStream::Stderr,
                    b"error",
                ),
                Err(broker_error)
            );
        }
    }
}
