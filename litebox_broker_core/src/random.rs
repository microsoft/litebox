// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-authoritative cryptographic randomness.

use litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE;
use thiserror::Error;

use crate::{BrokerError, BrokerSession, Result};

/// Failure reported by a trusted random provider.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("trusted random provider failed")]
pub struct RandomProviderError;

/// Trusted source of cryptographically secure random bytes.
///
/// A successful call must overwrite every byte in `output` with fresh,
/// cryptographically secure output. Concurrent calls must be safe and
/// cryptographically independent. Implementations must not cache userspace
/// generator state that could be reused after a process fork or VM snapshot.
pub trait RandomProvider: Send + Sync {
    /// Fills `output` completely with cryptographically secure random bytes.
    fn fill(&self, output: &mut [u8]) -> core::result::Result<(), RandomProviderError>;
}

#[cfg(test)]
pub(crate) struct TestRandomProvider;

#[cfg(test)]
impl RandomProvider for TestRandomProvider {
    fn fill(&self, output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        output.fill(0x5a);
        Ok(())
    }
}

/// Fills `output` from the random provider configured for this broker.
pub fn fill(session: &BrokerSession, output: &mut [u8]) -> Result<()> {
    if output.len() > MAX_RANDOM_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    if output.is_empty() {
        return Ok(());
    }
    session
        .core
        .random_provider
        .fill(output)
        .map_err(|_| BrokerError::Internal)
}
