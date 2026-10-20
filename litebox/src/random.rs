// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-provided cryptographic randomness.

use litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE;
use thiserror::Error;

use crate::broker::error::BrokerControlError;
use crate::{LiteBox, sync::RawSyncPrimitivesProvider};
use litebox_platform::buffer::{Buffer, ReadBuffer};

/// A broker could not fill a random-byte request.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FillRandomError {
    /// The brokered random source is unavailable.
    #[error("brokered random source is unavailable")]
    Unavailable,
    /// The buffer to fill is inaccessible.
    #[error("random buffer is inaccessible")]
    Fault,
}

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Fills `buf` completely with cryptographically secure random bytes.
    ///
    /// Non-empty requests require a negotiated broker.
    pub fn fill_random(&self, mut buf: impl ReadBuffer) -> Result<(), FillRandomError> {
        if buf.is_empty() {
            return Ok(());
        }
        let broker = self.broker_control().ok_or(FillRandomError::Unavailable)?;
        let mut filled = 0;
        while filled < buf.len() {
            let length = (buf.len() - filled).min(MAX_RANDOM_TRANSFER_SIZE as usize);
            broker
                .fill_random(&mut (&mut buf).sub_buffer(filled, length))
                .map_err(|error| match error {
                    BrokerControlError::Fault => FillRandomError::Fault,
                    _ => FillRandomError::Unavailable,
                })?;
            filled += length;
        }
        Ok(())
    }
}
