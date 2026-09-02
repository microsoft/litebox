// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-provided cryptographic randomness.

use thiserror::Error;

use crate::{LiteBox, sync::RawSyncPrimitivesProvider};

/// A broker could not fill a random-byte request.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("brokered random source is unavailable")]
pub struct FillRandomError;

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Fills `output` completely with cryptographically secure random bytes.
    ///
    /// Non-empty requests require a negotiated broker and may contain at most
    /// 256 bytes.
    pub fn fill_random(&self, output: &mut [u8]) -> Result<(), FillRandomError> {
        if output.is_empty() {
            return Ok(());
        }
        self.broker_control()
            .ok_or(FillRandomError)?
            .fill_random(output)
            .map_err(|_| FillRandomError)
    }
}
