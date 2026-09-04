// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-provided standard output.

use litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE;
pub use litebox_broker_protocol::stdio::StdioOutputStream;
use thiserror::Error;

use crate::{LiteBox, sync::RawSyncPrimitivesProvider};

/// A broker could not write to a standard output stream.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("brokered standard output is unavailable")]
pub struct WriteStdioError;

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Writes bytes to the selected standard output stream.
    ///
    /// Empty writes succeed without a broker. Non-empty writes require a
    /// negotiated broker and may write at most one broker transfer.
    pub fn write_stdio(
        &self,
        stream: StdioOutputStream,
        input: &[u8],
    ) -> Result<usize, WriteStdioError> {
        if input.is_empty() {
            return Ok(0);
        }
        let broker = self.broker_control().ok_or(WriteStdioError)?;
        let input = &input[..input.len().min(MAX_STDIO_TRANSFER_SIZE as usize)];
        broker
            .write_stdio(stream, input)
            .map_err(|_| WriteStdioError)
    }
}
