// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-provided standard I/O.

use litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE;
pub use litebox_broker_protocol::stdio::{StdioOutputStream, StdioStream};
use thiserror::Error;

use crate::{LiteBox, sync::RawSyncPrimitivesProvider};

/// A broker could not read from standard input.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("brokered standard input is unavailable")]
pub struct ReadStdioError;

/// A broker could not write to a standard output stream.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("brokered standard output is unavailable")]
pub struct WriteStdioError;

/// A broker could not determine whether a standard stream is connected to a
/// terminal.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("brokered standard-stream terminal query is unavailable")]
pub struct StdioTerminalError;

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Determines whether a standard stream is connected to a terminal.
    ///
    /// This query requires a negotiated broker.
    pub fn is_stdio_terminal(&self, stream: StdioStream) -> Result<bool, StdioTerminalError> {
        self.broker_control()
            .ok_or(StdioTerminalError)?
            .is_stdio_terminal(stream)
            .map_err(|_| StdioTerminalError)
    }

    /// Reads bytes from standard input.
    ///
    /// Empty reads succeed without a broker. Non-empty reads require a
    /// negotiated broker, block until input or end-of-file, and may read at
    /// most one broker transfer.
    pub fn read_stdio(&self, output: &mut [u8]) -> Result<usize, ReadStdioError> {
        if output.is_empty() {
            return Ok(0);
        }
        let broker = self.broker_control().ok_or(ReadStdioError)?;
        let length = output.len().min(MAX_STDIO_TRANSFER_SIZE as usize);
        broker
            .read_stdio(&mut output[..length])
            .map_err(|_| ReadStdioError)
    }

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
