// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, StdioRequest, StdioResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_protocol::stdio::{
    IsTerminalStdioRequest, MAX_STDIO_TRANSFER_SIZE, ReadStdioRequest, StdioOutputStream,
    StdioStream, WriteStdioRequest,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Determines whether a standard stream is connected to a terminal.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response for a different operation.
    pub fn is_stdio_terminal(&self, stream: StdioStream) -> Result<bool, Channel::Error> {
        match self.request(BrokerOperation::Stdio(StdioRequest::IsTerminal(
            IsTerminalStdioRequest { stream },
        )))? {
            BrokerResult::Stdio(StdioResponse::IsTerminal(response)) => Ok(response.is_terminal),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected stdio response: {response:?}"),
        }
    }

    /// Reads standard input into an operation-scoped shared-buffer lease.
    ///
    /// The caller must retain exclusive ownership of the sequence's slots
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error, returns a response
    /// for a different operation, or reports an oversized read.
    pub fn read_stdio(
        &self,
        buffer: SharedBufferSequence,
        destination: &mut [u8],
    ) -> Result<usize, Channel::Error> {
        if buffer.length() > MAX_STDIO_TRANSFER_SIZE {
            return Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted,
            ));
        }
        self.validate_shared_buffer(buffer, destination.len());
        match self.request(BrokerOperation::Stdio(StdioRequest::Read(
            ReadStdioRequest { buffer },
        )))? {
            BrokerResult::Stdio(StdioResponse::Read(response)) => {
                assert!(
                    response.read <= buffer.length(),
                    "broker returned oversized shared stdio read"
                );
                let read = response.read as usize;
                self.read_shared_buffer(buffer, &mut destination[..read]);
                Ok(read)
            }
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected stdio response: {response:?}"),
        }
    }

    /// Writes bytes staged in an operation-scoped shared-buffer lease to a
    /// standard output stream.
    ///
    /// The caller must retain exclusive ownership of the sequence's slots
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error, returns a response
    /// for a different operation, or reports an oversized write.
    pub fn write_stdio(
        &self,
        stream: StdioOutputStream,
        buffer: SharedBufferSequence,
        data: &[u8],
    ) -> Result<usize, Channel::Error> {
        if buffer.length() > MAX_STDIO_TRANSFER_SIZE {
            return Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted,
            ));
        }
        self.write_shared_buffer(buffer, data);
        match self.request(BrokerOperation::Stdio(StdioRequest::Write(
            WriteStdioRequest { stream, buffer },
        )))? {
            BrokerResult::Stdio(StdioResponse::Write(response)) => {
                let written = response.written as usize;
                assert!(
                    written <= data.len(),
                    "broker returned oversized shared stdio write"
                );
                Ok(written)
            }
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected stdio response: {response:?}"),
        }
    }
}
