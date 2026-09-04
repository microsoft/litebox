// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, StdioRequest, StdioResponse,
};
use litebox_broker_protocol::shared_buffer::SharedBufferDescriptor;
use litebox_broker_protocol::stdio::{
    MAX_STDIO_TRANSFER_SIZE, StdioOutputStream, WriteStdioRequest,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Writes bytes staged in an operation-scoped shared-buffer lease to a
    /// standard output stream.
    ///
    /// The caller must retain exclusive ownership of the descriptor's slot
    /// until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error, returns a response
    /// for a different operation, or reports an oversized write.
    pub fn write_stdio(
        &self,
        stream: StdioOutputStream,
        buffer: SharedBufferDescriptor,
        data: &[u8],
    ) -> Result<usize, Channel::Error> {
        if buffer.length > MAX_STDIO_TRANSFER_SIZE {
            return Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted,
            ));
        }
        assert_eq!(
            data.len(),
            buffer.length as usize,
            "shared stdio write data must match its descriptor"
        );
        self.shared_buffers
            .write(buffer.slot_index, data)
            .expect("validated shared stdio write range must be accessible");
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
