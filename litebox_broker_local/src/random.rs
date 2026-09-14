// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE;
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Fills `output` from a broker-provided random source.
    ///
    /// # Panics
    ///
    /// Panics if `output` does not match the shared-buffer sequence or the
    /// broker returns a response for a different operation.
    pub fn fill_random(
        &self,
        buffer: SharedBufferSequence,
        output: &mut [u8],
    ) -> Result<(), Channel::Error> {
        assert!(
            buffer.length() <= MAX_RANDOM_TRANSFER_SIZE,
            "shared random sequence exceeds the transfer limit"
        );
        assert_eq!(
            output.len(),
            buffer.length() as usize,
            "shared data must match its buffer sequence"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
        match self.request(BrokerOperation::FillRandom(buffer))? {
            BrokerResult::RandomFilled => {
                self.read_shared_buffer(buffer, output);
                Ok(())
            }
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected random response: {response:?}"),
        }
    }
}
