// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE;
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::transfer::CopyToFn;
use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Fills an operation-scoped shared-buffer lease from a broker-provided
    /// random source, and lends its bytes to `copy_to`.
    ///
    /// # Panics
    ///
    /// Panics if the sequence is invalid or exceeds the transfer limit, or if
    /// the broker returns a response for a different operation.
    pub fn fill_random(
        &self,
        buffer: SharedBufferSequence,
        copy_to: &mut CopyToFn<'_>,
    ) -> Result<(), Channel::Error> {
        assert!(
            buffer.length() <= MAX_RANDOM_TRANSFER_SIZE,
            "shared random sequence exceeds the transfer limit"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
        match self.request(BrokerOperation::FillRandom(buffer))? {
            BrokerResult::RandomFilled => {
                self.lend_shared_buffer(buffer, 0, buffer.length() as usize, copy_to)
            }
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected random response: {response:?}"),
        }
    }
}
