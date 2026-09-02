// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::random::{FillRandomRequest, MAX_RANDOM_TRANSFER_SIZE};
use litebox_broker_protocol::shared_buffer::SharedBufferDescriptor;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Fills `output` from a broker-provided random source.
    ///
    /// # Panics
    ///
    /// Panics if `output` does not match the shared-buffer descriptor or the
    /// broker returns a response for a different operation.
    pub fn fill_random(
        &self,
        buffer: SharedBufferDescriptor,
        output: &mut [u8],
    ) -> Result<(), Channel::Error> {
        assert!(
            buffer.length <= MAX_RANDOM_TRANSFER_SIZE,
            "shared random descriptor exceeds the transfer limit"
        );
        assert_eq!(
            output.len(),
            buffer.length as usize,
            "random destination length must match its shared-buffer descriptor"
        );
        self.shared_buffers
            .layout()
            .range(buffer.slot_index, output.len())
            .expect("shared random descriptor must identify a valid slot range");
        match self.request(BrokerOperation::FillRandom(FillRandomRequest { buffer }))? {
            BrokerResult::RandomFilled => {
                self.shared_buffers
                    .read(buffer.slot_index, output)
                    .expect("validated random shared-buffer read must fit its slot");
                Ok(())
            }
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected random response: {response:?}"),
        }
    }
}
