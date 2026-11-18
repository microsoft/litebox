// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::segment::{SegmentRequest, SegmentResponse};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Issues a shared segment operation.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a mismatched response.
    pub fn segment(&self, request: SegmentRequest) -> Result<SegmentResponse, Channel::Error> {
        match self.request(BrokerOperation::Segment(request))? {
            BrokerResult::Segment(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected segment response: {response:?}"),
        }
    }
}
