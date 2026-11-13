// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ThreadId;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, ThreadRequest, ThreadResponse,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker thread belonging to this process.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_thread(&self) -> Result<ThreadId, Channel::Error> {
        match self.request_thread(ThreadRequest::Create)? {
            ThreadResponse::Create(thread_id) => Ok(thread_id),
            response @ ThreadResponse::Exit => {
                panic!("broker returned unexpected thread response: {response:?}")
            }
        }
    }

    /// Records broker thread exit after local teardown completes.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn exit_thread(&self, thread_id: ThreadId) -> Result<(), Channel::Error> {
        match self.request_thread(ThreadRequest::Exit(thread_id))? {
            ThreadResponse::Exit => Ok(()),
            response @ ThreadResponse::Create(_) => {
                panic!("broker returned unexpected thread response: {response:?}")
            }
        }
    }

    fn request_thread(&self, request: ThreadRequest) -> Result<ThreadResponse, Channel::Error> {
        match self.request(BrokerOperation::Thread(request))? {
            BrokerResult::Thread(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected thread response: {response:?}"),
        }
    }
}
