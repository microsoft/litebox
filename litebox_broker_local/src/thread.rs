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

#[cfg(test)]
mod tests {
    use litebox_broker_protocol::RequestId;
    use litebox_broker_protocol::message::BrokerRequest;

    use super::*;
    use crate::test_support::test_broker_local;
    use crate::tests::{FakeControlChannel, noop_shared_memory};

    #[test]
    fn thread_lifecycle_sends_owned_id() {
        let thread_id = ThreadId(7);
        let channel = FakeControlChannel::new(
            None,
            Some(BrokerResult::Thread(ThreadResponse::Create(thread_id))),
        );
        let local = test_broker_local(channel, noop_shared_memory());

        assert_eq!(local.create_thread().unwrap(), thread_id);
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(0),
                operation: BrokerOperation::Thread(ThreadRequest::Create),
            })
        );

        *local.channel.response.borrow_mut() = Some(BrokerResult::Thread(ThreadResponse::Exit));
        local.exit_thread(thread_id).unwrap();
        assert_eq!(
            local.channel.sent_request.borrow().clone(),
            Some(BrokerRequest {
                request_id: RequestId(1),
                operation: BrokerOperation::Thread(ThreadRequest::Exit(thread_id)),
            })
        );
    }
}
