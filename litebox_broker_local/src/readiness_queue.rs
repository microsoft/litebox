// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, ReadinessQueueRequest, ReadinessQueueResponse,
};
use litebox_broker_protocol::readiness_queue::{
    AddReadinessQueueEntryRequest, MAX_READINESS_QUEUE_EVENTS, ModifyReadinessQueueEntryRequest,
    READY_EVENT_SIZE, ReadinessQueueError, ReadinessQueueInterest, ReadyEvent,
    RemoveReadinessQueueEntryRequest, TakeReadyRequest,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

type ReadinessQueueResult<T> = core::result::Result<T, ReadinessQueueError>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates an empty broker-owned readiness queue.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued readiness queue request.
    pub fn create_readiness_queue(&self) -> Result<ObjectHandle, Channel::Error> {
        match self.request_readiness_queue(ReadinessQueueRequest::Create)? {
            ReadinessQueueResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected readiness queue response: {response:?}"),
        }
    }

    /// Adds an entry watching `target` under `key` to a readiness queue.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued readiness queue request.
    pub fn add_readiness_queue_entry(
        &self,
        queue: ObjectHandle,
        target: ObjectHandle,
        key: u64,
        interest: ReadinessQueueInterest,
    ) -> Result<ReadinessQueueResult<()>, Channel::Error> {
        let request = ReadinessQueueRequest::Add(AddReadinessQueueEntryRequest {
            queue,
            target,
            key,
            interest,
        });
        match self.request_readiness_queue(request)? {
            ReadinessQueueResponse::Add => Ok(Ok(())),
            ReadinessQueueResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected readiness queue response: {response:?}"),
        }
    }

    /// Replaces the interest of a readiness queue's entry watching `target`
    /// under `key`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued readiness queue request.
    pub fn modify_readiness_queue_entry(
        &self,
        queue: ObjectHandle,
        target: ObjectHandle,
        key: u64,
        interest: ReadinessQueueInterest,
    ) -> Result<ReadinessQueueResult<()>, Channel::Error> {
        let request = ReadinessQueueRequest::Modify(ModifyReadinessQueueEntryRequest {
            queue,
            target,
            key,
            interest,
        });
        match self.request_readiness_queue(request)? {
            ReadinessQueueResponse::Modify => Ok(Ok(())),
            ReadinessQueueResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected readiness queue response: {response:?}"),
        }
    }

    /// Removes a readiness queue's entry watching `target` under `key`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued readiness queue request.
    pub fn remove_readiness_queue_entry(
        &self,
        queue: ObjectHandle,
        target: ObjectHandle,
        key: u64,
    ) -> Result<ReadinessQueueResult<()>, Channel::Error> {
        let request =
            ReadinessQueueRequest::Remove(RemoveReadinessQueueEntryRequest { queue, target, key });
        match self.request_readiness_queue(request)? {
            ReadinessQueueResponse::Remove => Ok(Ok(())),
            ReadinessQueueResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected readiness queue response: {response:?}"),
        }
    }

    /// Takes up to `events.len()` ready events from a readiness queue without
    /// waiting, staging them in an operation-scoped shared buffer lease and
    /// returning how many it stored in `events`.
    ///
    /// The caller must retain exclusive ownership of the sequence's slots
    /// until this method returns. Fails with `ResourceExhausted` if `events`
    /// is longer than [`MAX_READINESS_QUEUE_EVENTS`].
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued readiness queue request, if
    /// `events` is empty, or if `buffer` is not a valid lease holding exactly
    /// `events.len()` encoded events.
    pub fn take_ready(
        &self,
        queue: ObjectHandle,
        buffer: SharedBufferSequence,
        events: &mut [ReadyEvent],
    ) -> Result<usize, Channel::Error> {
        assert!(!events.is_empty(), "a take must request at least one event");
        if events.len() > MAX_READINESS_QUEUE_EVENTS as usize {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        assert_eq!(
            events.len() * READY_EVENT_SIZE as usize,
            buffer.length() as usize,
            "shared events must match their buffer sequence"
        );
        let _ = buffer
            .descriptors(self.shared_buffers.layout())
            .expect("shared buffer sequence must identify valid slot ranges");
        let response =
            self.request_readiness_queue(ReadinessQueueRequest::TakeReady(TakeReadyRequest {
                queue,
                buffer,
            }))?;
        let ReadinessQueueResponse::TakeReady(response) = response else {
            panic!("broker returned unexpected readiness queue response: {response:?}");
        };
        let count = response.count as usize;
        assert!(
            count <= events.len(),
            "broker returned more ready events than requested"
        );
        for (index, event) in events[..count].iter_mut().enumerate() {
            let mut encoded = [0; READY_EVENT_SIZE as usize];
            self.read_shared_buffer_at(buffer, index * READY_EVENT_SIZE as usize, &mut encoded);
            *event = ReadyEvent::decode(&encoded);
        }
        Ok(count)
    }

    fn request_readiness_queue(
        &self,
        request: ReadinessQueueRequest,
    ) -> Result<ReadinessQueueResponse, Channel::Error> {
        match self.request(BrokerOperation::ReadinessQueue(request))? {
            BrokerResult::ReadinessQueue(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected readiness queue response: {response:?}");
            }
        }
    }
}
