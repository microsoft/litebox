// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::event::{
    AddEventRequest, ConsumeEventRequest, ConsumeEventResponse, CreateEventRequest,
    EventConsumeMode,
};
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, EventRequest, EventResponse,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned event object with initial readiness credits.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued event request.
    pub fn create_event_with_count(
        &self,
        initial_count: u64,
    ) -> Result<ObjectHandle, Channel::Error> {
        let response =
            self.request_event(EventRequest::Create(CreateEventRequest { initial_count }))?;
        match response {
            EventResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected event response: {response:?}"),
        }
    }

    /// Adds readiness credits to a broker-owned event object.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued event request.
    pub fn add_event(
        &self,
        handle: ObjectHandle,
        value: u64,
    ) -> Result<ReadinessFlags, Channel::Error> {
        let response = self.request_event(EventRequest::Add(AddEventRequest { handle, value }))?;
        match response {
            EventResponse::Add(response) => Ok(response.readiness),
            response => panic!("broker returned unexpected event response: {response:?}"),
        }
    }

    /// Consumes readiness credits from a broker-owned event object.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued event request.
    pub fn consume_event(
        &self,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> Result<ConsumeEventResponse, Channel::Error> {
        let response =
            self.request_event(EventRequest::Consume(ConsumeEventRequest { handle, mode }))?;
        match response {
            EventResponse::Consume(response) => Ok(response),
            response => panic!("broker returned unexpected event response: {response:?}"),
        }
    }

    fn request_event(&self, request: EventRequest) -> Result<EventResponse, Channel::Error> {
        match self.request(BrokerOperation::Event(request))? {
            BrokerResult::Event(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResult::ObjectClosed
            | BrokerResult::Readiness(_)
            | BrokerResult::Pipe(_)) => {
                panic!("broker returned unexpected event response: {response:?}");
            }
        }
    }
}
