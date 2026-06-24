// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::event::{
    AddEventRequest, ConsumeEventRequest, ConsumeEventResponse, CreateEventRequest,
    EventConsumeMode, ReadinessState, WaitEventRequest,
};
use litebox_broker_protocol::message::{CoreRequest, CoreResponse, EventRequest, EventResponse};

use crate::{BrokerLocal, Result};

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self) -> Result<ObjectHandle, Channel::Error> {
        self.create_event_with_count(0)
    }

    /// Creates a broker-owned event object with initial readiness credits.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued event request.
    pub fn create_event_with_count(
        &mut self,
        initial_count: u64,
    ) -> Result<ObjectHandle, Channel::Error> {
        let response =
            self.request_event(EventRequest::Create(CreateEventRequest { initial_count }))?;
        match response {
            EventResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected event response: {response:?}"),
        }
    }

    /// Checks whether an event wait would complete now.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued event request.
    pub fn wait_event(&mut self, handle: ObjectHandle) -> Result<ReadinessState, Channel::Error> {
        let response = self.request_event(EventRequest::Wait(WaitEventRequest { handle }))?;
        match response {
            EventResponse::Wait(response) => Ok(response.readiness),
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
        &mut self,
        handle: ObjectHandle,
        value: u64,
    ) -> Result<ReadinessState, Channel::Error> {
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
        &mut self,
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

    fn request_event(&mut self, request: EventRequest) -> Result<EventResponse, Channel::Error> {
        let CoreResponse::Event(response) = self.request(CoreRequest::Event(request))?;
        Ok(response)
    }
}
