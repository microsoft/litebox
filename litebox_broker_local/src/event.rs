// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{
    AddEventRequest, BrokerResponse, ConsumeEventRequest, ConsumeEventResponse, CoreRequest,
    CoreResponse, CreateEventRequest, EventConsumeMode, EventRequest, EventResponse,
    LocalControlChannel, ObjectHandle, ReadinessState, WaitEventRequest,
};

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self) -> Result<ObjectHandle, Channel::Error> {
        self.create_event_with_count(0)
    }

    /// Creates a broker-owned event object with initial readiness credits.
    pub fn create_event_with_count(
        &mut self,
        initial_count: u64,
    ) -> Result<ObjectHandle, Channel::Error> {
        let response =
            self.request_event(EventRequest::Create(CreateEventRequest { initial_count }))?;
        match response {
            EventResponse::Create(response) => Ok(response.handle),
            response => Err(BrokerLocalError::UnexpectedResponse(BrokerResponse::Core(
                CoreResponse::Event(response),
            ))),
        }
    }

    /// Checks whether an event wait would complete now.
    pub fn wait_event(&mut self, handle: ObjectHandle) -> Result<ReadinessState, Channel::Error> {
        let response = self.request_event(EventRequest::Wait(WaitEventRequest { handle }))?;
        match response {
            EventResponse::Wait(response) => Ok(response.readiness),
            response => Err(BrokerLocalError::UnexpectedResponse(BrokerResponse::Core(
                CoreResponse::Event(response),
            ))),
        }
    }

    /// Adds readiness credits to a broker-owned event object.
    pub fn add_event(
        &mut self,
        handle: ObjectHandle,
        value: u64,
    ) -> Result<ReadinessState, Channel::Error> {
        let response = self.request_event(EventRequest::Add(AddEventRequest { handle, value }))?;
        match response {
            EventResponse::Add(response) => Ok(response.readiness),
            response => Err(BrokerLocalError::UnexpectedResponse(BrokerResponse::Core(
                CoreResponse::Event(response),
            ))),
        }
    }

    /// Consumes readiness credits from a broker-owned event object.
    pub fn consume_event(
        &mut self,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> Result<ConsumeEventResponse, Channel::Error> {
        let response =
            self.request_event(EventRequest::Consume(ConsumeEventRequest { handle, mode }))?;
        match response {
            EventResponse::Consume(response) => Ok(response),
            response => Err(BrokerLocalError::UnexpectedResponse(BrokerResponse::Core(
                CoreResponse::Event(response),
            ))),
        }
    }

    fn request_event(&mut self, request: EventRequest) -> Result<EventResponse, Channel::Error> {
        let CoreResponse::Event(response) = self.request(CoreRequest::Event(request))?;
        Ok(response)
    }
}
