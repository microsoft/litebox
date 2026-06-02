// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{
    AddEventRequest, BrokerRequest, BrokerResponse, ClientControlChannel, ConsumeEventRequest,
    ConsumeEventResponse, CoreRequest, CoreResponse, CreateEventRequest, EventConsumeMode,
    EventRequest, EventResponse, ObjectHandle, ReadinessState, WaitEventRequest, WaitOutcome,
};

use crate::{BrokerClient, ClientError, Result};

impl<T: ClientControlChannel> BrokerClient<T> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self) -> Result<ObjectHandle, T::Error> {
        self.create_event_with_count(0)
    }

    /// Creates a broker-owned event object with initial readiness credits.
    pub fn create_event_with_count(
        &mut self,
        initial_count: u64,
    ) -> Result<ObjectHandle, T::Error> {
        self.ensure_negotiated()?;
        match self.request(event_request(EventRequest::Create(
            CreateEventRequest::new(initial_count),
        )))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Create(response))) => {
                Ok(response.handle)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }

    /// Checks whether an event wait would complete now.
    pub fn wait_event(&mut self, handle: ObjectHandle) -> Result<WaitOutcome, T::Error> {
        self.ensure_negotiated()?;
        match self.request(event_request(EventRequest::Wait(WaitEventRequest::new(
            handle,
        ))))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Wait(response))) => {
                Ok(response.outcome)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }

    /// Adds readiness credits to a broker-owned event object.
    pub fn add_event(
        &mut self,
        handle: ObjectHandle,
        value: u64,
    ) -> Result<ReadinessState, T::Error> {
        self.ensure_negotiated()?;
        match self.request(event_request(EventRequest::Add(AddEventRequest::new(
            handle, value,
        ))))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Add(response))) => {
                Ok(response.readiness)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }

    /// Consumes readiness credits from a broker-owned event object.
    pub fn consume_event(
        &mut self,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> Result<ConsumeEventResponse, T::Error> {
        self.ensure_negotiated()?;
        match self.request(event_request(EventRequest::Consume(
            ConsumeEventRequest::new(handle, mode),
        )))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Consume(response))) => {
                Ok(response)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }
}

const fn event_request(request: EventRequest) -> BrokerRequest {
    BrokerRequest::Core(CoreRequest::Event(request))
}
