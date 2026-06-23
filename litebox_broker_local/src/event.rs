// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{
    AddEventRequest, BrokerRequest, BrokerResponse, ConsumeEventRequest, ConsumeEventResponse,
    CoreRequest, CoreResponse, CreateEventRequest, EventConsumeMode, EventRequest, EventResponse,
    LocalControlChannel, ObjectHandle, ReadinessState, WaitEventRequest, WaitOutcome,
};

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<T: LocalControlChannel> BrokerLocal<T> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self) -> Result<ObjectHandle, T::Error> {
        self.create_event_with_count(0)
    }

    /// Creates a broker-owned event object with initial readiness credits.
    pub fn create_event_with_count(
        &mut self,
        initial_count: u64,
    ) -> Result<ObjectHandle, T::Error> {
        match self.request(event_request(EventRequest::Create(CreateEventRequest {
            initial_count,
        })))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Create(response))) => {
                Ok(response.handle)
            }
            response => Err(BrokerLocalError::UnexpectedResponse(response)),
        }
    }

    /// Checks whether an event wait would complete now.
    pub fn wait_event(&mut self, handle: ObjectHandle) -> Result<WaitOutcome, T::Error> {
        match self.request(event_request(EventRequest::Wait(WaitEventRequest {
            handle,
        })))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Wait(response))) => {
                Ok(response.outcome)
            }
            response => Err(BrokerLocalError::UnexpectedResponse(response)),
        }
    }

    /// Adds readiness credits to a broker-owned event object.
    pub fn add_event(
        &mut self,
        handle: ObjectHandle,
        value: u64,
    ) -> Result<ReadinessState, T::Error> {
        match self.request(event_request(EventRequest::Add(AddEventRequest {
            handle,
            value,
        })))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Add(response))) => {
                Ok(response.readiness)
            }
            response => Err(BrokerLocalError::UnexpectedResponse(response)),
        }
    }

    /// Consumes readiness credits from a broker-owned event object.
    pub fn consume_event(
        &mut self,
        handle: ObjectHandle,
        mode: EventConsumeMode,
    ) -> Result<ConsumeEventResponse, T::Error> {
        match self.request(event_request(EventRequest::Consume(ConsumeEventRequest {
            handle,
            mode,
        })))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Consume(response))) => {
                Ok(response)
            }
            response => Err(BrokerLocalError::UnexpectedResponse(response)),
        }
    }
}

const fn event_request(request: EventRequest) -> BrokerRequest {
    BrokerRequest::Core(CoreRequest::Event(request))
}
