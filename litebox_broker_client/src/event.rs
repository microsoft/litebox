// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, CoreRequest, CoreResponse, EventRequest, EventResponse,
    ObjectHandle, ReadinessState, WaitOutcome,
};

use litebox_broker_channel::ClientControlChannel;

use crate::{BrokerClient, ClientError, Result};

impl<T: ClientControlChannel> BrokerClient<T> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self) -> Result<ObjectHandle, T::Error> {
        self.ensure_negotiated()?;
        match self.request(event_request(EventRequest::Create))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Created { handle })) => {
                Ok(handle)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }

    /// Checks whether an event wait would complete now.
    pub fn wait_event(&mut self, handle: ObjectHandle) -> Result<WaitOutcome, T::Error> {
        self.ensure_negotiated()?;
        match self.request(event_request(EventRequest::Wait { handle }))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Waited { outcome })) => {
                Ok(outcome)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }

    /// Signals a broker-owned event object.
    pub fn signal_event(&mut self, handle: ObjectHandle) -> Result<ReadinessState, T::Error> {
        self.ensure_negotiated()?;
        match self.request(event_request(EventRequest::Signal { handle }))? {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Signaled { readiness })) => {
                Ok(readiness)
            }
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }
}

const fn event_request(request: EventRequest) -> BrokerRequest {
    BrokerRequest::Core(CoreRequest::Event(request))
}
