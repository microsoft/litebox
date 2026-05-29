// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, ObjectHandle, ReadinessState, WaitOutcome,
};

use litebox_broker_transport::ClientTransport;

use crate::{BrokerClient, ClientError, Result};

impl<T: ClientTransport> BrokerClient<T> {
    /// Creates a broker-owned event object.
    pub fn create_event(&mut self) -> Result<ObjectHandle, T::Error> {
        self.ensure_negotiated()?;
        match self.request(BrokerRequest::CreateEvent)? {
            BrokerResponse::Handle(handle) => Ok(handle),
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }

    /// Checks whether an event wait would complete now.
    pub fn wait_event(&mut self, handle: ObjectHandle) -> Result<WaitOutcome, T::Error> {
        self.ensure_negotiated()?;
        match self.request(BrokerRequest::WaitEvent { handle })? {
            BrokerResponse::Wait(outcome) => Ok(outcome),
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }

    /// Signals a broker-owned event object.
    pub fn signal_event(&mut self, handle: ObjectHandle) -> Result<ReadinessState, T::Error> {
        self.ensure_negotiated()?;
        match self.request(BrokerRequest::SignalEvent { handle })? {
            BrokerResponse::Readiness(readiness) => Ok(readiness),
            response => Err(ClientError::UnexpectedResponse(response)),
        }
    }
}
