// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{
    AddEventRequest, BrokerRequest, BrokerResponse, ConsumeEventRequest, CoreRequest, CoreResponse,
    CreateEventRequest, ErrorCode, EventConsumeMode, EventRequest, EventResponse, ObjectHandle,
    WaitEventRequest, WaitOutcome,
};

/// Error returned by the deployment-provided broker control path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerControlError;

/// Local-core access to the negotiated broker control channel.
///
/// LiteBox owns broker-backed local objects and constructs broker protocol
/// requests. Deployment code owns endpoint selection and supplies the connected
/// transport behind this protocol-level boundary.
pub trait BrokerControl: Send + Sync {
    /// Sends one active broker request and returns its response.
    fn request(
        &self,
        request: BrokerRequest,
    ) -> core::result::Result<BrokerResponse, BrokerControlError>;
}

/// Error returned by broker-backed local-core objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerObjectError {
    /// The broker control path failed.
    Control,
    /// The broker rejected the object handle, type, or rights.
    InvalidObject,
    /// The operation would block.
    WouldBlock,
    /// The broker object cannot accept more state.
    ResourceExhausted,
    /// The broker returned an unexpected response for the request.
    UnexpectedResponse,
    /// The broker returned an error not represented by this local-core object API.
    Internal,
}

/// How a broker event consume operation should remove readiness credits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerEventConsumeMode {
    /// Consume all currently available credits.
    All,
    /// Consume one credit.
    One,
}

impl BrokerEventConsumeMode {
    const fn to_protocol(self) -> EventConsumeMode {
        match self {
            Self::All => EventConsumeMode::All,
            Self::One => EventConsumeMode::One,
        }
    }
}

/// Broker-backed event object owned by the local core.
#[derive(Clone)]
pub struct BrokerEvent {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
}

impl BrokerEvent {
    pub(crate) fn create(
        broker: Arc<dyn BrokerControl>,
        initial_count: u64,
    ) -> Result<Self, BrokerObjectError> {
        let response = request_event(
            &broker,
            EventRequest::Create(CreateEventRequest::new(initial_count)),
        )?;
        let EventResponse::Create(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(Self {
            broker,
            handle: response.handle,
        })
    }

    /// Consumes readiness credits from the event.
    pub fn consume(&self, mode: BrokerEventConsumeMode) -> Result<u64, BrokerObjectError> {
        let response = self.request(EventRequest::Consume(ConsumeEventRequest::new(
            self.handle,
            mode.to_protocol(),
        )))?;
        let EventResponse::Consume(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(response.value)
    }

    /// Adds readiness credits to the event.
    pub fn add(&self, value: u64) -> Result<(), BrokerObjectError> {
        let response = self.request(EventRequest::Add(AddEventRequest::new(self.handle, value)))?;
        let EventResponse::Add(_) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(())
    }

    /// Returns whether an event wait would complete now.
    pub fn is_read_ready(&self) -> Result<bool, BrokerObjectError> {
        let response = self.request(EventRequest::Wait(WaitEventRequest::new(self.handle)))?;
        let EventResponse::Wait(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(matches!(response.outcome, WaitOutcome::Ready(_)))
    }

    fn request(&self, request: EventRequest) -> Result<EventResponse, BrokerObjectError> {
        request_event(&self.broker, request)
    }
}

fn request_event(
    broker: &Arc<dyn BrokerControl>,
    request: EventRequest,
) -> Result<EventResponse, BrokerObjectError> {
    let response = broker
        .request(BrokerRequest::Core(CoreRequest::Event(request)))
        .map_err(|_| BrokerObjectError::Control)?;
    match response {
        BrokerResponse::Core(CoreResponse::Event(response)) => Ok(response),
        BrokerResponse::Error(error) => Err(error_to_object_error(error)),
        _ => Err(BrokerObjectError::UnexpectedResponse),
    }
}

const fn error_to_object_error(error: ErrorCode) -> BrokerObjectError {
    match error {
        ErrorCode::InvalidRights | ErrorCode::WrongObjectType | ErrorCode::StaleHandle => {
            BrokerObjectError::InvalidObject
        }
        ErrorCode::WouldBlock => BrokerObjectError::WouldBlock,
        ErrorCode::ResourceExhausted => BrokerObjectError::ResourceExhausted,
        _ => BrokerObjectError::Internal,
    }
}
