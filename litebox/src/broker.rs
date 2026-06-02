// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{
    AddEventRequest, BrokerRequest, BrokerResponse, ConsumeEventRequest, CoreRequest, CoreResponse,
    CreateEventRequest, ErrorCode, EventConsumeMode, EventRequest, EventResponse, ObjectHandle,
    WaitEventRequest, WaitOutcome,
};

use crate::{
    event::{EventCounter, EventCounterConsumeMode, EventCounterError, EventCounterSource, Events},
    platform::TimeProvider,
    sync::{RawSyncPrimitivesProvider, RwLock},
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

pub(crate) struct BrokerState<Platform: RawSyncPrimitivesProvider> {
    control: RwLock<Platform, Option<Arc<dyn BrokerControl>>>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerState<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            control: RwLock::new(None),
        }
    }

    pub(crate) fn set_control(&self, broker_control: Arc<dyn BrokerControl>) {
        *self.control.write() = Some(broker_control);
    }

    pub(crate) fn create_event_counter(
        &self,
        initial_count: u64,
        requires_blocking: bool,
    ) -> Result<EventCounter<Platform>, EventCounterError>
    where
        Platform: TimeProvider + 'static,
    {
        if requires_blocking {
            return EventCounter::new_local(initial_count);
        }
        let Some(control) = self.control.read().clone() else {
            return EventCounter::new_local(initial_count);
        };
        create_broker_event_counter(control, initial_count)
    }
}

#[derive(Clone)]
struct BrokerEvent {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
}

struct BrokerEventCounter {
    event: BrokerEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerObjectError {
    Control,
    InvalidObject,
    WouldBlock,
    ResourceExhausted,
    UnexpectedResponse,
    Internal,
}

impl BrokerEvent {
    fn create(
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

    fn consume(&self, mode: EventCounterConsumeMode) -> Result<u64, BrokerObjectError> {
        let response = self.request(EventRequest::Consume(ConsumeEventRequest::new(
            self.handle,
            to_protocol_consume_mode(mode),
        )))?;
        let EventResponse::Consume(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(response.value)
    }

    fn add(&self, value: u64) -> Result<(), BrokerObjectError> {
        let response = self.request(EventRequest::Add(AddEventRequest::new(self.handle, value)))?;
        let EventResponse::Add(_) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(())
    }

    fn is_read_ready(&self) -> Result<bool, BrokerObjectError> {
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

impl<Platform> EventCounterSource<Platform> for BrokerEventCounter
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn supports_blocking_operations(&self) -> bool {
        false
    }

    fn read(&self, mode: EventCounterConsumeMode) -> Result<u64, EventCounterError> {
        self.event
            .consume(mode)
            .map_err(broker_error_to_event_counter_error)
    }

    fn write(&self, value: u64) -> Result<(), EventCounterError> {
        self.event
            .add(value)
            .map_err(broker_error_to_event_counter_error)
    }

    fn check_io_events(&self) -> Events {
        // The broker protocol currently exposes read readiness only. Keep write
        // readiness optimistic and surface counter-limit failures from write
        // until broker write-readiness plumbing exists.
        let mut events = Events::OUT;
        if self.event.is_read_ready().unwrap_or(false) {
            events |= Events::IN;
        }
        events
    }
}

fn create_broker_event_counter<Platform>(
    broker: Arc<dyn BrokerControl>,
    initial_count: u64,
) -> Result<EventCounter<Platform>, EventCounterError>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider + 'static,
{
    let event =
        BrokerEvent::create(broker, initial_count).map_err(broker_error_to_event_counter_error)?;
    Ok(EventCounter::from_source(BrokerEventCounter { event }))
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

const fn to_protocol_consume_mode(mode: EventCounterConsumeMode) -> EventConsumeMode {
    match mode {
        EventCounterConsumeMode::All => EventConsumeMode::All,
        EventCounterConsumeMode::One => EventConsumeMode::One,
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

const fn broker_error_to_event_counter_error(error: BrokerObjectError) -> EventCounterError {
    match error {
        BrokerObjectError::InvalidObject => EventCounterError::InvalidInput,
        BrokerObjectError::WouldBlock => EventCounterError::WouldBlock,
        BrokerObjectError::ResourceExhausted => EventCounterError::ResourceExhausted,
        _ => EventCounterError::Io,
    }
}
