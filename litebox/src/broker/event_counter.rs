// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::{
    AddEventRequest, BrokerRequest, BrokerResponse, ConsumeEventRequest, CoreRequest, CoreResponse,
    CreateEventRequest, ErrorCode, EventConsumeMode, EventRequest, EventResponse, ObjectHandle,
    WaitEventRequest, WaitOutcome,
};

use super::{BrokerControl, BrokerState};
use crate::{
    event::{
        Events, IOPollable, observer::Observer, polling::Pollee, polling::TryOpError,
        wait::WaitContext,
    },
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// Errors returned by broker-backed local-core event counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventCounterError {
    /// The requested operation is invalid for this event counter.
    InvalidInput,
    /// The operation would block.
    WouldBlock,
    /// The event counter cannot accept more state.
    ResourceExhausted,
    /// The backing authority or transport failed.
    Io,
}

/// How an event counter read should consume readiness credits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventCounterConsumeMode {
    /// Consume all currently available credits.
    All,
    /// Consume one credit.
    One,
}

/// A broker-backed local-core event counter.
pub struct EventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    event: BrokerEvent,
    pollee: Pollee<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> BrokerState<Platform> {
    pub(crate) fn create_event_counter(
        &self,
        initial_count: u64,
    ) -> Result<Option<EventCounter<Platform>>, EventCounterError>
    where
        Platform: TimeProvider,
    {
        let Some(control) = self.control.read().clone() else {
            return Ok(None);
        };
        EventCounter::new(control, initial_count).map(Some)
    }
}

#[derive(Clone)]
struct BrokerEvent {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
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

impl<Platform> EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn new(broker: Arc<dyn BrokerControl>, initial_count: u64) -> Result<Self, EventCounterError> {
        let event = BrokerEvent::create(broker, initial_count)
            .map_err(broker_error_to_event_counter_error)?;
        Ok(Self {
            event,
            pollee: Pollee::new(),
        })
    }

    /// Returns whether blocking reads and writes are supported.
    pub fn supports_blocking_operations(&self) -> bool {
        false
    }

    /// Reads the event counter.
    pub fn read(
        &self,
        _cx: &WaitContext<'_, Platform>,
        _nonblock: bool,
        mode: EventCounterConsumeMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        let value = map_broker_result(self.event.consume(mode))?;
        self.pollee.notify_observers(Events::OUT);
        Ok(value)
    }

    /// Writes readiness credits to the event counter.
    pub fn write(
        &self,
        _cx: &WaitContext<'_, Platform>,
        _nonblock: bool,
        value: u64,
    ) -> Result<usize, TryOpError<EventCounterError>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(EventCounterError::InvalidInput));
        }
        map_broker_result(self.event.add(value))?;
        self.pollee.notify_observers(Events::IN);
        Ok(core::mem::size_of::<u64>())
    }
}

impl<Platform> IOPollable for EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
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

fn map_broker_result<T>(
    result: Result<T, BrokerObjectError>,
) -> Result<T, TryOpError<EventCounterError>> {
    match result {
        Ok(value) => Ok(value),
        Err(BrokerObjectError::WouldBlock) => Err(TryOpError::TryAgain),
        Err(error) => Err(TryOpError::Other(broker_error_to_event_counter_error(
            error,
        ))),
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
