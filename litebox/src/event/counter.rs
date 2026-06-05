// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

pub use litebox_broker_protocol::EventConsumeMode as EventCounterReadMode;
use litebox_broker_protocol::{
    AddEventRequest, ConsumeEventRequest, ConsumeEventResponse, CoreRequest, CoreResponse,
    CreateEventRequest, EventRequest, EventResponse, ObjectHandle, ReadinessState,
    WaitEventRequest, WaitOutcome,
};

use crate::{
    LiteBox,
    broker::{
        BrokerControl,
        error::{BrokerObjectError, map_broker_object_result},
    },
    event::{
        Events, IOPollable, observer::Observer, polling::Pollee, polling::TryOpError,
        wait::WaitContext,
    },
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// Errors returned by local-core event counters.
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
    /// The backing authority returned a response shape that does not match the request.
    UnexpectedResponse,
    /// No backing authority is available for this event counter.
    Unavailable,
}

/// A local-core event counter object.
pub struct EventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollee: Pollee<Platform>,
    blocking_operations_supported: bool,
}

impl<Platform> EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    /// Creates a local-core event counter.
    pub fn new(litebox: &LiteBox<Platform>, initial_count: u64) -> Result<Self, EventCounterError> {
        let Some(broker) = litebox.broker_control() else {
            return Err(EventCounterError::Unavailable);
        };
        let response = broker
            .request(CoreRequest::Event(EventRequest::Create(
                CreateEventRequest::new(initial_count),
            )))
            .map_err(BrokerObjectError::from)
            .and_then(event_response_from_core)
            .map_err(EventCounterError::from)?;
        let EventResponse::Create(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse.into());
        };
        Ok(Self {
            broker,
            handle: response.handle,
            pollee: Pollee::new(),
            blocking_operations_supported: true,
        })
    }

    /// Returns whether blocking reads and writes are supported.
    pub fn supports_blocking_operations(&self) -> bool {
        self.blocking_operations_supported
    }

    /// Reads the event counter.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        mode: EventCounterReadMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        self.pollee.wait(cx, nonblock, Events::IN, || {
            let response = map_broker_object_result(self.consume(mode))?;
            if response.readiness.write_ready {
                self.pollee.notify_observers(Events::OUT);
            }
            Ok(response.value)
        })
    }

    /// Writes readiness credits to the event counter.
    pub fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        value: u64,
    ) -> Result<usize, TryOpError<EventCounterError>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(EventCounterError::InvalidInput));
        }
        self.pollee.wait(cx, nonblock, Events::OUT, || {
            let readiness = map_broker_object_result(self.add(value))?;
            if value != 0 && readiness.read_ready {
                self.pollee.notify_observers(Events::IN);
            }
            Ok(core::mem::size_of::<u64>())
        })
    }

    fn consume(
        &self,
        mode: EventCounterReadMode,
    ) -> Result<ConsumeEventResponse, BrokerObjectError> {
        let response = self.request_event(EventRequest::Consume(ConsumeEventRequest::new(
            self.handle,
            mode,
        )))?;
        let EventResponse::Consume(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(response)
    }

    fn add(&self, value: u64) -> Result<ReadinessState, BrokerObjectError> {
        let response =
            self.request_event(EventRequest::Add(AddEventRequest::new(self.handle, value)))?;
        let EventResponse::Add(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(response.readiness)
    }

    fn readiness_state(&self) -> Result<ReadinessState, BrokerObjectError> {
        let response =
            self.request_event(EventRequest::Wait(WaitEventRequest::new(self.handle)))?;
        let EventResponse::Wait(response) = response else {
            return Err(BrokerObjectError::UnexpectedResponse);
        };
        Ok(match response.outcome {
            WaitOutcome::Ready(readiness) | WaitOutcome::WouldBlock(readiness) => readiness,
            _ => return Err(BrokerObjectError::UnexpectedResponse),
        })
    }

    fn request_event(&self, request: EventRequest) -> Result<EventResponse, BrokerObjectError> {
        self.broker
            .request(CoreRequest::Event(request))
            .map_err(BrokerObjectError::from)
            .and_then(event_response_from_core)
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
        let Ok(readiness) = self.readiness_state() else {
            return Events::empty();
        };
        let mut events = Events::empty();
        if readiness.read_ready {
            events |= Events::IN;
        }
        if readiness.write_ready {
            events |= Events::OUT;
        }
        events
    }
}

fn event_response_from_core(response: CoreResponse) -> Result<EventResponse, BrokerObjectError> {
    match response {
        CoreResponse::Event(response) => Ok(response),
        _ => Err(BrokerObjectError::UnexpectedResponse),
    }
}
