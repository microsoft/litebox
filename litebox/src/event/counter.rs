// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
pub use litebox_broker_protocol::event::EventConsumeMode as EventCounterReadMode;
use litebox_broker_protocol::event::{ConsumeEventResponse, ReadinessState};
use thiserror::Error;

use crate::{
    LiteBox,
    broker::{
        BrokerControl,
        error::{BrokerControlError, BrokerObjectError},
    },
    event::{
        Events, IOPollable, observer::Observer, polling::Pollee, polling::TryOpError,
        wait::WaitContext,
    },
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// Errors returned by local-core event counters.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventCounterError {
    #[error("invalid event counter input")]
    InvalidInput,
    #[error("event counter operation would block")]
    WouldBlock,
    #[error("event counter resource exhausted")]
    ResourceExhausted,
    #[error("event counter permission denied")]
    PermissionDenied,
    #[error("event counter I/O failed")]
    Io,
    #[error("event counter backing authority unavailable")]
    Unavailable,
}

/// A local-core event counter object.
pub struct EventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollee: Pollee<Platform>,
}

impl<Platform> EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    /// Creates a local-core event counter.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued event request.
    pub fn new(litebox: &LiteBox<Platform>, initial_count: u64) -> Result<Self, EventCounterError> {
        let Some(broker) = litebox.broker_control() else {
            return Err(EventCounterError::Unavailable);
        };
        let handle = broker
            .create_event_with_count(initial_count)
            .map_err(BrokerObjectError::from)
            .map_err(EventCounterError::from)?;
        Ok(Self {
            broker,
            handle,
            pollee: Pollee::new(),
        })
    }

    /// Reads the event counter.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        mode: EventCounterReadMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        self.pollee.wait(cx, nonblock, Events::IN, || {
            let response = self.consume(mode)?;
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
            let readiness = self.add(value)?;
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
        self.broker
            .consume_event(self.handle, mode)
            .map_err(|error| self.broker_request_error(error))
    }

    fn add(&self, value: u64) -> Result<ReadinessState, BrokerObjectError> {
        self.broker
            .add_event(self.handle, value)
            .map_err(|error| self.broker_request_error(error))
    }

    fn broker_request_error(&self, error: BrokerControlError) -> BrokerObjectError {
        let error = error.into();
        if error != BrokerObjectError::WouldBlock {
            self.pollee.notify_observers(Events::ERR);
        }
        error
    }
}

impl<Platform> Drop for EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn drop(&mut self) {
        let _ = self.broker.close_object(self.handle);
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
        let readiness = match self
            .broker
            .wait_event(self.handle)
            .map_err(|error| self.broker_request_error(error))
        {
            Ok(readiness) => readiness,
            Err(BrokerObjectError::WouldBlock) => return Events::empty(),
            Err(_) => return Events::ERR,
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
