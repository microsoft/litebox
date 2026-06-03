// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    broker::event::BrokerEventCounter,
    event::{Events, IOPollable, observer::Observer, polling::TryOpError, wait::WaitContext},
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// How an event-counter read consumes the current counter value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventCounterReadMode {
    /// Consume the full counter value.
    All,
    /// Consume one counter credit.
    One,
}

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

enum EventCounterBackend<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Broker(BrokerEventCounter<Platform>),
}

/// A local-core event counter object.
///
/// The object API is independent of the current backing implementation. The
/// split-broker POC uses a broker-backed counter, while future migrations can add
/// other backends without changing shim-facing call sites.
pub struct EventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    backend: EventCounterBackend<Platform>,
}

impl<Platform> EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    pub(crate) fn from_broker(event: BrokerEventCounter<Platform>) -> Self {
        Self {
            backend: EventCounterBackend::Broker(event),
        }
    }

    /// Returns whether blocking reads and writes are supported.
    pub fn supports_blocking_operations(&self) -> bool {
        match &self.backend {
            EventCounterBackend::Broker(_) => {
                BrokerEventCounter::<Platform>::supports_blocking_operations()
            }
        }
    }

    /// Reads the event counter.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        mode: EventCounterReadMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        match &self.backend {
            EventCounterBackend::Broker(event) => event.read(cx, nonblock, mode),
        }
    }

    /// Writes readiness credits to the event counter.
    pub fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        value: u64,
    ) -> Result<usize, TryOpError<EventCounterError>> {
        match &self.backend {
            EventCounterBackend::Broker(event) => event.write(cx, nonblock, value),
        }
    }
}

impl<Platform> IOPollable for EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        match &self.backend {
            EventCounterBackend::Broker(event) => event.register_observer(observer, mask),
        }
    }

    fn check_io_events(&self) -> Events {
        match &self.backend {
            EventCounterBackend::Broker(event) => event.check_io_events(),
        }
    }
}
