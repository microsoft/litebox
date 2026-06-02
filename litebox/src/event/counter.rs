// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::{Arc, Weak};

use super::{
    Events, IOPollable,
    observer::Observer,
    polling::{Pollee, TryOpError},
    wait::WaitContext,
};
use crate::{
    broker::{BrokerControl, BrokerEvent, BrokerEventConsumeMode, BrokerObjectError},
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};

const MAX_EVENT_COUNT: u64 = u64::MAX - 1;

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
}

/// How an event counter read should consume readiness credits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventCounterConsumeMode {
    /// Consume all currently available credits.
    All,
    /// Consume one credit.
    One,
}

impl EventCounterConsumeMode {
    const fn to_broker(self) -> BrokerEventConsumeMode {
        match self {
            Self::All => BrokerEventConsumeMode::All,
            Self::One => BrokerEventConsumeMode::One,
        }
    }
}

/// A local-core event counter.
///
/// This object provides eventfd-like counter semantics without exposing whether
/// the backing state is local-private or broker-mediated.
pub struct EventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    backend: EventCounterBackend<Platform>,
    pollee: Pollee<Platform>,
}

enum EventCounterBackend<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Local { counter: Mutex<Platform, u64> },
    Broker { event: BrokerEvent },
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventCounter<Platform> {
    pub(crate) fn new_local(initial_count: u64) -> Result<Self, EventCounterError> {
        if initial_count > MAX_EVENT_COUNT {
            return Err(EventCounterError::ResourceExhausted);
        }
        Ok(Self {
            backend: EventCounterBackend::Local {
                counter: Mutex::new(initial_count),
            },
            pollee: Pollee::new(),
        })
    }

    pub(crate) fn new_broker(event: BrokerEvent) -> Self {
        Self {
            backend: EventCounterBackend::Broker { event },
            pollee: Pollee::new(),
        }
    }

    pub(crate) fn new_broker_from_control(
        broker: Arc<dyn BrokerControl>,
        initial_count: u64,
    ) -> Result<Self, EventCounterError> {
        BrokerEvent::create(broker, initial_count)
            .map(Self::new_broker)
            .map_err(broker_error_to_event_counter_error)
    }

    /// Returns whether blocking reads and writes are supported.
    pub fn supports_blocking_operations(&self) -> bool {
        match self.backend {
            EventCounterBackend::Local { .. } => true,
            EventCounterBackend::Broker { .. } => false,
        }
    }

    /// Reads the event counter, optionally blocking until the counter is ready.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        mode: EventCounterConsumeMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        if !self.supports_blocking_operations() {
            return self.try_read(mode);
        }
        self.pollee
            .wait(cx, nonblock, Events::IN, || self.try_read(mode))
    }

    /// Writes readiness credits to the event counter, optionally blocking until
    /// the counter can accept them.
    pub fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        value: u64,
    ) -> Result<usize, TryOpError<EventCounterError>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(EventCounterError::InvalidInput));
        }
        if !self.supports_blocking_operations() {
            return self.try_write(value);
        }
        self.pollee
            .wait(cx, nonblock, Events::OUT, || self.try_write(value))
    }

    fn try_read(
        &self,
        mode: EventCounterConsumeMode,
    ) -> Result<u64, TryOpError<EventCounterError>> {
        match &self.backend {
            EventCounterBackend::Local { counter } => {
                let mut counter = counter.lock();
                if *counter == 0 {
                    return Err(TryOpError::TryAgain);
                }

                let res = match mode {
                    EventCounterConsumeMode::All => *counter,
                    EventCounterConsumeMode::One => 1,
                };
                *counter -= res;

                drop(counter);
                self.pollee.notify_observers(Events::OUT);
                Ok(res)
            }
            EventCounterBackend::Broker { event } => match event.consume(mode.to_broker()) {
                Ok(value) => {
                    self.pollee.notify_observers(Events::OUT);
                    Ok(value)
                }
                Err(BrokerObjectError::WouldBlock) => Err(TryOpError::TryAgain),
                Err(error) => Err(TryOpError::Other(broker_error_to_event_counter_error(
                    error,
                ))),
            },
        }
    }

    fn try_write(&self, value: u64) -> Result<usize, TryOpError<EventCounterError>> {
        match &self.backend {
            EventCounterBackend::Local { counter } => {
                let mut counter = counter.lock();
                if let Some(new_value) = (*counter)
                    .checked_add(value)
                    .filter(|count| *count <= MAX_EVENT_COUNT)
                {
                    *counter = new_value;
                    drop(counter);
                    self.pollee.notify_observers(Events::IN);
                    return Ok(core::mem::size_of::<u64>());
                }

                Err(TryOpError::TryAgain)
            }
            EventCounterBackend::Broker { event } => match event.add(value) {
                Ok(()) => {
                    self.pollee.notify_observers(Events::IN);
                    Ok(core::mem::size_of::<u64>())
                }
                Err(BrokerObjectError::WouldBlock | BrokerObjectError::ResourceExhausted) => {
                    Err(TryOpError::TryAgain)
                }
                Err(error) => Err(TryOpError::Other(broker_error_to_event_counter_error(
                    error,
                ))),
            },
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventCounter<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        match &self.backend {
            EventCounterBackend::Local { counter } => {
                let counter = counter.lock();
                let mut events = Events::empty();
                if *counter != 0 {
                    events |= Events::IN;
                }
                if *counter < MAX_EVENT_COUNT {
                    events |= Events::OUT;
                }
                events
            }
            EventCounterBackend::Broker { event } => {
                // The broker protocol currently exposes read readiness only. Keep
                // write readiness optimistic and surface counter-limit failures
                // from write until broker write-readiness plumbing exists.
                let mut events = Events::OUT;
                if event.is_read_ready().unwrap_or(false) {
                    events |= Events::IN;
                }
                events
            }
        }
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
