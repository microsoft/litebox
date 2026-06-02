// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{boxed::Box, sync::Weak};

use super::{
    Events, IOPollable,
    observer::Observer,
    polling::{Pollee, TryOpError},
    wait::WaitContext,
};
use crate::{
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

/// A local-core event counter.
///
/// This object provides eventfd-like counter semantics without exposing whether
/// the backing state is local-private or externally mediated.
pub struct EventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    source: Box<dyn EventCounterSource<Platform>>,
    pollee: Pollee<Platform>,
}

pub(crate) trait EventCounterSource<Platform>: Send + Sync
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn supports_blocking_operations(&self) -> bool;
    fn read(&self, mode: EventCounterConsumeMode) -> Result<u64, EventCounterError>;
    fn write(&self, value: u64) -> Result<(), EventCounterError>;
    fn check_io_events(&self) -> Events;
}

struct LocalEventCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    counter: Mutex<Platform, u64>,
}

impl<Platform> EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider + 'static,
{
    pub(crate) fn new_local(initial_count: u64) -> Result<Self, EventCounterError> {
        if initial_count > MAX_EVENT_COUNT {
            return Err(EventCounterError::ResourceExhausted);
        }
        Ok(Self::from_source(LocalEventCounter {
            counter: Mutex::new(initial_count),
        }))
    }

    pub(crate) fn from_source(source: impl EventCounterSource<Platform> + 'static) -> Self {
        Self {
            source: Box::new(source),
            pollee: Pollee::new(),
        }
    }
}

impl<Platform> EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    /// Returns whether blocking reads and writes are supported.
    pub fn supports_blocking_operations(&self) -> bool {
        self.source.supports_blocking_operations()
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
        let value = map_source_result(self.source.read(mode))?;
        self.pollee.notify_observers(Events::OUT);
        Ok(value)
    }

    fn try_write(&self, value: u64) -> Result<usize, TryOpError<EventCounterError>> {
        let size = map_write_result(self.source.write(value))?;
        self.pollee.notify_observers(Events::IN);
        Ok(size)
    }
}

impl<Platform> IOPollable for EventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.source.check_io_events()
    }
}

impl<Platform> EventCounterSource<Platform> for LocalEventCounter<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn supports_blocking_operations(&self) -> bool {
        true
    }

    fn read(&self, mode: EventCounterConsumeMode) -> Result<u64, EventCounterError> {
        let mut counter = self.counter.lock();
        if *counter == 0 {
            return Err(EventCounterError::WouldBlock);
        }

        let res = match mode {
            EventCounterConsumeMode::All => *counter,
            EventCounterConsumeMode::One => 1,
        };
        *counter -= res;
        Ok(res)
    }

    fn write(&self, value: u64) -> Result<(), EventCounterError> {
        let mut counter = self.counter.lock();
        let new_value = (*counter)
            .checked_add(value)
            .filter(|count| *count <= MAX_EVENT_COUNT)
            .ok_or(EventCounterError::WouldBlock)?;
        *counter = new_value;
        Ok(())
    }

    fn check_io_events(&self) -> Events {
        let counter = self.counter.lock();
        let mut events = Events::empty();
        if *counter != 0 {
            events |= Events::IN;
        }
        if *counter < MAX_EVENT_COUNT {
            events |= Events::OUT;
        }
        events
    }
}

fn map_write_result(
    result: Result<(), EventCounterError>,
) -> Result<usize, TryOpError<EventCounterError>> {
    map_source_result(result.map(|()| core::mem::size_of::<u64>()))
}

fn map_source_result<T>(
    result: Result<T, EventCounterError>,
) -> Result<T, TryOpError<EventCounterError>> {
    match result {
        Ok(value) => Ok(value),
        Err(EventCounterError::WouldBlock) => Err(TryOpError::TryAgain),
        Err(error) => Err(TryOpError::Other(error)),
    }
}
