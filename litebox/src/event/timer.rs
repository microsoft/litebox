// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
pub use litebox_broker_protocol::timer::TimerSpec;
use thiserror::Error;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry,
        error::{BrokerControlError, BrokerObjectError},
        readiness_events,
    },
    event::{
        Events, IOPollable, observer::Observer, polling::Pollee, polling::TryOpError,
        wait::WaitContext,
    },
    platform::TimeProvider,
    sync::RawSyncPrimitivesProvider,
};

/// Errors returned by local-core timers.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimerError {
    #[error("timer operation would block")]
    WouldBlock,
    #[error("timer resource exhausted")]
    ResourceExhausted,
    #[error("timer permission denied")]
    PermissionDenied,
    #[error("timer was cancelled by a clock change")]
    Cancelled,
    #[error("timer I/O failed")]
    Io,
    #[error("timer backing authority unavailable")]
    Unavailable,
}

impl From<BrokerObjectError> for TryOpError<TimerError> {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::TryAgain,
            error => Self::Other(error.into()),
        }
    }
}

impl From<BrokerObjectError> for TimerError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::WouldBlock,
            BrokerObjectError::ResourceExhausted | BrokerObjectError::OutOfMemory => {
                Self::ResourceExhausted
            }
            BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::PeerClosed
            | BrokerObjectError::UnsupportedOperation => Self::Io,
        }
    }
}

/// A local-core timer backed by a broker-owned host timerfd.
pub struct Timer<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform> Timer<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    /// Creates a local-core timer for the given clock.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued timer request.
    pub fn new(litebox: &LiteBox<Platform>, clock_id: i32) -> Result<Self, TimerError> {
        let Some(broker) = litebox.broker_control() else {
            return Err(TimerError::Unavailable);
        };
        let handle = broker
            .create_timer(clock_id)
            .map_err(BrokerObjectError::from)
            .map_err(TimerError::from)?;
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Ok(Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        })
    }

    /// Arms or disarms the timer, returning the setting previously in effect.
    pub fn set_time(&self, specification: TimerSpec, flags: u32) -> Result<TimerSpec, TimerError> {
        let (previous, readiness) = self
            .broker
            .set_timer(self.handle, specification, flags)
            .map_err(|error| self.broker_request_error(error))?;
        // Re-arming clears any prior pending expiration; wake observers so a
        // level-triggered poller re-checks the newly authoritative readiness.
        self.pollee.notify_observers(readiness_events(readiness));
        Ok(previous)
    }

    /// Returns the time remaining until the next expiration and the interval.
    pub fn get_time(&self) -> Result<TimerSpec, TimerError> {
        self.broker
            .get_timer(self.handle)
            .map_err(|error| self.broker_request_error(error))
            .map_err(TimerError::from)
    }

    /// Reads the accumulated expiration count, blocking until the timer expires
    /// unless `nonblock` is set.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
    ) -> Result<u64, TryOpError<TimerError>> {
        self.pollee.wait(cx, nonblock, Events::IN, || {
            let (expirations, cancelled, _readiness) = self.drain()?;
            if cancelled {
                return Err(TryOpError::Other(TimerError::Cancelled));
            }
            Ok(expirations)
        })
    }

    fn drain(&self) -> Result<(u64, bool, ReadinessFlags), BrokerObjectError> {
        self.broker
            .read_timer(self.handle)
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

impl<Platform> Drop for Timer<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

impl<Platform> IOPollable for Timer<Platform>
where
    Platform: RawSyncPrimitivesProvider + TimeProvider,
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let readiness = match self
            .broker
            .check_readiness(self.handle)
            .map_err(|error| self.broker_request_error(error))
        {
            Ok(readiness) => readiness,
            Err(BrokerObjectError::WouldBlock) => return Events::empty(),
            Err(_) => return Events::ERR,
        };
        readiness_events(readiness)
    }
}
