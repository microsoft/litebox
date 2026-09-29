// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed timers.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
pub use litebox_broker_protocol::timer::TimerSpec;
use litebox_platform::time::TimeProvider;
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
    sync::RawSyncPrimitivesProvider,
};

/// Errors returned by local-core timers.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimerError {
    #[error("timer resource exhausted")]
    ResourceExhausted,
    #[error("timer permission denied")]
    PermissionDenied,
    #[error("timer I/O failed")]
    Io,
    #[error("timer backing authority unavailable")]
    Unavailable,
}

/// A local-core timer whose schedule and expirations are owned by the broker.
///
/// The timer is readable ([`Events::IN`]) while it has unconsumed expirations.
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
    /// Creates a disarmed timer.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued timer request.
    pub fn new(litebox: &LiteBox<Platform>) -> Result<Self, TimerError> {
        let Some(broker) = litebox.broker_control() else {
            return Err(TimerError::Unavailable);
        };
        let handle = broker
            .create_timer()
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

    /// Arms the timer to first expire after `spec.value_ns` and then every
    /// `spec.interval_ns`, or disarms it if `spec.value_ns` is zero.
    ///
    /// Unconsumed expirations are discarded. Returns the previous schedule.
    pub fn set(&self, spec: TimerSpec) -> Result<TimerSpec, TimerError> {
        self.broker
            .set_timer(self.handle, spec)
            .map_err(|error| self.broker_request_error(error).into())
    }

    /// Returns the time until the next expiration, or zero if disarmed, and
    /// the interval.
    pub fn get(&self) -> Result<TimerSpec, TimerError> {
        self.broker
            .get_timer(self.handle)
            .map_err(|error| self.broker_request_error(error).into())
    }

    /// Consumes the expirations since the last read, waiting for one unless
    /// `nonblock` is set.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
    ) -> Result<u64, TryOpError<TimerError>> {
        self.pollee.wait(cx, nonblock, Events::IN, || {
            self.broker
                .read_timer(self.handle)
                .map_err(|error| self.broker_request_error(error).into())
        })
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
        match self
            .broker
            .check_readiness(self.handle)
            .map_err(|error| self.broker_request_error(error))
        {
            Ok(readiness) => readiness_events(readiness),
            Err(_) => Events::ERR,
        }
    }
}
