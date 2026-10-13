// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed timers.

use alloc::sync::Arc;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{FileOpenFlags, FileStatusFlags};
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
    fs::errors::StatusFlagsError,
    process::ProcessError,
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
    #[error("timer I/O failed")]
    Io,
    #[error("timer backing authority unavailable")]
    Unavailable,
}

/// A local-core timer whose schedule, expirations, and status flags are owned by
/// the broker.
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
    /// Creates a disarmed timer with the status flags `flags`, within
    /// [`FileOpenFlags::STATUS`].
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued timer request.
    pub fn new(litebox: &LiteBox<Platform>, flags: FileOpenFlags) -> Result<Self, TimerError> {
        let Some(broker) = litebox.broker_control() else {
            return Err(TimerError::Unavailable);
        };
        let handle = broker
            .create_timer(flags)
            .map_err(BrokerObjectError::from)
            .map_err(TimerError::from)?;
        Ok(Self::from_handle(litebox, broker, handle))
    }

    fn from_handle(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// The broker handle this timer owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Arms the timer to first expire after `spec.value_ns` and then every
    /// `spec.interval_ns`, or disarms it if `spec.value_ns` is zero.
    ///
    /// Unconsumed expirations are discarded. Returns the previous schedule.
    pub fn set(&self, spec: TimerSpec) -> Result<TimerSpec, TimerError> {
        self.broker
            .set_timer(self.handle, spec)
            .map_err(|error| self.request_error(error))
    }

    /// Returns the time until the next expiration, or zero if disarmed, and
    /// the interval.
    pub fn get(&self) -> Result<TimerSpec, TimerError> {
        self.broker
            .get_timer(self.handle)
            .map_err(|error| self.request_error(error))
    }

    /// Consumes the expirations since the last read, waiting for one unless
    /// the timer is non-blocking.
    pub fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, TryOpError<TimerError>> {
        // On a non-blocking timer, the broker returns `NonBlockingWouldBlock`
        // instead of `WouldBlock`, so the wait returns instead of blocking.
        self.pollee.wait(cx, false, Events::IN, || {
            self.broker
                .read_timer(self.handle)
                .map_err(|error| self.broker_request_error(error))
        })
    }

    /// Returns the timer's access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`],
    /// to their values in `flags`.
    ///
    /// Every reference to the timer, including those in other processes, sees
    /// the change.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }

    fn request_error(&self, error: BrokerControlError) -> TimerError {
        match self.broker_request_error(error) {
            TryOpError::Other(error) => error,
            TryOpError::TryAgain | TryOpError::WaitError(_) => TimerError::WouldBlock,
        }
    }

    fn broker_request_error(&self, error: BrokerControlError) -> TryOpError<TimerError> {
        if error == BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock) {
            return TryOpError::Other(TimerError::WouldBlock);
        }
        let error = BrokerObjectError::from(error);
        if error != BrokerObjectError::WouldBlock {
            self.pollee.notify_observers(Events::ERR);
        }
        error.into()
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Returns the timer this process inherited from its parent as `handle`
    /// through [`PendingChild::inherit`](crate::process::PendingChild::inherit).
    ///
    /// The timer owns `handle`, so callers adopt each handle once and share
    /// the timer for every other use.
    pub fn adopt_inherited_timer(
        &self,
        handle: ObjectHandle,
    ) -> Result<Timer<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(Timer::from_handle(self, broker, handle))
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
