// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed guest process creation and child termination.

use alloc::sync::Arc;

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::process::{ProcessExitStatus, ProcessIdentity};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use litebox_platform::time::TimeProvider;

use crate::LiteBox;
use crate::broker::{
    BrokerControl, BrokerPollableRegistry, error::BrokerControlError, readiness_events,
};
use crate::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use crate::sync::RawSyncPrimitivesProvider;

/// Error returned by the broker-backed process service.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProcessError {
    /// This LiteBox process has no broker process service.
    #[error("process creation is unavailable")]
    Unavailable,
    /// The broker association failed.
    #[error("process service failed")]
    ServiceFailed,
    /// Process duplication is disabled by policy.
    #[error("process duplication is denied")]
    PolicyDenied,
    /// Another pending child process already exists.
    #[error("a child process is already pending")]
    Busy,
    /// Process capacity is exhausted.
    #[error("process capacity is exhausted")]
    ResourceExhausted,
    /// Memory capacity is exhausted.
    #[error("process memory is exhausted")]
    OutOfMemory,
    /// The child process is invalid or no longer available.
    #[error("invalid child process")]
    InvalidChild,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Allocates one pending child process.
    pub fn allocate_child_process(&self) -> Result<ChildProcess<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let child = broker.allocate_child_process()?;
        Ok(ChildProcess::new(
            self,
            broker,
            child.process_id,
            child.handle,
        ))
    }

    /// Starts a new child process in a fresh runner.
    ///
    /// # Panics
    ///
    /// Panics if the broker does not return a handle for the new child.
    pub fn start_child_process(
        &self,
        payload: &[u8],
    ) -> Result<(ProcessIdentity, ChildProcess<Platform>), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let started = broker.start_child_process(None, payload)?;
        let handle = started
            .handle
            .expect("broker must return a handle for a newly started child");
        let child = ChildProcess::new(self, broker, started.identity.process_id, handle);
        Ok((started.identity, child))
    }
}

/// Parent-owned handle to one broker child process.
///
/// The child reports [`Events::IN`] once it terminates. Dropping the handle
/// reaps the child and releases its retained exit status.
pub struct ChildProcess<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    process_id: ProcessId,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> ChildProcess<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        process_id: ProcessId,
        handle: ObjectHandle,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            process_id,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// Returns the broker-assigned child process ID.
    pub fn process_id(&self) -> ProcessId {
        self.process_id
    }

    /// Transfers this pending child to a fresh runner.
    pub fn start(&self, payload: &[u8]) -> Result<ProcessIdentity, ProcessError> {
        Ok(self
            .broker
            .start_child_process(Some(self.process_id), payload)?
            .identity)
    }

    /// Returns the child's termination status, or `None` while the child is live.
    pub fn exit_status(&self) -> Result<Option<ProcessExitStatus>, ProcessError> {
        match self.broker.process_exit_status(self.handle) {
            Ok(status) => Ok(Some(status)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for ChildProcess<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for ChildProcess<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

impl From<BrokerControlError> for ProcessError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::AssociationFailed => Self::ServiceFailed,
            BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => Self::Unavailable,
            BrokerControlError::Broker(ErrorCode::PolicyDenied) => Self::PolicyDenied,
            BrokerControlError::Broker(ErrorCode::WouldBlock) => Self::Busy,
            BrokerControlError::Broker(ErrorCode::ResourceExhausted) => Self::ResourceExhausted,
            BrokerControlError::Broker(ErrorCode::OutOfMemory) => Self::OutOfMemory,
            BrokerControlError::Broker(
                ErrorCode::UnknownObject | ErrorCode::PeerClosed | ErrorCode::ProtocolState,
            ) => Self::InvalidChild,
            BrokerControlError::Broker(error) => {
                panic!("process service returned unexpected error: {error}")
            }
        }
    }
}
