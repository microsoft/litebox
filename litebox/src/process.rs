// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed guest process creation and child waiting.

use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::process::{ChildExit, ProcessIdentity, WaitChildTarget};
use litebox_platform::time::TimeProvider;

use crate::LiteBox;
use crate::broker::error::BrokerControlError;
use crate::event::Events;
use crate::event::polling::TryOpError;
use crate::event::wait::WaitContext;
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
    /// The pending child identity is invalid or no longer available.
    #[error("invalid pending child process")]
    InvalidChild,
}

/// Error returned while waiting for a child process.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum WaitChildError {
    /// No direct child matches the wait target.
    #[error("no matching child process")]
    NoChild,
    /// The broker association failed.
    #[error("process service failed")]
    ServiceFailed,
}

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Allocates one pending child process.
    pub fn allocate_child_process(&self) -> Result<ProcessId, ProcessError> {
        self.broker_control()
            .ok_or(ProcessError::Unavailable)?
            .allocate_child_process()
            .map_err(ProcessError::from)
    }

    /// Starts a new child or transfers an existing pending child to a fresh runner.
    pub fn start_child_process(
        &self,
        child_process_id: Option<ProcessId>,
        payload: &[u8],
    ) -> Result<ProcessIdentity, ProcessError> {
        self.broker_control()
            .ok_or(ProcessError::Unavailable)?
            .start_child_process(child_process_id, payload)
            .map_err(ProcessError::from)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Consumes one terminated direct child matching `target`.
    ///
    /// While a matching child is still live, this waits for a broker child-state
    /// notification, or returns [`TryOpError::TryAgain`] when `nonblock` is set.
    pub fn wait_child(
        &self,
        cx: &WaitContext<'_, Platform>,
        target: WaitChildTarget,
        nonblock: bool,
    ) -> Result<ChildExit, TryOpError<WaitChildError>> {
        // Without a broker process service this process cannot have children.
        let broker = self
            .broker_control()
            .ok_or(TryOpError::Other(WaitChildError::NoChild))?;
        let registry = self.broker_pollable_registry();
        registry.child_state().wait(cx, nonblock, Events::IN, || {
            match broker.wait_child(target) {
                Ok(exit) => Ok(exit),
                Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Err(TryOpError::TryAgain),
                Err(error) => Err(TryOpError::Other(error.into())),
            }
        })
    }
}

impl From<BrokerControlError> for WaitChildError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Broker(ErrorCode::UnknownObject) => Self::NoChild,
            BrokerControlError::AssociationFailed
            | BrokerControlError::Broker(ErrorCode::PeerClosed) => Self::ServiceFailed,
            BrokerControlError::Broker(error) => {
                panic!("child wait returned unexpected error: {error}")
            }
        }
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
