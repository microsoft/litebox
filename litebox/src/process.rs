// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed guest process creation.

use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::process::{
    ProcessBootstrapFormat, ProcessBootstrapVersion, ProcessIdentity,
};

use crate::LiteBox;
use crate::broker::error::BrokerControlError;
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
    /// Process or memory capacity is exhausted.
    #[error("process capacity is exhausted")]
    ResourceExhausted,
    /// The pending child identity is invalid or no longer available.
    #[error("invalid pending child process")]
    InvalidChild,
}

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Allocates one pending child process.
    pub fn create_child_process(&self) -> Result<ProcessId, ProcessError> {
        self.broker_control()
            .ok_or(ProcessError::Unavailable)?
            .create_child_process()
            .map_err(ProcessError::from)
    }

    /// Starts a new child or transfers an existing pending child to a fresh runner.
    pub fn start_child_process(
        &self,
        child_process_id: Option<ProcessId>,
        format: ProcessBootstrapFormat,
        version: ProcessBootstrapVersion,
        payload: &[u8],
    ) -> Result<ProcessIdentity, ProcessError> {
        self.broker_control()
            .ok_or(ProcessError::Unavailable)?
            .start_child_process(child_process_id, format, version, payload)
            .map_err(ProcessError::from)
    }
}

impl From<BrokerControlError> for ProcessError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::AssociationFailed => Self::ServiceFailed,
            BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => Self::Unavailable,
            BrokerControlError::Broker(ErrorCode::PolicyDenied) => Self::PolicyDenied,
            BrokerControlError::Broker(ErrorCode::WouldBlock) => Self::Busy,
            BrokerControlError::Broker(ErrorCode::ResourceExhausted | ErrorCode::OutOfMemory) => {
                Self::ResourceExhausted
            }
            BrokerControlError::Broker(
                ErrorCode::UnknownObject | ErrorCode::PeerClosed | ErrorCode::ProtocolState,
            ) => Self::InvalidChild,
            BrokerControlError::Broker(error) => {
                panic!("process service returned unexpected error: {error}")
            }
        }
    }
}
