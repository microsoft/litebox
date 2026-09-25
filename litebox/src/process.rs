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

/// Error returned by the constrained `vfork` process service.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum VforkError {
    /// This LiteBox process has no broker process service.
    #[error("process creation is unavailable")]
    Unavailable,
    /// The broker association failed.
    #[error("process service failed")]
    ServiceFailed,
    /// Process duplication is disabled by policy.
    #[error("process duplication is denied")]
    PolicyDenied,
    /// Another pending `vfork` child already exists.
    #[error("a vfork child is already pending")]
    Busy,
    /// Process or memory capacity is exhausted.
    #[error("process capacity is exhausted")]
    ResourceExhausted,
    /// The pending child identity is invalid or no longer available.
    #[error("invalid pending vfork child")]
    InvalidChild,
}

impl<Platform: RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Allocates one pending child for a constrained `vfork` execution window.
    pub fn create_vfork_child(&self) -> Result<ProcessIdentity, VforkError> {
        self.broker_control()
            .ok_or(VforkError::Unavailable)?
            .create_vfork_child()
            .map_err(VforkError::from)
    }

    /// Transfers one pending `vfork` child into a fresh runner.
    pub fn start_vfork_child(
        &self,
        child_process_id: ProcessId,
        format: ProcessBootstrapFormat,
        version: ProcessBootstrapVersion,
        payload: &[u8],
    ) -> Result<(), VforkError> {
        self.broker_control()
            .ok_or(VforkError::Unavailable)?
            .start_vfork_child(child_process_id, format, version, payload)
            .map_err(VforkError::from)
    }
}

impl From<BrokerControlError> for VforkError {
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
                panic!("process service returned unexpected vfork error: {error}")
            }
        }
    }
}
