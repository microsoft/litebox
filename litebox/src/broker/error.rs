// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_local::BrokerLocalError;
use litebox_broker_protocol::ErrorCode;
use thiserror::Error;

use crate::event::{counter::EventCounterError, polling::TryOpError};

/// Error returned by the deployment-provided broker control path.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum BrokerControlError {
    #[error("broker control transport failed")]
    Transport,
    #[error("broker returned operation error: {0}")]
    Broker(#[source] ErrorCode),
}

/// Internal normalized error for broker-backed object adapters.
///
/// This keeps protocol/control-channel failures separate from the public
/// object-specific API error exposed by each local-core facade.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum BrokerObjectError {
    #[error("broker control failed")]
    Control,
    #[error("invalid broker object")]
    InvalidObject,
    #[error("broker object operation would block")]
    WouldBlock,
    #[error("broker object resource exhausted")]
    ResourceExhausted,
    #[error("broker object permission denied")]
    PermissionDenied,
}

impl From<BrokerControlError> for BrokerObjectError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Transport => Self::Control,
            BrokerControlError::Broker(error) => error.into(),
        }
    }
}

impl From<ErrorCode> for BrokerObjectError {
    fn from(error: ErrorCode) -> Self {
        match error {
            ErrorCode::InvalidRights | ErrorCode::UnknownObject => Self::InvalidObject,
            ErrorCode::WouldBlock => Self::WouldBlock,
            ErrorCode::ResourceExhausted => Self::ResourceExhausted,
            ErrorCode::PolicyDenied => Self::PermissionDenied,
            ErrorCode::UnsupportedVersion
            | ErrorCode::MalformedRequest
            | ErrorCode::ProtocolState
            | ErrorCode::UnsupportedOperation
            | ErrorCode::Internal => panic!("broker returned unrecoverable error: {error}"),
            _ => panic!("broker returned unsupported error: {error}"),
        }
    }
}

impl<E> From<BrokerLocalError<E>> for BrokerControlError {
    fn from(error: BrokerLocalError<E>) -> Self {
        match error {
            BrokerLocalError::Channel(_) | BrokerLocalError::ChannelClosed => Self::Transport,
            BrokerLocalError::Broker(error) => Self::Broker(error),
        }
    }
}

impl From<BrokerObjectError> for TryOpError<EventCounterError> {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::TryAgain,
            error => Self::Other(error.into()),
        }
    }
}

impl From<BrokerObjectError> for EventCounterError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::WouldBlock,
            BrokerObjectError::ResourceExhausted => Self::ResourceExhausted,
            BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            BrokerObjectError::Control | BrokerObjectError::InvalidObject => Self::Io,
        }
    }
}
