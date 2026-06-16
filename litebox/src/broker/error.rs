// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ErrorCode;
use thiserror::Error;

use crate::event::{counter::EventCounterError, polling::TryOpError};

/// Error returned by the deployment-provided broker control path.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum BrokerControlError {
    #[error("broker control transport failed")]
    Transport,
    #[error("broker returned operation error: {0}")]
    Broker(#[source] ErrorCode),
    #[error("broker returned unexpected response")]
    UnexpectedResponse,
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
    #[error("broker returned unexpected response")]
    UnexpectedResponse,
    #[error("internal broker object error")]
    Internal,
}

impl From<BrokerControlError> for BrokerObjectError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Transport => Self::Control,
            BrokerControlError::Broker(error) => error.into(),
            BrokerControlError::UnexpectedResponse => Self::UnexpectedResponse,
        }
    }
}

impl From<ErrorCode> for BrokerObjectError {
    fn from(error: ErrorCode) -> Self {
        match error {
            ErrorCode::InvalidRights | ErrorCode::UnknownObject => Self::InvalidObject,
            ErrorCode::WouldBlock => Self::WouldBlock,
            ErrorCode::ResourceExhausted => Self::ResourceExhausted,
            _ => Self::Internal,
        }
    }
}

pub(crate) fn map_broker_object_result<T>(
    result: Result<T, BrokerObjectError>,
) -> Result<T, TryOpError<EventCounterError>> {
    match result {
        Ok(value) => Ok(value),
        Err(BrokerObjectError::WouldBlock) => Err(TryOpError::TryAgain),
        Err(error) => Err(TryOpError::Other(error.into())),
    }
}

impl From<BrokerObjectError> for EventCounterError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::WouldBlock,
            BrokerObjectError::ResourceExhausted => Self::ResourceExhausted,
            BrokerObjectError::UnexpectedResponse => Self::UnexpectedResponse,
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::Internal => Self::Io,
        }
    }
}
