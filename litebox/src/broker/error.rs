// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ErrorCode;

use crate::event::{counter::EventCounterError, polling::TryOpError};

/// Error returned by the deployment-provided broker control path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum BrokerControlError {
    /// The broker control transport failed.
    Transport,
    /// The broker returned an operation error.
    Broker(ErrorCode),
    /// The broker returned a response shape that does not match the request.
    UnexpectedResponse,
}

/// Internal normalized error for broker-backed object adapters.
///
/// This keeps protocol/control-channel failures separate from the public
/// object-specific API error exposed by each local-core facade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BrokerObjectError {
    /// The deployment-provided broker control path failed.
    Control,
    /// The broker rejected the cached object handle, type, or rights.
    InvalidObject,
    /// The object operation would block in its current broker-side state.
    WouldBlock,
    /// The object or broker-side state cannot grow further.
    ResourceExhausted,
    /// The broker returned a response shape that does not match the request.
    UnexpectedResponse,
    /// The broker reported a non-recoverable or unsupported object error.
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
            ErrorCode::InvalidRights | ErrorCode::UnknownObject | ErrorCode::WrongObjectType => {
                Self::InvalidObject
            }
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
