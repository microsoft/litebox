// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ErrorCode;

use crate::event::polling::TryOpError;

/// Error returned by the deployment-provided broker control path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerControlError {
    /// The broker control transport failed.
    Transport,
    /// The broker returned an operation error.
    Broker(ErrorCode),
    /// The broker returned a response shape that does not match the request.
    UnexpectedResponse,
}

/// Errors returned by broker-backed local-core event counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventCounterError {
    /// The requested operation is invalid for this event counter.
    InvalidInput,
    /// The operation would block.
    WouldBlock,
    /// The event counter cannot accept more state.
    ResourceExhausted,
    /// The backing authority or transport failed.
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BrokerObjectError {
    Control,
    InvalidObject,
    WouldBlock,
    ResourceExhausted,
    UnexpectedResponse,
    Internal,
}

pub(super) const fn control_error_to_object_error(error: BrokerControlError) -> BrokerObjectError {
    match error {
        BrokerControlError::Transport => BrokerObjectError::Control,
        BrokerControlError::Broker(error) => error_code_to_object_error(error),
        BrokerControlError::UnexpectedResponse => BrokerObjectError::UnexpectedResponse,
    }
}

const fn error_code_to_object_error(error: ErrorCode) -> BrokerObjectError {
    match error {
        ErrorCode::InvalidRights
        | ErrorCode::UnknownObject
        | ErrorCode::WrongObjectType
        | ErrorCode::StaleHandle => BrokerObjectError::InvalidObject,
        ErrorCode::WouldBlock => BrokerObjectError::WouldBlock,
        ErrorCode::ResourceExhausted => BrokerObjectError::ResourceExhausted,
        _ => BrokerObjectError::Internal,
    }
}

pub(super) fn map_broker_object_result<T>(
    result: Result<T, BrokerObjectError>,
) -> Result<T, TryOpError<EventCounterError>> {
    match result {
        Ok(value) => Ok(value),
        Err(BrokerObjectError::WouldBlock) => Err(TryOpError::TryAgain),
        Err(error) => Err(TryOpError::Other(object_error_to_event_counter_error(
            error,
        ))),
    }
}

pub(super) const fn object_error_to_event_counter_error(
    error: BrokerObjectError,
) -> EventCounterError {
    match error {
        BrokerObjectError::InvalidObject => EventCounterError::InvalidInput,
        BrokerObjectError::WouldBlock => EventCounterError::WouldBlock,
        BrokerObjectError::ResourceExhausted => EventCounterError::ResourceExhausted,
        _ => EventCounterError::Io,
    }
}
