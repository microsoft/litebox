// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use thiserror::Error;

use litebox_broker_protocol::error::ErrorCode;

/// Broker authority error category.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BrokerError {
    #[error("broker policy denied the operation")]
    PolicyDenied,
    #[error("unknown broker object")]
    UnknownObject,
    #[error("invalid broker rights")]
    InvalidRights,
    #[error("broker resource exhausted")]
    ResourceExhausted,
    #[error("broker core already exists")]
    BrokerCoreAlreadyExists,
    #[error("broker operation would block")]
    WouldBlock,
    #[error("unsupported broker operation")]
    UnsupportedOperation,
}

impl From<BrokerError> for ErrorCode {
    fn from(error: BrokerError) -> Self {
        match error {
            BrokerError::PolicyDenied => Self::PolicyDenied,
            BrokerError::UnknownObject => Self::UnknownObject,
            BrokerError::InvalidRights => Self::InvalidRights,
            BrokerError::ResourceExhausted => Self::ResourceExhausted,
            BrokerError::BrokerCoreAlreadyExists => Self::Internal,
            BrokerError::WouldBlock => Self::WouldBlock,
            BrokerError::UnsupportedOperation => Self::UnsupportedOperation,
        }
    }
}
