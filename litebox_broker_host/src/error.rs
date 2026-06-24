// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_core::BrokerError;
use litebox_broker_protocol::error::ErrorCode;
use thiserror::Error;

/// Errors returned by a broker-host receive/send loop.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerHostError<E> {
    #[error("broker channel failed: {0}")]
    Channel(#[source] E),
    #[error("broker setup failed: {0}")]
    Broker(#[source] ErrorCode),
}

impl<E> From<BrokerError> for BrokerHostError<E> {
    fn from(error: BrokerError) -> Self {
        Self::Broker(error.into())
    }
}

/// Broker-host receive/send loop result type.
pub type Result<T, E> = core::result::Result<T, BrokerHostError<E>>;
