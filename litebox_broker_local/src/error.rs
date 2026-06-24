// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{BrokerResponse, ErrorCode};
use thiserror::Error;

/// Errors returned by active broker-local control requests.
#[derive(Debug, Error)]
pub enum BrokerLocalError<E> {
    #[error("broker channel failed: {0}")]
    Channel(#[source] E),
    #[error("broker closed the channel")]
    ChannelClosed,
    #[error("broker rejected request: {0}")]
    Broker(#[source] ErrorCode),
    #[error("broker returned unexpected response: {0:?}")]
    UnexpectedResponse(BrokerResponse),
}

/// Broker-local control adapter result type.
pub type Result<T, E> = core::result::Result<T, BrokerLocalError<E>>;
