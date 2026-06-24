// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{BrokerResponse, ErrorCode, ProtocolVersion};
use thiserror::Error;

/// Errors returned while negotiating the broker-local control adapter.
#[derive(Debug, Error)]
pub enum BrokerLocalNegotiationError<E> {
    #[error("broker channel failed: {0}")]
    Channel(#[source] E),
    #[error("broker closed the channel")]
    ChannelClosed,
    #[error(
        "broker accepted incompatible protocol negotiation: requested {requested:?}, broker supports {broker_protocol_version:?}"
    )]
    IncompatibleNegotiation {
        /// Protocol version requested by this local adapter.
        requested: ProtocolVersion,
        /// Protocol version advertised by the broker.
        broker_protocol_version: ProtocolVersion,
    },
    #[error(
        "broker does not support requested protocol version {requested:?}; broker supports {broker_protocol_version:?}"
    )]
    UnsupportedVersion {
        /// Protocol version requested by this local adapter.
        requested: ProtocolVersion,
        /// Protocol version advertised by the broker.
        broker_protocol_version: ProtocolVersion,
    },
    #[error("broker rejected request: {0}")]
    Broker(#[source] ErrorCode),
    #[error("broker returned unexpected response: {0:?}")]
    UnexpectedResponse(BrokerResponse),
}

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

/// Broker-local control adapter negotiation result type.
pub type NegotiationResult<T, E> = core::result::Result<T, BrokerLocalNegotiationError<E>>;

/// Broker-local control adapter result type.
pub type Result<T, E> = core::result::Result<T, BrokerLocalError<E>>;
