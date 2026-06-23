// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::{BrokerResponse, ErrorCode, ProtocolVersion};
use thiserror::Error;

/// Errors returned by the broker-local control adapter.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerLocalError<E> {
    #[error("broker channel failed: {0}")]
    Channel(#[source] E),
    #[error("broker local adapter has not negotiated protocol version")]
    NotNegotiated,
    #[error("broker local adapter already negotiated")]
    AlreadyNegotiated,
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
        "broker local adapter cannot request protocol version {requested:?}; local adapter supports {local_protocol_version:?}"
    )]
    UnsupportedLocalVersion {
        /// Protocol version requested by the caller.
        requested: ProtocolVersion,
        /// Protocol version supported by this local implementation.
        local_protocol_version: ProtocolVersion,
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

/// Broker-local control adapter result type.
pub type Result<T, E> = core::result::Result<T, BrokerLocalError<E>>;
