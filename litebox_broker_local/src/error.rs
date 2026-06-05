// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

use litebox_broker_protocol::{BrokerResponse, ErrorCode, ProtocolVersion};

/// Errors returned by the broker-local control adapter.
#[derive(Debug)]
#[non_exhaustive]
pub enum BrokerLocalError<E> {
    /// The control channel failed.
    Channel(E),
    /// An operation requiring an active broker session was called before negotiation.
    NotNegotiated,
    /// Negotiation was requested after the local adapter was already active.
    AlreadyNegotiated,
    /// The broker closed the channel before returning a response.
    ChannelClosed,
    /// The broker returned a response this local adapter does not understand.
    UnknownResponse,
    /// The broker accepted negotiation with a version that cannot serve the request.
    IncompatibleNegotiation {
        /// Protocol version requested by this local adapter.
        requested: ProtocolVersion,
        /// Protocol version advertised by the broker.
        broker_protocol_version: ProtocolVersion,
    },
    /// This local adapter cannot speak the requested protocol version.
    UnsupportedLocalVersion {
        /// Protocol version requested by the caller.
        requested: ProtocolVersion,
        /// Protocol version supported by this local implementation.
        local_protocol_version: ProtocolVersion,
    },
    /// The active broker session cannot serve an operation requiring a newer version.
    UnsupportedNegotiatedVersion {
        /// Protocol version required by the operation.
        required: ProtocolVersion,
        /// Effective protocol version negotiated for this connection.
        negotiated_protocol_version: ProtocolVersion,
    },
    /// The broker does not support the requested protocol version.
    UnsupportedVersion {
        /// Protocol version requested by this local adapter.
        requested: ProtocolVersion,
        /// Protocol version advertised by the broker.
        broker_protocol_version: ProtocolVersion,
    },
    /// The broker rejected the request.
    Broker(ErrorCode),
    /// The broker returned a response type that does not match the request.
    UnexpectedResponse(BrokerResponse),
}

impl<E: fmt::Display> fmt::Display for BrokerLocalError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Channel(error) => write!(f, "broker channel failed: {error}"),
            Self::NotNegotiated => {
                write!(
                    f,
                    "broker local adapter has not negotiated protocol version"
                )
            }
            Self::AlreadyNegotiated => f.write_str("broker local adapter already negotiated"),
            Self::ChannelClosed => write!(f, "broker closed the channel"),
            Self::UnknownResponse => f.write_str("unknown broker response"),
            Self::IncompatibleNegotiation {
                requested,
                broker_protocol_version,
            } => write!(
                f,
                "broker accepted incompatible protocol negotiation: requested {requested:?}, broker supports {broker_protocol_version:?}"
            ),
            Self::UnsupportedLocalVersion {
                requested,
                local_protocol_version,
            } => write!(
                f,
                "broker local adapter cannot request protocol version {requested:?}; local adapter supports {local_protocol_version:?}"
            ),
            Self::UnsupportedNegotiatedVersion {
                required,
                negotiated_protocol_version,
            } => write!(
                f,
                "broker session protocol version {negotiated_protocol_version:?} does not support required version {required:?}"
            ),
            Self::UnsupportedVersion {
                requested,
                broker_protocol_version,
            } => write!(
                f,
                "broker does not support requested protocol version {requested:?}; broker supports {broker_protocol_version:?}"
            ),
            Self::Broker(error) => write!(f, "broker rejected request: {error}"),
            Self::UnexpectedResponse(response) => {
                write!(f, "broker returned unexpected response: {response:?}")
            }
        }
    }
}

impl<E> core::error::Error for BrokerLocalError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Channel(error) => Some(error),
            Self::Broker(error) => Some(error),
            Self::NotNegotiated
            | Self::AlreadyNegotiated
            | Self::ChannelClosed
            | Self::UnknownResponse
            | Self::IncompatibleNegotiation { .. }
            | Self::UnsupportedLocalVersion { .. }
            | Self::UnsupportedNegotiatedVersion { .. }
            | Self::UnsupportedVersion { .. }
            | Self::UnexpectedResponse(_) => None,
        }
    }
}

/// Broker-local control adapter result type.
pub type Result<T, E> = core::result::Result<T, BrokerLocalError<E>>;
