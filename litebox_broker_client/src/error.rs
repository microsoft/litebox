// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

use litebox_broker_protocol::{BrokerResponse, ErrorCode};

/// Errors returned by the broker client adapter.
#[derive(Debug)]
pub enum ClientError<E> {
    /// The transport failed.
    Transport(E),
    /// An operation requiring an active broker session was called before negotiation.
    NotNegotiated,
    /// Negotiation was requested after the client was already active.
    AlreadyNegotiated,
    /// The broker closed the transport before returning a response.
    TransportClosed,
    /// The broker returned a response tag this client does not understand.
    UnknownResponse { tag: u8 },
    /// BrokerCore rejected the request.
    Broker(ErrorCode),
    /// The broker returned a response type that does not match the request.
    UnexpectedResponse(BrokerResponse),
}

impl<E: fmt::Display> fmt::Display for ClientError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "broker transport failed: {error}"),
            Self::NotNegotiated => write!(f, "broker client has not negotiated protocol version"),
            Self::AlreadyNegotiated => f.write_str("broker client already negotiated"),
            Self::TransportClosed => write!(f, "broker closed the transport"),
            Self::UnknownResponse { tag } => write!(f, "unknown broker response tag {tag}"),
            Self::Broker(error) => write!(f, "broker rejected request: {error}"),
            Self::UnexpectedResponse(response) => {
                write!(f, "broker returned unexpected response: {response:?}")
            }
        }
    }
}

impl<E> core::error::Error for ClientError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Broker(error) => Some(error),
            Self::NotNegotiated
            | Self::AlreadyNegotiated
            | Self::TransportClosed
            | Self::UnknownResponse { .. }
            | Self::UnexpectedResponse(_) => None,
        }
    }
}

/// Broker client result type.
pub type Result<T, E> = core::result::Result<T, ClientError<E>>;
