// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::fmt;

use litebox_broker_core::{
    BrokerConnection, BrokerCore, CloseReason, DispatchOutcome, PolicyEngine,
};
use litebox_broker_transport::{ReceivedRequest, ServerTransport};

/// Serves one broker connection over the provided connected transport.
pub fn serve_connection<P, T>(
    core: &mut BrokerCore<P>,
    transport: &mut T,
) -> Result<ConnectionTermination, BrokerServeError<T::Error>>
where
    P: PolicyEngine,
    T: ServerTransport,
{
    let peer_credential = transport
        .peer_credential()
        .map_err(BrokerServeError::Transport)?;
    let mut connection = core
        .create_connection(peer_credential)
        .map_err(|_error| BrokerServeError::ConnectionSetup)?;

    let result = serve_request_loop(core, transport, &mut connection);
    core.close_connection(connection);
    result
}

fn serve_request_loop<P, T>(
    core: &mut BrokerCore<P>,
    transport: &mut T,
    connection: &mut BrokerConnection,
) -> Result<ConnectionTermination, BrokerServeError<T::Error>>
where
    P: PolicyEngine,
    T: ServerTransport,
{
    loop {
        let Some(received) = transport
            .recv_request()
            .map_err(BrokerServeError::Transport)?
        else {
            break;
        };

        let dispatch = match received {
            ReceivedRequest::Request(request) => {
                core.handle_connection_request(connection, request)
            }
            ReceivedRequest::Unknown { tag } => {
                core.handle_unknown_connection_request(connection, tag)
            }
        };
        transport
            .send_response(&dispatch.response())
            .map_err(BrokerServeError::Transport)?;
        if let DispatchOutcome::Close(reason) = dispatch.outcome() {
            return Ok(ConnectionTermination::BrokerClosed(reason));
        }
    }

    Ok(ConnectionTermination::PeerClosed)
}

/// Terminal outcome for a successfully served broker connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionTermination {
    /// The peer cleanly closed the transport.
    PeerClosed,
    /// BrokerCore sent a terminal protocol response and closed the connection.
    BrokerClosed(CloseReason),
}

/// Errors returned by a broker receive/send loop.
#[derive(Debug)]
pub enum BrokerServeError<E> {
    /// BrokerCore could not allocate state for a new connection.
    ConnectionSetup,
    /// The concrete transport failed.
    Transport(E),
}

impl<E: fmt::Display> fmt::Display for BrokerServeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionSetup => f.write_str("broker connection setup failed"),
            Self::Transport(error) => write!(f, "broker transport failed: {error}"),
        }
    }
}

impl<E> core::error::Error for BrokerServeError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ConnectionSetup => None,
            Self::Transport(error) => Some(error),
        }
    }
}
