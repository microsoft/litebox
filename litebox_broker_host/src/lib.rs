// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Channel-neutral broker-side protocol/core adapter.
//!
//! This crate wires `litebox_broker_core` to any implementation of the neutral
//! host-side control-channel trait. Concrete channels live in separate crates such as
//! `litebox_broker_transport`.

#![no_std]

#[cfg(test)]
extern crate std;

use core::fmt;

use litebox_broker_core::{BrokerCore, BrokerError, BrokerSession, CallerCredential, event};
use litebox_broker_protocol::{
    AddEventResponse, BrokerRequest, BrokerResponse, CoreRequest, CoreResponse,
    CreateEventResponse, ErrorCode, EventRequest, EventResponse, HostControlChannel,
    INITIAL_PROTOCOL_VERSION, PeerCredential, ProtocolVersion, ReceivedBrokerRequest,
    WaitEventResponse,
};

mod error;

pub use error::{BrokerHostError, Result};

/// Protocol version this broker host implementation supports.
pub const HOST_PROTOCOL_VERSION: ProtocolVersion = INITIAL_PROTOCOL_VERSION;

/// Serves one broker connection over the provided connected control channel.
pub fn serve_connection<T>(
    core: &BrokerCore,
    channel: &mut T,
) -> Result<ConnectionTermination, T::Error>
where
    T: HostControlChannel,
{
    let peer_credential = channel
        .peer_credential()
        .map_err(BrokerHostError::Channel)?;
    let caller_credential = caller_credential_from_peer(peer_credential)
        .map_err(|()| BrokerHostError::AssociationSetup)?;
    let session = core
        .create_session(caller_credential)
        .map_err(|_error| BrokerHostError::AssociationSetup)?;

    serve_request_loop(channel, &session)
}

fn serve_request_loop<T>(
    channel: &mut T,
    session: &BrokerSession,
) -> Result<ConnectionTermination, T::Error>
where
    T: HostControlChannel,
{
    let mut state = ConnectionState::AwaitingNegotiation;
    loop {
        let Some(received) = channel.recv_request().map_err(BrokerHostError::Channel)? else {
            break;
        };

        let dispatch = handle_received_request(session, &mut state, received);
        channel
            .send_response(&dispatch.response)
            .map_err(BrokerHostError::Channel)?;
        if let DispatchOutcome::Close(reason) = dispatch.outcome {
            return Ok(ConnectionTermination::BrokerClosed(reason));
        }
    }

    Ok(ConnectionTermination::PeerClosed)
}

fn caller_credential_from_peer(
    peer_credential: PeerCredential,
) -> core::result::Result<CallerCredential, ()> {
    if peer_credential == PeerCredential::Unauthenticated {
        Ok(CallerCredential::Unauthenticated)
    } else {
        Err(())
    }
}

fn handle_received_request(
    session: &BrokerSession,
    state: &mut ConnectionState,
    received: ReceivedBrokerRequest,
) -> BrokerDispatch {
    match received {
        ReceivedBrokerRequest::Request(request) => handle_request(session, state, request),
        _ => handle_unknown_request(*state),
    }
}

fn handle_request(
    session: &BrokerSession,
    state: &mut ConnectionState,
    request: BrokerRequest,
) -> BrokerDispatch {
    match *state {
        ConnectionState::AwaitingNegotiation => match request {
            BrokerRequest::Negotiate { protocol_version } => {
                negotiate_version(state, protocol_version)
            }
            _ => BrokerDispatch::close_after(
                BrokerResponse::Error(ErrorCode::ProtocolState),
                CloseReason::ProtocolViolation,
            ),
        },
        ConnectionState::Active {
            negotiated_protocol_version,
        } => handle_active_request(session, negotiated_protocol_version, request),
    }
}

fn handle_active_request(
    session: &BrokerSession,
    _negotiated_protocol_version: ProtocolVersion,
    request: BrokerRequest,
) -> BrokerDispatch {
    match request {
        BrokerRequest::Negotiate { .. } => BrokerDispatch::close_after(
            BrokerResponse::Error(ErrorCode::ProtocolState),
            CloseReason::ProtocolViolation,
        ),
        BrokerRequest::Core(request) => {
            BrokerDispatch::continue_after(handle_core_request(session, request))
        }
        _ => BrokerDispatch::continue_after(BrokerResponse::Error(ErrorCode::UnsupportedOperation)),
    }
}

fn handle_core_request(session: &BrokerSession, request: CoreRequest) -> BrokerResponse {
    match request {
        CoreRequest::Event(request) => handle_event_request(session, request),
        _ => BrokerResponse::Error(ErrorCode::UnsupportedOperation),
    }
}

fn handle_event_request(session: &BrokerSession, request: EventRequest) -> BrokerResponse {
    match request {
        EventRequest::Create(request) => {
            handle_core_result(event::create(session, request.initial_count), |handle| {
                BrokerResponse::Core(CoreResponse::Event(EventResponse::Create(
                    CreateEventResponse::new(handle),
                )))
            })
        }
        EventRequest::Wait(request) => {
            handle_core_result(event::wait(session, request.handle), |outcome| {
                BrokerResponse::Core(CoreResponse::Event(EventResponse::Wait(
                    WaitEventResponse::new(outcome),
                )))
            })
        }
        EventRequest::Add(request) => handle_core_result(
            event::add(session, request.handle, request.value),
            |readiness| {
                BrokerResponse::Core(CoreResponse::Event(EventResponse::Add(
                    AddEventResponse::new(readiness),
                )))
            },
        ),
        EventRequest::Consume(request) => handle_core_result(
            event::consume(session, request.handle, request.mode),
            |consumption| {
                BrokerResponse::Core(CoreResponse::Event(EventResponse::Consume(consumption)))
            },
        ),
        _ => BrokerResponse::Error(ErrorCode::UnsupportedOperation),
    }
}

fn handle_unknown_request(state: ConnectionState) -> BrokerDispatch {
    if state == ConnectionState::AwaitingNegotiation {
        BrokerDispatch::close_after(
            BrokerResponse::Error(ErrorCode::ProtocolState),
            CloseReason::ProtocolViolation,
        )
    } else {
        BrokerDispatch::continue_after(BrokerResponse::Error(ErrorCode::UnsupportedOperation))
    }
}

fn negotiate_version(
    state: &mut ConnectionState,
    protocol_version: ProtocolVersion,
) -> BrokerDispatch {
    if protocol_version.is_supported_by(HOST_PROTOCOL_VERSION) {
        *state = ConnectionState::Active {
            negotiated_protocol_version: protocol_version,
        };
        BrokerDispatch::continue_after(BrokerResponse::Negotiated {
            broker_protocol_version: HOST_PROTOCOL_VERSION,
        })
    } else {
        BrokerDispatch::continue_after(BrokerResponse::VersionMismatch {
            broker_protocol_version: HOST_PROTOCOL_VERSION,
        })
    }
}

fn handle_core_result<T>(
    result: litebox_broker_core::Result<T>,
    into_response: impl FnOnce(T) -> BrokerResponse,
) -> BrokerResponse {
    match result {
        Ok(value) => into_response(value),
        Err(error) => BrokerResponse::Error(to_protocol_error(error)),
    }
}

fn to_protocol_error(error: BrokerError) -> ErrorCode {
    match error {
        BrokerError::PolicyDenied => ErrorCode::PolicyDenied,
        BrokerError::UnknownObject => ErrorCode::UnknownObject,
        BrokerError::InvalidRights => ErrorCode::InvalidRights,
        BrokerError::ResourceExhausted => ErrorCode::ResourceExhausted,
        BrokerError::WouldBlock => ErrorCode::WouldBlock,
        BrokerError::UnsupportedOperation => ErrorCode::UnsupportedOperation,
        _ => ErrorCode::Internal,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    AwaitingNegotiation,
    Active {
        negotiated_protocol_version: ProtocolVersion,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BrokerDispatch {
    response: BrokerResponse,
    outcome: DispatchOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchOutcome {
    Continue,
    Close(CloseReason),
}

impl BrokerDispatch {
    const fn continue_after(response: BrokerResponse) -> Self {
        Self {
            response,
            outcome: DispatchOutcome::Continue,
        }
    }

    const fn close_after(response: BrokerResponse, reason: CloseReason) -> Self {
        Self {
            response,
            outcome: DispatchOutcome::Close(reason),
        }
    }
}

/// Reason the broker host closed the connection after sending a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// The peer violated the request sequencing state machine.
    ProtocolViolation,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolViolation => f.write_str("protocol violation"),
        }
    }
}

/// Terminal outcome for a successfully served broker connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionTermination {
    /// The peer cleanly closed the channel.
    PeerClosed,
    /// The host sent a terminal protocol response and closed the connection.
    BrokerClosed(CloseReason),
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_core::{PolicyEngine, PrincipalRights};
    use litebox_broker_protocol::CreateEventRequest;

    #[test]
    fn host_request_handling_uses_one_broker_core() {
        let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
            PrincipalRights::all(),
        ))
        .unwrap();

        serve_connection_negotiates_routes_one_request_and_returns_peer_closed(&broker);
        serve_connection_closes_after_protocol_violation(&broker);
        serve_connection_returns_channel_error_when_response_send_fails(&broker);
    }

    fn serve_connection_negotiates_routes_one_request_and_returns_peer_closed(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(std::vec::Vec::from([
            Ok(Some(ReceivedBrokerRequest::Request(
                BrokerRequest::Negotiate {
                    protocol_version: HOST_PROTOCOL_VERSION,
                },
            ))),
            Ok(Some(ReceivedBrokerRequest::Request(event_create_request(
                0,
            )))),
            Ok(None),
        ]));

        assert_eq!(
            serve_connection(broker, &mut channel).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.responses[0],
            BrokerResponse::Negotiated {
                broker_protocol_version: HOST_PROTOCOL_VERSION
            }
        );
        let handle = match &channel.responses[1] {
            BrokerResponse::Core(CoreResponse::Event(EventResponse::Create(response))) => {
                response.handle
            }
            response => panic!("unexpected response: {response:?}"),
        };
        assert_ne!(handle.0, 0);
    }

    fn serve_connection_closes_after_protocol_violation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(std::vec::Vec::from([
            Ok(Some(ReceivedBrokerRequest::Request(event_create_request(
                0,
            )))),
            Ok(Some(ReceivedBrokerRequest::Request(
                BrokerRequest::Negotiate {
                    protocol_version: HOST_PROTOCOL_VERSION,
                },
            ))),
        ]));

        assert_eq!(
            serve_connection(broker, &mut channel).unwrap(),
            ConnectionTermination::BrokerClosed(CloseReason::ProtocolViolation)
        );
        assert_eq!(
            channel.responses,
            [BrokerResponse::Error(ErrorCode::ProtocolState)]
        );
        assert_eq!(channel.requests.len(), 1);
    }

    fn serve_connection_returns_channel_error_when_response_send_fails(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(std::vec::Vec::from([Ok(Some(
            ReceivedBrokerRequest::Request(BrokerRequest::Negotiate {
                protocol_version: HOST_PROTOCOL_VERSION,
            }),
        ))]));
        channel.send_error = true;

        match serve_connection(broker, &mut channel) {
            Err(BrokerHostError::Channel(())) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert!(channel.responses.is_empty());
    }

    const fn event_request(request: EventRequest) -> BrokerRequest {
        BrokerRequest::Core(CoreRequest::Event(request))
    }

    const fn event_create_request(initial_count: u64) -> BrokerRequest {
        event_request(EventRequest::Create(CreateEventRequest::new(initial_count)))
    }

    struct FakeHostControlChannel {
        requests: std::vec::Vec<core::result::Result<Option<ReceivedBrokerRequest>, ()>>,
        responses: std::vec::Vec<BrokerResponse>,
        send_error: bool,
    }

    impl FakeHostControlChannel {
        fn new(
            requests: std::vec::Vec<core::result::Result<Option<ReceivedBrokerRequest>, ()>>,
        ) -> Self {
            Self {
                requests,
                responses: std::vec::Vec::new(),
                send_error: false,
            }
        }
    }

    impl HostControlChannel for FakeHostControlChannel {
        type Error = ();

        fn peer_credential(&self) -> core::result::Result<PeerCredential, Self::Error> {
            Ok(PeerCredential::Unauthenticated)
        }

        fn recv_request(
            &mut self,
        ) -> core::result::Result<Option<ReceivedBrokerRequest>, Self::Error> {
            if self.requests.is_empty() {
                Ok(None)
            } else {
                self.requests.remove(0)
            }
        }

        fn send_response(
            &mut self,
            response: &BrokerResponse,
        ) -> core::result::Result<(), Self::Error> {
            if self.send_error {
                return Err(());
            }
            self.responses.push(response.clone());
            Ok(())
        }
    }
}
