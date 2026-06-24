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

use litebox_broker_core::{BrokerCore, BrokerSession, CallerCredential, event};
use litebox_broker_protocol::{
    AddEventResponse, BROKER_PROTOCOL_VERSION, BrokerRequest, BrokerResponse, CoreRequest,
    CoreResponse, CreateEventResponse, ErrorCode, EventRequest, EventResponse, HostControlChannel,
    PeerCredential, WaitEventResponse,
};

mod error;

pub use error::{BrokerHostError, Result};

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
    let caller_credential = match peer_credential {
        PeerCredential::Unauthenticated => CallerCredential::Unauthenticated,
        _ => return Err(BrokerHostError::Broker(ErrorCode::PolicyDenied)),
    };
    let session = core.create_session(caller_credential)?;

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
        let Some(request) = channel.recv_request().map_err(BrokerHostError::Channel)? else {
            break;
        };

        let dispatch = handle_request(session, &mut state, request);
        channel
            .send_response(&dispatch.response)
            .map_err(BrokerHostError::Channel)?;
        if let DispatchOutcome::Close(reason) = dispatch.outcome {
            return Ok(ConnectionTermination::BrokerClosed(reason));
        }
    }

    Ok(ConnectionTermination::PeerClosed)
}

fn handle_request(
    session: &BrokerSession,
    state: &mut ConnectionState,
    request: BrokerRequest,
) -> BrokerDispatch {
    match *state {
        ConnectionState::AwaitingNegotiation => match request {
            BrokerRequest::Negotiate { protocol_version } => {
                if protocol_version == BROKER_PROTOCOL_VERSION {
                    *state = ConnectionState::Active;
                    BrokerDispatch {
                        response: BrokerResponse::Negotiated {
                            broker_protocol_version: BROKER_PROTOCOL_VERSION,
                        },
                        outcome: DispatchOutcome::Continue,
                    }
                } else {
                    BrokerDispatch {
                        response: BrokerResponse::VersionMismatch {
                            broker_protocol_version: BROKER_PROTOCOL_VERSION,
                        },
                        outcome: DispatchOutcome::Continue,
                    }
                }
            }
            BrokerRequest::Core(_) => BrokerDispatch {
                response: BrokerResponse::Error(ErrorCode::ProtocolState),
                outcome: DispatchOutcome::Close(CloseReason::ProtocolViolation),
            },
        },
        ConnectionState::Active => handle_active_request(session, request),
    }
}

fn handle_active_request(session: &BrokerSession, request: BrokerRequest) -> BrokerDispatch {
    match request {
        BrokerRequest::Negotiate { .. } => BrokerDispatch {
            response: BrokerResponse::Error(ErrorCode::ProtocolState),
            outcome: DispatchOutcome::Close(CloseReason::ProtocolViolation),
        },
        BrokerRequest::Core(CoreRequest::Event(request)) => BrokerDispatch {
            response: handle_event_request(session, request),
            outcome: DispatchOutcome::Continue,
        },
    }
}

fn handle_event_request(session: &BrokerSession, request: EventRequest) -> BrokerResponse {
    match request {
        EventRequest::Create(request) => match event::create(session, request.initial_count) {
            Ok(handle) => BrokerResponse::Core(CoreResponse::Event(EventResponse::Create(
                CreateEventResponse { handle },
            ))),
            Err(error) => BrokerResponse::Error(error.into()),
        },
        EventRequest::Wait(request) => match event::wait(session, request.handle) {
            Ok(readiness) => BrokerResponse::Core(CoreResponse::Event(EventResponse::Wait(
                WaitEventResponse { readiness },
            ))),
            Err(error) => BrokerResponse::Error(error.into()),
        },
        EventRequest::Add(request) => {
            match event::add(session, request.handle, request.value) {
                Ok(readiness) => BrokerResponse::Core(CoreResponse::Event(EventResponse::Add(
                    AddEventResponse { readiness },
                ))),
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
        EventRequest::Consume(request) => {
            match event::consume(session, request.handle, request.mode) {
                Ok(consumption) => {
                    BrokerResponse::Core(CoreResponse::Event(EventResponse::Consume(consumption)))
                }
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionState {
    AwaitingNegotiation,
    Active,
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
            Ok(Some(BrokerRequest::Negotiate {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })),
            Ok(Some(event_create_request(0))),
            Ok(None),
        ]));

        assert_eq!(
            serve_connection(broker, &mut channel).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.responses[0],
            BrokerResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
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
            Ok(Some(event_create_request(0))),
            Ok(Some(BrokerRequest::Negotiate {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })),
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
            BrokerRequest::Negotiate {
                protocol_version: BROKER_PROTOCOL_VERSION,
            },
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
        event_request(EventRequest::Create(CreateEventRequest { initial_count }))
    }

    struct FakeHostControlChannel {
        requests: std::vec::Vec<core::result::Result<Option<BrokerRequest>, ()>>,
        responses: std::vec::Vec<BrokerResponse>,
        send_error: bool,
    }

    impl FakeHostControlChannel {
        fn new(requests: std::vec::Vec<core::result::Result<Option<BrokerRequest>, ()>>) -> Self {
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

        fn recv_request(&mut self) -> core::result::Result<Option<BrokerRequest>, Self::Error> {
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
