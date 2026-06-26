// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Channel-neutral broker-side protocol/core adapter.
//!
//! This crate wires `litebox_broker_core` to implementations of the neutral
//! host-side control and notification channel traits. Concrete channels live in
//! separate crates such as `litebox_broker_transport`.

#![no_std]

#[cfg(test)]
extern crate std;

use litebox_broker_core::{BrokerCore, BrokerSession, CallerCredential};
use litebox_broker_protocol::channel::{
    HostControlChannel, HostNotificationChannel, HostReceive, PeerCredential,
};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{AddEventResponse, CreateEventResponse, WaitEventResponse};
use litebox_broker_protocol::message::{
    BrokerHandshakeResponse, BrokerNotification, BrokerRequest, BrokerResponse,
    EventReadinessNotification, EventRequest, EventResponse,
};
use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle};

mod error;

pub use error::{BrokerHostError, Result};

/// Authenticates, negotiates, and serves one broker connection over the control channel.
pub fn serve_connection<Channel>(
    core: &BrokerCore,
    channel: &mut Channel,
) -> Result<ConnectionTermination, Channel::Error>
where
    Channel: HostControlChannel,
{
    match negotiate_connection(core, channel)? {
        NegotiatedConnection::Active(session) => serve_request_loop(channel, &session),
        NegotiatedConnection::Terminated(termination) => Ok(termination),
    }
}

/// Authenticates, negotiates, and serves one broker connection with notifications.
///
/// Control requests and responses remain strictly paired on the control channel.
/// Readiness notifications are sent over the separate notification channel after
/// state-changing event requests complete.
pub fn serve_connection_with_notifications<ControlChannel, NotificationChannel>(
    core: &BrokerCore,
    control_channel: &mut ControlChannel,
    notification_channel: &mut NotificationChannel,
) -> Result<ConnectionTermination, ControlChannel::Error>
where
    ControlChannel: HostControlChannel,
    NotificationChannel: HostNotificationChannel<Error = ControlChannel::Error>,
{
    match negotiate_connection(core, control_channel)? {
        NegotiatedConnection::Active(session) => {
            serve_request_loop_with_notifications(control_channel, &session, notification_channel)
        }
        NegotiatedConnection::Terminated(termination) => Ok(termination),
    }
}

fn negotiate_connection<Channel>(
    core: &BrokerCore,
    channel: &mut Channel,
) -> Result<NegotiatedConnection, Channel::Error>
where
    Channel: HostControlChannel,
{
    let peer_credential = channel
        .peer_credential()
        .map_err(BrokerHostError::Channel)?;
    let caller_credential = match peer_credential {
        PeerCredential::Unauthenticated => CallerCredential::Unauthenticated,
        _ => return Err(BrokerHostError::Broker(ErrorCode::PolicyDenied)),
    };
    let session = core.create_session(caller_credential)?;

    loop {
        let request = match channel
            .recv_handshake_request()
            .map_err(BrokerHostError::Channel)?
        {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                channel
                    .send_handshake_response(&BrokerHandshakeResponse::Error(
                        ErrorCode::ProtocolState,
                    ))
                    .map_err(BrokerHostError::Channel)?;
                return Ok(NegotiatedConnection::Terminated(
                    ConnectionTermination::ProtocolViolation,
                ));
            }
            HostReceive::PeerClosed => {
                return Ok(NegotiatedConnection::Terminated(
                    ConnectionTermination::PeerClosed,
                ));
            }
        };

        let negotiated = request.protocol_version == BROKER_PROTOCOL_VERSION;
        let response = if negotiated {
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }
        } else {
            BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }
        };
        channel
            .send_handshake_response(&response)
            .map_err(BrokerHostError::Channel)?;
        if negotiated {
            break;
        }
    }

    Ok(NegotiatedConnection::Active(session))
}

fn serve_request_loop<Channel>(
    channel: &mut Channel,
    session: &BrokerSession,
) -> Result<ConnectionTermination, Channel::Error>
where
    Channel: HostControlChannel,
{
    loop {
        let request = match channel.recv_request().map_err(BrokerHostError::Channel)? {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                channel
                    .send_response(&BrokerResponse::Error(ErrorCode::ProtocolState))
                    .map_err(BrokerHostError::Channel)?;
                return Ok(ConnectionTermination::ProtocolViolation);
            }
            HostReceive::PeerClosed => break,
        };

        let response = handle_request(session, request);
        channel
            .send_response(&response)
            .map_err(BrokerHostError::Channel)?;
    }

    Ok(ConnectionTermination::PeerClosed)
}

fn serve_request_loop_with_notifications<ControlChannel, NotificationChannel>(
    control_channel: &mut ControlChannel,
    session: &BrokerSession,
    notification_channel: &mut NotificationChannel,
) -> Result<ConnectionTermination, ControlChannel::Error>
where
    ControlChannel: HostControlChannel,
    NotificationChannel: HostNotificationChannel<Error = ControlChannel::Error>,
{
    loop {
        let request = match control_channel
            .recv_request()
            .map_err(BrokerHostError::Channel)?
        {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                control_channel
                    .send_response(&BrokerResponse::Error(ErrorCode::ProtocolState))
                    .map_err(BrokerHostError::Channel)?;
                return Ok(ConnectionTermination::ProtocolViolation);
            }
            HostReceive::PeerClosed => break,
        };

        let readiness_handle = event_readiness_notification_handle(&request);
        let response = handle_request(session, request);
        control_channel
            .send_response(&response)
            .map_err(BrokerHostError::Channel)?;
        if let Some(notification) = event_readiness_notification(readiness_handle, &response) {
            notification_channel
                .send_notification(&notification)
                .map_err(BrokerHostError::Channel)?;
        }
    }

    Ok(ConnectionTermination::PeerClosed)
}

fn handle_request(session: &BrokerSession, request: BrokerRequest) -> BrokerResponse {
    match request {
        BrokerRequest::CloseObject(handle) => match session.close_object_reference(handle) {
            Ok(()) => BrokerResponse::ObjectClosed,
            Err(error) => BrokerResponse::Error(error.into()),
        },
        BrokerRequest::Event(request) => handle_event_request(session, request),
    }
}

fn handle_event_request(session: &BrokerSession, request: EventRequest) -> BrokerResponse {
    match request {
        EventRequest::Create(request) => {
            match litebox_broker_core::event::create(session, request.initial_count) {
                Ok(handle) => {
                    BrokerResponse::Event(EventResponse::Create(CreateEventResponse { handle }))
                }
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
        EventRequest::Wait(request) => {
            match litebox_broker_core::event::wait(session, request.handle) {
                Ok(readiness) => {
                    BrokerResponse::Event(EventResponse::Wait(WaitEventResponse { readiness }))
                }
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
        EventRequest::Add(request) => {
            match litebox_broker_core::event::add(session, request.handle, request.value) {
                Ok(readiness) => {
                    BrokerResponse::Event(EventResponse::Add(AddEventResponse { readiness }))
                }
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
        EventRequest::Consume(request) => {
            match litebox_broker_core::event::consume(session, request.handle, request.mode) {
                Ok(consumption) => BrokerResponse::Event(EventResponse::Consume(consumption)),
                Err(error) => BrokerResponse::Error(error.into()),
            }
        }
    }
}

fn event_readiness_notification_handle(request: &BrokerRequest) -> Option<ObjectHandle> {
    match request {
        BrokerRequest::Event(EventRequest::Add(request)) => Some(request.handle),
        BrokerRequest::Event(EventRequest::Consume(request)) => Some(request.handle),
        _ => None,
    }
}

fn event_readiness_notification(
    handle: Option<ObjectHandle>,
    response: &BrokerResponse,
) -> Option<BrokerNotification> {
    match (handle, response) {
        (Some(handle), BrokerResponse::Event(EventResponse::Add(response))) => Some(
            BrokerNotification::EventReadiness(EventReadinessNotification {
                handle,
                readiness: response.readiness,
            }),
        ),
        (Some(handle), BrokerResponse::Event(EventResponse::Consume(response))) => Some(
            BrokerNotification::EventReadiness(EventReadinessNotification {
                handle,
                readiness: response.readiness,
            }),
        ),
        _ => None,
    }
}

enum NegotiatedConnection {
    Active(BrokerSession),
    Terminated(ConnectionTermination),
}

/// Terminal outcome after processing one broker connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionTermination {
    /// The peer cleanly closed the channel.
    PeerClosed,
    /// The broker sent a protocol-state error before closing the channel.
    ProtocolViolation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_core::{PolicyEngine, PrincipalRights};
    use litebox_broker_protocol::event::{CreateEventRequest, WaitEventRequest};
    use litebox_broker_protocol::message::BrokerHandshakeRequest;
    use litebox_broker_protocol::{ObjectHandle, ProtocolVersion};

    #[test]
    fn host_request_handling_uses_one_broker_core() {
        let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
            PrincipalRights::all(),
        ))
        .unwrap();

        serve_connection_negotiates_routes_one_request_and_returns_peer_closed(&broker);
        serve_connection_retries_after_version_mismatch(&broker);
        serve_connection_rejects_active_request_before_negotiation(&broker);
        serve_connection_rejects_handshake_request_after_negotiation(&broker);
        serve_connection_returns_channel_error_when_response_send_fails(&broker);
        active_request_closes_object_reference(&broker);
    }

    fn serve_connection_negotiates_routes_one_request_and_returns_peer_closed(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerRequest::Event(
                    EventRequest::Create(CreateEventRequest { initial_count: 0 }),
                ))),
                Ok(HostReceive::PeerClosed),
            ]),
        );

        assert_eq!(
            serve_connection(broker, &mut channel).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses[0],
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }
        );
        let handle = match &channel.responses[0] {
            BrokerResponse::Event(EventResponse::Create(response)) => response.handle,
            response => panic!("unexpected response: {response:?}"),
        };
        assert_ne!(handle.0, 0);
    }

    fn serve_connection_retries_after_version_mismatch(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: ProtocolVersion(BROKER_PROTOCOL_VERSION.0 + 1),
                })),
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: BROKER_PROTOCOL_VERSION,
                })),
            ]),
            std::vec::Vec::from([Ok(HostReceive::PeerClosed)]),
        );

        assert_eq!(
            serve_connection(broker, &mut channel).unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses,
            [
                BrokerHandshakeResponse::VersionMismatch {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION
                },
                BrokerHandshakeResponse::Negotiated {
                    broker_protocol_version: BROKER_PROTOCOL_VERSION
                }
            ]
        );
    }

    fn serve_connection_rejects_active_request_before_negotiation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::ProtocolViolation)]),
            std::vec::Vec::new(),
        );

        assert_eq!(
            serve_connection(broker, &mut channel).unwrap(),
            ConnectionTermination::ProtocolViolation
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::Error(ErrorCode::ProtocolState)]
        );
        assert!(channel.responses.is_empty());
    }

    fn serve_connection_rejects_handshake_request_after_negotiation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::ProtocolViolation)]),
        );

        assert_eq!(
            serve_connection(broker, &mut channel).unwrap(),
            ConnectionTermination::ProtocolViolation
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }]
        );
        assert_eq!(
            channel.responses,
            [BrokerResponse::Error(ErrorCode::ProtocolState)]
        );
    }

    fn serve_connection_returns_channel_error_when_response_send_fails(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::new(),
        );
        channel.send_error = true;

        match serve_connection(broker, &mut channel) {
            Err(BrokerHostError::Channel(())) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert!(channel.handshake_responses.is_empty());
    }

    fn active_request_closes_object_reference(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let response = handle_request(
            &session,
            BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        );
        let BrokerResponse::Event(EventResponse::Create(response)) = response else {
            panic!("unexpected create response: {response:?}");
        };
        let handle = response.handle;

        assert_eq!(
            handle_request(&session, BrokerRequest::CloseObject(handle)),
            BrokerResponse::ObjectClosed
        );
        assert_eq!(
            handle_request(
                &session,
                BrokerRequest::Event(EventRequest::Wait(WaitEventRequest { handle }))
            ),
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
        assert_eq!(
            handle_request(
                &session,
                BrokerRequest::CloseObject(ObjectHandle(handle.0 + 1))
            ),
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
    }

    struct FakeHostControlChannel {
        handshake_requests:
            std::vec::Vec<core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>>,
        requests: std::vec::Vec<core::result::Result<HostReceive<BrokerRequest>, ()>>,
        handshake_responses: std::vec::Vec<BrokerHandshakeResponse>,
        responses: std::vec::Vec<BrokerResponse>,
        send_error: bool,
    }

    impl FakeHostControlChannel {
        fn new(
            handshake_requests: std::vec::Vec<
                core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>,
            >,
            requests: std::vec::Vec<core::result::Result<HostReceive<BrokerRequest>, ()>>,
        ) -> Self {
            Self {
                handshake_requests,
                requests,
                handshake_responses: std::vec::Vec::new(),
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

        fn recv_handshake_request(
            &mut self,
        ) -> core::result::Result<HostReceive<BrokerHandshakeRequest>, Self::Error> {
            if self.handshake_requests.is_empty() {
                Ok(HostReceive::PeerClosed)
            } else {
                self.handshake_requests.remove(0)
            }
        }

        fn send_handshake_response(
            &mut self,
            response: &BrokerHandshakeResponse,
        ) -> core::result::Result<(), Self::Error> {
            if self.send_error {
                return Err(());
            }
            self.handshake_responses.push(response.clone());
            Ok(())
        }

        fn recv_request(
            &mut self,
        ) -> core::result::Result<HostReceive<BrokerRequest>, Self::Error> {
            if self.requests.is_empty() {
                Ok(HostReceive::PeerClosed)
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
