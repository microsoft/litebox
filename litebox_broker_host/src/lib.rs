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

use litebox_broker_core::{BrokerCore, BrokerSession, CallerCredential};
use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
use litebox_broker_protocol::channel::{
    HostControlChannel, HostNotificationChannel, HostReceive, PeerCredential,
};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{AddEventResponse, CreateEventResponse, WaitEventResponse};
use litebox_broker_protocol::message::{
    BrokerHandshakeResponse, BrokerNotification, BrokerRequest, BrokerResponse,
    EventReadinessNotification, EventRequest, EventResponse,
};

mod error;

pub use error::{BrokerHostError, Result};

/// Authenticates, negotiates, and serves one broker association over paired
/// control and notification channels.
///
/// The deployment must bind both channels to the same authenticated peer
/// association. Active requests and responses remain on the control channel;
/// broker-initiated readiness wakeups are sent on the notification channel.
pub fn serve_connection<ControlChannel, NotificationChannel, ChannelError>(
    core: &BrokerCore,
    control_channel: &mut ControlChannel,
    notification_channel: &mut NotificationChannel,
) -> Result<ConnectionTermination, ChannelError>
where
    ControlChannel: HostControlChannel<Error = ChannelError>,
    NotificationChannel: HostNotificationChannel<Error = ChannelError>,
{
    let peer_credential = control_channel
        .peer_credential()
        .map_err(BrokerHostError::Channel)?;
    let caller_credential = match peer_credential {
        PeerCredential::Unauthenticated => CallerCredential::Unauthenticated,
        _ => return Err(BrokerHostError::Broker(ErrorCode::PolicyDenied)),
    };
    let session = core.create_session(caller_credential)?;
    let mut connection = HostConnection {
        session,
        notification_channel,
    };

    loop {
        let request = match control_channel
            .recv_handshake_request()
            .map_err(BrokerHostError::Channel)?
        {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                control_channel
                    .send_handshake_response(&BrokerHandshakeResponse::Error(
                        ErrorCode::ProtocolState,
                    ))
                    .map_err(BrokerHostError::Channel)?;
                return Ok(ConnectionTermination::ProtocolViolation);
            }
            HostReceive::PeerClosed => return Ok(ConnectionTermination::PeerClosed),
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
        control_channel
            .send_handshake_response(&response)
            .map_err(BrokerHostError::Channel)?;
        if negotiated {
            break;
        }
    }

    serve_request_loop(control_channel, &mut connection)
}

fn serve_request_loop<ControlChannel, NotificationChannel, ChannelError>(
    control_channel: &mut ControlChannel,
    connection: &mut HostConnection<'_, NotificationChannel>,
) -> Result<ConnectionTermination, ChannelError>
where
    ControlChannel: HostControlChannel<Error = ChannelError>,
    NotificationChannel: HostNotificationChannel<Error = ChannelError>,
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

        let response = handle_request(connection, request).map_err(BrokerHostError::Channel)?;
        control_channel
            .send_response(&response)
            .map_err(BrokerHostError::Channel)?;
    }

    Ok(ConnectionTermination::PeerClosed)
}

/// Broker-host state for one authenticated control/notification association.
struct HostConnection<'a, NotificationChannel> {
    session: BrokerSession,
    notification_channel: &'a mut NotificationChannel,
}

impl<NotificationChannel> HostConnection<'_, NotificationChannel>
where
    NotificationChannel: HostNotificationChannel,
{
    fn notify_event_readiness(
        &mut self,
        notification: EventReadinessNotification,
    ) -> core::result::Result<(), NotificationChannel::Error> {
        self.notification_channel
            .send_notification(&BrokerNotification::EventReadiness(notification))
    }
}

fn handle_request<NotificationChannel>(
    connection: &mut HostConnection<'_, NotificationChannel>,
    request: BrokerRequest,
) -> core::result::Result<BrokerResponse, NotificationChannel::Error>
where
    NotificationChannel: HostNotificationChannel,
{
    match request {
        BrokerRequest::CloseObject(handle) => {
            match connection.session.close_object_reference(handle) {
                Ok(()) => Ok(BrokerResponse::ObjectClosed),
                Err(error) => Ok(BrokerResponse::Error(error.into())),
            }
        }
        BrokerRequest::Event(request) => handle_event_request(connection, request),
    }
}

fn handle_event_request<NotificationChannel>(
    connection: &mut HostConnection<'_, NotificationChannel>,
    request: EventRequest,
) -> core::result::Result<BrokerResponse, NotificationChannel::Error>
where
    NotificationChannel: HostNotificationChannel,
{
    match request {
        EventRequest::Create(request) => {
            match litebox_broker_core::event::create(&connection.session, request.initial_count) {
                Ok(handle) => Ok(BrokerResponse::Event(EventResponse::Create(
                    CreateEventResponse { handle },
                ))),
                Err(error) => Ok(BrokerResponse::Error(error.into())),
            }
        }
        EventRequest::Wait(request) => {
            match litebox_broker_core::event::wait(&connection.session, request.handle) {
                Ok(readiness) => Ok(BrokerResponse::Event(EventResponse::Wait(
                    WaitEventResponse { readiness },
                ))),
                Err(error) => Ok(BrokerResponse::Error(error.into())),
            }
        }
        EventRequest::Add(request) => {
            match litebox_broker_core::event::add(
                &connection.session,
                request.handle,
                request.value,
            ) {
                Ok(readiness) => {
                    connection.notify_event_readiness(EventReadinessNotification {
                        handle: request.handle,
                        readiness,
                    })?;
                    Ok(BrokerResponse::Event(EventResponse::Add(
                        AddEventResponse { readiness },
                    )))
                }
                Err(error) => Ok(BrokerResponse::Error(error.into())),
            }
        }
        EventRequest::Consume(request) => {
            match litebox_broker_core::event::consume(
                &connection.session,
                request.handle,
                request.mode,
            ) {
                Ok(consumption) => {
                    connection.notify_event_readiness(EventReadinessNotification {
                        handle: request.handle,
                        readiness: consumption.readiness,
                    })?;
                    Ok(BrokerResponse::Event(EventResponse::Consume(consumption)))
                }
                Err(error) => Ok(BrokerResponse::Error(error.into())),
            }
        }
    }
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
        serve_request_loop_sends_event_readiness_notifications(&broker);
        host_connection_sends_event_readiness_notifications(&broker);
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
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
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
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
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
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
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
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(broker, &mut channel, &mut notifications).unwrap(),
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
        let mut notifications = FakeHostNotificationChannel::default();

        match serve_connection(broker, &mut channel, &mut notifications) {
            Err(BrokerHostError::Channel(())) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert!(channel.handshake_responses.is_empty());
    }

    fn serve_request_loop_sends_event_readiness_notifications(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = litebox_broker_core::event::create(&session, 0).unwrap();
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::new(),
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerRequest::Event(
                    EventRequest::Add(litebox_broker_protocol::event::AddEventRequest {
                        handle,
                        value: 1,
                    }),
                ))),
                Ok(HostReceive::Message(BrokerRequest::Event(
                    EventRequest::Consume(litebox_broker_protocol::event::ConsumeEventRequest {
                        handle,
                        mode: litebox_broker_protocol::event::EventConsumeMode::One,
                    }),
                ))),
                Ok(HostReceive::PeerClosed),
            ]),
        );
        let mut notifications = FakeHostNotificationChannel::default();
        {
            let mut connection = HostConnection {
                session,
                notification_channel: &mut notifications,
            };
            assert_eq!(
                serve_request_loop(&mut channel, &mut connection).unwrap(),
                ConnectionTermination::PeerClosed
            );
        }
        assert_eq!(
            notifications.notifications,
            [
                BrokerNotification::EventReadiness(EventReadinessNotification {
                    handle,
                    readiness: litebox_broker_protocol::event::ReadinessState {
                        read_ready: true,
                        write_ready: true,
                    },
                }),
                BrokerNotification::EventReadiness(EventReadinessNotification {
                    handle,
                    readiness: litebox_broker_protocol::event::ReadinessState {
                        read_ready: false,
                        write_ready: true,
                    },
                }),
            ]
        );
    }

    fn host_connection_sends_event_readiness_notifications(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = litebox_broker_core::event::create(&session, 0).unwrap();
        let readiness = litebox_broker_protocol::event::ReadinessState {
            read_ready: true,
            write_ready: true,
        };
        let notification = EventReadinessNotification { handle, readiness };
        let mut notifications = FakeHostNotificationChannel::default();
        {
            let mut connection = HostConnection {
                session,
                notification_channel: &mut notifications,
            };
            connection.notify_event_readiness(notification).unwrap();
        }

        assert_eq!(
            notifications.notifications,
            [BrokerNotification::EventReadiness(notification)]
        );
    }

    fn active_request_closes_object_reference(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let mut notifications = FakeHostNotificationChannel::default();
        let mut connection = HostConnection {
            session,
            notification_channel: &mut notifications,
        };
        let response = handle_request(
            &mut connection,
            BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        )
        .unwrap();
        let BrokerResponse::Event(EventResponse::Create(response)) = response else {
            panic!("unexpected create response: {response:?}");
        };
        let handle = response.handle;

        assert_eq!(
            handle_request(&mut connection, BrokerRequest::CloseObject(handle)).unwrap(),
            BrokerResponse::ObjectClosed
        );
        assert_eq!(
            handle_request(
                &mut connection,
                BrokerRequest::Event(EventRequest::Wait(WaitEventRequest { handle }))
            )
            .unwrap(),
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
        assert_eq!(
            handle_request(
                &mut connection,
                BrokerRequest::CloseObject(ObjectHandle(handle.0 + 1))
            )
            .unwrap(),
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

    #[derive(Default)]
    struct FakeHostNotificationChannel {
        notifications: std::vec::Vec<BrokerNotification>,
    }

    impl HostNotificationChannel for FakeHostNotificationChannel {
        type Error = ();

        fn send_notification(
            &mut self,
            notification: &BrokerNotification,
        ) -> core::result::Result<(), Self::Error> {
            self.notifications.push(notification.clone());
            Ok(())
        }
    }
}
