// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Channel-neutral broker-side protocol/core adapter.
//!
//! This crate wires `litebox_broker_core` to any implementation of the neutral
//! host-side control-channel trait. Concrete channels live in separate crates such as
//! `litebox_broker_transport`.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use litebox_broker_core::{BrokerCore, BrokerSession, CallerCredential};
use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
use litebox_broker_protocol::channel::{
    HostControlChannel, HostNotificationChannel, HostReceive, PeerCredential,
};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{AddEventResponse, CreateEventResponse};
use litebox_broker_protocol::message::{
    BrokerHandshakeResponse, BrokerRequest, BrokerResponse, EventRequest, EventResponse,
    PipeRequest, PipeResponse,
};
use litebox_broker_protocol::pipe::{
    CreatePipeResponse, PIPE_TRANSFER_BUFFER_SIZE, ReadPipeResponse, WritePipeResponse,
};
use litebox_broker_protocol::shared_memory::SharedMemory;

mod error;

pub use error::{BrokerHostError, Result};

/// Authenticates, negotiates, and serves one broker association over paired
/// control and notification channels.
///
/// The deployment must bind both channels to the same authenticated peer
/// association. Active requests and responses remain on the control channel;
/// broker-initiated readiness wakeups are sent on the notification channel.
/// Event mutations caused by control requests return readiness in their control
/// response and do not also emit a duplicate notification.
///
/// `shared_memory` belongs to this association and is reused at offset zero for
/// serialized pipe transfers. `send_shared_memory` runs after version
/// negotiation and before active requests begin.
pub fn serve_connection<ControlChannel, NotificationChannel, ChannelError>(
    core: &BrokerCore,
    control_channel: &mut ControlChannel,
    _notification_channel: &mut NotificationChannel,
    shared_memory: &dyn SharedMemory,
    send_shared_memory: impl FnOnce(&mut ControlChannel) -> core::result::Result<(), ChannelError>,
) -> Result<ConnectionTermination, ChannelError>
where
    ControlChannel: HostControlChannel<Error = ChannelError>,
    NotificationChannel: HostNotificationChannel<Error = ChannelError>,
{
    if shared_memory.len() != PIPE_TRANSFER_BUFFER_SIZE {
        return Err(BrokerHostError::Broker(ErrorCode::Internal));
    }
    let peer_credential = control_channel
        .peer_credential()
        .map_err(BrokerHostError::Channel)?;
    let caller_credential = match peer_credential {
        PeerCredential::HostGuaranteed => CallerCredential::HostGuaranteed,
        PeerCredential::Unauthenticated => CallerCredential::Unauthenticated,
        _ => return Err(BrokerHostError::Broker(ErrorCode::PolicyDenied)),
    };
    let session = core.create_session(caller_credential)?;
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
            send_shared_memory(control_channel).map_err(BrokerHostError::Channel)?;
            break;
        }
    }

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

        let response = complete_request(handle_request(&session, request, shared_memory))
            .map_err(BrokerHostError::Broker)?;
        control_channel
            .send_response(&response)
            .map_err(BrokerHostError::Channel)?;
    }

    Ok(ConnectionTermination::PeerClosed)
}

type RequestResult<T> = core::result::Result<T, RequestFailure>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestFailure {
    /// Send an error response and continue serving the association.
    Respond(ErrorCode),
    /// Terminate the association without sending a response.
    Abort(ErrorCode),
}

fn complete_request(
    result: RequestResult<BrokerResponse>,
) -> core::result::Result<BrokerResponse, ErrorCode> {
    match result {
        Ok(response) => Ok(response),
        Err(RequestFailure::Respond(error)) => Ok(BrokerResponse::Error(error)),
        Err(RequestFailure::Abort(error)) => Err(error),
    }
}

fn handle_request(
    session: &BrokerSession,
    request: BrokerRequest,
    shared_memory: &dyn SharedMemory,
) -> RequestResult<BrokerResponse> {
    match request {
        BrokerRequest::CloseObject(handle) => session
            .close_object_reference(handle)
            .map(|()| BrokerResponse::ObjectClosed)
            .map_err(|error| RequestFailure::Respond(error.into())),
        BrokerRequest::CheckReadiness(handle) => session
            .check_readiness(handle)
            .map(BrokerResponse::Readiness)
            .map_err(|error| RequestFailure::Respond(error.into())),
        BrokerRequest::Event(request) => {
            handle_event_request(session, request).map(BrokerResponse::Event)
        }
        BrokerRequest::Pipe(request) => {
            handle_pipe_request(session, request, shared_memory).map(BrokerResponse::Pipe)
        }
    }
}

fn handle_pipe_request(
    session: &BrokerSession,
    request: PipeRequest,
    shared_memory: &dyn SharedMemory,
) -> RequestResult<PipeResponse> {
    match request {
        PipeRequest::Create(request) => {
            litebox_broker_core::pipe::create(session, request.capacity, request.atomic_write_size)
                .map(|(read_handle, write_handle)| {
                    PipeResponse::Create(CreatePipeResponse {
                        read_handle,
                        write_handle,
                    })
                })
                .map_err(|error| RequestFailure::Respond(error.into()))
        }
        PipeRequest::Read(request) => {
            if request.length as usize > PIPE_TRANSFER_BUFFER_SIZE {
                return Err(RequestFailure::Respond(ErrorCode::MalformedRequest));
            }
            let data = litebox_broker_core::pipe::read(session, request.handle, request.length)
                .map_err(|error| RequestFailure::Respond(error.into()))?;
            shared_memory
                .write(0, &data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            Ok(PipeResponse::Read(ReadPipeResponse {
                read: data
                    .len()
                    .try_into()
                    .map_err(|_| RequestFailure::Abort(ErrorCode::ResourceExhausted))?,
            }))
        }
        PipeRequest::Write(request) => {
            if request.length as usize > PIPE_TRANSFER_BUFFER_SIZE {
                return Err(RequestFailure::Respond(ErrorCode::MalformedRequest));
            }
            let length = request.length as usize;
            let mut data = Vec::new();
            if data.try_reserve_exact(length).is_err() {
                return Err(RequestFailure::Respond(ErrorCode::OutOfMemory));
            }
            data.resize(length, 0);
            shared_memory
                .read(0, &mut data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            litebox_broker_core::pipe::write(session, request.handle, &data)
                .map_err(|error| RequestFailure::Respond(error.into()))
                .and_then(|written| {
                    Ok(PipeResponse::Write(WritePipeResponse {
                        written: written
                            .try_into()
                            .map_err(|_| RequestFailure::Abort(ErrorCode::ResourceExhausted))?,
                    }))
                })
        }
    }
}

fn handle_event_request(
    session: &BrokerSession,
    request: EventRequest,
) -> RequestResult<EventResponse> {
    match request {
        EventRequest::Create(request) => {
            litebox_broker_core::event::create(session, request.initial_count)
                .map(|handle| EventResponse::Create(CreateEventResponse { handle }))
                .map_err(|error| RequestFailure::Respond(error.into()))
        }
        EventRequest::Add(request) => {
            litebox_broker_core::event::add(session, request.handle, request.value)
                .map(|readiness| EventResponse::Add(AddEventResponse { readiness }))
                .map_err(|error| RequestFailure::Respond(error.into()))
        }
        EventRequest::Consume(request) => {
            litebox_broker_core::event::consume(session, request.handle, request.mode)
                .map(EventResponse::Consume)
                .map_err(|error| RequestFailure::Respond(error.into()))
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
    use core::cell::Cell;
    use litebox_broker_core::{ObjectRights, PolicyEngine};
    use litebox_broker_protocol::channel::HostControlChannel;
    use litebox_broker_protocol::event::{
        AddEventRequest, ConsumeEventRequest, CreateEventRequest, EventConsumeMode,
    };
    use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerNotification};
    use litebox_broker_protocol::pipe::{CreatePipeRequest, ReadPipeRequest, WritePipeRequest};
    use litebox_broker_protocol::shared_memory::SharedMemoryError;
    use litebox_broker_protocol::{ObjectHandle, ProtocolVersion};
    use std::sync::{Arc, Mutex};

    #[test]
    fn host_request_handling_uses_one_broker_core() {
        let broker = BrokerCore::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .unwrap();

        serve_connection_negotiates_routes_one_request_and_returns_peer_closed(&broker);
        serve_connection_retries_after_version_mismatch(&broker);
        serve_connection_skips_setup_after_version_mismatch(&broker);
        serve_connection_rejects_active_request_before_negotiation(&broker);
        serve_connection_rejects_handshake_request_after_negotiation(&broker);
        serve_connection_returns_channel_error_when_response_send_fails(&broker);
        serve_connection_returns_event_readiness_in_control_responses(&broker);
        serve_connection_continues_after_recoverable_request_failure(&broker);
        serve_connection_aborts_without_response_on_shared_memory_failure(&broker);
        active_request_closes_object_reference(&broker);
        association_shared_memory_stages_pipe_data(&broker);
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
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
                |_| Ok(()),
            )
            .unwrap(),
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
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
                |_| Ok(()),
            )
            .unwrap(),
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

    fn serve_connection_skips_setup_after_version_mismatch(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerHandshakeRequest {
                    protocol_version: ProtocolVersion(BROKER_PROTOCOL_VERSION.0 - 1),
                })),
                Ok(HostReceive::PeerClosed),
            ]),
            std::vec::Vec::new(),
        );
        let mut notifications = FakeHostNotificationChannel::default();
        let setup_called = Cell::new(false);

        assert_eq!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
                |_| {
                    setup_called.set(true);
                    Ok(())
                },
            )
            .unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: BROKER_PROTOCOL_VERSION
            }]
        );
        assert!(!setup_called.get());
    }

    fn serve_connection_rejects_active_request_before_negotiation(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::ProtocolViolation)]),
            std::vec::Vec::new(),
        );
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
                |_| Ok(()),
            )
            .unwrap(),
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
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
                |_| Ok(()),
            )
            .unwrap(),
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

        match serve_connection(
            broker,
            &mut channel,
            &mut notifications,
            &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
            |_| Ok(()),
        ) {
            Err(BrokerHostError::Channel(())) => {}
            result => panic!("unexpected serve result: {result:?}"),
        }
        assert!(channel.handshake_responses.is_empty());
    }

    fn serve_connection_returns_event_readiness_in_control_responses(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerRequest::Event(
                EventRequest::Create(CreateEventRequest { initial_count: 0 }),
            )))]),
        );
        channel.enqueue_readiness_requests_after_create = true;
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
                |_| Ok(()),
            )
            .unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert!(notifications.notifications.is_empty());
        assert_eq!(
            &channel.responses[1..],
            [
                BrokerResponse::Event(EventResponse::Add(AddEventResponse {
                    readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ
                        | litebox_broker_protocol::readiness::ReadinessFlags::WRITE,
                })),
                BrokerResponse::Event(EventResponse::Consume(
                    litebox_broker_protocol::event::ConsumeEventResponse {
                        value: 1,
                        readiness: litebox_broker_protocol::readiness::ReadinessFlags::WRITE,
                    }
                )),
            ]
        );
    }

    fn serve_connection_continues_after_recoverable_request_failure(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerRequest::Pipe(
                    PipeRequest::Read(ReadPipeRequest {
                        handle: ObjectHandle(u64::MAX),
                        length: 1,
                    }),
                ))),
                Ok(HostReceive::Message(BrokerRequest::Event(
                    EventRequest::Create(CreateEventRequest { initial_count: 0 }),
                ))),
                Ok(HostReceive::PeerClosed),
            ]),
        );
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
                |_| Ok(()),
            )
            .unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.responses[0],
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
        assert!(matches!(
            channel.responses[1],
            BrokerResponse::Event(EventResponse::Create(_))
        ));
    }

    fn serve_connection_aborts_without_response_on_shared_memory_failure(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerRequest::Pipe(
                PipeRequest::Create(CreatePipeRequest {
                    capacity: 64,
                    atomic_write_size: 16,
                }),
            )))]),
        );
        channel.enqueue_write_request_after_pipe_create = true;
        let mut notifications = FakeHostNotificationChannel::default();

        assert!(matches!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &FailingSharedMemory,
                |_| Ok(()),
            ),
            Err(BrokerHostError::Broker(ErrorCode::Internal))
        ));
        assert_eq!(channel.responses.len(), 1);
        assert!(matches!(
            channel.responses[0],
            BrokerResponse::Pipe(PipeResponse::Create(_))
        ));
    }

    fn active_request_closes_object_reference(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let response = handle_test_request(
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
            handle_test_request(&session, BrokerRequest::CloseObject(handle)),
            BrokerResponse::ObjectClosed
        );
        assert_eq!(
            handle_test_request(&session, BrokerRequest::CheckReadiness(handle)),
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
        assert_eq!(
            handle_test_request(
                &session,
                BrokerRequest::CloseObject(ObjectHandle(handle.0 + 1))
            ),
            BrokerResponse::Error(ErrorCode::UnknownObject)
        );
    }

    fn association_shared_memory_stages_pipe_data(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let memory = TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE);
        let created = handle_test_request_with_memory(
            &session,
            BrokerRequest::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 64,
                atomic_write_size: 16,
            })),
            &memory,
        );
        let BrokerResponse::Pipe(PipeResponse::Create(response)) = created else {
            panic!("expected successful pipe creation");
        };

        memory.write(0, &[1, 2, 3]).unwrap();
        let write = handle_test_request_with_memory(
            &session,
            BrokerRequest::Pipe(PipeRequest::Write(WritePipeRequest {
                handle: response.write_handle,
                length: 3,
            })),
            &memory,
        );
        assert_eq!(
            write,
            BrokerResponse::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 }))
        );

        let read = handle_test_request_with_memory(
            &session,
            BrokerRequest::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle: response.read_handle,
                length: 3,
            })),
            &memory,
        );
        assert_eq!(
            read,
            BrokerResponse::Pipe(PipeResponse::Read(ReadPipeResponse { read: 3 }))
        );
        let mut data = [0; 3];
        memory.read(0, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3]);

        let invalid_range = handle_test_request_with_memory(
            &session,
            BrokerRequest::Pipe(PipeRequest::Write(WritePipeRequest {
                handle: response.write_handle,
                length: u32::try_from(PIPE_TRANSFER_BUFFER_SIZE).unwrap() + 1,
            })),
            &memory,
        );
        assert_eq!(
            invalid_range,
            BrokerResponse::Error(ErrorCode::MalformedRequest)
        );
    }

    fn handle_test_request(session: &BrokerSession, request: BrokerRequest) -> BrokerResponse {
        handle_test_request_with_memory(
            session,
            request,
            &TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE),
        )
    }

    fn handle_test_request_with_memory(
        session: &BrokerSession,
        request: BrokerRequest,
        shared_memory: &dyn SharedMemory,
    ) -> BrokerResponse {
        complete_request(handle_request(session, request, shared_memory)).unwrap()
    }

    struct FakeHostControlChannel {
        handshake_requests:
            std::vec::Vec<core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>>,
        requests: std::vec::Vec<core::result::Result<HostReceive<BrokerRequest>, ()>>,
        handshake_responses: std::vec::Vec<BrokerHandshakeResponse>,
        responses: std::vec::Vec<BrokerResponse>,
        enqueue_readiness_requests_after_create: bool,
        enqueue_write_request_after_pipe_create: bool,
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
                enqueue_readiness_requests_after_create: false,
                enqueue_write_request_after_pipe_create: false,
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
            if self.enqueue_readiness_requests_after_create
                && let BrokerResponse::Event(EventResponse::Create(response)) = response
            {
                self.requests
                    .push(Ok(HostReceive::Message(BrokerRequest::Event(
                        EventRequest::Add(AddEventRequest {
                            handle: response.handle,
                            value: 1,
                        }),
                    ))));
                self.requests
                    .push(Ok(HostReceive::Message(BrokerRequest::Event(
                        EventRequest::Consume(ConsumeEventRequest {
                            handle: response.handle,
                            mode: EventConsumeMode::One,
                        }),
                    ))));
                self.requests.push(Ok(HostReceive::PeerClosed));
            }
            if self.enqueue_write_request_after_pipe_create
                && let BrokerResponse::Pipe(PipeResponse::Create(response)) = response
            {
                self.requests
                    .push(Ok(HostReceive::Message(BrokerRequest::Pipe(
                        PipeRequest::Write(WritePipeRequest {
                            handle: response.write_handle,
                            length: 1,
                        }),
                    ))));
                self.requests.push(Ok(HostReceive::PeerClosed));
            }
            self.responses.push(response.clone());
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let source = memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct FailingSharedMemory;

    impl SharedMemory for FailingSharedMemory {
        fn len(&self) -> usize {
            PIPE_TRANSFER_BUFFER_SIZE
        }

        fn read(
            &self,
            _offset: usize,
            _destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            Err(SharedMemoryError::InvalidRange)
        }

        fn write(
            &self,
            _offset: usize,
            _source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            Err(SharedMemoryError::InvalidRange)
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
