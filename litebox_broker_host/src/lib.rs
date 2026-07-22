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
use litebox_broker_protocol::channel::{
    HostControlChannel, HostNotificationChannel, HostReceive, PeerCredential,
};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::event::{AddEventResponse, CreateEventResponse};
use litebox_broker_protocol::message::{
    BrokerHandshakeResponse, BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
    EventRequest, EventResponse, PipeRequest, PipeResponse,
};
use litebox_broker_protocol::pipe::{
    CreatePipeResponse, MAX_PIPE_TRANSFER_SIZE, ReadPipeResponse, WritePipeResponse,
};
use litebox_broker_protocol::shared_memory::{
    SHARED_BUFFER_LAYOUT, SHARED_BUFFER_SLOT_COUNT, SharedBufferDescriptor, SharedBufferPool,
    SharedBufferSlotIndex, SharedMemory,
};
use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, RequestId};

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
/// `shared_buffers` belongs to this association. Payload descriptors are
/// validated against trusted per-slot claim state. `send_shared_memory` runs
/// after version negotiation and before active requests begin.
pub fn serve_connection<ControlChannel, NotificationChannel, Memory, ChannelError>(
    core: &BrokerCore,
    control_channel: &mut ControlChannel,
    _notification_channel: &mut NotificationChannel,
    shared_buffers: &SharedBufferPool<Memory>,
    send_shared_memory: impl FnOnce(&mut ControlChannel) -> core::result::Result<(), ChannelError>,
) -> Result<ConnectionTermination, ChannelError>
where
    ControlChannel: HostControlChannel<Error = ChannelError>,
    NotificationChannel: HostNotificationChannel<Error = ChannelError>,
    Memory: SharedMemory,
{
    if shared_buffers.layout() != SHARED_BUFFER_LAYOUT {
        return Err(BrokerHostError::SharedBufferLayoutMismatch);
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

    let mut shared_buffer_usage = SharedBufferUsage::new();
    loop {
        let request = match control_channel
            .recv_request()
            .map_err(BrokerHostError::Channel)?
        {
            HostReceive::Message(request) => request,
            HostReceive::ProtocolViolation => {
                return Ok(ConnectionTermination::ProtocolViolation);
            }
            HostReceive::PeerClosed => break,
        };

        let BrokerRequest {
            request_id,
            operation,
        } = request;
        let buffer_descriptor = match &operation {
            BrokerOperation::Pipe(PipeRequest::Read(request)) => Some(request.buffer),
            BrokerOperation::Pipe(PipeRequest::Write(request)) => Some(request.buffer),
            BrokerOperation::CloseObject(_)
            | BrokerOperation::CheckReadiness(_)
            | BrokerOperation::Event(_)
            | BrokerOperation::Pipe(PipeRequest::Create(_)) => None,
        };
        if let Some(descriptor) = buffer_descriptor {
            shared_buffer_usage
                .begin(request_id, descriptor, shared_buffers.layout())
                .map_err(BrokerHostError::Broker)?;
        }
        let result = complete_request(handle_request(&session, operation, shared_buffers))
            .map_err(BrokerHostError::Broker)?;
        control_channel
            .send_response(&BrokerResponse { request_id, result })
            .map_err(BrokerHostError::Channel)?;
        if let Some(descriptor) = buffer_descriptor {
            shared_buffer_usage.end(request_id, descriptor.slot_index);
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedBufferSlotState {
    Unused,
    Idle(RequestId),
    Active(RequestId),
}

struct SharedBufferUsage {
    slots: [SharedBufferSlotState; SHARED_BUFFER_SLOT_COUNT as usize],
}

impl SharedBufferUsage {
    const fn new() -> Self {
        Self {
            slots: [SharedBufferSlotState::Unused; SHARED_BUFFER_SLOT_COUNT as usize],
        }
    }

    fn begin(
        &mut self,
        request_id: RequestId,
        descriptor: SharedBufferDescriptor,
        layout: litebox_broker_protocol::shared_memory::SharedBufferLayout,
    ) -> core::result::Result<(), ErrorCode> {
        if layout
            .range(descriptor.slot_index, descriptor.length as usize)
            .is_err()
        {
            return Err(ErrorCode::MalformedRequest);
        }
        let slot = &mut self.slots[descriptor.slot_index.0 as usize];
        // A local lease spans response consumption, so honest reuse of this slot
        // always carries a newer, non-wrapping request ID.
        match *slot {
            SharedBufferSlotState::Unused => {}
            SharedBufferSlotState::Idle(last_request_id) if request_id > last_request_id => {}
            SharedBufferSlotState::Idle(_) | SharedBufferSlotState::Active(_) => {
                return Err(ErrorCode::MalformedRequest);
            }
        }
        *slot = SharedBufferSlotState::Active(request_id);
        Ok(())
    }

    fn end(&mut self, request_id: RequestId, slot_index: SharedBufferSlotIndex) {
        let slot = &mut self.slots[slot_index.0 as usize];
        assert_eq!(
            *slot,
            SharedBufferSlotState::Active(request_id),
            "shared-buffer slot state changed before response emission"
        );
        *slot = SharedBufferSlotState::Idle(request_id);
    }
}

fn complete_request(
    result: RequestResult<BrokerResult>,
) -> core::result::Result<BrokerResult, ErrorCode> {
    match result {
        Ok(response) => Ok(response),
        Err(RequestFailure::Respond(error)) => Ok(BrokerResult::Error(error)),
        Err(RequestFailure::Abort(error)) => Err(error),
    }
}

fn handle_request<Memory: SharedMemory>(
    session: &BrokerSession,
    operation: BrokerOperation,
    shared_buffers: &SharedBufferPool<Memory>,
) -> RequestResult<BrokerResult> {
    match operation {
        BrokerOperation::CloseObject(handle) => session
            .close_object_reference(handle)
            .map(|()| BrokerResult::ObjectClosed)
            .map_err(|error| RequestFailure::Respond(error.into())),
        BrokerOperation::CheckReadiness(handle) => session
            .check_readiness(handle)
            .map(BrokerResult::Readiness)
            .map_err(|error| RequestFailure::Respond(error.into())),
        BrokerOperation::Event(request) => {
            handle_event_request(session, request).map(BrokerResult::Event)
        }
        BrokerOperation::Pipe(request) => {
            handle_pipe_request(session, request, shared_buffers).map(BrokerResult::Pipe)
        }
    }
}

fn handle_pipe_request<Memory: SharedMemory>(
    session: &BrokerSession,
    request: PipeRequest,
    shared_buffers: &SharedBufferPool<Memory>,
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
            if request.buffer.length > MAX_PIPE_TRANSFER_SIZE {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let data =
                litebox_broker_core::pipe::read(session, request.handle, request.buffer.length)
                    .map_err(|error| RequestFailure::Respond(error.into()))?;
            shared_buffers
                .write(request.buffer.slot_index, &data)
                .map_err(|_| RequestFailure::Abort(ErrorCode::Internal))?;
            Ok(PipeResponse::Read(ReadPipeResponse {
                read: data
                    .len()
                    .try_into()
                    .map_err(|_| RequestFailure::Abort(ErrorCode::ResourceExhausted))?,
            }))
        }
        PipeRequest::Write(request) => {
            if request.buffer.length > MAX_PIPE_TRANSFER_SIZE {
                return Err(RequestFailure::Abort(ErrorCode::MalformedRequest));
            }
            let length = request.buffer.length as usize;
            let mut data = Vec::new();
            if data.try_reserve_exact(length).is_err() {
                return Err(RequestFailure::Respond(ErrorCode::OutOfMemory));
            }
            data.resize(length, 0);
            shared_buffers
                .read(request.buffer.slot_index, &mut data)
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
    /// The peer violated the protocol.
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
    use litebox_broker_protocol::shared_memory::{
        SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE,
        SharedBufferDescriptor, SharedBufferPool, SharedMemoryError,
    };
    use litebox_broker_protocol::{ObjectHandle, ProtocolVersion, RequestId};
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
        serve_connection_aborts_on_stale_shared_buffer_request(&broker);
        serve_connection_aborts_without_response_on_shared_memory_failure(&broker);
        serve_connection_rejects_incompatible_shared_buffer_layout(&broker);
        active_request_closes_object_reference(&broker);
        association_shared_buffer_descriptors_stage_pipe_data(&broker);
        shared_buffer_usage_rejects_invalid_descriptors();
    }

    fn serve_connection_negotiates_routes_one_request_and_returns_peer_closed(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(BrokerOperation::Event(
                    EventRequest::Create(CreateEventRequest { initial_count: 0 }),
                ))),
                Ok(HostReceive::PeerClosed),
            ]),
        );
        channel.next_request_id = 41;
        let mut notifications = FakeHostNotificationChannel::default();

        assert_eq!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &test_shared_buffers(),
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
        let handle = match &channel.results[0] {
            BrokerResult::Event(EventResponse::Create(response)) => response.handle,
            response => panic!("unexpected response: {response:?}"),
        };
        assert_ne!(handle.0, 0);
        assert_eq!(channel.response_ids, [RequestId(41)]);
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
                &test_shared_buffers(),
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
                &test_shared_buffers(),
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
                &test_shared_buffers(),
                |_| Ok(()),
            )
            .unwrap(),
            ConnectionTermination::ProtocolViolation
        );
        assert_eq!(
            channel.handshake_responses,
            [BrokerHandshakeResponse::Error(ErrorCode::ProtocolState)]
        );
        assert!(channel.results.is_empty());
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
                &test_shared_buffers(),
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
        assert!(channel.results.is_empty());
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
            &test_shared_buffers(),
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
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerOperation::Event(
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
                &test_shared_buffers(),
                |_| Ok(()),
            )
            .unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert!(notifications.notifications.is_empty());
        assert_eq!(
            &channel.results[1..],
            [
                BrokerResult::Event(EventResponse::Add(AddEventResponse {
                    readiness: litebox_broker_protocol::readiness::ReadinessFlags::READ
                        | litebox_broker_protocol::readiness::ReadinessFlags::WRITE,
                })),
                BrokerResult::Event(EventResponse::Consume(
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
                Ok(HostReceive::Message(BrokerOperation::Pipe(
                    PipeRequest::Read(ReadPipeRequest {
                        handle: ObjectHandle(u64::MAX),
                        buffer: descriptor(0, 1),
                    }),
                ))),
                Ok(HostReceive::Message(BrokerOperation::Event(
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
                &test_shared_buffers(),
                |_| Ok(()),
            )
            .unwrap(),
            ConnectionTermination::PeerClosed
        );
        assert_eq!(
            channel.results[0],
            BrokerResult::Error(ErrorCode::UnknownObject)
        );
        assert!(matches!(
            channel.results[1],
            BrokerResult::Event(EventResponse::Create(_))
        ));
        assert_eq!(channel.response_ids, [RequestId(0), RequestId(1)]);
    }

    fn serve_connection_aborts_on_stale_shared_buffer_request(broker: &BrokerCore) {
        let stale_request = BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
            handle: ObjectHandle(u64::MAX),
            buffer: descriptor(0, 1),
        }));
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([
                Ok(HostReceive::Message(stale_request.clone())),
                Ok(HostReceive::Message(stale_request)),
            ]),
        );
        channel.request_id_step = 0;
        let mut notifications = FakeHostNotificationChannel::default();

        assert!(matches!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &test_shared_buffers(),
                |_| Ok(()),
            ),
            Err(BrokerHostError::Broker(ErrorCode::MalformedRequest))
        ));
        assert_eq!(
            channel.results,
            [BrokerResult::Error(ErrorCode::UnknownObject)]
        );
        assert_eq!(channel.response_ids, [RequestId(0)]);
    }

    fn serve_connection_aborts_without_response_on_shared_memory_failure(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerOperation::Pipe(
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
                &SharedBufferPool::new(FailingSharedMemory, SHARED_BUFFER_LAYOUT).unwrap(),
                |_| Ok(()),
            ),
            Err(BrokerHostError::Broker(ErrorCode::Internal))
        ));
        assert_eq!(channel.results.len(), 1);
        assert!(matches!(
            channel.results[0],
            BrokerResult::Pipe(PipeResponse::Create(_))
        ));
    }

    fn serve_connection_rejects_incompatible_shared_buffer_layout(broker: &BrokerCore) {
        let mut channel = FakeHostControlChannel::new(
            std::vec::Vec::from([Ok(HostReceive::Message(BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            }))]),
            std::vec::Vec::new(),
        );
        let mut notifications = FakeHostNotificationChannel::default();
        let incompatible_layout = litebox_broker_protocol::shared_memory::SharedBufferLayout::new(
            u32::try_from(SHARED_BUFFER_POOL_SIZE).unwrap(),
            1,
        )
        .unwrap();
        let shared_buffers = SharedBufferPool::new(
            TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE),
            incompatible_layout,
        )
        .unwrap();
        let setup_called = Cell::new(false);

        assert!(matches!(
            serve_connection(
                broker,
                &mut channel,
                &mut notifications,
                &shared_buffers,
                |_| {
                    setup_called.set(true);
                    Ok(())
                },
            ),
            Err(BrokerHostError::SharedBufferLayoutMismatch)
        ));
        assert!(!setup_called.get());
        assert!(channel.handshake_responses.is_empty());
    }

    fn active_request_closes_object_reference(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let response = handle_test_request(
            &session,
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        );
        let BrokerResult::Event(EventResponse::Create(response)) = response else {
            panic!("unexpected create response: {response:?}");
        };
        let handle = response.handle;

        assert_eq!(
            handle_test_request(&session, BrokerOperation::CloseObject(handle)),
            BrokerResult::ObjectClosed
        );
        assert_eq!(
            handle_test_request(&session, BrokerOperation::CheckReadiness(handle)),
            BrokerResult::Error(ErrorCode::UnknownObject)
        );
        assert_eq!(
            handle_test_request(
                &session,
                BrokerOperation::CloseObject(ObjectHandle(handle.0 + 1))
            ),
            BrokerResult::Error(ErrorCode::UnknownObject)
        );
    }

    fn association_shared_buffer_descriptors_stage_pipe_data(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let memory = TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE);
        let shared_buffers = SharedBufferPool::new(memory.clone(), SHARED_BUFFER_LAYOUT).unwrap();
        shared_buffers
            .write(SharedBufferSlotIndex(1), &[9])
            .unwrap();
        let created = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 64,
                atomic_write_size: 16,
            })),
            &shared_buffers,
        );
        let BrokerResult::Pipe(PipeResponse::Create(response)) = created else {
            panic!("expected successful pipe creation");
        };

        shared_buffers
            .write(SharedBufferSlotIndex(2), &[1, 2, 3])
            .unwrap();
        let write = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Pipe(PipeRequest::Write(WritePipeRequest {
                handle: response.write_handle,
                buffer: descriptor(2, 3),
            })),
            &shared_buffers,
        );
        assert_eq!(
            write,
            BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 }))
        );

        let read = handle_test_request_with_buffers(
            &session,
            BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle: response.read_handle,
                buffer: descriptor(4, 3),
            })),
            &shared_buffers,
        );
        assert_eq!(
            read,
            BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse { read: 3 }))
        );
        let mut data = [0; 3];
        shared_buffers
            .read(SharedBufferSlotIndex(4), &mut data)
            .unwrap();
        assert_eq!(data, [1, 2, 3]);
        let mut second_slot = [0];
        shared_buffers
            .read(SharedBufferSlotIndex(1), &mut second_slot)
            .unwrap();
        assert_eq!(second_slot, [9]);
    }

    fn shared_buffer_usage_rejects_invalid_descriptors() {
        let mut usage = SharedBufferUsage::new();
        usage
            .begin(RequestId(1), descriptor(0, 3), SHARED_BUFFER_LAYOUT)
            .unwrap();
        assert_eq!(
            usage.begin(RequestId(2), descriptor(0, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        usage.end(RequestId(1), SharedBufferSlotIndex(0));
        assert_eq!(
            usage.begin(RequestId(1), descriptor(0, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            usage.begin(RequestId(0), descriptor(0, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        assert!(
            usage
                .begin(RequestId(3), descriptor(0, 3), SHARED_BUFFER_LAYOUT)
                .is_ok()
        );
        assert_eq!(
            usage.begin(RequestId(2), descriptor(16, 3), SHARED_BUFFER_LAYOUT),
            Err(ErrorCode::MalformedRequest)
        );
        assert_eq!(
            usage.begin(
                RequestId(2),
                descriptor(1, SHARED_BUFFER_SLOT_SIZE + 1),
                SHARED_BUFFER_LAYOUT
            ),
            Err(ErrorCode::MalformedRequest)
        );
    }

    const fn descriptor(slot: u32, length: u32) -> SharedBufferDescriptor {
        SharedBufferDescriptor {
            slot_index: SharedBufferSlotIndex(slot),
            length,
        }
    }

    fn handle_test_request(session: &BrokerSession, operation: BrokerOperation) -> BrokerResult {
        handle_test_request_with_buffers(session, operation, &test_shared_buffers())
    }

    fn handle_test_request_with_buffers<Memory: SharedMemory>(
        session: &BrokerSession,
        operation: BrokerOperation,
        shared_buffers: &SharedBufferPool<Memory>,
    ) -> BrokerResult {
        complete_request(handle_request(session, operation, shared_buffers)).unwrap()
    }

    fn test_shared_buffers() -> SharedBufferPool<TestSharedMemory> {
        SharedBufferPool::new(
            TestSharedMemory::new(SHARED_BUFFER_POOL_SIZE),
            SHARED_BUFFER_LAYOUT,
        )
        .unwrap()
    }

    struct FakeHostControlChannel {
        handshake_requests:
            std::vec::Vec<core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>>,
        operations: std::vec::Vec<core::result::Result<HostReceive<BrokerOperation>, ()>>,
        handshake_responses: std::vec::Vec<BrokerHandshakeResponse>,
        results: std::vec::Vec<BrokerResult>,
        response_ids: std::vec::Vec<RequestId>,
        next_request_id: u64,
        request_id_step: u64,
        enqueue_readiness_requests_after_create: bool,
        enqueue_write_request_after_pipe_create: bool,
        send_error: bool,
    }

    impl FakeHostControlChannel {
        fn new(
            handshake_requests: std::vec::Vec<
                core::result::Result<HostReceive<BrokerHandshakeRequest>, ()>,
            >,
            operations: std::vec::Vec<core::result::Result<HostReceive<BrokerOperation>, ()>>,
        ) -> Self {
            Self {
                handshake_requests,
                operations,
                handshake_responses: std::vec::Vec::new(),
                results: std::vec::Vec::new(),
                response_ids: std::vec::Vec::new(),
                next_request_id: 0,
                request_id_step: 1,
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
            let received = if self.operations.is_empty() {
                HostReceive::PeerClosed
            } else {
                self.operations.remove(0)?
            };
            Ok(match received {
                HostReceive::Message(request) => {
                    let request_id = RequestId(self.next_request_id);
                    self.next_request_id += self.request_id_step;
                    HostReceive::Message(BrokerRequest {
                        request_id,
                        operation: request,
                    })
                }
                HostReceive::ProtocolViolation => HostReceive::ProtocolViolation,
                HostReceive::PeerClosed => HostReceive::PeerClosed,
            })
        }

        fn send_response(
            &mut self,
            response: &BrokerResponse,
        ) -> core::result::Result<(), Self::Error> {
            if self.send_error {
                return Err(());
            }
            let result = &response.result;
            if self.enqueue_readiness_requests_after_create
                && let BrokerResult::Event(EventResponse::Create(response)) = result
            {
                self.operations
                    .push(Ok(HostReceive::Message(BrokerOperation::Event(
                        EventRequest::Add(AddEventRequest {
                            handle: response.handle,
                            value: 1,
                        }),
                    ))));
                self.operations
                    .push(Ok(HostReceive::Message(BrokerOperation::Event(
                        EventRequest::Consume(ConsumeEventRequest {
                            handle: response.handle,
                            mode: EventConsumeMode::One,
                        }),
                    ))));
                self.operations.push(Ok(HostReceive::PeerClosed));
            }
            if self.enqueue_write_request_after_pipe_create
                && let BrokerResult::Pipe(PipeResponse::Create(response)) = result
            {
                self.operations
                    .push(Ok(HostReceive::Message(BrokerOperation::Pipe(
                        PipeRequest::Write(WritePipeRequest {
                            handle: response.write_handle,
                            buffer: descriptor(0, 1),
                        }),
                    ))));
                self.operations.push(Ok(HostReceive::PeerClosed));
            }
            self.results.push(result.clone());
            self.response_ids.push(response.request_id);
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
            SHARED_BUFFER_POOL_SIZE
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
