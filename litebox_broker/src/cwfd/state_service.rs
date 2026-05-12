// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-side handlers for the state-object subset of the control protocol.
//!
//! Where [`crate::fd_token_service`] handles host-fd opcodes
//! (Register / Materialize / Release on `BrokerFdTokenRegistry`),
//! this module handles state-object opcodes (Eventfd Create/Read/Write,
//! Subscribe, Unsubscribe, and state-handle Release) against
//! [`crate::state_registry::BrokerStateRegistry`].
//!
//! The control-socket dispatcher in [`crate::fd_token_socket`]
//! routes opcodes here based on the opcode value.
//!
//! # Per-connection state
//!
//! Each control-socket connection carries optional notification-ring
//! state ([`ConnState::notification_sender`]). The worker registers
//! its ring once via `RegisterNotificationRing`; subsequent
//! `SubscribeEventfd` calls use that sender.

use crate::eventfd_state::{EventfdError, EventfdState};
use crate::state_registry::{BrokerStateRegistry, StateHandle, StateRegistryError};
use crate::subscription_list::{SubscribeError, UnsubscribeError};
use litebox_common_linux::fd_token_protocol::{
    Frame, Opcode, OwnedFrame, StatusCode, build_create_eventfd_response_ok, build_error_response,
    build_read_eventfd_response_ok, build_register_notification_ring_response_ok,
    build_release_response_ok, build_subscribe_eventfd_response_ok, build_unsubscribe_response_ok,
    build_write_eventfd_response_ok, parse_create_eventfd_body, parse_handle_body,
    parse_subscribe_eventfd_body, parse_unsubscribe_body, parse_write_eventfd_body,
};
use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_ring::NotificationSender;
use litebox_common_linux::shmem_ring::ShmemRingPair;
use std::os::unix::io::OwnedFd;
use std::sync::{Arc, Mutex};

/// Per-connection mutable state. Currently carries the optional
/// notification-ring sender registered via RegisterNotificationRing.
#[derive(Default)]
pub struct ConnState {
    notification_sender: Option<Arc<Mutex<NotificationSender>>>,
}

impl ConnState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The result of handling one state-object request.
#[derive(Debug)]
pub struct HandlerResult {
    pub frame: OwnedFrame,
    pub out_fd: Option<OwnedFd>,
}

/// Dispatches a state-object request. The caller (the control-socket
/// loop) supplies the registry, the per-connection state, the decoded
/// request frame, and any attached fds.
pub fn handle_request(
    registry: &BrokerStateRegistry,
    conn: &mut ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    match request.opcode {
        Opcode::RegisterNotificationRing => {
            handle_register_notification_ring(conn, request, in_fds)
        }
        Opcode::CreateEventfd => handle_create_eventfd(registry, request, in_fds),
        Opcode::ReadEventfd => handle_read_eventfd(registry, request, in_fds),
        Opcode::WriteEventfd => handle_write_eventfd(registry, request, in_fds),
        Opcode::SubscribeEventfd => handle_subscribe_eventfd(registry, conn, request, in_fds),
        Opcode::Unsubscribe => handle_unsubscribe(registry, request, in_fds),
        Opcode::Release => handle_release_state(registry, request, in_fds),
        Opcode::DupHandle => handle_dup_handle(registry, request, in_fds),
        other => HandlerResult {
            frame: build_error_response(
                other.response_for().unwrap_or(Opcode::ReleaseResponse),
                StatusCode::Protocol,
            ),
            out_fd: None,
        },
    }
}

fn handle_register_notification_ring(
    conn: &mut ConnState,
    _request: &Frame<'_>,
    mut in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if in_fds.len() != 2 {
        return HandlerResult {
            frame: build_error_response(
                Opcode::RegisterNotificationRingResponse,
                StatusCode::Protocol,
            ),
            out_fd: None,
        };
    }
    let tx_fd = in_fds.remove(0);
    let rx_fd = in_fds.remove(0);
    let (writer, _reader_unused) = match ShmemRingPair::open(tx_fd, rx_fd) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(error = ?err, "RegisterNotificationRing: ShmemRingPair::open failed");
            return HandlerResult {
                frame: build_error_response(
                    Opcode::RegisterNotificationRingResponse,
                    StatusCode::Internal,
                ),
                out_fd: None,
            };
        }
    };
    conn.notification_sender = Some(Arc::new(Mutex::new(NotificationSender::new(writer))));
    HandlerResult {
        frame: build_register_notification_ring_response_ok(),
        out_fd: None,
    }
}

fn handle_create_eventfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::CreateEventfdResponse);
    }
    let (initial, semaphore) = match parse_create_eventfd_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::CreateEventfdResponse),
    };
    let state = EventfdState::new(initial, semaphore);
    let handle = registry.register(state);
    HandlerResult {
        frame: build_create_eventfd_response_ok(handle.id()),
        out_fd: None,
    }
}

fn handle_read_eventfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ReadEventfdResponse);
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::ReadEventfdResponse),
    };
    let handle = StateHandle::from_id(handle_id);
    let state = match registry.resolve(handle, SubsystemTag::Eventfd) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::ReadEventfdResponse, StatusCode::UnknownHandle);
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return status_err(Opcode::ReadEventfdResponse, StatusCode::SubsystemMismatch);
        }
        Err(_) => return status_err(Opcode::ReadEventfdResponse, StatusCode::Internal),
    };
    let eventfd = state
        .as_any()
        .downcast_ref::<EventfdState>()
        .expect("subsystem_tag check guarantees EventfdState");
    match eventfd.read() {
        Ok(v) => HandlerResult {
            frame: build_read_eventfd_response_ok(v),
            out_fd: None,
        },
        Err(EventfdError::WouldBlock) => {
            status_err(Opcode::ReadEventfdResponse, StatusCode::WouldBlock)
        }
        Err(EventfdError::InvalidWriteValue(_)) => {
            // Should never happen on read.
            status_err(Opcode::ReadEventfdResponse, StatusCode::Internal)
        }
    }
}

fn handle_write_eventfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::WriteEventfdResponse);
    }
    let (handle_id, value) = match parse_write_eventfd_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::WriteEventfdResponse),
    };
    let handle = StateHandle::from_id(handle_id);
    let state = match registry.resolve(handle, SubsystemTag::Eventfd) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::WriteEventfdResponse, StatusCode::UnknownHandle);
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return status_err(Opcode::WriteEventfdResponse, StatusCode::SubsystemMismatch);
        }
        Err(_) => return status_err(Opcode::WriteEventfdResponse, StatusCode::Internal),
    };
    let eventfd = state
        .as_any()
        .downcast_ref::<EventfdState>()
        .expect("subsystem_tag check guarantees EventfdState");
    match eventfd.write(value) {
        Ok(()) => HandlerResult {
            frame: build_write_eventfd_response_ok(),
            out_fd: None,
        },
        Err(EventfdError::WouldBlock) => {
            status_err(Opcode::WriteEventfdResponse, StatusCode::WouldBlock)
        }
        Err(EventfdError::InvalidWriteValue(_)) => {
            status_err(Opcode::WriteEventfdResponse, StatusCode::InvalidValue)
        }
    }
}

fn handle_subscribe_eventfd(
    registry: &BrokerStateRegistry,
    conn: &ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SubscribeEventfdResponse);
    }
    let (handle_id, subscription_id, events_mask) = match parse_subscribe_eventfd_body(request.body)
    {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::SubscribeEventfdResponse),
    };
    let Some(sender) = conn.notification_sender.as_ref().cloned() else {
        return status_err(
            Opcode::SubscribeEventfdResponse,
            StatusCode::NoNotificationRing,
        );
    };
    let handle = StateHandle::from_id(handle_id);
    // P2.0.5 generalization: dispatch via the StateObject trait so
    // the same SubscribeEventfd opcode services every broker-managed
    // fd kind. We resolve untyped (no SubsystemTag check) because
    // the kind is recorded inside the state object — and Subscribe
    // is genuinely kind-agnostic at the wire level.
    let state = match registry.resolve_untyped(handle) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::SubscribeEventfdResponse, StatusCode::UnknownHandle);
        }
        Err(_) => return status_err(Opcode::SubscribeEventfdResponse, StatusCode::Internal),
    };
    match state.subscribe(subscription_id, events_mask, sender) {
        Ok(()) => HandlerResult {
            frame: build_subscribe_eventfd_response_ok(),
            out_fd: None,
        },
        Err(SubscribeError::DuplicateId(_)) => status_err(
            Opcode::SubscribeEventfdResponse,
            StatusCode::DuplicateSubscription,
        ),
        Err(SubscribeError::UnknownEventBits { .. }) => {
            protocol_err(Opcode::SubscribeEventfdResponse)
        }
    }
}

fn handle_unsubscribe(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::UnsubscribeResponse);
    }
    let (handle_id, subscription_id) = match parse_unsubscribe_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::UnsubscribeResponse),
    };
    let handle = StateHandle::from_id(handle_id);
    // P2.0.5 generalization: kind-agnostic via the StateObject trait.
    let state = match registry.resolve_untyped(handle) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::UnsubscribeResponse, StatusCode::UnknownHandle);
        }
        Err(_) => return status_err(Opcode::UnsubscribeResponse, StatusCode::Internal),
    };
    match state.unsubscribe(subscription_id) {
        Ok(()) => HandlerResult {
            frame: build_unsubscribe_response_ok(),
            out_fd: None,
        },
        Err(UnsubscribeError::UnknownId(_)) => {
            status_err(Opcode::UnsubscribeResponse, StatusCode::UnknownSubscription)
        }
    }
}

fn handle_release_state(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ReleaseResponse);
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::ReleaseResponse),
    };
    match registry.release(StateHandle::from_id(handle_id)) {
        Ok(()) => HandlerResult {
            frame: build_release_response_ok(),
            out_fd: None,
        },
        Err(StateRegistryError::UnknownHandle(_)) => {
            status_err(Opcode::ReleaseResponse, StatusCode::UnknownHandle)
        }
        Err(_) => status_err(Opcode::ReleaseResponse, StatusCode::Internal),
    }
}

fn handle_dup_handle(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::DupHandleResponse);
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::DupHandleResponse),
    };
    match registry.dup(StateHandle::from_id(handle_id)) {
        Ok(_) => HandlerResult {
            frame: litebox_common_linux::fd_token_protocol::build_dup_handle_response_ok(),
            out_fd: None,
        },
        Err(StateRegistryError::UnknownHandle(_)) => {
            status_err(Opcode::DupHandleResponse, StatusCode::UnknownHandle)
        }
        Err(_) => status_err(Opcode::DupHandleResponse, StatusCode::Internal),
    }
}

fn protocol_err(response_opcode: Opcode) -> HandlerResult {
    HandlerResult {
        frame: build_error_response(response_opcode, StatusCode::Protocol),
        out_fd: None,
    }
}

fn status_err(response_opcode: Opcode, status: StatusCode) -> HandlerResult {
    HandlerResult {
        frame: build_error_response(response_opcode, status),
        out_fd: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::fd_token_protocol::{
        build_create_eventfd_request, build_read_eventfd_request, build_subscribe_eventfd_request,
        build_unsubscribe_request, build_write_eventfd_request, decode,
    };
    use litebox_common_linux::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
    use litebox_common_linux::notification_ring::NotificationReceiver;

    fn make_ring_for_conn(conn: &mut ConnState) -> NotificationReceiver {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().unwrap();
        let (broker_writer, _broker_reader_unused) = pair.into_parts();
        let (_worker_writer_unused, worker_reader) = ShmemRingPair::open(tx_fd, rx_fd).unwrap();
        conn.notification_sender =
            Some(Arc::new(Mutex::new(NotificationSender::new(broker_writer))));
        NotificationReceiver::new(worker_reader)
    }

    fn run(
        registry: &BrokerStateRegistry,
        conn: &mut ConnState,
        request: &OwnedFrame,
    ) -> HandlerResult {
        let bytes = request.encode().unwrap();
        let frame = decode(&bytes).unwrap();
        handle_request(registry, conn, &frame, Vec::new())
    }

    #[test]
    fn create_eventfd_returns_handle() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let result = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        assert_eq!(result.frame.opcode, Opcode::CreateEventfdResponse);
        assert_eq!(result.frame.status, StatusCode::Ok);
        assert_eq!(registry.live_handle_count(), 1);
    }

    #[test]
    fn read_write_eventfd_round_trip() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let create = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        let handle_id = u64::from_le_bytes(create.frame.body[..8].try_into().unwrap());

        let write = run(
            &registry,
            &mut conn,
            &build_write_eventfd_request(handle_id, 7),
        );
        assert_eq!(write.frame.status, StatusCode::Ok);

        let read = run(&registry, &mut conn, &build_read_eventfd_request(handle_id));
        assert_eq!(read.frame.status, StatusCode::Ok);
        let value = u64::from_le_bytes(read.frame.body[..8].try_into().unwrap());
        assert_eq!(value, 7);
    }

    #[test]
    fn read_empty_returns_wouldblock() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let create = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        let handle_id = u64::from_le_bytes(create.frame.body[..8].try_into().unwrap());

        let read = run(&registry, &mut conn, &build_read_eventfd_request(handle_id));
        assert_eq!(read.frame.status, StatusCode::WouldBlock);
    }

    #[test]
    fn write_max_returns_invalid_value() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let create = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        let handle_id = u64::from_le_bytes(create.frame.body[..8].try_into().unwrap());

        let write = run(
            &registry,
            &mut conn,
            &build_write_eventfd_request(handle_id, u64::MAX),
        );
        assert_eq!(write.frame.status, StatusCode::InvalidValue);
    }

    #[test]
    fn unknown_handle_returns_unknown() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let read = run(&registry, &mut conn, &build_read_eventfd_request(9999));
        assert_eq!(read.frame.status, StatusCode::UnknownHandle);
    }

    #[test]
    fn subscribe_without_notification_ring_errors() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let create = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        let handle_id = u64::from_le_bytes(create.frame.body[..8].try_into().unwrap());

        let sub = run(
            &registry,
            &mut conn,
            &build_subscribe_eventfd_request(handle_id, 1, NOTIFY_EVENT_IN),
        );
        assert_eq!(sub.frame.status, StatusCode::NoNotificationRing);
    }

    #[test]
    fn subscribe_then_write_delivers_notification() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let mut receiver = make_ring_for_conn(&mut conn);

        let create = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        let handle_id = u64::from_le_bytes(create.frame.body[..8].try_into().unwrap());

        // Subscribe to IN+OUT. Priming will deliver OUT (counter=0).
        let sub = run(
            &registry,
            &mut conn,
            &build_subscribe_eventfd_request(handle_id, 42, NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT),
        );
        assert_eq!(sub.frame.status, StatusCode::Ok);

        let priming = receiver.recv().unwrap();
        assert_eq!(priming.subscription_id(), 42);
        assert_eq!(priming.events(), NOTIFY_EVENT_OUT);

        // Write 1 → counter=1; IN+OUT ready.
        let write = run(
            &registry,
            &mut conn,
            &build_write_eventfd_request(handle_id, 1),
        );
        assert_eq!(write.frame.status, StatusCode::Ok);
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 42);
        assert_eq!(frame.events(), NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);

        // Read drains → counter=0; only OUT ready.
        let read = run(&registry, &mut conn, &build_read_eventfd_request(handle_id));
        assert_eq!(read.frame.status, StatusCode::Ok);
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.events(), NOTIFY_EVENT_OUT);
    }

    #[test]
    fn unsubscribe_stops_notifications() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let mut _receiver = make_ring_for_conn(&mut conn);

        let create = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        let handle_id = u64::from_le_bytes(create.frame.body[..8].try_into().unwrap());

        let sub = run(
            &registry,
            &mut conn,
            &build_subscribe_eventfd_request(handle_id, 1, NOTIFY_EVENT_IN),
        );
        assert_eq!(sub.frame.status, StatusCode::Ok);

        let unsub = run(
            &registry,
            &mut conn,
            &build_unsubscribe_request(handle_id, 1),
        );
        assert_eq!(unsub.frame.status, StatusCode::Ok);

        let unsub2 = run(
            &registry,
            &mut conn,
            &build_unsubscribe_request(handle_id, 1),
        );
        assert_eq!(unsub2.frame.status, StatusCode::UnknownSubscription);
    }

    #[test]
    fn release_state_handle_drops_from_registry() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let create = run(
            &registry,
            &mut conn,
            &build_create_eventfd_request(0, false),
        );
        let handle_id = u64::from_le_bytes(create.frame.body[..8].try_into().unwrap());
        assert_eq!(registry.live_handle_count(), 1);

        let release = run(
            &registry,
            &mut conn,
            &litebox_common_linux::fd_token_protocol::build_release_request(handle_id),
        );
        assert_eq!(release.frame.status, StatusCode::Ok);
        assert_eq!(registry.live_handle_count(), 0);
    }
}
