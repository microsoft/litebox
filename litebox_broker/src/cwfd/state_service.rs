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

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use crate::cwfd::pidfd_state::{PidfdError, PidfdState};
use crate::eventfd_state::{EventfdError, EventfdState};
use crate::pgrp_signal_inbox::{
    PgrpSignalInbox, SubscribeError as PgrpSubscribeError, UnsubscribeError as PgrpUnsubscribeError,
};
use crate::pipe_state::{PipeError, PipeReadEnd, PipeWriteEnd};
use crate::process_state::ProcessState;
use crate::pty_state::{PtyError, PtyState};
use crate::signalfd_state::SignalfdState;
use crate::socketpair_state::{SocketPairEnd, SocketPairError};
use crate::state_registry::{
    BrokerStateRegistry, StateHandle, StateObjectEnum, StateRegistryError,
};
use crate::subscription_list::{SubscribeError, UnsubscribeError};
use crate::tcp_conn_state::{TcpConnError, TcpConnState};
use litebox_common_linux::fd_token_protocol::PtyEndpoint;
use litebox_common_linux::fd_token_protocol::{
    Frame, Opcode, OwnedFrame, StatusCode, build_create_eventfd_response_ok,
    build_create_pidfd_response_ok, build_create_pipe_response_ok, build_create_pty_response_ok,
    build_create_signalfd_response_ok, build_create_socketpair_response_ok,
    build_deliver_signal_inbox_response_ok, build_error_response,
    build_mark_process_exited_response_ok, build_open_pty_slave_response_ok,
    build_pidfd_exited_response_ok, build_poll_tcp_conn_events_response_ok,
    build_pty_ioctl_response_ok, build_pty_read_response_ok, build_pty_write_response_ok,
    build_push_siginfo_response_ok, build_read_eventfd_response_ok, build_read_pipe_response_ok,
    build_read_siginfo_response_ok, build_read_socketpair_response_ok,
    build_read_tcp_conn_response_ok, build_register_notification_ring_response_ok,
    build_register_process_response_ok, build_release_response_ok, build_set_pgid_response_ok,
    build_set_sid_response_ok, build_shutdown_socketpair_write_response_ok,
    build_shutdown_tcp_conn_response_ok, build_subscribe_eventfd_response_ok,
    build_subscribe_process_exit_response_ok, build_subscribe_pty_response_ok,
    build_subscribe_signal_inbox_response_ok, build_unsubscribe_response_ok,
    build_unsubscribe_signal_inbox_response_ok, build_write_eventfd_response_ok,
    build_write_pipe_response_ok, build_write_socketpair_response_ok,
    build_write_tcp_conn_response_ok, parse_create_eventfd_body, parse_create_pidfd_body,
    parse_create_pipe_body, parse_create_signalfd_body, parse_create_socketpair_body,
    parse_deliver_signal_inbox_body, parse_handle_body, parse_mark_process_exited_body,
    parse_open_pty_slave_body, parse_pidfd_exited_request, parse_poll_tcp_conn_events_body,
    parse_pty_ioctl_body, parse_pty_read_body, parse_pty_write_body, parse_push_siginfo_body,
    parse_read_pipe_body, parse_read_socketpair_body, parse_read_tcp_conn_body,
    parse_set_pgid_body, parse_set_sid_body, parse_shutdown_socketpair_write_body,
    parse_shutdown_tcp_conn_body, parse_subscribe_eventfd_body, parse_subscribe_process_exit_body,
    parse_subscribe_pty_body, parse_subscribe_signal_inbox_body, parse_unsubscribe_body,
    parse_unsubscribe_signal_inbox_body, parse_write_eventfd_body, parse_write_pipe_body,
    parse_write_socketpair_body, parse_write_tcp_conn_body,
};
use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_ring::NotificationSender;
use litebox_common_linux::shmem_ring::ShmemRingPair;
use std::os::unix::io::OwnedFd;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionRegistry {
    State,
    Process,
}

/// Per-connection mutable state. Currently carries the optional
/// notification-ring sender registered via RegisterNotificationRing.
///
/// The [`Default`] implementation is intended for synthetic/test-only
/// connections; in that case `conn_id == 0` means "no real connection".
#[derive(Default)]
pub struct ConnState {
    /// Monotone per-process counter assigned at connection accept time.
    /// Globally unique within this broker process; 1:1 with
    /// FdTokenClient::connect. Used as the second half of `(pgid, conn_id)`
    /// composite keys for pgrp-signal subscription tracking — see
    /// files/pty-signal-delivery-rpc-design.md §2.
    pub conn_id: u64,
    notification_sender: Option<Arc<Mutex<NotificationSender>>>,
    /// PE.9 fix: per-conn subscription bookkeeping. Each entry records
    /// a (registry, handle_id, subscription_id) tuple this conn issued
    /// via any of the Subscribe* opcodes. On disconnect, the socket
    /// loop drains this list and force-unsubscribes each one so
    /// subscriptions don't outlive the conn that owns them (eager
    /// cleanup, in addition to the SubscriptionList::notify reactive
    /// auto-removal on send failure). Belt and braces.
    tracked_subscriptions: Vec<(SubscriptionRegistry, u64, u64)>,
}

impl ConnState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_conn_id(conn_id: u64) -> Self {
        Self {
            conn_id,
            ..Self::default()
        }
    }

    pub fn notification_sender(&self) -> Option<Arc<Mutex<NotificationSender>>> {
        self.notification_sender.as_ref().cloned()
    }

    /// Record a Subscribe* success. Called from each subscribe
    /// handler immediately after the underlying SubscriptionList
    /// has accepted the subscription.
    pub fn record_subscription(
        &mut self,
        registry: SubscriptionRegistry,
        handle_id: u64,
        subscription_id: u64,
    ) {
        self.tracked_subscriptions
            .push((registry, handle_id, subscription_id));
    }

    /// Forget a tracked subscription. Called from handle_unsubscribe
    /// on success so we don't try to double-unsubscribe at disconnect.
    pub fn forget_subscription(
        &mut self,
        registry: SubscriptionRegistry,
        handle_id: u64,
        subscription_id: u64,
    ) -> bool {
        if let Some(idx) = self
            .tracked_subscriptions
            .iter()
            .position(|&(r, h, s)| r == registry && h == handle_id && s == subscription_id)
        {
            self.tracked_subscriptions.swap_remove(idx);
            true
        } else {
            false
        }
    }

    /// Drain all tracked subscriptions. Called from the socket loop's
    /// cleanup_on_disconnect path.
    pub fn drain_tracked_subscriptions(&mut self) -> Vec<(SubscriptionRegistry, u64, u64)> {
        std::mem::take(&mut self.tracked_subscriptions)
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
        Opcode::CreatePidfd => handle_create_pidfd(registry, request, in_fds),
        Opcode::PidfdExited => handle_pidfd_exited(registry, request, in_fds),
        Opcode::ReadEventfd => handle_read_eventfd(registry, request, in_fds),
        Opcode::WriteEventfd => handle_write_eventfd(registry, request, in_fds),
        Opcode::CreateSignalfd => handle_create_signalfd(registry, request, in_fds),
        Opcode::CreatePipe => handle_create_pipe(registry, request, in_fds),
        Opcode::ReadPipe => handle_read_pipe(registry, request, in_fds),
        Opcode::WritePipe => handle_write_pipe(registry, request, in_fds),
        Opcode::CreateSocketPair => handle_create_socketpair(registry, request, in_fds),
        Opcode::ReadSocketPair => handle_read_socketpair(registry, request, in_fds),
        Opcode::WriteSocketPair => handle_write_socketpair(registry, request, in_fds),
        Opcode::ShutdownSocketPairWrite => {
            handle_shutdown_socketpair_write(registry, request, in_fds)
        }
        Opcode::ReadTcpConn => handle_read_tcp_conn(registry, request, in_fds),
        Opcode::WriteTcpConn => handle_write_tcp_conn(registry, request, in_fds),
        Opcode::ShutdownTcpConn => handle_shutdown_tcp_conn(registry, request, in_fds),
        Opcode::PollTcpConnEvents => handle_poll_tcp_conn_events(registry, request, in_fds),
        Opcode::ReadSiginfo => handle_read_siginfo(registry, request, in_fds),
        Opcode::PushSiginfo => handle_push_siginfo(registry, request, in_fds),
        Opcode::CreatePty => handle_create_pty(registry, request, in_fds),
        Opcode::OpenPtySlave => handle_open_pty_slave(registry, request, in_fds),
        Opcode::PtyRead => handle_pty_read(registry, request, in_fds),
        Opcode::PtyWrite => handle_pty_write(registry, None, request, in_fds),
        Opcode::SubscribePty => handle_subscribe_pty(registry, conn, request, in_fds),
        Opcode::PtyIoctl => handle_pty_ioctl(registry, None, request, in_fds),
        Opcode::SubscribeEventfd => handle_subscribe_eventfd(registry, conn, request, in_fds),
        Opcode::Unsubscribe => handle_unsubscribe(registry, conn, request, in_fds),
        Opcode::Release => handle_release_state(registry, request, in_fds),
        Opcode::DupHandle => handle_dup_handle(registry, request, in_fds),
        Opcode::RegisterProcess => handle_register_process(registry, request, in_fds),
        Opcode::SubscribeProcessExit => {
            handle_subscribe_process_exit(registry, conn, request, in_fds)
        }
        Opcode::MarkProcessExited => handle_mark_process_exited(registry, request, in_fds),
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

pub fn handle_set_pgid(
    process_registry: &BrokerStateRegistry,
    inbox: &PgrpSignalInbox,
    conn: &ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SetPgidResponse);
    }
    let (caller_pid, target_pid, new_pgid) = match parse_set_pgid_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SetPgidResponse),
    };
    for pid in [caller_pid, target_pid] {
        match process_registry.resolve(StateHandle::from_id(u64::from(pid)), SubsystemTag::Process)
        {
            Ok(_) => {}
            Err(StateRegistryError::UnknownHandle(_)) => {
                return status_err(Opcode::SetPgidResponse, StatusCode::UnknownHandle);
            }
            Err(StateRegistryError::TagMismatch { .. }) => {
                return status_err(Opcode::SetPgidResponse, StatusCode::SubsystemMismatch);
            }
            Err(_) => return status_err(Opcode::SetPgidResponse, StatusCode::Internal),
        }
    }
    // Contract: the broker does not know which worker currently hosts target_pid;
    // SetPgid eagerly stamps the calling connection, and each worker must refresh
    // its PgrpSignalInbox subscription when its local ProcessRegistry pgid changes.
    inbox.stamp_pgid(conn.conn_id, new_pgid);
    HandlerResult {
        frame: build_set_pgid_response_ok(),
        out_fd: None,
    }
}

pub fn handle_set_sid(
    process_registry: &BrokerStateRegistry,
    inbox: &PgrpSignalInbox,
    conn: &ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SetSidResponse);
    }
    let caller_pid = match parse_set_sid_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SetSidResponse),
    };
    match process_registry.resolve(
        StateHandle::from_id(u64::from(caller_pid)),
        SubsystemTag::Process,
    ) {
        Ok(_) => {}
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::SetSidResponse, StatusCode::UnknownHandle);
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return status_err(Opcode::SetSidResponse, StatusCode::SubsystemMismatch);
        }
        Err(_) => return status_err(Opcode::SetSidResponse, StatusCode::Internal),
    }
    inbox.stamp_pgid(conn.conn_id, caller_pid);
    HandlerResult {
        frame: build_set_sid_response_ok(caller_pid),
        out_fd: None,
    }
}

pub fn handle_subscribe_signal_inbox(
    inbox: &PgrpSignalInbox,
    conn: &mut ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SubscribeSignalInboxResponse);
    }
    let (pgid, signal_mask, subscription_id, events_mask) =
        match parse_subscribe_signal_inbox_body(request.body) {
            Ok(v) => v,
            Err(_) => return protocol_err(Opcode::SubscribeSignalInboxResponse),
        };
    let Some(sender) = conn.notification_sender() else {
        return status_err(
            Opcode::SubscribeSignalInboxResponse,
            StatusCode::NoNotificationRing,
        );
    };
    match inbox.subscribe(
        pgid,
        conn.conn_id,
        subscription_id,
        signal_mask,
        events_mask,
        sender,
    ) {
        Ok(()) => HandlerResult {
            frame: build_subscribe_signal_inbox_response_ok(),
            out_fd: None,
        },
        Err(PgrpSubscribeError::DuplicateConnection { .. }) => status_err(
            Opcode::SubscribeSignalInboxResponse,
            StatusCode::DuplicateSubscription,
        ),
        Err(PgrpSubscribeError::UnknownEventBits { .. }) => {
            protocol_err(Opcode::SubscribeSignalInboxResponse)
        }
    }
}

pub fn handle_deliver_signal_inbox(
    inbox: &PgrpSignalInbox,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::DeliverSignalInboxResponse);
    }
    let (pgid, signum) = match parse_deliver_signal_inbox_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::DeliverSignalInboxResponse),
    };
    let siginfo = vec![0u8; core::mem::size_of::<litebox_common_linux::signal::Siginfo>()];
    inbox.deliver(pgid, signum, &siginfo);
    HandlerResult {
        frame: build_deliver_signal_inbox_response_ok(),
        out_fd: None,
    }
}

pub fn handle_unsubscribe_signal_inbox(
    inbox: &PgrpSignalInbox,
    conn: &mut ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::UnsubscribeSignalInboxResponse);
    }
    let (pgid, _subscription_id) = match parse_unsubscribe_signal_inbox_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::UnsubscribeSignalInboxResponse),
    };
    match inbox.unsubscribe(pgid, conn.conn_id) {
        Ok(()) => HandlerResult {
            frame: build_unsubscribe_signal_inbox_response_ok(),
            out_fd: None,
        },
        Err(PgrpUnsubscribeError::UnknownConnection { .. }) => status_err(
            Opcode::UnsubscribeSignalInboxResponse,
            StatusCode::UnknownSubscription,
        ),
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

fn handle_create_pidfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::CreatePidfdResponse);
    }
    let target_host_pid = match parse_create_pidfd_body(request.body) {
        Ok(pid) => pid,
        Err(_) => return protocol_err(Opcode::CreatePidfdResponse),
    };
    let state = match PidfdState::new(target_host_pid) {
        Ok(state) => state,
        Err(PidfdError::Open { .. }) => {
            return status_err(Opcode::CreatePidfdResponse, StatusCode::Internal);
        }
    };
    let handle = registry.register(state);
    HandlerResult {
        frame: build_create_pidfd_response_ok(handle.id()),
        out_fd: None,
    }
}

fn handle_pidfd_exited(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::PidfdExitedResponse);
    }
    let handle_id = match parse_pidfd_exited_request(request.body) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::PidfdExitedResponse),
    };
    let handle = StateHandle::from_id(handle_id);
    let state = match registry.resolve_untyped(handle) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::PidfdExitedResponse, StatusCode::UnknownHandle);
        }
        Err(_) => return status_err(Opcode::PidfdExitedResponse, StatusCode::Internal),
    };
    let StateObjectEnum::Pidfd(pidfd) = state.as_ref() else {
        return status_err(Opcode::PidfdExitedResponse, StatusCode::SubsystemMismatch);
    };
    HandlerResult {
        frame: build_pidfd_exited_response_ok(pidfd.exited()),
        out_fd: None,
    }
}

fn handle_register_process(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::RegisterProcessResponse);
    }
    if !request.body.is_empty() {
        return protocol_err(Opcode::RegisterProcessResponse);
    }
    // ProcessState payload is empty in Phase 1; the StateHandle id IS
    // the globally-unique guest pid. The registry's monotonic
    // allocator yields sequential u64 ids; this registry instance is
    // dedicated to processes, so the low 32 bits of the handle are a
    // valid Linux pid.
    let handle = registry.register(ProcessState::arc());
    HandlerResult {
        frame: build_register_process_response_ok(handle.id()),
        out_fd: None,
    }
}

fn handle_subscribe_process_exit(
    registry: &BrokerStateRegistry,
    conn: &mut ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SubscribeProcessExitResponse);
    }
    let (pid, subscription_id, events_mask) = match parse_subscribe_process_exit_body(request.body)
    {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::SubscribeProcessExitResponse),
    };
    let Some(sender) = conn.notification_sender.as_ref().cloned() else {
        return status_err(
            Opcode::SubscribeProcessExitResponse,
            StatusCode::NoNotificationRing,
        );
    };
    let state = match registry.resolve(StateHandle::from_id(pid), SubsystemTag::Process) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(
                Opcode::SubscribeProcessExitResponse,
                StatusCode::UnknownHandle,
            );
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return status_err(
                Opcode::SubscribeProcessExitResponse,
                StatusCode::SubsystemMismatch,
            );
        }
        Err(_) => return status_err(Opcode::SubscribeProcessExitResponse, StatusCode::Internal),
    };
    let StateObjectEnum::Process(process) = state.as_ref() else {
        return status_err(
            Opcode::SubscribeProcessExitResponse,
            StatusCode::SubsystemMismatch,
        );
    };
    let handle = StateHandle::from_id(pid);
    if registry.dup(handle).is_err() {
        return status_err(
            Opcode::SubscribeProcessExitResponse,
            StatusCode::UnknownHandle,
        );
    }
    match process.subscribe(subscription_id, events_mask, sender) {
        Ok(snapshot) => {
            conn.record_subscription(SubscriptionRegistry::Process, pid, subscription_id);
            HandlerResult {
                frame: build_subscribe_process_exit_response_ok(snapshot.map(|s| s.exit_code)),
                out_fd: None,
            }
        }
        Err(SubscribeError::DuplicateId(_)) => {
            let _ = registry.release(handle);
            status_err(
                Opcode::SubscribeProcessExitResponse,
                StatusCode::DuplicateSubscription,
            )
        }
        Err(SubscribeError::UnknownEventBits { .. }) => {
            let _ = registry.release(handle);
            protocol_err(Opcode::SubscribeProcessExitResponse)
        }
    }
}

fn handle_mark_process_exited(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::MarkProcessExitedResponse);
    }
    let (pid, exit_code) = match parse_mark_process_exited_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::MarkProcessExitedResponse),
    };
    let state = match registry.resolve(StateHandle::from_id(pid), SubsystemTag::Process) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::MarkProcessExitedResponse, StatusCode::UnknownHandle);
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return status_err(
                Opcode::MarkProcessExitedResponse,
                StatusCode::SubsystemMismatch,
            );
        }
        Err(_) => return status_err(Opcode::MarkProcessExitedResponse, StatusCode::Internal),
    };
    let StateObjectEnum::Process(process) = state.as_ref() else {
        return status_err(
            Opcode::MarkProcessExitedResponse,
            StatusCode::SubsystemMismatch,
        );
    };
    process.mark_exited(exit_code);
    HandlerResult {
        frame: build_mark_process_exited_response_ok(),
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
    let StateObjectEnum::Eventfd(eventfd) = state.as_ref() else {
        return status_err(Opcode::ReadEventfdResponse, StatusCode::SubsystemMismatch);
    };
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
    let StateObjectEnum::Eventfd(eventfd) = state.as_ref() else {
        return status_err(Opcode::WriteEventfdResponse, StatusCode::SubsystemMismatch);
    };
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

fn handle_create_pipe(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::CreatePipeResponse);
    }
    let (capacity, atomic) = match parse_create_pipe_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::CreatePipeResponse),
    };
    let Ok(capacity) = usize::try_from(capacity) else {
        return protocol_err(Opcode::CreatePipeResponse);
    };
    let Ok(atomic) = usize::try_from(atomic) else {
        return protocol_err(Opcode::CreatePipeResponse);
    };
    let (read_end, write_end) = crate::pipe_state::new_pipe(capacity, atomic);
    let read_handle = registry.register(read_end.clone());
    let write_handle = registry.register(write_end);
    // PE.14: stamp the read end with its handle id so PipeReadEnd::Drop
    // can include it in the DATA LOSS invariant log.
    read_end
        .handle_id
        .store(read_handle.id(), std::sync::atomic::Ordering::Relaxed);
    HandlerResult {
        frame: build_create_pipe_response_ok(read_handle.id(), write_handle.id()),
        out_fd: None,
    }
}

fn resolve_pipe_read(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<Arc<PipeReadEnd>, StatusCode> {
    match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::Pipe) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::PipeReadEnd(read_end) => Ok(Arc::clone(read_end)),
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_) => Err(StatusCode::SubsystemMismatch),
        },
        Err(StateRegistryError::UnknownHandle(_)) => Err(StatusCode::UnknownHandle),
        Err(StateRegistryError::TagMismatch { .. }) => Err(StatusCode::SubsystemMismatch),
        Err(_) => Err(StatusCode::Internal),
    }
}

fn resolve_pipe_write(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<Arc<PipeWriteEnd>, StatusCode> {
    match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::Pipe) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::PipeWriteEnd(write_end) => Ok(Arc::clone(write_end)),
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_) => Err(StatusCode::SubsystemMismatch),
        },
        Err(StateRegistryError::UnknownHandle(_)) => Err(StatusCode::UnknownHandle),
        Err(StateRegistryError::TagMismatch { .. }) => Err(StatusCode::SubsystemMismatch),
        Err(_) => Err(StatusCode::Internal),
    }
}

fn handle_read_pipe(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ReadPipeResponse);
    }
    let (handle_id, max_len) = match parse_read_pipe_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::ReadPipeResponse),
    };
    let Ok(max_len) = usize::try_from(max_len) else {
        return protocol_err(Opcode::ReadPipeResponse);
    };
    let state = match resolve_pipe_read(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::ReadPipeResponse, status),
    };
    match state.read(max_len) {
        Ok(bytes) => HandlerResult {
            frame: build_read_pipe_response_ok(&bytes),
            out_fd: None,
        },
        Err(PipeError::WouldBlock) => status_err(Opcode::ReadPipeResponse, StatusCode::WouldBlock),
        Err(_) => status_err(Opcode::ReadPipeResponse, StatusCode::InvalidValue),
    }
}

fn handle_write_pipe(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::WritePipeResponse);
    }
    let (handle_id, bytes) = match parse_write_pipe_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::WritePipeResponse),
    };
    let state = match resolve_pipe_write(registry, handle_id) {
        Ok(s) => s,
        Err(status) => {
            return status_err(Opcode::WritePipeResponse, status);
        }
    };
    match state.write(&bytes) {
        Ok(n) => HandlerResult {
            frame: build_write_pipe_response_ok(n as u64),
            out_fd: None,
        },
        Err(PipeError::WouldBlock) => status_err(Opcode::WritePipeResponse, StatusCode::WouldBlock),
        Err(PipeError::PeerClosed) => {
            status_err(Opcode::WritePipeResponse, StatusCode::InvalidValue)
        }
        Err(_) => status_err(Opcode::WritePipeResponse, StatusCode::Internal),
    }
}

fn handle_create_socketpair(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::CreateSocketPairResponse);
    }
    let (capacity, atomic) = match parse_create_socketpair_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::CreateSocketPairResponse),
    };
    let Ok(capacity) = usize::try_from(capacity) else {
        return protocol_err(Opcode::CreateSocketPairResponse);
    };
    let Ok(atomic) = usize::try_from(atomic) else {
        return protocol_err(Opcode::CreateSocketPairResponse);
    };
    let (end_a, end_b) = crate::socketpair_state::new_socketpair(capacity, atomic);
    let handle_a = registry.register(end_a.clone());
    let handle_b = registry.register(end_b.clone());
    // PE.14: stamp each endpoint with its handle id (mirrors pipe pattern).
    end_a
        .handle_id
        .store(handle_a.id(), std::sync::atomic::Ordering::Relaxed);
    end_b
        .handle_id
        .store(handle_b.id(), std::sync::atomic::Ordering::Relaxed);
    HandlerResult {
        frame: build_create_socketpair_response_ok(handle_a.id(), handle_b.id()),
        out_fd: None,
    }
}

fn resolve_socketpair_end(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<Arc<SocketPairEnd>, StatusCode> {
    match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::UnixSocket) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::SocketPairEnd(end) => Ok(Arc::clone(end)),
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::Process(_) => Err(StatusCode::SubsystemMismatch),
        },
        Err(StateRegistryError::UnknownHandle(_)) => Err(StatusCode::UnknownHandle),
        Err(StateRegistryError::TagMismatch { .. }) => Err(StatusCode::SubsystemMismatch),
        Err(_) => Err(StatusCode::Internal),
    }
}

fn handle_read_socketpair(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ReadSocketPairResponse);
    }
    let (handle_id, max_len) = match parse_read_socketpair_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::ReadSocketPairResponse),
    };
    let Ok(max_len) = usize::try_from(max_len) else {
        return protocol_err(Opcode::ReadSocketPairResponse);
    };
    let state = match resolve_socketpair_end(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::ReadSocketPairResponse, status),
    };
    match state.read(max_len) {
        Ok(bytes) => HandlerResult {
            frame: build_read_socketpair_response_ok(&bytes),
            out_fd: None,
        },
        Err(SocketPairError::WouldBlock) => {
            status_err(Opcode::ReadSocketPairResponse, StatusCode::WouldBlock)
        }
        Err(_) => status_err(Opcode::ReadSocketPairResponse, StatusCode::InvalidValue),
    }
}

fn handle_write_socketpair(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::WriteSocketPairResponse);
    }
    let (handle_id, bytes) = match parse_write_socketpair_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::WriteSocketPairResponse),
    };
    let state = match resolve_socketpair_end(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::WriteSocketPairResponse, status),
    };
    match state.write(&bytes) {
        Ok(n) => HandlerResult {
            frame: build_write_socketpair_response_ok(n as u64),
            out_fd: None,
        },
        Err(SocketPairError::WouldBlock) => {
            status_err(Opcode::WriteSocketPairResponse, StatusCode::WouldBlock)
        }
        Err(SocketPairError::PeerClosed) => {
            status_err(Opcode::WriteSocketPairResponse, StatusCode::InvalidValue)
        }
    }
}

fn handle_shutdown_socketpair_write(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ShutdownSocketPairWriteResponse);
    }
    let handle_id = match parse_shutdown_socketpair_write_body(request.body) {
        Ok(handle_id) => handle_id,
        Err(_) => return protocol_err(Opcode::ShutdownSocketPairWriteResponse),
    };
    let state = match resolve_socketpair_end(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::ShutdownSocketPairWriteResponse, status),
    };
    state.shutdown_write();
    HandlerResult {
        frame: build_shutdown_socketpair_write_response_ok(),
        out_fd: None,
    }
}

fn resolve_tcp_conn(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<Arc<TcpConnState>, StatusCode> {
    match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::TcpSocket) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::TcpConn(conn) => Ok(Arc::clone(conn)),
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_) => Err(StatusCode::SubsystemMismatch),
        },
        Err(StateRegistryError::UnknownHandle(_)) => Err(StatusCode::UnknownHandle),
        Err(StateRegistryError::TagMismatch { .. }) => Err(StatusCode::SubsystemMismatch),
        Err(_) => Err(StatusCode::Internal),
    }
}

fn handle_read_tcp_conn(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ReadTcpConnResponse);
    }
    let (handle_id, max_len) = match parse_read_tcp_conn_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::ReadTcpConnResponse),
    };
    let Ok(max_len) = usize::try_from(max_len) else {
        return protocol_err(Opcode::ReadTcpConnResponse);
    };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::ReadTcpConnResponse, status),
    };
    match state.read(max_len) {
        Ok(bytes) => HandlerResult {
            frame: build_read_tcp_conn_response_ok(&bytes),
            out_fd: None,
        },
        Err(TcpConnError::WouldBlock) => {
            status_err(Opcode::ReadTcpConnResponse, StatusCode::WouldBlock)
        }
        Err(TcpConnError::PeerClosed) => {
            status_err(Opcode::ReadTcpConnResponse, StatusCode::InvalidValue)
        }
        Err(TcpConnError::Io) => status_err(Opcode::ReadTcpConnResponse, StatusCode::Internal),
    }
}

fn handle_write_tcp_conn(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::WriteTcpConnResponse);
    }
    let (handle_id, bytes) = match parse_write_tcp_conn_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::WriteTcpConnResponse),
    };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::WriteTcpConnResponse, status),
    };
    match state.write(&bytes) {
        Ok(n) => HandlerResult {
            frame: build_write_tcp_conn_response_ok(n as u64),
            out_fd: None,
        },
        Err(TcpConnError::WouldBlock) => {
            status_err(Opcode::WriteTcpConnResponse, StatusCode::WouldBlock)
        }
        Err(TcpConnError::PeerClosed) => {
            status_err(Opcode::WriteTcpConnResponse, StatusCode::InvalidValue)
        }
        Err(TcpConnError::Io) => status_err(Opcode::WriteTcpConnResponse, StatusCode::Internal),
    }
}

fn handle_shutdown_tcp_conn(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ShutdownTcpConnResponse);
    }
    let (handle_id, read, write) = match parse_shutdown_tcp_conn_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::ShutdownTcpConnResponse),
    };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::ShutdownTcpConnResponse, status),
    };
    match state.shutdown(read, write) {
        Ok(()) => HandlerResult {
            frame: build_shutdown_tcp_conn_response_ok(),
            out_fd: None,
        },
        Err(_) => status_err(Opcode::ShutdownTcpConnResponse, StatusCode::Internal),
    }
}

fn handle_poll_tcp_conn_events(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::PollTcpConnEventsResponse);
    }
    let handle_id = match parse_poll_tcp_conn_events_body(request.body) {
        Ok(handle_id) => handle_id,
        Err(_) => return protocol_err(Opcode::PollTcpConnEventsResponse),
    };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::PollTcpConnEventsResponse, status),
    };
    HandlerResult {
        frame: build_poll_tcp_conn_events_response_ok(state.current_events()),
        out_fd: None,
    }
}

fn handle_create_signalfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::CreateSignalfdResponse);
    }
    let (lo, hi) = match parse_create_signalfd_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::CreateSignalfdResponse),
    };
    let state = match SignalfdState::new(lo, hi) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(error = %err, "CreateSignalfd failed");
            return status_err(Opcode::CreateSignalfdResponse, StatusCode::Internal);
        }
    };
    let handle = registry.register(state);
    HandlerResult {
        frame: build_create_signalfd_response_ok(handle.id()),
        out_fd: None,
    }
}

fn handle_read_siginfo(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ReadSiginfoResponse);
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::ReadSiginfoResponse),
    };
    let state = match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::Signalfd) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::ReadSiginfoResponse, StatusCode::UnknownHandle);
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return status_err(Opcode::ReadSiginfoResponse, StatusCode::SubsystemMismatch);
        }
        Err(_) => return status_err(Opcode::ReadSiginfoResponse, StatusCode::Internal),
    };
    let StateObjectEnum::Signalfd(signalfd) = state.as_ref() else {
        return status_err(Opcode::ReadSiginfoResponse, StatusCode::SubsystemMismatch);
    };
    match signalfd.read_siginfo() {
        Ok(Some(payload)) => HandlerResult {
            frame: build_read_siginfo_response_ok(&payload),
            out_fd: None,
        },
        Ok(None) => status_err(Opcode::ReadSiginfoResponse, StatusCode::WouldBlock),
        Err(err) => {
            tracing::warn!(error = %err, "ReadSiginfo failed");
            status_err(Opcode::ReadSiginfoResponse, StatusCode::Internal)
        }
    }
}

fn handle_push_siginfo(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::PushSiginfoResponse);
    }
    let (handle_id, payload) = match parse_push_siginfo_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::PushSiginfoResponse),
    };
    if payload.len() != 128 {
        return status_err(Opcode::PushSiginfoResponse, StatusCode::InvalidValue);
    }
    let state = match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::Signalfd) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::PushSiginfoResponse, StatusCode::UnknownHandle);
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return status_err(Opcode::PushSiginfoResponse, StatusCode::SubsystemMismatch);
        }
        Err(_) => return status_err(Opcode::PushSiginfoResponse, StatusCode::Internal),
    };
    let StateObjectEnum::Signalfd(signalfd) = state.as_ref() else {
        return status_err(Opcode::PushSiginfoResponse, StatusCode::SubsystemMismatch);
    };
    signalfd.enqueue_siginfo(payload);
    HandlerResult {
        frame: build_push_siginfo_response_ok(),
        out_fd: None,
    }
}

fn handle_create_pty(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() || !request.body.is_empty() {
        return protocol_err(Opcode::CreatePtyResponse);
    }
    let pty_id = u32::try_from(registry.live_handle_count() / 2).unwrap_or(u32::MAX);
    let pair = PtyState::new_pair(pty_id);
    let master = registry.register(pair.master);
    let slave = registry.register(pair.slave);
    HandlerResult {
        frame: build_create_pty_response_ok(master.id(), slave.id(), pair.pty_id),
        out_fd: None,
    }
}

fn handle_open_pty_slave(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::OpenPtySlaveResponse);
    }
    let pty_id = match parse_open_pty_slave_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::OpenPtySlaveResponse),
    };
    for entry in registry.diagnostic_snapshot() {
        if entry.subsystem_tag != SubsystemTag::Pty {
            continue;
        }
        let handle = StateHandle::from_id(entry.handle_id);
        let Ok(state) = registry.resolve(handle, SubsystemTag::Pty) else {
            continue;
        };
        let StateObjectEnum::Pty(pty) = state.as_ref() else {
            continue;
        };
        if pty.pty_id() == pty_id
            && pty.endpoint() == litebox_common_linux::fd_token_protocol::PtyEndpoint::Slave
        {
            if registry.dup(handle).is_err() {
                return status_err(Opcode::OpenPtySlaveResponse, StatusCode::Internal);
            }
            return HandlerResult {
                frame: build_open_pty_slave_response_ok(entry.handle_id, pty_id),
                out_fd: None,
            };
        }
    }
    status_err(Opcode::OpenPtySlaveResponse, StatusCode::UnknownHandle)
}

fn resolve_pty(
    registry: &BrokerStateRegistry,
    handle_id: u64,
    response: Opcode,
) -> Result<Arc<PtyState>, HandlerResult> {
    match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::Pty) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::Pty(pty) => Ok(Arc::clone(pty)),
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_) => {
                Err(status_err(response, StatusCode::SubsystemMismatch))
            }
        },
        Err(StateRegistryError::UnknownHandle(_)) => {
            Err(status_err(response, StatusCode::UnknownHandle))
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            Err(status_err(response, StatusCode::SubsystemMismatch))
        }
        Err(_) => Err(status_err(response, StatusCode::Internal)),
    }
}

fn handle_pty_read(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::PtyReadResponse);
    }
    let (handle_id, max_len) = match parse_pty_read_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::PtyReadResponse),
    };
    let state = match resolve_pty(registry, handle_id, Opcode::PtyReadResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.read(max_len as usize) {
        Ok(data) => HandlerResult {
            frame: build_pty_read_response_ok(&data),
            out_fd: None,
        },
        Err(PtyError::WouldBlock) => status_err(Opcode::PtyReadResponse, StatusCode::WouldBlock),
        Err(PtyError::Invalid) => status_err(Opcode::PtyReadResponse, StatusCode::InvalidValue),
        Err(PtyError::Closed) => HandlerResult {
            frame: build_pty_read_response_ok(&[]),
            out_fd: None,
        },
    }
}

pub fn handle_pty_write(
    registry: &BrokerStateRegistry,
    pgrp_signal_inbox: Option<&PgrpSignalInbox>,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::PtyWriteResponse);
    }
    let (handle_id, data) = match parse_pty_write_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::PtyWriteResponse),
    };
    let state = match resolve_pty(registry, handle_id, Opcode::PtyWriteResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.write(&data) {
        Ok(result) => {
            if let Some(inbox) = pgrp_signal_inbox {
                let siginfo =
                    vec![0u8; core::mem::size_of::<litebox_common_linux::signal::Siginfo>()];
                for (pgrp, signum) in &result.signal_pgrps {
                    if *pgrp > 0 && *signum > 0 {
                        inbox.deliver(*pgrp as u32, *signum as u32, &siginfo);
                    }
                }
            }
            HandlerResult {
                frame: build_pty_write_response_ok(result.bytes_written as u32),
                out_fd: None,
            }
        }
        Err(PtyError::WouldBlock) => status_err(Opcode::PtyWriteResponse, StatusCode::WouldBlock),
        Err(PtyError::Invalid) | Err(PtyError::Closed) => {
            status_err(Opcode::PtyWriteResponse, StatusCode::InvalidValue)
        }
    }
}

pub fn handle_pty_ioctl(
    registry: &BrokerStateRegistry,
    pgrp_signal_inbox: Option<&PgrpSignalInbox>,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::PtyIoctlResponse);
    }
    let (handle_id, op, payload) = match parse_pty_ioctl_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::PtyIoctlResponse),
    };
    let state = match resolve_pty(registry, handle_id, Opcode::PtyIoctlResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    // Caller ids are supplied as best-effort payload-independent defaults until
    // Phase G's broker process/session model can validate job control globally.
    match state.ioctl(op, &payload, 1, 1, 1) {
        Ok(result) => {
            if let (Some(inbox), Some((pgrp, signum))) = (pgrp_signal_inbox, result.signal_pgrp)
                && pgrp > 0
                && signum > 0
            {
                let siginfo =
                    vec![0u8; core::mem::size_of::<litebox_common_linux::signal::Siginfo>()];
                inbox.deliver(pgrp as u32, signum as u32, &siginfo);
            }
            HandlerResult {
                frame: build_pty_ioctl_response_ok(&result.payload),
                out_fd: None,
            }
        }
        Err(PtyError::WouldBlock) => status_err(Opcode::PtyIoctlResponse, StatusCode::WouldBlock),
        Err(PtyError::Invalid) | Err(PtyError::Closed) => {
            status_err(Opcode::PtyIoctlResponse, StatusCode::InvalidValue)
        }
    }
}

fn handle_subscribe_pty(
    registry: &BrokerStateRegistry,
    conn: &mut ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SubscribePtyResponse);
    }
    let (handle_id, subscription_id, events_mask) = match parse_subscribe_pty_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::SubscribePtyResponse),
    };
    let Some(sender) = conn.notification_sender.as_ref().cloned() else {
        return status_err(Opcode::SubscribePtyResponse, StatusCode::NoNotificationRing);
    };
    let state = match resolve_pty(registry, handle_id, Opcode::SubscribePtyResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.subscribe(subscription_id, events_mask, sender) {
        Ok(()) => {
            conn.record_subscription(SubscriptionRegistry::State, handle_id, subscription_id);
            HandlerResult {
                frame: build_subscribe_pty_response_ok(),
                out_fd: None,
            }
        }
        Err(SubscribeError::DuplicateId(_)) => status_err(
            Opcode::SubscribePtyResponse,
            StatusCode::DuplicateSubscription,
        ),
        Err(SubscribeError::UnknownEventBits { .. }) => protocol_err(Opcode::SubscribePtyResponse),
    }
}

fn handle_subscribe_eventfd(
    registry: &BrokerStateRegistry,
    conn: &mut ConnState,
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
    let state = match registry.resolve_untyped(handle) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::SubscribeEventfdResponse, StatusCode::UnknownHandle);
        }
        Err(_) => return status_err(Opcode::SubscribeEventfdResponse, StatusCode::Internal),
    };
    match state.subscribe(subscription_id, events_mask, sender) {
        Ok(()) => {
            conn.record_subscription(SubscriptionRegistry::State, handle_id, subscription_id);
            HandlerResult {
                frame: build_subscribe_eventfd_response_ok(),
                out_fd: None,
            }
        }
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
    conn: &mut ConnState,
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
    let state = match registry.resolve_untyped(handle) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return status_err(Opcode::UnsubscribeResponse, StatusCode::UnknownHandle);
        }
        Err(_) => return status_err(Opcode::UnsubscribeResponse, StatusCode::Internal),
    };
    match state.unsubscribe(subscription_id) {
        Ok(()) => {
            let registry_kind = if state.subsystem_tag() == SubsystemTag::Process {
                SubscriptionRegistry::Process
            } else {
                SubscriptionRegistry::State
            };
            if conn.forget_subscription(registry_kind, handle_id, subscription_id)
                && registry_kind == SubscriptionRegistry::Process
            {
                let _ = registry.release(handle);
            }
            HandlerResult {
                frame: build_unsubscribe_response_ok(),
                out_fd: None,
            }
        }
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
    // Before release, peek at the handle's PtyState (if any) so we
    // can apply endpoint-specific post-release semantics.
    // Specifically: when a slave handle's refcount drops to 1, only
    // the master's anchor remains — no user-space slave fd-holders.
    // Notify master with POLLHUP+POLLIN (kernel-PTY semantic).
    let pty_state: Option<Arc<StateObjectEnum>> = registry
        .resolve(StateHandle::from_id(handle_id), SubsystemTag::Pty)
        .ok();
    match registry.release(StateHandle::from_id(handle_id)) {
        Ok(new_rc) => {
            if let Some(state) = pty_state
                && let StateObjectEnum::Pty(pty) = state.as_ref()
                && pty.endpoint() == PtyEndpoint::Slave
                && new_rc == 1
            {
                // Last user-space slave fd-holder released; only the
                // master's anchor remains. Notify master with HUP+IN.
                pty.notify_slave_close_to_master();
            }
            HandlerResult {
                frame: build_release_response_ok(),
                out_fd: None,
            }
        }
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
        build_create_eventfd_request, build_mark_process_exited_request,
        build_read_eventfd_request, build_register_process_request,
        build_subscribe_eventfd_request, build_subscribe_process_exit_request,
        build_unsubscribe_request, build_write_eventfd_request, decode,
        parse_subscribe_process_exit_response_ok,
    };
    use litebox_common_linux::notification_frame::{
        NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
    };
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

        // Clean up before drop to satisfy strict subscription
        // invariants in {Eventfd,Pidfd,Process,Pty}State::drop.
        let unsub = run(
            &registry,
            &mut conn,
            &build_unsubscribe_request(handle_id, 42),
        );
        assert_eq!(unsub.frame.status, StatusCode::Ok);
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
    fn process_subscribe_then_mark_delivers_notification() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let mut receiver = make_ring_for_conn(&mut conn);

        let register = run(&registry, &mut conn, &build_register_process_request());
        assert_eq!(register.frame.status, StatusCode::Ok);
        let pid = u64::from_le_bytes(register.frame.body[..8].try_into().unwrap());

        let sub = run(
            &registry,
            &mut conn,
            &build_subscribe_process_exit_request(
                u32::try_from(pid).unwrap(),
                77,
                NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP,
            ),
        );
        assert_eq!(sub.frame.status, StatusCode::Ok);
        assert_eq!(
            parse_subscribe_process_exit_response_ok(&sub.frame.body).unwrap(),
            None
        );

        let mark = run(
            &registry,
            &mut conn,
            &build_mark_process_exited_request(u32::try_from(pid).unwrap(), 33),
        );
        assert_eq!(mark.frame.status, StatusCode::Ok);
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 77);
        assert_eq!(frame.events(), NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
        assert_eq!(frame.payload_bytes(), Some(&33i32.to_le_bytes()[..]));

        // Clean up subscription before drop.
        let unsub = run(
            &registry,
            &mut conn,
            &build_unsubscribe_request(u64::from(pid), 77),
        );
        assert_eq!(unsub.frame.status, StatusCode::Ok);
    }

    #[test]
    fn process_late_subscribe_returns_exit_snapshot() {
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let mut receiver = make_ring_for_conn(&mut conn);

        let register = run(&registry, &mut conn, &build_register_process_request());
        let pid = u64::from_le_bytes(register.frame.body[..8].try_into().unwrap());
        let pid = u32::try_from(pid).unwrap();
        let mark = run(
            &registry,
            &mut conn,
            &build_mark_process_exited_request(pid, 44),
        );
        assert_eq!(mark.frame.status, StatusCode::Ok);

        let sub = run(
            &registry,
            &mut conn,
            &build_subscribe_process_exit_request(pid, 78, NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP),
        );
        assert_eq!(sub.frame.status, StatusCode::Ok);
        assert_eq!(
            parse_subscribe_process_exit_response_ok(&sub.frame.body).unwrap(),
            Some(44)
        );
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.subscription_id(), 78);
        assert_eq!(frame.payload_bytes(), Some(&44i32.to_le_bytes()[..]));

        // Clean up subscription before drop.
        let unsub = run(
            &registry,
            &mut conn,
            &build_unsubscribe_request(u64::from(pid), 78),
        );
        assert_eq!(unsub.frame.status, StatusCode::Ok);
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
