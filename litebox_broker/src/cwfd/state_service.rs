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

use crate::cwfd::inet_dgram_state::{InetDgramError, InetDgramState, is_broker_dns_service};
use crate::cwfd::inet_listener_state::{
    AddressFamily, InetListenerError, InetListenerState, decode_sockaddr, encode_sockaddr,
    family_from_u8,
};
use crate::cwfd::inet_raw_state::{InetRawError, InetRawState};
use crate::cwfd::pidfd_state::{PidfdError, PidfdState};
use crate::eventfd_state::{EventfdError, EventfdState};
use crate::inotify_dispatcher::InotifyDispatcher;
use crate::inotify_state::InotifyState;
use crate::pgrp_signal_inbox::{
    PgrpSignalInbox, SubscribeError as PgrpSubscribeError, UnsubscribeError as PgrpUnsubscribeError,
};
use crate::pipe_state::{PipeError, PipeReadEnd, PipeWriteEnd};
use crate::process_state::ProcessState;
use crate::pty_state::{PtyError, PtyState};
use crate::signalfd_state::SignalfdState;
use crate::socket_dgram_state::{
    SocketDgramError, SocketDgramState, decode_addr as decode_socket_dgram_addr,
    encode_addr as encode_socket_dgram_addr,
};
use crate::socket_seqpacket_state::{
    SocketSeqPacketError, SocketSeqPacketState, decode_addr as decode_socket_seqpacket_addr,
    encode_addr as encode_socket_seqpacket_addr,
};
use crate::socketpair_state::{SocketPairEnd, SocketPairError};
use crate::state_registry::{
    BrokerStateRegistry, StateHandle, StateObjectEnum, StateRegistryError,
};
use crate::subscription_list::{SubscribeError, UnsubscribeError};
use crate::tcp_conn_state::{TcpConnError, TcpConnState};
use crate::timerfd_state::{TimerfdError, TimerfdState};
use litebox_common_linux::fd_token_protocol as proto;
use litebox_common_linux::fd_token_protocol::PtyEndpoint;

use litebox_common_linux::fd_token_protocol::{
    Frame, Opcode, OwnedFrame, StatusCode, build_create_eventfd_response_ok,
    build_create_pidfd_response_ok, build_create_pipe_response_ok, build_create_pty_response_ok,
    build_create_signalfd_response_ok, build_create_socketpair_response_ok,
    build_create_timerfd_response_ok, build_deliver_signal_inbox_response_ok, build_error_response,
    build_get_timerfd_response_ok, build_inet_listener_accept_response_ok,
    build_inet_listener_bind_response_ok, build_inet_listener_create_response_ok,
    build_inet_listener_getsockname_response_ok, build_inet_listener_getsockopt_response_ok,
    build_inet_listener_listen_response_ok, build_inet_listener_query_events_response_ok,
    build_inet_raw_query_events_response_ok, build_inet_raw_recvfrom_response_ok,
    build_inet_raw_sendto_response_ok, build_inet_tcp_conn_getsockopt_response_ok,
    build_inet_tcp_conn_setsockopt_response_ok, build_inotify_add_watch_response_ok,
    build_inotify_init1_response_ok, build_inotify_read_response_ok,
    build_inotify_rm_watch_response_ok, build_mark_process_exited_response_ok,
    build_open_pty_slave_response_ok, build_pidfd_exited_response_ok,
    build_poll_tcp_conn_events_response_ok, build_pty_ioctl_response_ok,
    build_pty_read_response_ok, build_pty_write_response_ok, build_push_siginfo_response_ok,
    build_read_eventfd_response_ok, build_read_pipe_response_ok, build_read_siginfo_response_ok,
    build_read_socketpair_response_ok, build_read_tcp_conn_response_ok,
    build_read_timerfd_response_ok, build_register_notification_ring_response_ok,
    build_register_process_response_ok, build_release_response_ok, build_set_pgid_response_ok,
    build_set_sid_response_ok, build_set_timerfd_response_ok,
    build_shutdown_socketpair_write_response_ok, build_shutdown_tcp_conn_response_ok,
    build_subscribe_eventfd_response_ok, build_subscribe_process_exit_response_ok,
    build_subscribe_pty_response_ok, build_subscribe_signal_inbox_response_ok,
    build_unsubscribe_response_ok, build_unsubscribe_signal_inbox_response_ok,
    build_write_eventfd_response_ok, build_write_pipe_response_ok,
    build_write_socketpair_response_ok, build_write_tcp_conn_response_ok,
    parse_create_eventfd_body, parse_create_pidfd_body, parse_create_pipe_body,
    parse_create_signalfd_body, parse_create_socketpair_body, parse_create_timerfd_body,
    parse_deliver_signal_inbox_body, parse_handle_body, parse_inet_listener_accept_body,
    parse_inet_listener_bind_body, parse_inet_listener_create_body,
    parse_inet_listener_getsockname_body, parse_inet_listener_getsockopt_body,
    parse_inet_listener_listen_body, parse_inet_listener_query_events_body,
    parse_inet_raw_create_body, parse_inet_raw_query_events_body, parse_inet_raw_recvfrom_body,
    parse_inet_raw_sendto_body, parse_inet_tcp_conn_getsockopt_body,
    parse_inet_tcp_conn_setsockopt_body, parse_inotify_add_watch_body, parse_inotify_init1_body,
    parse_inotify_read_body, parse_inotify_rm_watch_body, parse_mark_process_exited_body,
    parse_open_pty_slave_body, parse_pidfd_exited_request, parse_poll_tcp_conn_events_body,
    parse_pty_ioctl_body, parse_pty_read_body, parse_pty_write_body, parse_push_siginfo_body,
    parse_read_pipe_body, parse_read_socketpair_body, parse_read_tcp_conn_body,
    parse_set_pgid_body, parse_set_sid_body, parse_set_timerfd_body,
    parse_shutdown_socketpair_write_body, parse_shutdown_tcp_conn_body,
    parse_subscribe_eventfd_body, parse_subscribe_process_exit_body, parse_subscribe_pty_body,
    parse_subscribe_signal_inbox_body, parse_unsubscribe_body, parse_unsubscribe_signal_inbox_body,
    parse_write_eventfd_body, parse_write_pipe_body, parse_write_socketpair_body,
    parse_write_tcp_conn_body,
};

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_ring::NotificationSender;
use litebox_common_linux::shmem_ring::ShmemRingPair;
use std::os::unix::io::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    /// Legacy-pipes Phase 3 (D3): the per-connection 9P `Server` this
    /// fd-token-socket connection is paired with. Set by the broker
    /// listener at connection accept time when both channels (the 9P
    /// connection and this fd-token-socket connection) belong to the
    /// same shim.
    ///
    /// Used exclusively by the `RegisterOfd` and `CloneOfd` handlers
    /// to look up / mutate the shim's own per-connection fid table.
    /// Cross-connection access is **not** supported by design — the
    /// broker-global OFD registry is the only piece of state shared
    /// across connections (it lives in
    /// [`crate::ofd_registry::OfdRegistry`] and is reached through
    /// the `Server` instance held here).
    ///
    /// `None` for legacy bring-up paths that don't pair a 9P server
    /// with the fd-token-socket (test fixtures, the IPC-only control
    /// listener for cwfd-only flows). Handlers MUST treat `None` as
    /// "this op is not available on this connection" and return
    /// `SubsystemMismatch`.
    nine_p_server: Option<Arc<crate::nine_p::server::Server>>,
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

    /// Legacy-pipes Phase 3 (D3): pair this fd-token-socket
    /// connection with its sibling 9P `Server` instance. The broker
    /// listener calls this immediately after accepting the
    /// connection if both channels are bound to the same shim.
    pub fn set_nine_p_server(&mut self, server: Arc<crate::nine_p::server::Server>) {
        self.nine_p_server = Some(server);
    }

    /// Returns this connection's paired 9P `Server`, if any. Used
    /// by D3 handlers; returns `None` for fd-token-socket-only
    /// connections.
    pub fn nine_p_server(&self) -> Option<&Arc<crate::nine_p::server::Server>> {
        self.nine_p_server.as_ref()
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
    inotify_dispatcher: &Arc<InotifyDispatcher>,
    conn: &mut ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    let result = dispatch_request(registry, inotify_dispatcher, conn, request, in_fds);
    // A4 liveness chokepoint: every RPC implies the worker drained
    // its prior notification frame, so re-attempt any deferred edge
    // bits across the whole registry. See
    // `BrokerStateRegistry::try_flush_all_subscriptions` and the
    // `SubscriptionList` module-level invariants (I3, A4, A6).
    registry.try_flush_all_subscriptions();
    result
}

fn dispatch_request(
    registry: &BrokerStateRegistry,
    inotify_dispatcher: &Arc<InotifyDispatcher>,
    conn: &mut ConnState,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    // reason: unsupported variants intentionally share this fallback path.
    #[allow(clippy::wildcard_enum_match_arm)]
    match request.opcode {
        Opcode::RegisterNotificationRing => {
            handle_register_notification_ring(conn, request, in_fds)
        }
        Opcode::CreateEventfd => handle_create_eventfd(registry, request, in_fds),
        Opcode::CreateTimerfd => handle_create_timerfd(registry, request, in_fds),
        Opcode::ReadTimerfd => handle_read_timerfd(registry, request, in_fds),
        Opcode::SetTimerfd => handle_set_timerfd(registry, request, in_fds),
        Opcode::GetTimerfd => handle_get_timerfd(registry, request, in_fds),
        Opcode::CreatePidfd => handle_create_pidfd(registry, request, in_fds),
        Opcode::PidfdExited => handle_pidfd_exited(registry, request, in_fds),
        Opcode::ReadEventfd => handle_read_eventfd(registry, request, in_fds),
        Opcode::WriteEventfd => handle_write_eventfd(registry, request, in_fds),
        Opcode::CreateSignalfd => handle_create_signalfd(registry, request, in_fds),
        Opcode::InotifyInit1 => handle_inotify_init1(registry, inotify_dispatcher, request, in_fds),
        Opcode::InotifyAddWatch => handle_inotify_add_watch(registry, request, in_fds),
        Opcode::InotifyRmWatch => handle_inotify_rm_watch(registry, request, in_fds),
        Opcode::InotifyRead => handle_inotify_read(registry, request, in_fds),
        Opcode::InotifyQueryEvents => handle_query_events(registry, request, in_fds),
        Opcode::InetListenerCreate => handle_inet_listener_create(registry, request, in_fds),
        Opcode::InetListenerBind => handle_inet_listener_bind(registry, request, in_fds),
        Opcode::InetListenerListen => handle_inet_listener_listen(registry, request, in_fds),
        Opcode::InetListenerAccept => handle_inet_listener_accept(registry, request, in_fds),
        Opcode::InetListenerQueryEvents => {
            handle_inet_listener_query_events(registry, request, in_fds)
        }
        Opcode::InetListenerSetSockOpt => {
            handle_inet_listener_setsockopt(registry, request, in_fds)
        }
        Opcode::InetListenerGetSockName => {
            handle_inet_listener_getsockname(registry, request, in_fds)
        }
        Opcode::InetListenerGetSockOpt => {
            handle_inet_listener_getsockopt(registry, request, in_fds)
        }
        Opcode::InetRawCreate => handle_inet_raw_create(registry, request, in_fds),
        Opcode::InetRawSendTo => handle_inet_raw_sendto(registry, request, in_fds),
        Opcode::InetRawRecvFrom => handle_inet_raw_recvfrom(registry, request, in_fds),
        Opcode::InetRawQueryEvents => handle_inet_raw_query_events(registry, request, in_fds),
        Opcode::InetTcpConnCreate => handle_inet_tcp_conn_create(
            registry,
            request,
            in_fds,
            Opcode::InetTcpConnCreateResponse,
        ),
        Opcode::InetTcpConnConnect => handle_inet_tcp_conn_connect(
            registry,
            request,
            in_fds,
            Opcode::InetTcpConnConnectResponse,
        ),
        Opcode::InetTcpConnQueryEvents => handle_query_events(registry, request, in_fds),
        Opcode::InetTcpConnGetSockName => handle_inet_tcp_conn_getsockname(
            registry,
            request,
            in_fds,
            Opcode::InetTcpConnGetSockNameResponse,
        ),
        Opcode::InetTcpConnGetPeerName => handle_inet_tcp_conn_getpeername(
            registry,
            request,
            in_fds,
            Opcode::InetTcpConnGetPeerNameResponse,
        ),
        Opcode::InetDgramCreate => handle_inet_dgram_create(registry, request, in_fds),
        Opcode::InetDgramBind => handle_inet_dgram_bind(registry, request, in_fds),
        Opcode::InetDgramConnect => handle_inet_dgram_connect(registry, request, in_fds),
        Opcode::InetDgramSendTo => handle_inet_dgram_sendto(registry, request, in_fds),
        Opcode::InetDgramRecvFrom => handle_inet_dgram_recvfrom(registry, request, in_fds),
        Opcode::InetDgramShutdown => handle_inet_dgram_shutdown(registry, request, in_fds),
        Opcode::InetDgramGetSockName => handle_inet_dgram_getsockname(registry, request, in_fds),
        Opcode::InetDgramGetPeerName => handle_inet_dgram_getpeername(registry, request, in_fds),
        Opcode::InetDgramSetSockOpt => handle_inet_dgram_setsockopt(registry, request, in_fds),
        Opcode::InetDgramGetSockOpt => handle_inet_dgram_getsockopt(registry, request, in_fds),
        Opcode::InetDgramQueryEvents => handle_inet_dgram_query_events(registry, request, in_fds),
        Opcode::CreatePipe => handle_create_pipe(registry, request, in_fds),
        Opcode::ReadPipe => handle_read_pipe(registry, request, in_fds),
        Opcode::WritePipe => handle_write_pipe(registry, request, in_fds),
        Opcode::AttachHostFd => handle_attach_host_fd(registry, request, in_fds),
        Opcode::RegisterOfd => handle_register_ofd(conn, request),
        Opcode::CloneOfd => handle_clone_ofd(conn, request),
        Opcode::BindNinePSession => handle_bind_nine_p_session(conn, request),
        Opcode::CreateSocketDgram => handle_create_socket_dgram(registry, request, in_fds),
        Opcode::CreateSocketSeqPacket => handle_create_socket_seqpacket(registry, request, in_fds),
        Opcode::SocketDgramBind => handle_socket_dgram_bind(registry, request, in_fds),
        Opcode::SocketDgramConnect => handle_socket_dgram_connect(registry, request, in_fds),
        Opcode::SocketDgramSendTo => handle_socket_dgram_sendto(registry, request, in_fds),
        Opcode::SocketDgramRecvFrom => handle_socket_dgram_recvfrom(registry, request, in_fds),
        Opcode::SocketDgramShutdown => handle_socket_dgram_shutdown(registry, request, in_fds),
        Opcode::SocketDgramGetSockName => {
            handle_socket_dgram_getsockname(registry, request, in_fds)
        }
        Opcode::SocketDgramGetPeerName => {
            handle_socket_dgram_getpeername(registry, request, in_fds)
        }
        Opcode::SocketSeqPacketBind => handle_socket_seqpacket_bind(registry, request, in_fds),
        Opcode::SocketSeqPacketListen => handle_socket_seqpacket_listen(registry, request, in_fds),
        Opcode::SocketSeqPacketAccept => handle_socket_seqpacket_accept(registry, request, in_fds),
        Opcode::SocketSeqPacketConnect => {
            handle_socket_seqpacket_connect(registry, request, in_fds)
        }
        Opcode::SocketSeqPacketSend => handle_socket_seqpacket_send(registry, request, in_fds),
        Opcode::SocketSeqPacketRecv => handle_socket_seqpacket_recv(registry, request, in_fds),
        Opcode::SocketSeqPacketShutdown => {
            handle_socket_seqpacket_shutdown(registry, request, in_fds)
        }
        Opcode::SocketSeqPacketGetSockName => {
            handle_socket_seqpacket_getsockname(registry, request, in_fds)
        }
        Opcode::SocketSeqPacketGetPeerName => {
            handle_socket_seqpacket_getpeername(registry, request, in_fds)
        }
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
        Opcode::InetTcpConnSetSockOpt => handle_inet_tcp_conn_setsockopt(registry, request, in_fds),
        Opcode::InetTcpConnGetSockOpt => handle_inet_tcp_conn_getsockopt(registry, request, in_fds),
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
        Opcode::QueryEvents => handle_query_events(registry, request, in_fds),
        #[cfg(debug_assertions)]
        Opcode::DebugQueryStateObject => handle_debug_query_state_object(registry, request, in_fds),
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

fn resolve_or_register_process(
    process_registry: &BrokerStateRegistry,
    pid: u32,
) -> Result<(), StateRegistryError> {
    let handle = StateHandle::from_id(u64::from(pid));
    match process_registry.resolve(handle, SubsystemTag::Process) {
        Ok(_) => Ok(()),
        Err(StateRegistryError::UnknownHandle(_)) => process_registry
            .register_with_id(u64::from(pid), ProcessState::arc())
            .map(|_| ()),
        Err(err) => Err(err),
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
    match resolve_or_register_process(process_registry, caller_pid) {
        Ok(()) => {}
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

fn handle_create_timerfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::CreateTimerfdResponse);
    }
    let (clockid, flags) = match parse_create_timerfd_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::CreateTimerfdResponse),
    };
    let state = match TimerfdState::new(clockid, flags) {
        Ok(state) => state,
        Err(TimerfdError::InvalidValue) => {
            return status_err(Opcode::CreateTimerfdResponse, StatusCode::InvalidValue);
        }
        Err(TimerfdError::WouldBlock) => {
            return status_err(Opcode::CreateTimerfdResponse, StatusCode::Internal);
        }
    };
    let handle = registry.register(state);
    HandlerResult {
        frame: build_create_timerfd_response_ok(handle.id()),
        out_fd: None,
    }
}

fn resolve_timerfd(
    registry: &BrokerStateRegistry,
    handle_id: u64,
    response: Opcode,
) -> Result<Arc<TimerfdState>, HandlerResult> {
    let state = match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::Timerfd) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return Err(status_err(response, StatusCode::UnknownHandle));
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return Err(status_err(response, StatusCode::SubsystemMismatch));
        }
        Err(_) => return Err(status_err(response, StatusCode::Internal)),
    };
    match state.as_ref() {
        StateObjectEnum::Timerfd(timerfd) => Ok(Arc::clone(timerfd)),
        StateObjectEnum::Eventfd(_)
        | StateObjectEnum::PipeReadEnd(_)
        | StateObjectEnum::PipeWriteEnd(_)
        | StateObjectEnum::SocketPairEnd(_)
        | StateObjectEnum::SocketDgram(_)
        | StateObjectEnum::SocketSeqPacket(_)
        | StateObjectEnum::TcpConn(_)
        | StateObjectEnum::InetListener(_)
        | StateObjectEnum::InetDgram(_)
        | StateObjectEnum::InetRaw(_)
        | StateObjectEnum::Signalfd(_)
        | StateObjectEnum::Inotify(_)
        | StateObjectEnum::Pty(_)
        | StateObjectEnum::Pidfd(_)
        | StateObjectEnum::Process(_)
        | StateObjectEnum::HostFdAttached(_) => {
            unreachable!("registry returned wrong state variant for Timerfd tag")
        }
    }
}

fn handle_read_timerfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::ReadTimerfdResponse);
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::ReadTimerfdResponse),
    };
    let state = match resolve_timerfd(registry, handle_id, Opcode::ReadTimerfdResponse) {
        Ok(state) => state,
        Err(result) => return result,
    };
    match state.read() {
        Ok(v) => HandlerResult {
            frame: build_read_timerfd_response_ok(v),
            out_fd: None,
        },
        Err(TimerfdError::WouldBlock) => {
            status_err(Opcode::ReadTimerfdResponse, StatusCode::WouldBlock)
        }
        Err(TimerfdError::InvalidValue) => {
            status_err(Opcode::ReadTimerfdResponse, StatusCode::Internal)
        }
    }
}

fn handle_set_timerfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SetTimerfdResponse);
    }
    let (handle_id, new_value, flags) = match parse_set_timerfd_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SetTimerfdResponse),
    };
    let state = match resolve_timerfd(registry, handle_id, Opcode::SetTimerfdResponse) {
        Ok(state) => state,
        Err(result) => return result,
    };
    match state.settime(new_value, flags) {
        Ok(()) => HandlerResult {
            frame: build_set_timerfd_response_ok(),
            out_fd: None,
        },
        Err(TimerfdError::InvalidValue) => {
            status_err(Opcode::SetTimerfdResponse, StatusCode::InvalidValue)
        }
        Err(TimerfdError::WouldBlock) => {
            status_err(Opcode::SetTimerfdResponse, StatusCode::Internal)
        }
    }
}

fn handle_get_timerfd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::GetTimerfdResponse);
    }
    let handle_id = match parse_handle_body(request.body, request.opcode) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::GetTimerfdResponse),
    };
    let state = match resolve_timerfd(registry, handle_id, Opcode::GetTimerfdResponse) {
        Ok(state) => state,
        Err(result) => return result,
    };
    HandlerResult {
        frame: build_get_timerfd_response_ok(state.gettime()),
        out_fd: None,
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

/// Phase 3 (legacy-pipes retirement): receive an SCM_RIGHTS-passed host
/// fd, take ownership of it, and register it as a broker state object.
/// Returns the new state handle id. Workers thereafter interact with
/// the fd through `ReadPipe`/`WritePipe` RPCs (subject to the declared
/// direction).
fn handle_attach_host_fd(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    mut in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    use crate::cwfd::host_fd_state::{HostFdDirection, HostFdState};
    use litebox_common_linux::fd_token_protocol::{
        build_attach_host_fd_response_ok, parse_attach_host_fd_body,
    };

    // Must carry exactly one SCM_RIGHTS fd.
    if in_fds.len() != 1 {
        return protocol_err(Opcode::AttachHostFdResponse);
    }
    let dir_byte = match parse_attach_host_fd_body(request.body) {
        Ok(b) => b,
        Err(_) => return protocol_err(Opcode::AttachHostFdResponse),
    };
    let direction = match HostFdDirection::from_wire(dir_byte) {
        Some(d) => d,
        None => return protocol_err(Opcode::AttachHostFdResponse),
    };
    let fd = in_fds.remove(0);
    let state = HostFdState::from_received(fd, direction);
    let handle = registry.register(state);
    HandlerResult {
        frame: build_attach_host_fd_response_ok(handle.id()),
        out_fd: None,
    }
}

/// Legacy-pipes Phase 3 (D3): register an open 9P fid in the
/// broker-global OFD registry on behalf of the **parent** shim.
/// Handler is expected to run on the parent's fd-token-socket
/// connection; the `ConnState` carries the parent's per-connection
/// 9P `Server` instance, which owns the fid lookup.
///
/// Returns `SubsystemMismatch` if the connection isn't paired with
/// a 9P server (e.g., a fd-token-socket-only control connection).
/// Maps the inner `Server::register_fid_in_ofd_registry` errno to
/// the corresponding wire `StatusCode`.
fn handle_register_ofd(conn: &ConnState, request: &Frame<'_>) -> HandlerResult {
    use litebox_common_linux::fd_token_protocol::{
        build_register_ofd_response_ok, parse_register_ofd_body,
    };

    let fid = match parse_register_ofd_body(request.body) {
        Ok(f) => f,
        Err(_) => return protocol_err(Opcode::RegisterOfdResponse),
    };
    let server = match conn.nine_p_server() {
        Some(s) => s,
        None => {
            return HandlerResult {
                frame: build_error_response(
                    Opcode::RegisterOfdResponse,
                    StatusCode::SubsystemMismatch,
                ),
                out_fd: None,
            };
        }
    };
    match server.register_fid_in_ofd_registry(fid) {
        Ok(id) => HandlerResult {
            frame: build_register_ofd_response_ok(id.as_u64()),
            out_fd: None,
        },
        Err(errno) => HandlerResult {
            frame: build_error_response(Opcode::RegisterOfdResponse, errno_to_status(errno)),
            out_fd: None,
        },
    }
}

/// Legacy-pipes Phase 3 (D3): clone a previously-registered OFD
/// into a fresh 9P fid on the **worker's** own connection. Handler
/// is expected to run on the worker's fd-token-socket; the
/// `ConnState` carries the worker's per-connection 9P `Server`.
fn handle_clone_ofd(conn: &ConnState, request: &Frame<'_>) -> HandlerResult {
    use crate::ofd_registry::OpenFileId;
    use litebox_common_linux::fd_token_protocol::{
        build_clone_ofd_response_ok, parse_clone_ofd_body,
    };

    let (open_file_id, new_fid) = match parse_clone_ofd_body(request.body) {
        Ok(t) => t,
        Err(_) => return protocol_err(Opcode::CloneOfdResponse),
    };
    let server = match conn.nine_p_server() {
        Some(s) => s,
        None => {
            return HandlerResult {
                frame: build_error_response(
                    Opcode::CloneOfdResponse,
                    StatusCode::SubsystemMismatch,
                ),
                out_fd: None,
            };
        }
    };
    match server.clone_ofd_into_fid(OpenFileId::from_u64(open_file_id), new_fid) {
        Ok(()) => HandlerResult {
            frame: build_clone_ofd_response_ok(),
            out_fd: None,
        },
        Err(errno) => HandlerResult {
            frame: build_error_response(Opcode::CloneOfdResponse, errno_to_status(errno)),
            out_fd: None,
        },
    }
}

/// Legacy-pipes Phase 3 (D3 step 2d.2): pair this fd-token-socket
/// connection with a 9P session by its broker-assigned conn_id.
/// The shim issues this op early on the fd-token-socket so the
/// subsequent `RegisterOfd` / `CloneOfd` handlers can resolve fids
/// against `ConnState::nine_p_server`.
fn handle_bind_nine_p_session(conn: &mut ConnState, request: &Frame<'_>) -> HandlerResult {
    use litebox_common_linux::fd_token_protocol::{
        build_bind_nine_p_session_response_ok, parse_bind_nine_p_session_body,
    };

    let nine_p_conn_id = match parse_bind_nine_p_session_body(request.body) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::BindNinePSessionResponse),
    };
    let registry = match crate::nine_p_session_registry::global_registry() {
        Some(r) => r,
        None => {
            // Broker isn't running with a session registry (e.g.
            // unit-test contexts that bypass main). Treat as
            // unknown so callers see a deterministic failure.
            return HandlerResult {
                frame: build_error_response(
                    Opcode::BindNinePSessionResponse,
                    StatusCode::UnknownNinePSession,
                ),
                out_fd: None,
            };
        }
    };
    match registry.get(nine_p_conn_id) {
        Some(server) => {
            conn.set_nine_p_server(server);
            HandlerResult {
                frame: build_bind_nine_p_session_response_ok(),
                out_fd: None,
            }
        }
        None => HandlerResult {
            frame: build_error_response(
                Opcode::BindNinePSessionResponse,
                StatusCode::UnknownNinePSession,
            ),
            out_fd: None,
        },
    }
}

/// Map a libc errno (as `u32`) into the closest `StatusCode` wire
/// value. Used by the D3 handlers which receive errnos directly
/// from the 9P `Server` layer.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn errno_to_status(errno: u32) -> StatusCode {
    let signed = errno as i32;
    match signed {
        libc::EBADF => StatusCode::UnknownHandle,
        libc::EEXIST => StatusCode::DuplicateSubscription,
        libc::ENOMEM => StatusCode::Internal,
        libc::ENOTSUP | libc::EOPNOTSUPP => StatusCode::SubsystemMismatch,
        libc::EIO => StatusCode::Io,
        _ => StatusCode::Internal,
    }
}

enum PipeReader {
    Pipe(Arc<PipeReadEnd>),
    HostFd(Arc<crate::cwfd::host_fd_state::HostFdState>),
}

/// Resolved target of a `WritePipe` RPC. See [`PipeReader`].
enum PipeWriter {
    Pipe(Arc<PipeWriteEnd>),
    HostFd(Arc<crate::cwfd::host_fd_state::HostFdState>),
}

fn resolve_pipe_read(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<PipeReader, StatusCode> {
    match registry.resolve_untyped(StateHandle::from_id(handle_id)) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::PipeReadEnd(read_end) => Ok(PipeReader::Pipe(Arc::clone(read_end))),
            StateObjectEnum::HostFdAttached(state) => {
                if state.direction().allows_read() {
                    Ok(PipeReader::HostFd(Arc::clone(state)))
                } else {
                    Err(StatusCode::SubsystemMismatch)
                }
            }
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::InetListener(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::Timerfd(_) => Err(StatusCode::SubsystemMismatch),
        },
        Err(StateRegistryError::UnknownHandle(_)) => Err(StatusCode::UnknownHandle),
        Err(StateRegistryError::TagMismatch { .. }) => Err(StatusCode::SubsystemMismatch),
        Err(_) => Err(StatusCode::Internal),
    }
}

fn resolve_pipe_write(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<PipeWriter, StatusCode> {
    match registry.resolve_untyped(StateHandle::from_id(handle_id)) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::PipeWriteEnd(write_end) => Ok(PipeWriter::Pipe(Arc::clone(write_end))),
            StateObjectEnum::HostFdAttached(state) => {
                if state.direction().allows_write() {
                    Ok(PipeWriter::HostFd(Arc::clone(state)))
                } else {
                    Err(StatusCode::SubsystemMismatch)
                }
            }
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::InetListener(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::Timerfd(_) => Err(StatusCode::SubsystemMismatch),
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
    let target = match resolve_pipe_read(registry, handle_id) {
        Ok(t) => t,
        Err(status) => return status_err(Opcode::ReadPipeResponse, status),
    };
    match target {
        PipeReader::Pipe(state) => match state.read(max_len) {
            Ok(bytes) => HandlerResult {
                frame: build_read_pipe_response_ok(&bytes),
                out_fd: None,
            },
            Err(PipeError::WouldBlock) => {
                status_err(Opcode::ReadPipeResponse, StatusCode::WouldBlock)
            }
            Err(_) => status_err(Opcode::ReadPipeResponse, StatusCode::InvalidValue),
        },
        PipeReader::HostFd(state) => {
            use crate::cwfd::host_fd_state::HostFdError;
            match state.read(max_len) {
                Ok(bytes) => HandlerResult {
                    frame: build_read_pipe_response_ok(&bytes),
                    out_fd: None,
                },
                Err(HostFdError::WouldBlock) => {
                    status_err(Opcode::ReadPipeResponse, StatusCode::WouldBlock)
                }
                Err(HostFdError::DirectionMismatch) => {
                    status_err(Opcode::ReadPipeResponse, StatusCode::SubsystemMismatch)
                }
                Err(HostFdError::PeerClosed) => HandlerResult {
                    frame: build_read_pipe_response_ok(&[]),
                    out_fd: None,
                },
                Err(HostFdError::Io(_)) => {
                    status_err(Opcode::ReadPipeResponse, StatusCode::Internal)
                }
            }
        }
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
    let target = match resolve_pipe_write(registry, handle_id) {
        Ok(t) => t,
        Err(status) => {
            return status_err(Opcode::WritePipeResponse, status);
        }
    };
    match target {
        PipeWriter::Pipe(state) => {
            // HypB diag: log producer's handle_id before write fires (matches PIPE WRITE inner_addr).
            {
                use std::io::Write;
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/rst-diag.log")
                {
                    let _ = writeln!(
                        f,
                        "[HypB-diag] ts={ts} WRITE-PIPE-RPC handle={handle_id} bytes={}",
                        bytes.len()
                    );
                }
            }
            match state.write(&bytes) {
                Ok(n) => HandlerResult {
                    frame: build_write_pipe_response_ok(n as u64),
                    out_fd: None,
                },
                Err(PipeError::WouldBlock) => {
                    status_err(Opcode::WritePipeResponse, StatusCode::WouldBlock)
                }
                Err(PipeError::PeerClosed) => {
                    status_err(Opcode::WritePipeResponse, StatusCode::InvalidValue)
                }
                Err(_) => status_err(Opcode::WritePipeResponse, StatusCode::Internal),
            }
        }
        PipeWriter::HostFd(state) => {
            use crate::cwfd::host_fd_state::HostFdError;
            match state.write(&bytes) {
                Ok(n) => HandlerResult {
                    frame: build_write_pipe_response_ok(n as u64),
                    out_fd: None,
                },
                Err(HostFdError::WouldBlock) => {
                    status_err(Opcode::WritePipeResponse, StatusCode::WouldBlock)
                }
                Err(HostFdError::DirectionMismatch) => {
                    status_err(Opcode::WritePipeResponse, StatusCode::SubsystemMismatch)
                }
                Err(HostFdError::PeerClosed) => {
                    status_err(Opcode::WritePipeResponse, StatusCode::InvalidValue)
                }
                Err(HostFdError::Io(_)) => {
                    status_err(Opcode::WritePipeResponse, StatusCode::Internal)
                }
            }
        }
    }
}

fn socket_dgram_status(err: SocketDgramError) -> StatusCode {
    match err {
        SocketDgramError::WouldBlock => StatusCode::WouldBlock,
        SocketDgramError::InvalidSockaddr
        | SocketDgramError::AlreadyBound
        | SocketDgramError::AddrInUse
        | SocketDgramError::NoPeer
        | SocketDgramError::NotConnected
        | SocketDgramError::Shutdown => StatusCode::InvalidValue,
    }
}

fn resolve_socket_dgram(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<Arc<SocketDgramState>, StatusCode> {
    match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::UnixSocket) {
        Ok(s) => match s.as_ref() {
            StateObjectEnum::SocketDgram(state) => Ok(Arc::clone(state)),
            StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::InetListener(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::HostFdAttached(_)
            | StateObjectEnum::Timerfd(_) => Err(StatusCode::SubsystemMismatch),
        },
        Err(StateRegistryError::UnknownHandle(_)) => Err(StatusCode::UnknownHandle),
        Err(StateRegistryError::TagMismatch { .. }) => Err(StatusCode::SubsystemMismatch),
        Err(_) => Err(StatusCode::Internal),
    }
}

fn handle_create_socket_dgram(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() || proto::parse_create_socket_dgram_body(request.body).is_err() {
        return protocol_err(Opcode::CreateSocketDgramResponse);
    }
    let state = SocketDgramState::new();
    let handle = registry.register(state);
    HandlerResult {
        frame: proto::build_create_socket_dgram_response_ok(handle.id()),
        out_fd: None,
    }
}

fn handle_socket_dgram_bind(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketDgramBindResponse);
    }
    let (handle_id, raw_addr) = match proto::parse_socket_dgram_bind_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketDgramBindResponse),
    };
    let state = match resolve_socket_dgram(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::SocketDgramBindResponse, status),
    };
    let addr = match decode_socket_dgram_addr(&raw_addr) {
        Ok(addr) => addr,
        Err(err) => return status_err(Opcode::SocketDgramBindResponse, socket_dgram_status(err)),
    };
    match state.bind(addr) {
        Ok(bound) => HandlerResult {
            frame: proto::build_socket_dgram_bind_response_ok(&encode_socket_dgram_addr(&bound)),
            out_fd: None,
        },
        Err(err) => status_err(Opcode::SocketDgramBindResponse, socket_dgram_status(err)),
    }
}

fn handle_socket_dgram_connect(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketDgramConnectResponse);
    }
    let (handle_id, raw_addr) = match proto::parse_socket_dgram_connect_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketDgramConnectResponse),
    };
    let state = match resolve_socket_dgram(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::SocketDgramConnectResponse, status),
    };
    let addr = match decode_socket_dgram_addr(&raw_addr) {
        Ok(addr) => addr,
        Err(err) => {
            return status_err(Opcode::SocketDgramConnectResponse, socket_dgram_status(err));
        }
    };
    match state.connect(addr) {
        Ok(()) => HandlerResult {
            frame: proto::build_socket_dgram_connect_response_ok(),
            out_fd: None,
        },
        Err(err) => status_err(Opcode::SocketDgramConnectResponse, socket_dgram_status(err)),
    }
}

fn handle_socket_dgram_sendto(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketDgramSendToResponse);
    }
    let (handle_id, raw_addr, tokens, payload) =
        match proto::parse_socket_dgram_sendto_body(request.body) {
            Ok(v) => v,
            Err(_) => return protocol_err(Opcode::SocketDgramSendToResponse),
        };
    let state = match resolve_socket_dgram(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::SocketDgramSendToResponse, status),
    };
    let addr = if raw_addr.is_empty() {
        None
    } else {
        match decode_socket_dgram_addr(&raw_addr) {
            Ok(addr) => Some(addr),
            Err(err) => {
                return status_err(Opcode::SocketDgramSendToResponse, socket_dgram_status(err));
            }
        }
    };
    match state.sendto(addr, &payload, &tokens) {
        Ok(n) => HandlerResult {
            frame: proto::build_socket_dgram_sendto_response_ok(n as u64),
            out_fd: None,
        },
        Err(err) => status_err(Opcode::SocketDgramSendToResponse, socket_dgram_status(err)),
    }
}

fn handle_socket_dgram_recvfrom(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketDgramRecvFromResponse);
    }
    let (handle_id, max_len) = match proto::parse_socket_dgram_recvfrom_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketDgramRecvFromResponse),
    };
    let state = match resolve_socket_dgram(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::SocketDgramRecvFromResponse, status),
    };
    match state.recvfrom(max_len as usize) {
        Ok((addr, payload, flags, tokens)) => HandlerResult {
            frame: proto::build_socket_dgram_recvfrom_response_ok_with_tokens(
                &encode_socket_dgram_addr(&addr),
                &payload,
                flags,
                &tokens,
            ),
            out_fd: None,
        },
        Err(err) => status_err(
            Opcode::SocketDgramRecvFromResponse,
            socket_dgram_status(err),
        ),
    }
}

fn handle_socket_dgram_shutdown(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketDgramShutdownResponse);
    }
    let (handle_id, how) = match proto::parse_socket_dgram_shutdown_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketDgramShutdownResponse),
    };
    let state = match resolve_socket_dgram(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::SocketDgramShutdownResponse, status),
    };
    match state.shutdown(how) {
        Ok(()) => HandlerResult {
            frame: proto::build_socket_dgram_shutdown_response_ok(),
            out_fd: None,
        },
        Err(err) => status_err(
            Opcode::SocketDgramShutdownResponse,
            socket_dgram_status(err),
        ),
    }
}

fn handle_socket_dgram_getsockname(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketDgramGetSockNameResponse);
    }
    let handle_id = match parse_handle_body(request.body, Opcode::SocketDgramGetSockName) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketDgramGetSockNameResponse),
    };
    let state = match resolve_socket_dgram(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::SocketDgramGetSockNameResponse, status),
    };
    HandlerResult {
        frame: proto::build_socket_dgram_getsockname_response_ok(&encode_socket_dgram_addr(
            &state.getsockname(),
        )),
        out_fd: None,
    }
}

fn handle_socket_dgram_getpeername(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketDgramGetPeerNameResponse);
    }
    let handle_id = match parse_handle_body(request.body, Opcode::SocketDgramGetPeerName) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketDgramGetPeerNameResponse),
    };
    let state = match resolve_socket_dgram(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::SocketDgramGetPeerNameResponse, status),
    };
    match state.getpeername() {
        Ok(addr) => HandlerResult {
            frame: proto::build_socket_dgram_getpeername_response_ok(&encode_socket_dgram_addr(
                &addr,
            )),
            out_fd: None,
        },
        Err(err) => status_err(
            Opcode::SocketDgramGetPeerNameResponse,
            socket_dgram_status(err),
        ),
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
            StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::InetListener(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::HostFdAttached(_)
            | StateObjectEnum::Timerfd(_) => Err(StatusCode::SubsystemMismatch),
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

#[allow(dead_code)]
fn handle_inet_tcp_conn_create(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
    response_opcode: Opcode,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(response_opcode);
    }
    let family = match parse_inet_tcp_conn_create_body(request.body) {
        Some(family) => family,
        None => return protocol_err(response_opcode),
    };
    if family_from_u8(family).is_err() {
        return status_err(response_opcode, StatusCode::InvalidValue);
    }
    let handle = registry.register(TcpConnState::new_unconnected(family));
    HandlerResult {
        frame: build_handle_response_ok(response_opcode, handle.id()),
        out_fd: None,
    }
}

#[allow(dead_code)]
fn handle_inet_tcp_conn_connect(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
    response_opcode: Opcode,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(response_opcode);
    }
    let (handle_id, sockaddr, timeout_ms) = match parse_inet_tcp_conn_connect_body(request.body) {
        Some(parts) => parts,
        None => return protocol_err(response_opcode),
    };
    let mut target = match decode_sockaddr(&sockaddr) {
        Ok(target) => target,
        Err(_) => return status_err(response_opcode, StatusCode::InvalidValue),
    };
    if is_broker_dns_service(target) {
        target = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            crate::net_proxy::host_dns::discover_host_dns(),
            target.port(),
        ));
    }
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(state) => state,
        Err(status) => return status_err(response_opcode, status),
    };
    if let Some(listener) = registry.resolve_broker_held_inet_listener(
        target.port(),
        match target {
            std::net::SocketAddr::V4(_) => AddressFamily::V4,
            std::net::SocketAddr::V6(_) => AddressFamily::V6,
        },
    ) {
        match connect_to_broker_held_listener(&state, &listener) {
            Ok(()) => {
                return HandlerResult {
                    frame: build_empty_response_ok(response_opcode),
                    out_fd: None,
                };
            }
            Err(TcpConnError::WouldBlock) => {
                return status_err(response_opcode, StatusCode::WouldBlock);
            }
            Err(TcpConnError::PeerClosed | TcpConnError::Errno(_)) => {
                return status_err(response_opcode, StatusCode::InvalidValue);
            }
            Err(TcpConnError::Io) => return status_err(response_opcode, StatusCode::Internal),
        }
    }

    match state.start_connect(target, Duration::from_millis(u64::from(timeout_ms))) {
        Ok(()) => HandlerResult {
            frame: build_empty_response_ok(response_opcode),
            out_fd: None,
        },
        Err(TcpConnError::WouldBlock) => status_err(response_opcode, StatusCode::WouldBlock),
        Err(TcpConnError::PeerClosed | TcpConnError::Errno(_)) => {
            status_err(response_opcode, StatusCode::InvalidValue)
        }
        Err(TcpConnError::Io) => status_err(response_opcode, StatusCode::Internal),
    }
}

fn connect_to_broker_held_listener(
    state: &Arc<TcpConnState>,
    listener: &Arc<InetListenerState>,
) -> Result<(), TcpConnError> {
    let pair_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| TcpConnError::Io)?;
    pair_listener
        .set_nonblocking(false)
        .map_err(|_| TcpConnError::Io)?;
    let addr = pair_listener.local_addr().map_err(|_| TcpConnError::Io)?;
    let client = std::net::TcpStream::connect(addr).map_err(|_| TcpConnError::Io)?;
    let (server, peer) = pair_listener.accept().map_err(|_| TcpConnError::Io)?;
    listener
        .accept_inbound(server, peer)
        .map_err(inet_listener_error_to_tcp_conn_error)?;
    state.adopt_connected_stream(client)
}

fn inet_listener_error_to_tcp_conn_error(err: InetListenerError) -> TcpConnError {
    match err {
        InetListenerError::WouldBlock => TcpConnError::WouldBlock,
        InetListenerError::Io(_) => TcpConnError::Io,
        InetListenerError::InvalidFamily
        | InetListenerError::InvalidSockaddr
        | InetListenerError::AlreadyBound
        | InetListenerError::NotBound
        | InetListenerError::AlreadyListening => TcpConnError::Errno(libc::EINVAL),
    }
}

#[allow(dead_code)]
fn handle_inet_tcp_conn_getsockname(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
    response_opcode: Opcode,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(response_opcode);
    }
    let handle_id = match parse_single_handle_body(request.body) {
        Some(handle_id) => handle_id,
        None => return protocol_err(response_opcode),
    };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(state) => state,
        Err(status) => return status_err(response_opcode, status),
    };
    match state.getsockname() {
        Ok(sockaddr) => HandlerResult {
            frame: build_sockaddr_response_ok(response_opcode, &sockaddr),
            out_fd: None,
        },
        Err(TcpConnError::WouldBlock) => status_err(response_opcode, StatusCode::WouldBlock),
        Err(TcpConnError::PeerClosed | TcpConnError::Errno(_)) => {
            status_err(response_opcode, StatusCode::InvalidValue)
        }
        Err(TcpConnError::Io) => status_err(response_opcode, StatusCode::Internal),
    }
}

#[allow(dead_code)]
fn handle_inet_tcp_conn_getpeername(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
    response_opcode: Opcode,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(response_opcode);
    }
    let handle_id = match parse_single_handle_body(request.body) {
        Some(handle_id) => handle_id,
        None => return protocol_err(response_opcode),
    };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(state) => state,
        Err(status) => return status_err(response_opcode, status),
    };
    match state.getpeername() {
        Ok(sockaddr) => HandlerResult {
            frame: build_sockaddr_response_ok(response_opcode, &sockaddr),
            out_fd: None,
        },
        Err(TcpConnError::WouldBlock) => status_err(response_opcode, StatusCode::WouldBlock),
        Err(TcpConnError::PeerClosed | TcpConnError::Errno(_)) => {
            status_err(response_opcode, StatusCode::InvalidValue)
        }
        Err(TcpConnError::Io) => status_err(response_opcode, StatusCode::Internal),
    }
}

fn parse_inet_tcp_conn_create_body(body: &[u8]) -> Option<u8> {
    if body.len() != 8 || body[1..8].iter().any(|&b| b != 0) {
        return None;
    }
    Some(body[0])
}

fn parse_inet_tcp_conn_connect_body(body: &[u8]) -> Option<(u64, [u8; 28], u32)> {
    if body.len() != 40 {
        return None;
    }
    let handle = u64::from_le_bytes(body[0..8].try_into().ok()?);
    let mut sockaddr = [0u8; 28];
    sockaddr.copy_from_slice(&body[8..36]);
    let timeout_ms = u32::from_le_bytes(body[36..40].try_into().ok()?);
    Some((handle, sockaddr, timeout_ms))
}

fn parse_single_handle_body(body: &[u8]) -> Option<u64> {
    if body.len() != 8 {
        return None;
    }
    Some(u64::from_le_bytes(body.try_into().ok()?))
}

fn build_handle_response_ok(opcode: Opcode, handle_id: u64) -> OwnedFrame {
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: handle_id.to_le_bytes().to_vec(),
    }
}

fn build_empty_response_ok(opcode: Opcode) -> OwnedFrame {
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: Vec::new(),
    }
}

fn build_sockaddr_response_ok(opcode: Opcode, sockaddr: &[u8; 28]) -> OwnedFrame {
    OwnedFrame {
        opcode,
        status: StatusCode::Ok,
        caller_pid: 0,
        body: sockaddr.to_vec(),
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
            | StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::InetListener(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::HostFdAttached(_)
            | StateObjectEnum::Timerfd(_) => Err(StatusCode::SubsystemMismatch),
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
        Err(TcpConnError::PeerClosed | TcpConnError::Errno(_)) => {
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
        Err(TcpConnError::PeerClosed | TcpConnError::Errno(_)) => {
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

fn handle_inet_tcp_conn_setsockopt(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetTcpConnSetSockOptResponse);
    }
    let (handle_id, level, optname, optval) =
        match parse_inet_tcp_conn_setsockopt_body(request.body) {
            Ok(parts) => parts,
            Err(_) => return protocol_err(Opcode::InetTcpConnSetSockOptResponse),
        };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::InetTcpConnSetSockOptResponse, status),
    };
    match state.setsockopt(level, optname, &optval) {
        Ok(()) => HandlerResult {
            frame: build_inet_tcp_conn_setsockopt_response_ok(),
            out_fd: None,
        },
        Err(TcpConnError::Errno(errno)) if errno == libc::EOPNOTSUPP => status_err(
            Opcode::InetTcpConnSetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(TcpConnError::Errno(_)) => status_err(
            Opcode::InetTcpConnSetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(TcpConnError::WouldBlock | TcpConnError::PeerClosed) => status_err(
            Opcode::InetTcpConnSetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(TcpConnError::Io) => {
            status_err(Opcode::InetTcpConnSetSockOptResponse, StatusCode::Internal)
        }
    }
}

fn handle_inet_tcp_conn_getsockopt(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetTcpConnGetSockOptResponse);
    }
    let (handle_id, level, optname, optlen) =
        match parse_inet_tcp_conn_getsockopt_body(request.body) {
            Ok(parts) => parts,
            Err(_) => return protocol_err(Opcode::InetTcpConnGetSockOptResponse),
        };
    let state = match resolve_tcp_conn(registry, handle_id) {
        Ok(s) => s,
        Err(status) => return status_err(Opcode::InetTcpConnGetSockOptResponse, status),
    };
    match state.getsockopt(level, optname, optlen) {
        Ok(bytes) => HandlerResult {
            frame: build_inet_tcp_conn_getsockopt_response_ok(&bytes),
            out_fd: None,
        },
        Err(TcpConnError::Errno(errno)) if errno == libc::EOPNOTSUPP => status_err(
            Opcode::InetTcpConnGetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(TcpConnError::Errno(_)) => status_err(
            Opcode::InetTcpConnGetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(TcpConnError::WouldBlock | TcpConnError::PeerClosed) => status_err(
            Opcode::InetTcpConnGetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(TcpConnError::Io) => {
            status_err(Opcode::InetTcpConnGetSockOptResponse, StatusCode::Internal)
        }
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

fn handle_inet_dgram_create(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramCreateResponse);
    }
    let family = match proto::parse_inet_dgram_create_body(request.body)
        .ok()
        .and_then(|raw| family_from_u8(raw).ok())
    {
        Some(family) => family,
        None => return status_err(Opcode::InetDgramCreateResponse, StatusCode::InvalidValue),
    };
    let handle = registry.register(InetDgramState::new(family));
    HandlerResult {
        frame: proto::build_inet_dgram_create_response_ok(handle.id()),
        out_fd: None,
    }
}

fn resolve_inet_dgram(
    registry: &BrokerStateRegistry,
    handle_id: u64,
    response: Opcode,
) -> Result<Arc<InetDgramState>, HandlerResult> {
    let state = match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::InetDgram) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return Err(status_err(response, StatusCode::UnknownHandle));
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return Err(status_err(response, StatusCode::SubsystemMismatch));
        }
        Err(_) => return Err(status_err(response, StatusCode::Internal)),
    };
    match state.as_ref() {
        StateObjectEnum::InetDgram(dgram) => Ok(Arc::clone(dgram)),
        StateObjectEnum::Eventfd(_)
        | StateObjectEnum::PipeReadEnd(_)
        | StateObjectEnum::PipeWriteEnd(_)
        | StateObjectEnum::SocketPairEnd(_)
        | StateObjectEnum::SocketDgram(_)
        | StateObjectEnum::SocketSeqPacket(_)
        | StateObjectEnum::TcpConn(_)
        | StateObjectEnum::InetListener(_)
        | StateObjectEnum::InetRaw(_)
        | StateObjectEnum::Signalfd(_)
        | StateObjectEnum::Inotify(_)
        | StateObjectEnum::Pty(_)
        | StateObjectEnum::Pidfd(_)
        | StateObjectEnum::Process(_)
        | StateObjectEnum::HostFdAttached(_)
        | StateObjectEnum::Timerfd(_) => {
            unreachable!("registry returned wrong state variant for InetDgram tag")
        }
    }
}

fn handle_inet_dgram_bind(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramBindResponse);
    }
    let (handle_id, sockaddr) = match proto::parse_inet_dgram_bind_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetDgramBindResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramBindResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.bind(&sockaddr) {
        Ok(actual) => HandlerResult {
            frame: proto::build_inet_dgram_bind_response_ok(&actual),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramBindResponse, err),
    }
}

fn handle_inet_dgram_connect(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramConnectResponse);
    }
    let (handle_id, sockaddr) = match proto::parse_inet_dgram_connect_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetDgramConnectResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramConnectResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.connect(&sockaddr) {
        Ok(()) => HandlerResult {
            frame: proto::build_inet_dgram_connect_response_ok(),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramConnectResponse, err),
    }
}

fn handle_inet_dgram_sendto(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramSendToResponse);
    }
    let (handle_id, sockaddr, payload) = match proto::parse_inet_dgram_sendto_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetDgramSendToResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramSendToResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.sendto(&sockaddr, &payload) {
        Ok(written) => HandlerResult {
            frame: proto::build_inet_dgram_sendto_response_ok(written as u64),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramSendToResponse, err),
    }
}

fn handle_inet_dgram_recvfrom(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramRecvFromResponse);
    }
    let (handle_id, max_len) = match proto::parse_inet_dgram_recvfrom_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetDgramRecvFromResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramRecvFromResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.recvfrom(max_len as usize) {
        Ok((peer, payload, flags)) => HandlerResult {
            frame: proto::build_inet_dgram_recvfrom_response_ok(&peer, &payload, flags),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramRecvFromResponse, err),
    }
}

fn handle_inet_dgram_shutdown(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramShutdownResponse);
    }
    let (handle_id, how) = match proto::parse_inet_dgram_shutdown_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetDgramShutdownResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramShutdownResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.shutdown(how) {
        Ok(()) => HandlerResult {
            frame: proto::build_inet_dgram_shutdown_response_ok(),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramShutdownResponse, err),
    }
}

fn handle_inet_dgram_getsockname(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramGetSockNameResponse);
    }
    let handle_id = match proto::parse_inet_dgram_getsockname_body(request.body) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::InetDgramGetSockNameResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramGetSockNameResponse)
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.getsockname() {
        Ok(sockaddr) => HandlerResult {
            frame: proto::build_inet_dgram_getsockname_response_ok(&sockaddr),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramGetSockNameResponse, err),
    }
}

fn handle_inet_dgram_getpeername(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramGetPeerNameResponse);
    }
    let handle_id = match proto::parse_inet_dgram_getpeername_body(request.body) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::InetDgramGetPeerNameResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramGetPeerNameResponse)
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.getpeername() {
        Ok(sockaddr) => HandlerResult {
            frame: proto::build_inet_dgram_getpeername_response_ok(&sockaddr),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramGetPeerNameResponse, err),
    }
}

fn handle_inet_dgram_setsockopt(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramSetSockOptResponse);
    }
    let (handle_id, level, name, value) =
        match proto::parse_inet_dgram_setsockopt_body(request.body) {
            Ok(v) => v,
            Err(_) => return protocol_err(Opcode::InetDgramSetSockOptResponse),
        };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramSetSockOptResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.setsockopt(level, name, &value) {
        Ok(()) => HandlerResult {
            frame: proto::build_inet_dgram_setsockopt_response_ok(),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramSetSockOptResponse, err),
    }
}

fn handle_inet_dgram_getsockopt(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramGetSockOptResponse);
    }
    let (handle_id, level, name, max_len) =
        match proto::parse_inet_dgram_getsockopt_body(request.body) {
            Ok(v) => v,
            Err(_) => return protocol_err(Opcode::InetDgramGetSockOptResponse),
        };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramGetSockOptResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.getsockopt(level, name, max_len) {
        Ok(value) => HandlerResult {
            frame: proto::build_inet_dgram_getsockopt_response_ok(&value),
            out_fd: None,
        },
        Err(err) => dgram_error_response(Opcode::InetDgramGetSockOptResponse, err),
    }
}

fn handle_inet_dgram_query_events(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetDgramQueryEventsResponse);
    }
    let handle_id = match proto::parse_inet_dgram_query_events_body(request.body) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::InetDgramQueryEventsResponse),
    };
    let state = match resolve_inet_dgram(registry, handle_id, Opcode::InetDgramQueryEventsResponse)
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    HandlerResult {
        frame: proto::build_inet_dgram_query_events_response_ok(state.current_events()),
        out_fd: None,
    }
}

fn dgram_error_response(opcode: Opcode, err: InetDgramError) -> HandlerResult {
    match err {
        InetDgramError::WouldBlock => status_err(opcode, StatusCode::WouldBlock),
        InetDgramError::InvalidSockaddr
        | InetDgramError::AlreadyBound
        | InetDgramError::NotBound
        | InetDgramError::NotConnected
        | InetDgramError::Errno(_) => status_err(opcode, StatusCode::InvalidValue),
        InetDgramError::Io(_) => status_err(opcode, StatusCode::Internal),
    }
}

fn handle_inet_listener_create(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerCreateResponse);
    }
    let family = match parse_inet_listener_create_body(request.body).and_then(|raw| {
        family_from_u8(raw).map_err(|_| {
            litebox_common_linux::fd_token_protocol::ProtocolError::NonZeroReserved { reserved: 1 }
        })
    }) {
        Ok(family) => family,
        Err(_) => return status_err(Opcode::InetListenerCreateResponse, StatusCode::InvalidValue),
    };
    let state = InetListenerState::new(family);
    let handle = registry.register(state);
    HandlerResult {
        frame: build_inet_listener_create_response_ok(handle.id()),
        out_fd: None,
    }
}

fn resolve_inet_listener(
    registry: &BrokerStateRegistry,
    handle_id: u64,
    response: Opcode,
) -> Result<Arc<InetListenerState>, HandlerResult> {
    let state = match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::InetListener)
    {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return Err(status_err(response, StatusCode::UnknownHandle));
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return Err(status_err(response, StatusCode::SubsystemMismatch));
        }
        Err(_) => return Err(status_err(response, StatusCode::Internal)),
    };
    let StateObjectEnum::InetListener(listener) = state.as_ref() else {
        return Err(status_err(response, StatusCode::SubsystemMismatch));
    };
    Ok(Arc::clone(listener))
}

fn handle_inet_listener_setsockopt(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerSetSockOptResponse);
    }
    let (handle_id, level, optname, optval) =
        match proto::parse_inet_listener_setsockopt_body(request.body) {
            Ok(parts) => parts,
            Err(_) => return protocol_err(Opcode::InetListenerSetSockOptResponse),
        };
    let state =
        match resolve_inet_listener(registry, handle_id, Opcode::InetListenerSetSockOptResponse) {
            Ok(s) => s,
            Err(r) => return r,
        };
    match state.setsockopt(level, optname, &optval) {
        Ok(()) => HandlerResult {
            frame: proto::build_inet_listener_setsockopt_response_ok(),
            out_fd: None,
        },
        Err(
            InetListenerError::InvalidFamily
            | InetListenerError::InvalidSockaddr
            | InetListenerError::AlreadyBound,
        ) => status_err(
            Opcode::InetListenerSetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(InetListenerError::Io(_)) => {
            status_err(Opcode::InetListenerSetSockOptResponse, StatusCode::Internal)
        }
        Err(_) => status_err(
            Opcode::InetListenerSetSockOptResponse,
            StatusCode::InvalidValue,
        ),
    }
}

fn handle_inet_listener_getsockname(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerGetSockNameResponse);
    }
    let handle_id = match parse_inet_listener_getsockname_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetListenerGetSockNameResponse),
    };
    let state =
        match resolve_inet_listener(registry, handle_id, Opcode::InetListenerGetSockNameResponse) {
            Ok(s) => s,
            Err(r) => return r,
        };
    match state.getsockname() {
        Ok(sockaddr) => HandlerResult {
            frame: build_inet_listener_getsockname_response_ok(&sockaddr),
            out_fd: None,
        },
        Err(InetListenerError::NotBound) => status_err(
            Opcode::InetListenerGetSockNameResponse,
            StatusCode::InvalidValue,
        ),
        Err(InetListenerError::InvalidFamily | InetListenerError::InvalidSockaddr) => status_err(
            Opcode::InetListenerGetSockNameResponse,
            StatusCode::InvalidValue,
        ),
        Err(InetListenerError::Io(_)) => status_err(
            Opcode::InetListenerGetSockNameResponse,
            StatusCode::Internal,
        ),
        Err(_) => status_err(
            Opcode::InetListenerGetSockNameResponse,
            StatusCode::InvalidValue,
        ),
    }
}

fn handle_inet_listener_getsockopt(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerGetSockOptResponse);
    }
    let (handle_id, level, optname, optlen) =
        match parse_inet_listener_getsockopt_body(request.body) {
            Ok(parts) => parts,
            Err(_) => return protocol_err(Opcode::InetListenerGetSockOptResponse),
        };
    let state =
        match resolve_inet_listener(registry, handle_id, Opcode::InetListenerGetSockOptResponse) {
            Ok(s) => s,
            Err(r) => return r,
        };
    match state.getsockopt(level, optname, optlen) {
        Ok(value) => HandlerResult {
            frame: build_inet_listener_getsockopt_response_ok(&value),
            out_fd: None,
        },
        Err(InetListenerError::InvalidFamily | InetListenerError::InvalidSockaddr) => status_err(
            Opcode::InetListenerGetSockOptResponse,
            StatusCode::InvalidValue,
        ),
        Err(InetListenerError::Io(_)) => {
            status_err(Opcode::InetListenerGetSockOptResponse, StatusCode::Internal)
        }
        Err(_) => status_err(
            Opcode::InetListenerGetSockOptResponse,
            StatusCode::InvalidValue,
        ),
    }
}

fn handle_inet_listener_bind(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerBindResponse);
    }
    let (handle_id, sockaddr) = match parse_inet_listener_bind_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetListenerBindResponse),
    };
    let state = match resolve_inet_listener(registry, handle_id, Opcode::InetListenerBindResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    // If the requested port is already owned by the broker's net_proxy
    // inbound forwarder, use a virtual bind: inbound traffic flows in
    // via accept_inbound, so binding the host port (which would EADDRINUSE)
    // is both unnecessary and wrong.
    let requested_port = decode_sockaddr(&sockaddr).ok().map(|a| a.port());
    let use_virtual = match requested_port {
        Some(port) if port != 0 => registry.is_inbound_forwarded(port),
        _ => false,
    };
    if use_virtual
        && let Some(port) = requested_port
        && port != 0
        && registry.has_broker_held_inet_listener(
            port,
            state.family(),
            StateHandle::from_id(handle_id),
        )
    {
        return status_err(Opcode::InetListenerBindResponse, StatusCode::InvalidValue);
    }
    let bind_result = if use_virtual {
        state.virtual_bind(&sockaddr)
    } else {
        state.bind(&sockaddr)
    };
    match bind_result {
        Ok(actual) => {
            let actual_addr = match decode_sockaddr(&actual) {
                Ok(addr) => addr,
                Err(InetListenerError::InvalidSockaddr) | Err(InetListenerError::InvalidFamily) => {
                    return status_err(Opcode::InetListenerBindResponse, StatusCode::Internal);
                }
                Err(InetListenerError::AlreadyBound)
                | Err(InetListenerError::NotBound)
                | Err(InetListenerError::AlreadyListening)
                | Err(InetListenerError::WouldBlock)
                | Err(InetListenerError::Io(_)) => {
                    return status_err(Opcode::InetListenerBindResponse, StatusCode::Internal);
                }
            };
            if use_virtual
                && registry
                    .register_broker_held_inet_listener(
                        actual_addr.port(),
                        state.family(),
                        StateHandle::from_id(handle_id),
                    )
                    .is_err()
            {
                return status_err(Opcode::InetListenerBindResponse, StatusCode::InvalidValue);
            }
            HandlerResult {
                frame: build_inet_listener_bind_response_ok(&actual),
                out_fd: None,
            }
        }
        Err(
            InetListenerError::InvalidFamily
            | InetListenerError::InvalidSockaddr
            | InetListenerError::AlreadyBound,
        ) => status_err(Opcode::InetListenerBindResponse, StatusCode::InvalidValue),
        Err(InetListenerError::Io(_)) => {
            status_err(Opcode::InetListenerBindResponse, StatusCode::Internal)
        }
        Err(_) => status_err(Opcode::InetListenerBindResponse, StatusCode::InvalidValue),
    }
}

fn handle_inet_listener_listen(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerListenResponse);
    }
    let (handle_id, backlog) = match parse_inet_listener_listen_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetListenerListenResponse),
    };
    let state = match resolve_inet_listener(registry, handle_id, Opcode::InetListenerListenResponse)
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.listen(backlog) {
        Ok(()) => HandlerResult {
            frame: build_inet_listener_listen_response_ok(),
            out_fd: None,
        },
        Err(InetListenerError::NotBound | InetListenerError::AlreadyListening) => {
            status_err(Opcode::InetListenerListenResponse, StatusCode::InvalidValue)
        }
        Err(InetListenerError::Io(_)) => {
            status_err(Opcode::InetListenerListenResponse, StatusCode::Internal)
        }
        Err(_) => status_err(Opcode::InetListenerListenResponse, StatusCode::InvalidValue),
    }
}

fn handle_inet_listener_accept(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerAcceptResponse);
    }
    let handle_id = match parse_inet_listener_accept_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetListenerAcceptResponse),
    };
    let state = match resolve_inet_listener(registry, handle_id, Opcode::InetListenerAcceptResponse)
    {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.accept() {
        Ok((stream, peer)) => {
            let conn = TcpConnState::new(stream);
            let conn_handle = registry.register(conn);
            let peer = match encode_sockaddr(peer) {
                Ok(peer) => peer,
                Err(_) => {
                    return status_err(Opcode::InetListenerAcceptResponse, StatusCode::Internal);
                }
            };
            HandlerResult {
                frame: build_inet_listener_accept_response_ok(conn_handle.id(), &peer),
                out_fd: None,
            }
        }
        Err(InetListenerError::WouldBlock) => {
            status_err(Opcode::InetListenerAcceptResponse, StatusCode::WouldBlock)
        }
        Err(InetListenerError::NotBound) => {
            status_err(Opcode::InetListenerAcceptResponse, StatusCode::InvalidValue)
        }
        Err(InetListenerError::Io(_)) => {
            status_err(Opcode::InetListenerAcceptResponse, StatusCode::Internal)
        }
        Err(_) => status_err(Opcode::InetListenerAcceptResponse, StatusCode::InvalidValue),
    }
}

fn handle_inet_listener_query_events(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetListenerQueryEventsResponse);
    }
    let handle_id = match parse_inet_listener_query_events_body(request.body) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::InetListenerQueryEventsResponse),
    };
    let state =
        match resolve_inet_listener(registry, handle_id, Opcode::InetListenerQueryEventsResponse) {
            Ok(s) => s,
            Err(r) => return r,
        };
    HandlerResult {
        frame: build_inet_listener_query_events_response_ok(state.current_events()),
        out_fd: None,
    }
}

fn handle_inet_raw_create(
    _registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetRawCreateResponse);
    }
    let (family, protocol) = match parse_inet_raw_create_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetRawCreateResponse),
    };
    if family_from_u8(family).is_err() {
        return status_err(Opcode::InetRawCreateResponse, StatusCode::InvalidValue);
    }
    if i32::from(protocol) != libc::IPPROTO_ICMP {
        return status_err(
            Opcode::InetRawCreateResponse,
            StatusCode::ProtocolNotSupported,
        );
    }
    status_err(Opcode::InetRawCreateResponse, StatusCode::PermissionDenied)
}

fn resolve_inet_raw(
    registry: &BrokerStateRegistry,
    handle_id: u64,
    response: Opcode,
) -> Result<Arc<InetRawState>, HandlerResult> {
    let state = match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::InetRaw) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return Err(status_err(response, StatusCode::UnknownHandle));
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return Err(status_err(response, StatusCode::SubsystemMismatch));
        }
        Err(_) => return Err(status_err(response, StatusCode::Internal)),
    };
    let StateObjectEnum::InetRaw(raw) = state.as_ref() else {
        return Err(status_err(response, StatusCode::SubsystemMismatch));
    };
    Ok(Arc::clone(raw))
}

fn handle_inet_raw_sendto(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetRawSendToResponse);
    }
    let (handle_id, sockaddr, bytes) = match parse_inet_raw_sendto_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetRawSendToResponse),
    };
    let state = match resolve_inet_raw(registry, handle_id, Opcode::InetRawSendToResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.send_to(&sockaddr, &bytes) {
        Ok(written) => HandlerResult {
            #[allow(clippy::cast_possible_truncation)]
            frame: build_inet_raw_sendto_response_ok(written as u32),
            out_fd: None,
        },
        Err(InetRawError::WouldBlock) => {
            status_err(Opcode::InetRawSendToResponse, StatusCode::WouldBlock)
        }
        Err(InetRawError::InvalidValue) => {
            status_err(Opcode::InetRawSendToResponse, StatusCode::InvalidValue)
        }
        Err(InetRawError::PermissionDenied) => {
            status_err(Opcode::InetRawSendToResponse, StatusCode::PermissionDenied)
        }
    }
}

fn handle_inet_raw_recvfrom(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetRawRecvFromResponse);
    }
    let (handle_id, max_len) = match parse_inet_raw_recvfrom_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InetRawRecvFromResponse),
    };
    let state = match resolve_inet_raw(registry, handle_id, Opcode::InetRawRecvFromResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.recv_from(max_len) {
        Ok((sockaddr, bytes)) => HandlerResult {
            frame: build_inet_raw_recvfrom_response_ok(&sockaddr, &bytes),
            out_fd: None,
        },
        Err(InetRawError::WouldBlock) => {
            status_err(Opcode::InetRawRecvFromResponse, StatusCode::WouldBlock)
        }
        Err(InetRawError::InvalidValue) => {
            status_err(Opcode::InetRawRecvFromResponse, StatusCode::InvalidValue)
        }
        Err(InetRawError::PermissionDenied) => status_err(
            Opcode::InetRawRecvFromResponse,
            StatusCode::PermissionDenied,
        ),
    }
}

fn handle_inet_raw_query_events(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InetRawQueryEventsResponse);
    }
    let handle_id = match parse_inet_raw_query_events_body(request.body) {
        Ok(id) => id,
        Err(_) => return protocol_err(Opcode::InetRawQueryEventsResponse),
    };
    let state = match resolve_inet_raw(registry, handle_id, Opcode::InetRawQueryEventsResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    HandlerResult {
        frame: build_inet_raw_query_events_response_ok(state.current_events()),
        out_fd: None,
    }
}

fn handle_inotify_init1(
    registry: &BrokerStateRegistry,
    dispatcher: &Arc<InotifyDispatcher>,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InotifyInit1Response);
    }
    if parse_inotify_init1_body(request.body).is_err() {
        return protocol_err(Opcode::InotifyInit1Response);
    }
    let state = InotifyState::new(Arc::clone(dispatcher));
    let handle = registry.register(state);
    HandlerResult {
        frame: build_inotify_init1_response_ok(handle.id()),
        out_fd: None,
    }
}

fn resolve_inotify(
    registry: &BrokerStateRegistry,
    handle_id: u64,
    response: Opcode,
) -> Result<Arc<InotifyState>, HandlerResult> {
    let state = match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::Inotify) {
        Ok(s) => s,
        Err(StateRegistryError::UnknownHandle(_)) => {
            return Err(status_err(response, StatusCode::UnknownHandle));
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            return Err(status_err(response, StatusCode::SubsystemMismatch));
        }
        Err(_) => return Err(status_err(response, StatusCode::Internal)),
    };
    let StateObjectEnum::Inotify(inotify) = state.as_ref() else {
        return Err(status_err(response, StatusCode::SubsystemMismatch));
    };
    Ok(Arc::clone(inotify))
}

fn handle_inotify_add_watch(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InotifyAddWatchResponse);
    }
    let (handle_id, mask, path) = match parse_inotify_add_watch_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InotifyAddWatchResponse),
    };
    let state = match resolve_inotify(registry, handle_id, Opcode::InotifyAddWatchResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.add_watch(path, mask) {
        Ok(wd) => HandlerResult {
            frame: build_inotify_add_watch_response_ok(wd),
            out_fd: None,
        },
        Err(()) => status_err(Opcode::InotifyAddWatchResponse, StatusCode::InvalidValue),
    }
}

fn handle_inotify_rm_watch(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InotifyRmWatchResponse);
    }
    let (handle_id, wd) = match parse_inotify_rm_watch_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InotifyRmWatchResponse),
    };
    let state = match resolve_inotify(registry, handle_id, Opcode::InotifyRmWatchResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.remove_watch(wd) {
        Ok(()) => HandlerResult {
            frame: build_inotify_rm_watch_response_ok(),
            out_fd: None,
        },
        Err(()) => status_err(Opcode::InotifyRmWatchResponse, StatusCode::InvalidValue),
    }
}

fn handle_inotify_read(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::InotifyReadResponse);
    }
    let (handle_id, max_len) = match parse_inotify_read_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::InotifyReadResponse),
    };
    let state = match resolve_inotify(registry, handle_id, Opcode::InotifyReadResponse) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.read_events(max_len as usize) {
        Ok(Some(payload)) => HandlerResult {
            frame: build_inotify_read_response_ok(&payload),
            out_fd: None,
        },
        Ok(None) => status_err(Opcode::InotifyReadResponse, StatusCode::WouldBlock),
        Err(()) => status_err(Opcode::InotifyReadResponse, StatusCode::InvalidValue),
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
    // pty_id must be globally unique across the broker's lifetime so
    // `open_pty_slave(pty_id)` can unambiguously identify the matching
    // PtyPairState. The earlier `live_handle_count() / 2` formula
    // collided across pairs (e.g., nested PTY in script(1) under
    // dropbear yielded two pairs with pty_id=3), causing
    // open_pty_slave to dup the WRONG slave handle and the
    // user-slave-close detector to fire HUP on the wrong master —
    // which manifested as script(1) busy-looping on POLLHUP and
    // never exiting, breaking nested-PTY scenarios (Copilot CLI TUI).
    static NEXT_PTY_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let pty_id = NEXT_PTY_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pair = PtyState::new_pair(pty_id);
    let master_arc = std::sync::Arc::clone(&pair.master);
    let slave_arc = std::sync::Arc::clone(&pair.slave);
    let master = registry.register(pair.master);
    let slave = registry.register(pair.slave);
    // Record the registry handle ids on the shared PtyPairState so
    // handle_release_state can compute
    // `user_slave_count = rc(slave) - rc(master)` and fire master
    // POLLHUP only when the last user-space slave fd closes — not
    // when a fork-dup'd anchor ref incidentally brings rc(slave) to
    // 1, which was the previous (buggy) heuristic.
    master_arc.record_handles(master.id(), slave.id());
    drop(slave_arc);
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
            | StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::SocketSeqPacket(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::InetListener(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::HostFdAttached(_)
            | StateObjectEnum::Timerfd(_) => {
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
        Err(PtyError::Invalid) => status_err(Opcode::PtyWriteResponse, StatusCode::InvalidValue),
        // Real Linux PTY semantics: write to a slave whose master is
        // closed (or master whose all-slaves are closed) returns EIO.
        // Map `PtyError::Closed` → `StatusCode::Io` so the shim returns
        // `Errno::EIO` rather than `EINVAL`. Reproduced headlessly by
        // `PTYR.slave_write_after_master_close`; surfaced in
        // `copilot::tui.find_head` as a blank TUI screen (copilot's
        // render loop spun on unexpected EINVAL from `write(stdout)`).
        Err(PtyError::Closed) => status_err(Opcode::PtyWriteResponse, StatusCode::Io),
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
        Err(PtyError::Invalid) => status_err(Opcode::PtyIoctlResponse, StatusCode::InvalidValue),
        // PTY ioctls currently never report `Closed` (lifetime is
        // enforced by handle resolution above). If a future change to
        // `PtyState::ioctl` introduces this path, decide explicitly
        // whether it should map to `Io` or `InvalidValue` rather than
        // silently collapsing into one of them.
        Err(PtyError::Closed) => {
            unreachable!("PtyState::ioctl never returns Closed under current impl")
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
    //
    // For slave releases: fire master POLLHUP only when the last
    // user-space slave fd closes. Each master shim fd holds an
    // anchor on the slave (broker_pty.rs `slave_anchor_handle`), so
    // each master contributes +1 to both rc(master) and rc(slave).
    // Therefore the number of user-space slave fds is
    //   user_slave_count = rc(slave) - rc(master)
    // After this release, if user_slave_count transitions to 0 (and
    // the slave handle is still alive — rc(slave) > 0, otherwise
    // `Drop` will fire HUP on its own), notify the master.
    //
    // The previous heuristic ("fire when rc(slave) == 1 after
    // release") worked for single-worker setups where rc(slave) was
    // exactly 1 user-fd + 1 anchor. It failed under fork-inherit
    // (multiple workers each holding an anchor) and nested PTYs:
    // rc(slave) could transition through 1 incidentally during
    // anchor cycling, firing bogus POLLHUP that made `script(1)`
    // busy-loop on poll() and never exit — the Copilot CLI TUI hang.
    let pty_state: Option<Arc<StateObjectEnum>> = registry
        .resolve(StateHandle::from_id(handle_id), SubsystemTag::Pty)
        .ok();
    match registry.release(StateHandle::from_id(handle_id)) {
        Ok(new_rc) => {
            if let Some(state) = pty_state
                && let StateObjectEnum::Pty(pty) = state.as_ref()
                && pty.endpoint() == PtyEndpoint::Slave
                && new_rc > 0
            {
                let master_handle_id = pty.master_handle_id();
                if master_handle_id != 0 {
                    let rc_master = registry.refcount(StateHandle::from_id(master_handle_id));
                    let user_slave_count = new_rc.saturating_sub(rc_master);
                    if user_slave_count == 0 {
                        // Last user-space slave fd-holder released;
                        // remaining slave rcs are all master anchors.
                        // Notify master with HUP+IN.
                        pty.notify_slave_close_to_master();
                    }
                }
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

/// Resolves `handle_id` to its registered [`StateObjectEnum`] and
/// returns the broker's authoritative current event mask via
/// [`StateObjectEnum::current_events`]. Read-only and safe to call at
/// arbitrary cadence; no refcount mutation.
fn handle_query_events(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::QueryEventsResponse);
    }
    let handle_id =
        match litebox_common_linux::fd_token_protocol::parse_query_events_request(request.body) {
            Ok(id) => id,
            Err(_) => return protocol_err(Opcode::QueryEventsResponse),
        };
    let state = match registry.resolve_untyped(StateHandle::from_id(handle_id)) {
        Ok(state) => state,
        Err(_) => return status_err(Opcode::QueryEventsResponse, StatusCode::UnknownHandle),
    };
    HandlerResult {
        frame: litebox_common_linux::fd_token_protocol::build_query_events_response_ok(
            state.current_events(),
        ),
        out_fd: None,
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

#[cfg(debug_assertions)]
fn handle_debug_query_state_object(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::DebugQueryStateObjectResponse);
    }
    let handle_id =
        match litebox_common_linux::fd_token_protocol::parse_debug_query_state_object_request(
            request.body,
        ) {
            Ok(id) => id,
            Err(_) => return protocol_err(Opcode::DebugQueryStateObjectResponse),
        };
    let (tag, refcount, debug_info) = match registry.debug_query(StateHandle::from_id(handle_id)) {
        Ok(info) => info,
        Err(_) => {
            return status_err(
                Opcode::DebugQueryStateObjectResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    HandlerResult {
        frame: litebox_common_linux::fd_token_protocol::build_debug_query_state_object_response_ok(
            tag.as_u8(),
            refcount,
            &debug_info,
        ),
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
    use std::os::fd::FromRawFd;

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
        let inotify_dispatcher = Arc::new(InotifyDispatcher::new());
        handle_request(registry, &inotify_dispatcher, conn, &frame, Vec::new())
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

    // ---------------------------------------------------------------
    // Phase 3 (legacy-pipes retirement): AttachHostFd integration
    // tests. Drive the dispatch end-to-end (frame → handle_request →
    // HostFdState → read_pipe/write_pipe routing).
    // ---------------------------------------------------------------

    fn run_with_fds(
        registry: &BrokerStateRegistry,
        conn: &mut ConnState,
        request: &OwnedFrame,
        in_fds: Vec<OwnedFd>,
    ) -> HandlerResult {
        let bytes = request.encode().unwrap();
        let frame = decode(&bytes).unwrap();
        let inotify_dispatcher = Arc::new(InotifyDispatcher::new());
        handle_request(registry, &inotify_dispatcher, conn, &frame, in_fds)
    }

    fn make_host_pipe_pair() -> (OwnedFd, OwnedFd) {
        use std::os::fd::FromRawFd;
        let mut fds = [0i32; 2];
        // SAFETY: fds is a 2-element c_int array; pipe2 fills both.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(rc, 0, "pipe2 failed");
        // SAFETY: both fds are freshly created by pipe2.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn attach_host_fd_registers_handle() {
        use litebox_common_linux::fd_token_protocol::{
            build_attach_host_fd_request, host_fd_direction,
        };
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let (r, _w) = make_host_pipe_pair();
        let result = run_with_fds(
            &registry,
            &mut conn,
            &build_attach_host_fd_request(host_fd_direction::READ),
            vec![r],
        );
        assert_eq!(result.frame.opcode, Opcode::AttachHostFdResponse);
        assert_eq!(result.frame.status, StatusCode::Ok);
        assert_eq!(result.frame.body.len(), 8);
        let handle_id = u64::from_le_bytes(result.frame.body[..8].try_into().unwrap());
        assert!(handle_id > 0);
        assert_eq!(registry.live_handle_count(), 1);
    }

    #[test]
    fn attach_host_fd_missing_cmsg_is_protocol_error() {
        use litebox_common_linux::fd_token_protocol::{
            build_attach_host_fd_request, host_fd_direction,
        };
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let result = run_with_fds(
            &registry,
            &mut conn,
            &build_attach_host_fd_request(host_fd_direction::READ),
            vec![],
        );
        assert_eq!(result.frame.opcode, Opcode::AttachHostFdResponse);
        assert_eq!(result.frame.status, StatusCode::Protocol);
        assert_eq!(registry.live_handle_count(), 0);
    }

    #[test]
    fn attach_host_fd_invalid_direction_is_protocol_error() {
        use litebox_common_linux::fd_token_protocol::build_attach_host_fd_request;
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let (r, _w) = make_host_pipe_pair();
        let result = run_with_fds(
            &registry,
            &mut conn,
            // 99 is not a valid direction code.
            &build_attach_host_fd_request(99),
            vec![r],
        );
        assert_eq!(result.frame.opcode, Opcode::AttachHostFdResponse);
        assert_eq!(result.frame.status, StatusCode::Protocol);
    }

    #[test]
    fn attach_host_fd_then_read_pipe_round_trip() {
        use litebox_common_linux::fd_token_protocol::{
            build_attach_host_fd_request, build_read_pipe_request, host_fd_direction,
        };
        use std::io::Write;
        use std::os::fd::IntoRawFd;

        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let (r, w) = make_host_pipe_pair();
        // Attach the read end.
        let attach = run_with_fds(
            &registry,
            &mut conn,
            &build_attach_host_fd_request(host_fd_direction::READ),
            vec![r],
        );
        assert_eq!(attach.frame.status, StatusCode::Ok);
        let handle_id = u64::from_le_bytes(attach.frame.body[..8].try_into().unwrap());

        // Push data into the pipe via the writer end (still owned by
        // the test, simulating the worker that didn't transfer it).
        // SAFETY: w is the unique OwnedFd; into_raw_fd transfers
        // ownership without closing so File::from_raw_fd is sound.
        let mut writer = unsafe { std::fs::File::from_raw_fd(w.into_raw_fd()) };
        writer.write_all(b"hello").unwrap();
        drop(writer); // close → EOF on the broker-held read end
        // Tiny sleep to let the poll thread/kernel buffer settle.
        std::thread::sleep(std::time::Duration::from_millis(20));

        // ReadPipe RPC against the host-fd handle.
        let read = run(
            &registry,
            &mut conn,
            &build_read_pipe_request(handle_id, 64),
        );
        assert_eq!(read.frame.opcode, Opcode::ReadPipeResponse);
        assert_eq!(read.frame.status, StatusCode::Ok);
        // body[..8] = length prefix, then payload
        let len = u64::from_le_bytes(read.frame.body[..8].try_into().unwrap()) as usize;
        assert_eq!(len, 5);
        assert_eq!(&read.frame.body[8..8 + len], b"hello");
    }

    #[test]
    fn attach_host_fd_then_write_pipe_round_trip() {
        use litebox_common_linux::fd_token_protocol::{
            build_attach_host_fd_request, build_write_pipe_request, host_fd_direction,
        };
        use std::io::Read;
        use std::os::fd::IntoRawFd;

        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let (r, w) = make_host_pipe_pair();
        // Attach the write end.
        let attach = run_with_fds(
            &registry,
            &mut conn,
            &build_attach_host_fd_request(host_fd_direction::WRITE),
            vec![w],
        );
        assert_eq!(attach.frame.status, StatusCode::Ok);
        let handle_id = u64::from_le_bytes(attach.frame.body[..8].try_into().unwrap());

        // WritePipe RPC against the host-fd handle.
        let write = run(
            &registry,
            &mut conn,
            &build_write_pipe_request(handle_id, b"pong"),
        );
        assert_eq!(write.frame.opcode, Opcode::WritePipeResponse);
        assert_eq!(write.frame.status, StatusCode::Ok);

        // The reader end is still in test-process hands; verify it
        // sees the bytes.
        // SAFETY: r is unique here.
        let mut reader = unsafe { std::fs::File::from_raw_fd(r.into_raw_fd()) };
        let mut buf = [0u8; 64];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    #[test]
    fn attach_host_fd_read_only_rejects_write_pipe() {
        use litebox_common_linux::fd_token_protocol::{
            build_attach_host_fd_request, build_write_pipe_request, host_fd_direction,
        };
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let (r, _w) = make_host_pipe_pair();
        let attach = run_with_fds(
            &registry,
            &mut conn,
            &build_attach_host_fd_request(host_fd_direction::READ),
            vec![r],
        );
        let handle_id = u64::from_le_bytes(attach.frame.body[..8].try_into().unwrap());
        let write = run(
            &registry,
            &mut conn,
            &build_write_pipe_request(handle_id, b"x"),
        );
        assert_eq!(write.frame.opcode, Opcode::WritePipeResponse);
        assert_eq!(write.frame.status, StatusCode::SubsystemMismatch);
    }

    #[test]
    fn attach_host_fd_write_only_rejects_read_pipe() {
        use litebox_common_linux::fd_token_protocol::{
            build_attach_host_fd_request, build_read_pipe_request, host_fd_direction,
        };
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let (_r, w) = make_host_pipe_pair();
        let attach = run_with_fds(
            &registry,
            &mut conn,
            &build_attach_host_fd_request(host_fd_direction::WRITE),
            vec![w],
        );
        let handle_id = u64::from_le_bytes(attach.frame.body[..8].try_into().unwrap());
        let read = run(
            &registry,
            &mut conn,
            &build_read_pipe_request(handle_id, 64),
        );
        assert_eq!(read.frame.opcode, Opcode::ReadPipeResponse);
        assert_eq!(read.frame.status, StatusCode::SubsystemMismatch);
    }

    #[test]
    fn release_host_fd_handle_drops_from_registry() {
        use litebox_common_linux::fd_token_protocol::{
            build_attach_host_fd_request, host_fd_direction,
        };
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let (r, _w) = make_host_pipe_pair();
        let attach = run_with_fds(
            &registry,
            &mut conn,
            &build_attach_host_fd_request(host_fd_direction::READ),
            vec![r],
        );
        let handle_id = u64::from_le_bytes(attach.frame.body[..8].try_into().unwrap());
        assert_eq!(registry.live_handle_count(), 1);
        let release = run(
            &registry,
            &mut conn,
            &litebox_common_linux::fd_token_protocol::build_release_request(handle_id),
        );
        assert_eq!(release.frame.status, StatusCode::Ok);
        assert_eq!(registry.live_handle_count(), 0);
    }

    // ====================================================================
    // Legacy-pipes Phase 3 (D3): RegisterOfd / CloneOfd handler tests.
    //
    // The end-to-end OFD-sharing behaviour is covered by the
    // `ofd_registry` unit tests (the registry has its own
    // shared-position round-trip with a real tempfile). These tests
    // validate the wire dispatch + error-path mapping that this
    // handler is responsible for:
    //   - unpaired connection → SubsystemMismatch
    //   - unknown fid / id    → UnknownHandle
    // The happy-path round-trip (RegisterOfd → CloneOfd → worker
    // writes through new fid → shared offset visible to parent)
    // gets coverage at the harness level once the shim/runner
    // client lands (D3 step 2d).
    // ====================================================================

    #[test]
    fn register_ofd_without_nine_p_server_is_subsystem_mismatch() {
        use litebox_common_linux::fd_token_protocol::build_register_ofd_request;
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let result = run(&registry, &mut conn, &build_register_ofd_request(7));
        assert_eq!(result.frame.opcode, Opcode::RegisterOfdResponse);
        assert_eq!(result.frame.status, StatusCode::SubsystemMismatch);
    }

    #[test]
    fn clone_ofd_without_nine_p_server_is_subsystem_mismatch() {
        use litebox_common_linux::fd_token_protocol::build_clone_ofd_request;
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let result = run(&registry, &mut conn, &build_clone_ofd_request(0xCAFE, 9));
        assert_eq!(result.frame.opcode, Opcode::CloneOfdResponse);
        assert_eq!(result.frame.status, StatusCode::SubsystemMismatch);
    }

    fn make_test_server() -> Arc<crate::nine_p::server::Server> {
        use crate::nine_p::server::Server;
        use crate::ofd_registry::OfdRegistry;
        use crate::policy::AllowAllPolicy;
        let inotify_dispatcher = Arc::new(InotifyDispatcher::new());
        let mut server = Server::new(
            std::env::temp_dir(),
            Arc::new(AllowAllPolicy),
            false,
            inotify_dispatcher,
        );
        server.set_ofd_registry(Arc::new(OfdRegistry::new()));
        Arc::new(server)
    }

    #[test]
    fn register_ofd_unknown_fid_returns_unknown_handle() {
        use litebox_common_linux::fd_token_protocol::build_register_ofd_request;
        let server = make_test_server();
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        conn.set_nine_p_server(server);
        let result = run(&registry, &mut conn, &build_register_ofd_request(42));
        assert_eq!(result.frame.opcode, Opcode::RegisterOfdResponse);
        assert_eq!(result.frame.status, StatusCode::UnknownHandle);
    }

    #[test]
    fn clone_ofd_unknown_id_returns_unknown_handle() {
        use litebox_common_linux::fd_token_protocol::build_clone_ofd_request;
        let server = make_test_server();
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        conn.set_nine_p_server(server);
        let result = run(
            &registry,
            &mut conn,
            &build_clone_ofd_request(0xDEADBEEF, 5),
        );
        assert_eq!(result.frame.opcode, Opcode::CloneOfdResponse);
        assert_eq!(result.frame.status, StatusCode::UnknownHandle);
    }

    /// Malformed `RegisterOfd` body (wrong length) returns a
    /// protocol error frame.
    #[test]
    fn register_ofd_malformed_body_is_protocol_error() {
        let request = OwnedFrame {
            opcode: Opcode::RegisterOfd,
            status: StatusCode::Ok,
            caller_pid: 0,
            body: vec![0u8; 4], // should be 8 bytes
        };
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let result = run(&registry, &mut conn, &request);
        assert_eq!(result.frame.opcode, Opcode::RegisterOfdResponse);
        assert_eq!(result.frame.status, StatusCode::Protocol);
    }

    /// Malformed `CloneOfd` body (wrong length) returns a protocol
    /// error frame.
    #[test]
    fn clone_ofd_malformed_body_is_protocol_error() {
        let request = OwnedFrame {
            opcode: Opcode::CloneOfd,
            status: StatusCode::Ok,
            caller_pid: 0,
            body: vec![0u8; 12], // should be 16 bytes
        };
        let registry = BrokerStateRegistry::new();
        let mut conn = ConnState::new();
        let result = run(&registry, &mut conn, &request);
        assert_eq!(result.frame.opcode, Opcode::CloneOfdResponse);
        assert_eq!(result.frame.status, StatusCode::Protocol);
    }
}

fn socket_seqpacket_status(err: SocketSeqPacketError) -> StatusCode {
    match err {
        SocketSeqPacketError::WouldBlock => StatusCode::WouldBlock,
        SocketSeqPacketError::NoPeer
        | SocketSeqPacketError::NotConnected
        | SocketSeqPacketError::NotListening => StatusCode::UnknownHandle,
        SocketSeqPacketError::InvalidSockaddr
        | SocketSeqPacketError::AlreadyBound
        | SocketSeqPacketError::AddrInUse
        | SocketSeqPacketError::Shutdown
        | SocketSeqPacketError::AlreadyConnected => StatusCode::InvalidValue,
    }
}

fn resolve_socket_seqpacket(
    registry: &BrokerStateRegistry,
    handle_id: u64,
) -> Result<Arc<SocketSeqPacketState>, HandlerResult> {
    match registry.resolve(StateHandle::from_id(handle_id), SubsystemTag::UnixSocket) {
        Ok(state) => match state.as_ref() {
            StateObjectEnum::SocketSeqPacket(seqpacket) => Ok(Arc::clone(seqpacket)),
            StateObjectEnum::Eventfd(_)
            | StateObjectEnum::PipeReadEnd(_)
            | StateObjectEnum::PipeWriteEnd(_)
            | StateObjectEnum::SocketPairEnd(_)
            | StateObjectEnum::SocketDgram(_)
            | StateObjectEnum::TcpConn(_)
            | StateObjectEnum::InetListener(_)
            | StateObjectEnum::InetDgram(_)
            | StateObjectEnum::InetRaw(_)
            | StateObjectEnum::Signalfd(_)
            | StateObjectEnum::Inotify(_)
            | StateObjectEnum::Pty(_)
            | StateObjectEnum::Pidfd(_)
            | StateObjectEnum::Process(_)
            | StateObjectEnum::HostFdAttached(_)
            | StateObjectEnum::Timerfd(_) => Err(status_err(
                Opcode::ReleaseResponse,
                StatusCode::SubsystemMismatch,
            )),
        },
        Err(StateRegistryError::UnknownHandle(_)) => Err(status_err(
            Opcode::ReleaseResponse,
            StatusCode::UnknownHandle,
        )),
        Err(StateRegistryError::TagMismatch { .. }) => Err(status_err(
            Opcode::ReleaseResponse,
            StatusCode::SubsystemMismatch,
        )),
        Err(_) => Err(status_err(Opcode::ReleaseResponse, StatusCode::Internal)),
    }
}

fn handle_create_socket_seqpacket(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::CreateSocketSeqPacketResponse);
    }
    let pair = match proto::parse_create_socket_seqpacket_body(request.body) {
        Ok(pair) => pair,
        Err(_) => return protocol_err(Opcode::CreateSocketSeqPacketResponse),
    };
    if pair {
        let (a, b) = SocketSeqPacketState::new_pair();
        let ha = registry.register(a);
        let hb = registry.register(b);
        HandlerResult {
            frame: proto::build_create_socket_seqpacket_pair_response_ok(ha.id(), hb.id()),
            out_fd: None,
        }
    } else {
        let handle = registry.register(SocketSeqPacketState::new());
        HandlerResult {
            frame: proto::build_create_socket_seqpacket_response_ok(handle.id()),
            out_fd: None,
        }
    }
}

fn handle_socket_seqpacket_bind(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketBindResponse);
    }
    let (handle_id, raw_addr) = match proto::parse_socket_seqpacket_bind_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketBindResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketBindResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    let addr = match decode_socket_seqpacket_addr(&raw_addr) {
        Ok(a) => a,
        Err(e) => {
            return status_err(
                Opcode::SocketSeqPacketBindResponse,
                socket_seqpacket_status(e),
            );
        }
    };
    match state.bind(addr) {
        Ok(bound) => HandlerResult {
            frame: proto::build_socket_seqpacket_bind_response_ok(&encode_socket_seqpacket_addr(
                &bound,
            )),
            out_fd: None,
        },
        Err(e) => status_err(
            Opcode::SocketSeqPacketBindResponse,
            socket_seqpacket_status(e),
        ),
    }
}

fn handle_socket_seqpacket_listen(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketListenResponse);
    }
    let (handle_id, backlog) = match proto::parse_socket_seqpacket_listen_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketListenResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketListenResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    match state.listen(backlog) {
        Ok(()) => HandlerResult {
            frame: proto::build_socket_seqpacket_listen_response_ok(),
            out_fd: None,
        },
        Err(e) => status_err(
            Opcode::SocketSeqPacketListenResponse,
            socket_seqpacket_status(e),
        ),
    }
}

fn handle_socket_seqpacket_accept(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketAcceptResponse);
    }
    let handle_id = match proto::parse_socket_seqpacket_accept_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketAcceptResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketAcceptResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    match state.accept() {
        Ok(accepted) => {
            let h = registry.register(accepted);
            HandlerResult {
                frame: proto::build_socket_seqpacket_accept_response_ok(h.id()),
                out_fd: None,
            }
        }
        Err(e) => status_err(
            Opcode::SocketSeqPacketAcceptResponse,
            socket_seqpacket_status(e),
        ),
    }
}

fn handle_socket_seqpacket_connect(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketConnectResponse);
    }
    let (handle_id, raw_addr) = match proto::parse_socket_seqpacket_connect_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketConnectResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketConnectResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    let addr = match decode_socket_seqpacket_addr(&raw_addr) {
        Ok(a) => a,
        Err(e) => {
            return status_err(
                Opcode::SocketSeqPacketConnectResponse,
                socket_seqpacket_status(e),
            );
        }
    };
    match state.connect(addr) {
        Ok(()) => HandlerResult {
            frame: proto::build_socket_seqpacket_connect_response_ok(),
            out_fd: None,
        },
        Err(e) => status_err(
            Opcode::SocketSeqPacketConnectResponse,
            socket_seqpacket_status(e),
        ),
    }
}

fn handle_socket_seqpacket_send(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketSendResponse);
    }
    let (handle_id, payload) = match proto::parse_socket_seqpacket_send_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketSendResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketSendResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    match state.send(&payload) {
        Ok(n) => HandlerResult {
            frame: proto::build_socket_seqpacket_send_response_ok(n as u64),
            out_fd: None,
        },
        Err(e) => status_err(
            Opcode::SocketSeqPacketSendResponse,
            socket_seqpacket_status(e),
        ),
    }
}

fn handle_socket_seqpacket_recv(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketRecvResponse);
    }
    let (handle_id, max_len) = match proto::parse_socket_seqpacket_recv_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketRecvResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketRecvResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    match state.recv(max_len as usize) {
        Ok((payload, flags)) => HandlerResult {
            frame: proto::build_socket_seqpacket_recv_response_ok(&payload, flags),
            out_fd: None,
        },
        Err(e) => status_err(
            Opcode::SocketSeqPacketRecvResponse,
            socket_seqpacket_status(e),
        ),
    }
}

fn handle_socket_seqpacket_shutdown(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketShutdownResponse);
    }
    let (handle_id, how) = match proto::parse_socket_seqpacket_shutdown_body(request.body) {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketShutdownResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketShutdownResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    match state.shutdown(how) {
        Ok(()) => HandlerResult {
            frame: proto::build_socket_seqpacket_shutdown_response_ok(),
            out_fd: None,
        },
        Err(e) => status_err(
            Opcode::SocketSeqPacketShutdownResponse,
            socket_seqpacket_status(e),
        ),
    }
}

fn handle_socket_seqpacket_getsockname(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketGetSockNameResponse);
    }
    let handle_id = match proto::parse_handle_body(request.body, Opcode::SocketSeqPacketGetSockName)
    {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketGetSockNameResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketGetSockNameResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    HandlerResult {
        frame: proto::build_socket_seqpacket_getsockname_response_ok(
            &encode_socket_seqpacket_addr(&state.getsockname()),
        ),
        out_fd: None,
    }
}

fn handle_socket_seqpacket_getpeername(
    registry: &BrokerStateRegistry,
    request: &Frame<'_>,
    in_fds: Vec<OwnedFd>,
) -> HandlerResult {
    if !in_fds.is_empty() {
        return protocol_err(Opcode::SocketSeqPacketGetPeerNameResponse);
    }
    let handle_id = match proto::parse_handle_body(request.body, Opcode::SocketSeqPacketGetPeerName)
    {
        Ok(v) => v,
        Err(_) => return protocol_err(Opcode::SocketSeqPacketGetPeerNameResponse),
    };
    let state = match resolve_socket_seqpacket(registry, handle_id) {
        Ok(s) => s,
        Err(_) => {
            return status_err(
                Opcode::SocketSeqPacketGetPeerNameResponse,
                StatusCode::UnknownHandle,
            );
        }
    };
    match state.getpeername() {
        Ok(addr) => HandlerResult {
            frame: proto::build_socket_seqpacket_getpeername_response_ok(
                &encode_socket_seqpacket_addr(&addr),
            ),
            out_fd: None,
        },
        Err(e) => status_err(
            Opcode::SocketSeqPacketGetPeerNameResponse,
            socket_seqpacket_status(e),
        ),
    }
}
