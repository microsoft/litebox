// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Worker-side client for the broker control socket.
//!
//! Each worker connects to the broker once at startup and keeps the
//! resulting [`FdTokenClient`] for the worker's lifetime. The client
//! mediates **all** worker→broker control RPCs:
//!
//! - **Host-fd lifecycle** (Phase 3 carry-over): `register` /
//!   `materialize` / `release` on a host kernel fd.
//! - **Notification-ring setup** (Phase B): `register_notification_ring`
//!   hands the worker's broker→worker ring writer to the broker via
//!   SCM_RIGHTS; the broker then uses it to push state-change events.
//! - **Eventfd state-object ops** (Phase B): `create_eventfd`,
//!   `read_eventfd`, `write_eventfd`, `subscribe_eventfd`, `unsubscribe`.
//!
//! # Concurrency
//!
//! Holds the underlying [`UnixStream`] behind a [`Mutex`]; concurrent
//! callers serialise through it (protocol is strictly req/resp). A
//! worker that needs throughput beyond a single round-trip per call
//! opens multiple clients to the broker.

#![allow(clippy::wildcard_enum_match_arm)]
// StatusCode pass-through arms deliberately preserve broker statuses; converting every RPC remains incremental.

use crate::cwfd::broker_timerfd_provider::BrokerTimerfdSpec;
use crate::cwfd::fd_transfer_frame::PassedToken;
use crate::fd_token_protocol::{
    self as proto, BODY_MAX, CTRL_HEADER_LEN, Frame, Opcode, ProtocolError, PtyIoctlOp, StatusCode,
    build_attach_host_fd_request, build_bind_nine_p_session_request, build_clone_ofd_request,
    build_create_eventfd_request, build_create_pidfd_request, build_create_pipe_request,
    build_create_pty_request, build_create_signalfd_request, build_create_socketpair_request,
    build_create_timerfd_request, build_deliver_signal_inbox_request, build_get_timerfd_request,
    build_inet_listener_accept_request, build_inet_listener_bind_request,
    build_inet_listener_create_request, build_inet_listener_getsockname_request,
    build_inet_listener_getsockopt_request, build_inet_listener_listen_request,
    build_inet_listener_query_events_request, build_inet_listener_setsockopt_request,
    build_inet_raw_create_request, build_inet_raw_query_events_request,
    build_inet_raw_recvfrom_request, build_inet_raw_sendto_request,
    build_inet_tcp_conn_connect_request, build_inet_tcp_conn_create_request,
    build_inet_tcp_conn_getpeername_request, build_inet_tcp_conn_getsockname_request,
    build_inet_tcp_conn_getsockopt_request, build_inet_tcp_conn_query_events_request,
    build_inet_tcp_conn_setsockopt_request, build_inotify_add_watch_request,
    build_inotify_init1_request, build_inotify_read_request, build_inotify_rm_watch_request,
    build_mark_process_exited_request, build_materialize_request, build_open_pty_slave_request,
    build_pidfd_exited_request, build_poll_tcp_conn_events_request, build_pty_ioctl_request,
    build_pty_read_request, build_pty_write_request, build_push_siginfo_request,
    build_read_eventfd_request, build_read_pipe_request, build_read_siginfo_request,
    build_read_socketpair_request, build_read_tcp_conn_request, build_read_timerfd_request,
    build_register_notification_ring_request, build_register_ofd_request,
    build_register_process_request, build_register_request, build_release_request,
    build_set_pgid_request, build_set_sid_request, build_set_timerfd_request,
    build_shutdown_socketpair_write_request, build_shutdown_tcp_conn_request,
    build_socket_dgram_sendto_request_with_tokens, build_subscribe_eventfd_request,
    build_subscribe_process_exit_request, build_subscribe_pty_request,
    build_subscribe_signal_inbox_request, build_unsubscribe_request,
    build_unsubscribe_signal_inbox_request, build_write_eventfd_request, build_write_pipe_request,
    build_write_socketpair_request, build_write_tcp_conn_request, decode,
    parse_attach_host_fd_response_body, parse_bind_nine_p_session_response_body,
    parse_clone_ofd_response_body, parse_create_pidfd_response_ok, parse_create_pty_response_ok,
    parse_create_socketpair_response_body, parse_get_timerfd_response_ok, parse_handle_body,
    parse_inet_listener_accept_response_ok, parse_inet_listener_bind_response_ok,
    parse_inet_listener_create_response_ok, parse_inet_listener_getsockname_response_ok,
    parse_inet_listener_getsockopt_response_ok, parse_inet_listener_query_events_response_ok,
    parse_inet_raw_create_response_ok, parse_inet_raw_query_events_response_ok,
    parse_inet_raw_recvfrom_response_ok, parse_inet_raw_sendto_response_ok,
    parse_inet_tcp_conn_create_response_ok, parse_inet_tcp_conn_getpeername_response_ok,
    parse_inet_tcp_conn_getsockname_response_ok, parse_inet_tcp_conn_getsockopt_response_ok,
    parse_inet_tcp_conn_query_events_response_ok, parse_inotify_add_watch_response_ok,
    parse_inotify_read_response_body, parse_open_pty_slave_response_ok,
    parse_pidfd_exited_response_ok, parse_poll_tcp_conn_events_response_ok,
    parse_pty_ioctl_response_body, parse_pty_read_response_body, parse_pty_write_response_ok,
    parse_read_pipe_response_body, parse_read_siginfo_response_body,
    parse_read_socketpair_response_body, parse_read_tcp_conn_response_body,
    parse_register_ofd_response_body, parse_set_sid_response_ok,
    parse_subscribe_process_exit_response_ok, parse_write_pipe_response_ok,
    parse_write_socketpair_response_ok, parse_write_tcp_conn_response_ok,
};
use std::format;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::vec;
use std::vec::Vec;

/// Errors returned by [`FdTokenClient`] operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io error talking to broker control socket: {0}")]
    Io(#[from] io::Error),

    #[error("protocol error from broker: {0}")]
    Protocol(ProtocolError),

    #[error("broker returned unexpected response opcode {actual:?} (expected {expected:?})")]
    UnexpectedOpcode { expected: Opcode, actual: Opcode },

    #[error("broker returned StatusCode::Protocol — this client violated the protocol")]
    BrokerRejectedProtocol,

    #[error("broker returned UnknownHandle for id {handle_id}")]
    UnknownHandle { handle_id: u64 },

    #[error("eventfd op would block (counter empty on read, or saturated on write)")]
    WouldBlock,

    #[error("eventfd write of value {value} is invalid (u64::MAX)")]
    InvalidValue { value: u64 },

    #[error("subscription id {0} already in use on the target state")]
    DuplicateSubscription(u64),

    #[error("subscription id {0} not found on the target state")]
    UnknownSubscription(u64),

    #[error("operation rejected: handle's subsystem tag doesn't match the opcode")]
    SubsystemMismatch,

    #[error("worker has not registered a notification ring yet")]
    NoNotificationRing,

    #[error("operation denied by broker policy or host permissions")]
    PermissionDenied,

    #[error("protocol not supported by broker subsystem")]
    ProtocolNotSupported,

    #[error("broker internal error for opcode {opcode:?}")]
    BrokerInternal { opcode: Opcode },

    /// Runtime I/O failure reported by the broker (`StatusCode::Io`).
    /// Maps to `Errno::EIO` at the shim's syscall boundary. Distinct
    /// from `Io(io::Error)` (transport-level error talking to the
    /// broker control socket) and from `BrokerInternal` (broker bug).
    /// Canonical case: PTY write when the peer endpoint is closed.
    #[error("broker reported runtime I/O failure for opcode {opcode:?}")]
    OperationIo { opcode: Opcode },

    #[error("broker returned status {status:?} for opcode {opcode:?}")]
    OtherStatus { opcode: Opcode, status: StatusCode },

    #[error("broker response carried unexpected fd attachment for opcode {opcode:?}")]
    UnexpectedFdAttachment { opcode: Opcode },

    #[error("broker response missing required fd attachment for opcode {opcode:?}")]
    MissingFdAttachment { opcode: Opcode },

    #[error("broker control socket short-read: got {got}, expected at least {need}")]
    ShortRead { got: usize, need: usize },

    #[error("broker SCM_RIGHTS payload truncated by the kernel")]
    CmsgTruncated,
}

/// A connected, ready-to-use client for the broker control socket.
pub struct FdTokenClient {
    stream: Mutex<UnixStream>,
}

// Phase F.5+ PE.1 Step C: thread-local caller_pid stamp.
//
// Before any shim-side call into `FdTokenClient`, the shim sets this
// to the current guest pid (the pid the operation is being performed
// on behalf of). The `send_frame_with_fds` low-level send path stamps
// the encoded frame's header bytes 12-15 from this value.
//
// Zero (the default) means "unspecified" and preserves the pre-PE.1
// protocol shape — broker-side per-pid tracking degenerates to a
// single shared (0, id) bucket.
std::thread_local! {
    static CALLER_PID: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Sets the thread-local caller_pid stamp for outbound broker RPCs.
/// Returns a guard that restores the previous value on drop, so calls
/// can nest cleanly (e.g., a syscall handler stamps once, an inner
/// helper re-stamps for a sub-operation on behalf of a different pid).
pub fn set_caller_pid_scope(pid: u32) -> CallerPidScope {
    let previous = CALLER_PID.with(|c| {
        let prev = c.get();
        c.set(pid);
        prev
    });
    CallerPidScope { previous }
}

/// RAII guard returned by [`set_caller_pid_scope`].
pub struct CallerPidScope {
    previous: u32,
}

impl Drop for CallerPidScope {
    fn drop(&mut self) {
        CALLER_PID.with(|c| c.set(self.previous));
    }
}

/// Reads the current thread-local caller_pid stamp (mostly for tests
/// and diagnostics).
pub fn current_caller_pid() -> u32 {
    CALLER_PID.with(std::cell::Cell::get)
}

impl FdTokenClient {
    /// Connects to the broker control socket at `path`.
    pub fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }

    /// Builds a client from an already-connected stream. Useful when
    /// the caller wants to relocate the underlying fd before
    /// constructing the client (e.g., to INFRA_FD_MIN to avoid
    /// posix_spawn dup2 collisions).
    pub fn from_unix_stream(stream: UnixStream) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }

    // ---- Host-fd lifecycle (Phase 3 surface) -----------------------------

    /// Registers a host fd with the broker; returns its handle id.
    /// The fd is consumed (passed via SCM_RIGHTS).
    pub fn register(&self, fd: OwnedFd) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_register_request(), Some(&fd))?;
        drop(fd);
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::RegisterResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Materializes a fresh host fd for `handle_id`. The returned fd
    /// aliases the same kernel object as the original registered fd.
    pub fn materialize(&self, handle_id: u64) -> Result<OwnedFd, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_materialize_request(handle_id), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::MaterializeResponse)?;
        match resp.status {
            StatusCode::Ok => attached.ok_or(ClientError::MissingFdAttachment {
                opcode: resp.opcode,
            }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Duplicates a raw host fd and registers the duplicate with the broker.
    pub fn register_dup_raw_fd(&self, raw_fd: i32) -> Result<u64, ClientError> {
        // SAFETY: fcntl does not dereference pointers for F_DUPFD_CLOEXEC; raw_fd is
        // supplied by the caller and errors are reported via the return value.
        let duped = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duped < 0 {
            return Err(ClientError::Io(io::Error::last_os_error()));
        }
        // SAFETY: `duped` is a fresh fd returned by fcntl above.
        let owned = unsafe { OwnedFd::from_raw_fd(duped) };
        self.register(owned)
    }

    /// Materializes a broker token and returns ownership as a raw host fd.
    pub fn materialize_raw_fd(&self, handle_id: u64) -> Result<i32, ClientError> {
        self.materialize(handle_id).map(OwnedFd::into_raw_fd)
    }

    /// Decrements the registry refcount for `handle_id`. When the
    /// refcount reaches zero the broker frees the resource.
    pub fn release(&self, handle_id: u64) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_release_request(handle_id), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReleaseResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    // ---- Notification-ring setup (Phase B) -------------------------------

    /// Hands the worker's broker→worker notification ring memfds to
    /// the broker. Call once after `connect`. The broker stores the
    /// writer half and uses it for `subscribe`-triggered notifications;
    /// the other memfd is unused (kept for ShmemRingPair::open API
    /// symmetry — see module-level docs in notification_ring).
    #[allow(clippy::similar_names)] // the pair is inherently named tx/rx
    pub fn register_notification_ring(
        &self,
        notification_ring_tx_fd: OwnedFd,
        notification_ring_rx_fd: OwnedFd,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame_with_fds(
            &stream,
            &build_register_notification_ring_request(),
            &[&notification_ring_tx_fd, &notification_ring_rx_fd],
        )?;
        drop(notification_ring_tx_fd);
        drop(notification_ring_rx_fd);
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::RegisterNotificationRingResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    // ---- Process state-object ops (Phase 1: pid allocation) -------------

    /// Asks the broker to allocate a new globally-unique guest pid
    /// and register a corresponding `ProcessState` entry in the
    /// process registry with refcount = 1. The returned handle id IS
    /// the Linux guest pid (low 32 bits of the u64 handle).
    pub fn register_process(&self) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_register_process_request(), None)?;
        let (resp_bytes, _attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::RegisterProcessResponse)?;
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Phase F.5+ PE.1 Step D: release every (pid, *) entry the
    /// broker is tracking for this connection on behalf of `pid`.
    /// Returns the number of refs released (for diagnostics).
    pub fn release_all_for_pid(&self, pid: u32) -> Result<u32, ClientError> {
        use crate::fd_token_protocol::{
            build_release_all_for_pid_request, parse_release_all_for_pid_response_ok,
        };
        let stream = self.lock();
        send_frame(&stream, &build_release_all_for_pid_request(pid), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReleaseAllForPidResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_release_all_for_pid_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_with_handle(resp.opcode, s, u64::from(pid))),
        }
    }

    /// Marks a broker-owned process as exited and wakes subscribers.
    pub fn mark_process_exited(&self, pid: u32, exit_code: i32) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_mark_process_exited_request(pid, exit_code),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::MarkProcessExitedResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle {
                handle_id: u64::from(pid),
            }),
            s => Err(map_status_with_handle(resp.opcode, s, u64::from(pid))),
        }
    }

    /// Subscribes this worker to process-exit notifications. The success
    /// response carries a cached exit-code snapshot for late subscribers.
    pub fn subscribe_process_exit(
        &self,
        pid: u32,
        subscription_id: u64,
        events_mask: u32,
    ) -> Result<Option<i32>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_subscribe_process_exit_request(pid, subscription_id, events_mask),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SubscribeProcessExitResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_subscribe_process_exit_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle {
                handle_id: u64::from(pid),
            }),
            StatusCode::DuplicateSubscription => {
                Err(ClientError::DuplicateSubscription(subscription_id))
            }
            StatusCode::NoNotificationRing => Err(ClientError::NoNotificationRing),
            StatusCode::SubsystemMismatch => Err(ClientError::SubsystemMismatch),
            s => Err(map_status_with_handle(resp.opcode, s, u64::from(pid))),
        }
    }

    /// Stamps a process-group change in the broker before the shim-local cache mutates.
    pub fn set_pgid(
        &self,
        caller_pid: u32,
        target_pid: u32,
        new_pgid: u32,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_set_pgid_request(caller_pid, target_pid, new_pgid),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SetPgidResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle {
                handle_id: u64::from(target_pid),
            }),
            s => Err(map_status_with_handle(
                resp.opcode,
                s,
                u64::from(target_pid),
            )),
        }
    }

    /// Stamps session creation in the broker. The response pgid is caller_pid.
    pub fn set_sid(&self, caller_pid: u32) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_set_sid_request(caller_pid), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SetSidResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_set_sid_response_ok(resp.body).map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle {
                handle_id: u64::from(caller_pid),
            }),
            s => Err(map_status_with_handle(
                resp.opcode,
                s,
                u64::from(caller_pid),
            )),
        }
    }

    /// Subscribes this worker to broker-delivered pgrp signals.
    pub fn subscribe_signal_inbox(
        &self,
        pgid: u32,
        signal_mask: u32,
        subscription_id: u64,
        events_mask: u32,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_subscribe_signal_inbox_request(pgid, signal_mask, subscription_id, events_mask),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SubscribeSignalInboxResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::DuplicateSubscription => {
                Err(ClientError::DuplicateSubscription(subscription_id))
            }
            StatusCode::NoNotificationRing => Err(ClientError::NoNotificationRing),
            s => Err(map_status_with_handle(resp.opcode, s, u64::from(pgid))),
        }
    }

    /// Asks the broker to deliver a signal to subscribers of a pgrp.
    pub fn deliver_signal_inbox(&self, pgid: u32, signum: u32) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_deliver_signal_inbox_request(pgid, signum),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::DeliverSignalInboxResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            s => Err(map_status_with_handle(resp.opcode, s, u64::from(pgid))),
        }
    }

    /// Unsubscribes this worker from broker-delivered pgrp signals.
    pub fn unsubscribe_signal_inbox(
        &self,
        pgid: u32,
        subscription_id: u64,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_unsubscribe_signal_inbox_request(pgid, subscription_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::UnsubscribeSignalInboxResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownSubscription => {
                Err(ClientError::UnknownSubscription(subscription_id))
            }
            s => Err(map_status_with_handle(resp.opcode, s, u64::from(pgid))),
        }
    }

    // ---- Eventfd state-object ops (Phase B) ------------------------------

    /// Asks the broker to create an `EventfdState` with the given
    /// initial counter and semaphore mode. Returns the handle id.
    pub fn create_eventfd(&self, initial: u64, semaphore: bool) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_create_eventfd_request(initial, semaphore),
            None,
        )?;
        let (resp_bytes, _attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreateEventfdResponse)?;
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Performs the eventfd `read` op on the named handle.
    pub fn read_eventfd(&self, handle_id: u64) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_read_eventfd_request(handle_id), None)?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReadEventfdResponse)?;
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Performs the eventfd `write` op on the named handle.
    pub fn write_eventfd(&self, handle_id: u64, value: u64) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_write_eventfd_request(handle_id, value),
            None,
        )?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::WriteEventfdResponse)?;
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Asks the broker to create a `TimerfdState` with the given clock and flags.
    pub fn create_timerfd(&self, clockid: i32, flags: u32) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_create_timerfd_request(clockid, flags), None)?;
        let (resp_bytes, _attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreateTimerfdResponse)?;
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Performs the timerfd `read` op on the named handle.
    pub fn read_timerfd(&self, handle_id: u64) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_read_timerfd_request(handle_id), None)?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReadTimerfdResponse)?;
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Performs the timerfd `settime` op on the named handle.
    pub fn set_timerfd(
        &self,
        handle_id: u64,
        new_value: BrokerTimerfdSpec,
        flags: u32,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_set_timerfd_request(handle_id, new_value, flags),
            None,
        )?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SetTimerfdResponse)?;
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Performs the timerfd `gettime` op on the named handle.
    pub fn get_timerfd(&self, handle_id: u64) -> Result<BrokerTimerfdSpec, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_get_timerfd_request(handle_id), None)?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::GetTimerfdResponse)?;
        match resp.status {
            StatusCode::Ok => {
                parse_get_timerfd_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Asks the broker to create a pidfd watching `target_host_pid`.
    pub fn create_pidfd(&self, target_host_pid: u32) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_create_pidfd_request(target_host_pid), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreatePidfdResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_create_pidfd_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Queries whether a broker-hosted pidfd has observed target exit.
    pub fn pidfd_exited(&self, handle_id: u64) -> Result<bool, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_pidfd_exited_request(handle_id), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::PidfdExitedResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_pidfd_exited_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    // ---- Pty state-object ops (Phase E) ----------------------------------

    pub fn create_pty(&self) -> Result<(u64, u64, u32), ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_create_pty_request(), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreatePtyResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_create_pty_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn open_pty_slave(&self, pty_id: u32) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_open_pty_slave_request(pty_id), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::OpenPtySlaveResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_open_pty_slave_response_ok(resp.body)
                .map(|(handle, _)| handle)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle {
                handle_id: u64::from(pty_id),
            }),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn pty_read(&self, handle_id: u64, max_len: u32) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_pty_read_request(handle_id, max_len), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::PtyReadResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_pty_read_response_body(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn pty_write(&self, handle_id: u64, data: &[u8]) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_pty_write_request(handle_id, data), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::PtyWriteResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_pty_write_response_ok(resp.body).map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn subscribe_pty(
        &self,
        handle_id: u64,
        subscription_id: u64,
        events_mask: u32,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_subscribe_pty_request(handle_id, subscription_id, events_mask),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SubscribePtyResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::DuplicateSubscription => {
                Err(ClientError::DuplicateSubscription(subscription_id))
            }
            StatusCode::NoNotificationRing => Err(ClientError::NoNotificationRing),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn pty_ioctl(
        &self,
        handle_id: u64,
        op: PtyIoctlOp,
        payload: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_pty_ioctl_request(handle_id, op, payload),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::PtyIoctlResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_pty_ioctl_response_body(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    #[cfg(debug_assertions)]
    pub fn debug_query_state_object(
        &self,
        handle_id: u64,
    ) -> Result<proto::DebugStateObjectInfo, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_debug_query_state_object_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::DebugQueryStateObjectResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_debug_query_state_object_response_body(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Asks the broker to create a signalfd state with the given mask.
    pub fn create_signalfd(&self, sigmask_lo: u64, sigmask_hi: u64) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_create_signalfd_request(sigmask_lo, sigmask_hi),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreateSignalfdResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Reads one `signalfd_siginfo` payload from a broker-hosted signalfd.
    pub fn read_siginfo(&self, handle_id: u64) -> Result<Option<Vec<u8>>, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_read_siginfo_request(handle_id), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReadSiginfoResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_read_siginfo_response_body(resp.body)
                .map(Some)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Ok(None),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Pushes one shim-synthesized `signalfd_siginfo` payload into a broker-hosted signalfd.
    pub fn push_siginfo(&self, handle_id: u64, payload: &[u8]) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_push_siginfo_request(handle_id, payload),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::PushSiginfoResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: payload.len() as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Asks the broker to create an inotify state object.
    pub fn inotify_init1(&self, flags: u32) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_inotify_init1_request(flags), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InotifyInit1Response)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_handle_body(resp.body, resp.opcode).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn inotify_add_watch(
        &self,
        handle_id: u64,
        path: &str,
        mask: u32,
    ) -> Result<i32, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inotify_add_watch_request(handle_id, path, mask),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InotifyAddWatchResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inotify_add_watch_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: mask as u64 }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inotify_rm_watch(&self, handle_id: u64, wd: i32) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inotify_rm_watch_request(handle_id, wd),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InotifyRmWatchResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: wd as u64 }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inotify_read(
        &self,
        handle_id: u64,
        max_len: u32,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inotify_read_request(handle_id, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InotifyReadResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_inotify_read_response_body(resp.body)
                .map(Some)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Ok(None),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: max_len as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_listener_create(&self, family: u8) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_inet_listener_create_request(family), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerCreateResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_listener_create_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: family as u64,
            }),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn inet_listener_setsockopt(
        &self,
        handle_id: u64,
        level: u32,
        optname: u32,
        optval: &[u8],
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_listener_setsockopt_request(handle_id, level, optname, optval),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerSetSockOptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: optname as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_listener_getsockname(&self, handle_id: u64) -> Result<[u8; 28], ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_listener_getsockname_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerGetSockNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_inet_listener_getsockname_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_listener_getsockopt(
        &self,
        handle_id: u64,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_listener_getsockopt_request(handle_id, level, optname, optlen),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerGetSockOptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_listener_getsockopt_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: optname as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_listener_bind(
        &self,
        handle_id: u64,
        sockaddr: &[u8],
    ) -> Result<[u8; 28], ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_listener_bind_request(handle_id, sockaddr),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerBindResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_listener_bind_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: sockaddr.len() as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_listener_listen(&self, handle_id: u64, backlog: u32) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_listener_listen_request(handle_id, backlog),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerListenResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: backlog as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_listener_accept(&self, handle_id: u64) -> Result<(u64, [u8; 28]), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_listener_accept_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerAcceptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_listener_accept_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_listener_query_events(&self, handle_id: u64) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_listener_query_events_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetListenerQueryEventsResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_inet_listener_query_events_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Asks the broker to create a pipe state. The returned handle starts
    /// with one read-end ref and one write-end ref.
    pub fn create_pipe(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<(u64, u64), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_create_pipe_request(capacity, atomic_write_size),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreatePipeResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => crate::fd_token_protocol::parse_create_pipe_response_body(resp.body)
                .map_err(ClientError::Protocol),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Attaches a host fd to the broker as a `BrokerPipe`-shaped
    /// handle. The `direction` argument (one of
    /// `proto::host_fd_direction::{READ, WRITE, READ_WRITE}`) declares
    /// which of `read_pipe`/`write_pipe` the worker may invoke against
    /// the returned handle. The host fd is consumed (passed via
    /// SCM_RIGHTS; broker takes ownership thereafter).
    ///
    /// Phase 3 (legacy-pipes retirement) entry point: this replaces
    /// the parent dispatcher's host-fd relay. The worker installs the
    /// returned handle as a regular `BrokerPipeFd`, with all data
    /// flow routed through the broker's host-fd state machine.
    pub fn attach_host_fd(&self, fd: OwnedFd, direction: u8) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_attach_host_fd_request(direction), Some(&fd))?;
        drop(fd);
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::AttachHostFdResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_attach_host_fd_response_body(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Legacy-pipes Phase 3 (D3): register an already-open 9P fid
    /// for cross-connection sharing.
    ///
    /// Issued by the **parent** shim on its fd-token-socket. The
    /// broker walks its (paired) `nine_p::Server`'s fid table
    /// for `fid`, requires it to be open with a host `fs::File`,
    /// dups the host fd via `try_clone()` (kernel OFD sharing), and
    /// inserts the clone into the broker-global OFD registry under
    /// a fresh `OpenFileId`. The returned id is broker-scoped and
    /// the shim ships it to the worker shim via
    /// `--broker-fd-bridge fs_fid:<id>:...` for the worker's
    /// `clone_ofd` call.
    ///
    /// POSIX inherited-fd semantics (shared kernel position) are
    /// preserved automatically by the underlying `dup(2)`.
    pub fn register_ofd(&self, fid: u32) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_register_ofd_request(fid), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::RegisterOfdResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_register_ofd_response_body(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Legacy-pipes Phase 3 (D3): clone a previously-registered
    /// OFD into a new 9P fid on the worker's connection.
    ///
    /// Issued by the **worker** shim on its fd-token-socket. The
    /// broker looks up `open_file_id` in the global registry,
    /// increments its refcount, dups the underlying host fd via
    /// `try_clone()`, synthesises a fresh `FidState` (open,
    /// canonical, carrying the same path and OFD id so its
    /// eventual `Tclunk` releases the registry refcount), and
    /// installs it in the worker's (paired) `nine_p::Server`'s
    /// fid table at `new_fid`.
    ///
    /// After this returns Ok, the worker can issue regular 9P
    /// `Twrite`/`Tread` against `new_fid` and the operations
    /// share the kernel OFD with the parent's original fid.
    pub fn clone_ofd(&self, open_file_id: u64, new_fid: u32) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_clone_ofd_request(open_file_id, new_fid),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CloneOfdResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_clone_ofd_response_body(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    /// Legacy-pipes Phase 3 (D3 step 2d.2): pair this
    /// fd-token-socket with a 9P session by its broker-assigned
    /// `conn_id` (obtained from the bootstrap ACK of
    /// `connect_nine_p_channel`). Must be called once early on the
    /// fd-token-socket — before any `RegisterOfd` / `CloneOfd`
    /// op — so subsequent op handlers find a paired
    /// `nine_p::Server` in their `ConnState`.
    pub fn bind_nine_p_session(&self, nine_p_conn_id: u64) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_bind_nine_p_session_request(nine_p_conn_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::BindNinePSessionResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_bind_nine_p_session_response_body(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn read_pipe(&self, handle_id: u64, max_len: u64) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_read_pipe_request(handle_id, max_len), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReadPipeResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_read_pipe_response_body(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn write_pipe(&self, handle_id: u64, bytes: &[u8]) -> Result<usize, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_write_pipe_request(handle_id, bytes), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::WritePipeResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_write_pipe_response_ok(resp.body)
                .map(|n| n as usize)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn create_socketpair(
        &self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<(u64, u64), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_create_socketpair_request(capacity, atomic_write_size),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreateSocketPairResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_create_socketpair_response_body(resp.body).map_err(ClientError::Protocol)
            }
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn read_socketpair(&self, handle_id: u64, max_len: u64) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_read_socketpair_request(handle_id, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReadSocketPairResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_read_socketpair_response_body(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn write_socketpair(&self, handle_id: u64, bytes: &[u8]) -> Result<usize, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_write_socketpair_request(handle_id, bytes),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::WriteSocketPairResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_write_socketpair_response_ok(resp.body)
                .map(|n| n as usize)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn shutdown_socketpair_write(&self, handle_id: u64) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_shutdown_socketpair_write_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ShutdownSocketPairWriteResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_dgram_create(&self) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &proto::build_create_socket_dgram_request(), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreateSocketDgramResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_create_socket_dgram_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn socket_dgram_bind(&self, handle_id: u64, addr: &[u8]) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_dgram_bind_request(handle_id, addr),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketDgramBindResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                proto::parse_socket_dgram_bind_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_dgram_connect(&self, handle_id: u64, addr: &[u8]) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_dgram_connect_request(handle_id, addr),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketDgramConnectResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_dgram_sendto(
        &self,
        handle_id: u64,
        addr: &[u8],
        payload: &[u8],
        tokens: &[PassedToken],
    ) -> Result<usize, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_socket_dgram_sendto_request_with_tokens(handle_id, addr, payload, tokens),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketDgramSendToResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_dgram_sendto_response_ok(resp.body)
                .map(|n| n as usize)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_dgram_recvfrom(
        &self,
        handle_id: u64,
        max_len: u32,
    ) -> Result<(Vec<u8>, Vec<u8>, u32, Vec<PassedToken>), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_dgram_recvfrom_request(handle_id, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketDgramRecvFromResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_dgram_recvfrom_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_dgram_shutdown(&self, handle_id: u64, how: u8) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_dgram_shutdown_request(handle_id, how),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketDgramShutdownResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_dgram_getsockname(&self, handle_id: u64) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_dgram_getsockname_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketDgramGetSockNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_dgram_getsockname_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_dgram_getpeername(&self, handle_id: u64) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_dgram_getpeername_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketDgramGetPeerNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_dgram_getpeername_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_create(&self) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_create_socket_seqpacket_request(),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreateSocketSeqPacketResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_create_socket_seqpacket_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn socket_seqpacket_create_socketpair(&self) -> Result<(u64, u64), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_create_socket_seqpacket_pair_request(),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::CreateSocketSeqPacketResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_create_socket_seqpacket_pair_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn socket_seqpacket_bind(
        &self,
        handle_id: u64,
        addr: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_bind_request(handle_id, addr),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketBindResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_seqpacket_bind_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_listen(&self, handle_id: u64, backlog: u32) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_listen_request(handle_id, backlog),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketListenResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_accept(&self, handle_id: u64) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_accept_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketAcceptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_seqpacket_accept_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_connect(&self, handle_id: u64, addr: &[u8]) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_connect_request(handle_id, addr),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketConnectResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_send(
        &self,
        handle_id: u64,
        payload: &[u8],
        tokens: &[PassedToken],
    ) -> Result<usize, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_send_request_with_tokens(handle_id, payload, tokens),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketSendResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_seqpacket_send_response_ok(resp.body)
                .map(|n| n as usize)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_recv(
        &self,
        handle_id: u64,
        max_len: u32,
    ) -> Result<(Vec<u8>, u32, Vec<PassedToken>), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_recv_request(handle_id, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketRecvResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_seqpacket_recv_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_shutdown(&self, handle_id: u64, how: u8) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_shutdown_request(handle_id, how),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketShutdownResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_getsockname(&self, handle_id: u64) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_getsockname_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketGetSockNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_seqpacket_getsockname_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn socket_seqpacket_getpeername(&self, handle_id: u64) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_socket_seqpacket_getpeername_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SocketSeqPacketGetPeerNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_socket_seqpacket_getpeername_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_raw_create(&self, family: u8, protocol: u8) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_raw_create_request(family, protocol),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetRawCreateResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_raw_create_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: family as u64,
            }),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn inet_raw_sendto(
        &self,
        handle_id: u64,
        sockaddr: &[u8],
        bytes: &[u8],
    ) -> Result<usize, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_raw_sendto_request(handle_id, sockaddr, bytes),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetRawSendToResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_inet_raw_sendto_response_ok(resp.body)
                .map(|n| n as usize)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: bytes.len() as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_raw_recvfrom(
        &self,
        handle_id: u64,
        max_len: u64,
    ) -> Result<([u8; 28], Vec<u8>), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_raw_recvfrom_request(handle_id, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetRawRecvFromResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_raw_recvfrom_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: max_len }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_raw_query_events(&self, handle_id: u64) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_raw_query_events_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetRawQueryEventsResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_raw_query_events_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn tcp_conn_create(&self, family: u8) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(&stream, &build_inet_tcp_conn_create_request(family), None)?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetTcpConnCreateResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_tcp_conn_create_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: family as u64,
            }),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn tcp_conn_connect(
        &self,
        handle_id: u64,
        sockaddr: &[u8],
        timeout_ms: u32,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_tcp_conn_connect_request(handle_id, sockaddr, timeout_ms),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetTcpConnConnectResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: sockaddr.len() as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn tcp_conn_query_events(&self, handle_id: u64) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_tcp_conn_query_events_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetTcpConnQueryEventsResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_inet_tcp_conn_query_events_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn tcp_conn_getsockname(&self, handle_id: u64) -> Result<[u8; 28], ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_tcp_conn_getsockname_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetTcpConnGetSockNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_inet_tcp_conn_getsockname_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn tcp_conn_getpeername(&self, handle_id: u64) -> Result<[u8; 28], ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_tcp_conn_getpeername_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetTcpConnGetPeerNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_inet_tcp_conn_getpeername_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn tcp_conn_setsockopt(
        &self,
        handle_id: u64,
        level: u32,
        optname: u32,
        optval: &[u8],
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_tcp_conn_setsockopt_request(handle_id, level, optname, optval),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetTcpConnSetSockOptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: optname as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn tcp_conn_getsockopt(
        &self,
        handle_id: u64,
        level: u32,
        optname: u32,
        optlen: u32,
    ) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_inet_tcp_conn_getsockopt_request(handle_id, level, optname, optlen),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetTcpConnGetSockOptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_inet_tcp_conn_getsockopt_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: optname as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn read_tcp_conn(&self, handle_id: u64, max_len: u64) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_read_tcp_conn_request(handle_id, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ReadTcpConnResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_read_tcp_conn_response_body(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn write_tcp_conn(&self, handle_id: u64, bytes: &[u8]) -> Result<usize, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_write_tcp_conn_request(handle_id, bytes),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::WriteTcpConnResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => parse_write_tcp_conn_response_ok(resp.body)
                .map(|n| n as usize)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: 0 }),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn shutdown_tcp_conn(
        &self,
        handle_id: u64,
        read: bool,
        write: bool,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_shutdown_tcp_conn_request(handle_id, read, write),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::ShutdownTcpConnResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn poll_tcp_conn_events(&self, handle_id: u64) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_poll_tcp_conn_events_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::PollTcpConnEventsResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                parse_poll_tcp_conn_events_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_create(&self, family: u8) -> Result<u64, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_create_request(family),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramCreateResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                proto::parse_inet_dgram_create_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: family as u64,
            }),
            s => Err(map_status_no_handle(resp.opcode, s)),
        }
    }

    pub fn inet_dgram_bind(
        &self,
        handle_id: u64,
        sockaddr: &[u8],
    ) -> Result<[u8; 28], ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_bind_request(handle_id, sockaddr),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramBindResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => {
                proto::parse_inet_dgram_bind_response_ok(resp.body).map_err(ClientError::Protocol)
            }
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: sockaddr.len() as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_connect(&self, handle_id: u64, sockaddr: &[u8]) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_connect_request(handle_id, sockaddr),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramConnectResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: sockaddr.len() as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_sendto(
        &self,
        handle_id: u64,
        sockaddr: &[u8],
        payload: &[u8],
    ) -> Result<usize, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_sendto_request(handle_id, sockaddr, payload),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramSendToResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_inet_dgram_sendto_response_ok(resp.body)
                .map(|n| n as usize)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue {
                value: payload.len() as u64,
            }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_recvfrom(
        &self,
        handle_id: u64,
        max_len: u32,
    ) -> Result<([u8; 28], Vec<u8>, u32), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_recvfrom_request(handle_id, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramRecvFromResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_inet_dgram_recvfrom_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::WouldBlock => Err(ClientError::WouldBlock),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_shutdown(&self, handle_id: u64, how: u8) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_shutdown_request(handle_id, how),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramShutdownResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: how as u64 }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_getsockname(&self, handle_id: u64) -> Result<[u8; 28], ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_getsockname_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramGetSockNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_inet_dgram_getsockname_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_getpeername(&self, handle_id: u64) -> Result<[u8; 28], ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_getpeername_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramGetPeerNameResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_inet_dgram_getpeername_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_setsockopt(
        &self,
        handle_id: u64,
        level: i32,
        name: i32,
        value: &[u8],
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_setsockopt_request(handle_id, level, name, value),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramSetSockOptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: name as u64 }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_getsockopt(
        &self,
        handle_id: u64,
        level: i32,
        name: i32,
        max_len: u32,
    ) -> Result<Vec<u8>, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_getsockopt_request(handle_id, level, name, max_len),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramGetSockOptResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_inet_dgram_getsockopt_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::InvalidValue => Err(ClientError::InvalidValue { value: name as u64 }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    pub fn inet_dgram_query_events(&self, handle_id: u64) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &proto::build_inet_dgram_query_events_request(handle_id),
            None,
        )?;
        let (resp_bytes, attached) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::InetDgramQueryEventsResponse)?;
        if attached.is_some() {
            return Err(ClientError::UnexpectedFdAttachment {
                opcode: resp.opcode,
            });
        }
        match resp.status {
            StatusCode::Ok => proto::parse_inet_dgram_query_events_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Registers a subscription on an eventfd handle, bound to this
    /// worker's notification ring. The broker will push frames with
    /// `subscription_id` and the matched events bits whenever state
    /// changes match.
    pub fn subscribe_eventfd(
        &self,
        handle_id: u64,
        subscription_id: u64,
        events_mask: u32,
    ) -> Result<(), ClientError> {
        self.subscribe(handle_id, subscription_id, events_mask)
    }

    /// Generic subscribe. Reuses the `SubscribeEventfd` opcode (which
    /// the broker handles via the kind-agnostic `StateObject::subscribe`
    /// trait method), so it works for any broker state-object kind:
    /// eventfd, pidfd, pipe read/write end, pty.
    pub fn subscribe(
        &self,
        handle_id: u64,
        subscription_id: u64,
        events_mask: u32,
    ) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_subscribe_eventfd_request(handle_id, subscription_id, events_mask),
            None,
        )?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::SubscribeEventfdResponse)?;
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::DuplicateSubscription => {
                Err(ClientError::DuplicateSubscription(subscription_id))
            }
            StatusCode::NoNotificationRing => Err(ClientError::NoNotificationRing),
            StatusCode::SubsystemMismatch => Err(ClientError::SubsystemMismatch),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Removes a subscription by id.
    pub fn unsubscribe(&self, handle_id: u64, subscription_id: u64) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &build_unsubscribe_request(handle_id, subscription_id),
            None,
        )?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::UnsubscribeResponse)?;
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            StatusCode::UnknownSubscription => {
                Err(ClientError::UnknownSubscription(subscription_id))
            }
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Asks the broker to increment the refcount of an existing
    /// handle (typically before shipping it to a peer worker via
    /// SCM_RIGHTS). Returns Ok when the broker confirms the dup;
    /// the caller must arrange a matching release on the peer side
    /// when the peer's handle reference drops.
    pub fn dup_handle(&self, handle_id: u64) -> Result<(), ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &crate::fd_token_protocol::build_dup_handle_request(handle_id),
            None,
        )?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::DupHandleResponse)?;
        match resp.status {
            StatusCode::Ok => Ok(()),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    /// Asks the broker for the current `NOTIFY_EVENT_*` bitmask on
    /// `handle_id`. Synchronous; the broker's response is the
    /// authoritative current view of which events are set, computed
    /// from broker-side state. Used by worker-side `poll`/`select`/
    /// `epoll_wait` readiness queries so callers never depend on a
    /// stale subscription-mirror cache.
    pub fn query_events(&self, handle_id: u64) -> Result<u32, ClientError> {
        let stream = self.lock();
        send_frame(
            &stream,
            &crate::fd_token_protocol::build_query_events_request(handle_id),
            None,
        )?;
        let (resp_bytes, _) = recv_frame(&stream)?;
        let resp = decode(&resp_bytes).map_err(ClientError::Protocol)?;
        check_opcode(&resp, Opcode::QueryEventsResponse)?;
        match resp.status {
            StatusCode::Ok => crate::fd_token_protocol::parse_query_events_response_ok(resp.body)
                .map_err(ClientError::Protocol),
            StatusCode::UnknownHandle => Err(ClientError::UnknownHandle { handle_id }),
            s => Err(map_status_with_handle(resp.opcode, s, handle_id)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, UnixStream> {
        self.stream.lock().expect("FdTokenClient mutex poisoned")
    }
}

fn check_opcode(resp: &Frame<'_>, expected: Opcode) -> Result<(), ClientError> {
    if resp.opcode == expected {
        Ok(())
    } else {
        Err(ClientError::UnexpectedOpcode {
            expected,
            actual: resp.opcode,
        })
    }
}

fn map_status_no_handle(opcode: Opcode, status: StatusCode) -> ClientError {
    match status {
        StatusCode::Protocol => ClientError::BrokerRejectedProtocol,
        StatusCode::Internal => ClientError::BrokerInternal { opcode },
        StatusCode::Io => ClientError::OperationIo { opcode },
        StatusCode::UnknownHandle => ClientError::UnknownHandle { handle_id: 0 },
        StatusCode::InvalidValue => ClientError::InvalidValue { value: 0 },
        StatusCode::PermissionDenied => ClientError::PermissionDenied,
        StatusCode::ProtocolNotSupported => ClientError::ProtocolNotSupported,
        StatusCode::SubsystemMismatch => ClientError::SubsystemMismatch,
        s => ClientError::OtherStatus { opcode, status: s },
    }
}

fn map_status_with_handle(opcode: Opcode, status: StatusCode, _handle: u64) -> ClientError {
    match status {
        StatusCode::Protocol => ClientError::BrokerRejectedProtocol,
        StatusCode::Internal => ClientError::BrokerInternal { opcode },
        StatusCode::Io => ClientError::OperationIo { opcode },
        StatusCode::PermissionDenied => ClientError::PermissionDenied,
        StatusCode::ProtocolNotSupported => ClientError::ProtocolNotSupported,
        StatusCode::SubsystemMismatch => ClientError::SubsystemMismatch,
        s => ClientError::OtherStatus { opcode, status: s },
    }
}

// ---- Wire I/O ----------------------------------------------------------
//
// Reads/writes a Frame as: 16-byte header + body_len bytes, plus an
// optional SCM_RIGHTS fd attachment.

fn send_frame(
    stream: &UnixStream,
    frame: &proto::OwnedFrame,
    fd: Option<&OwnedFd>,
) -> Result<(), ClientError> {
    if let Some(f) = fd {
        send_frame_with_fds(stream, frame, &[f])
    } else {
        send_frame_with_fds(stream, frame, &[])
    }
}

fn send_frame_with_fds(
    stream: &UnixStream,
    frame: &proto::OwnedFrame,
    fds: &[&OwnedFd],
) -> Result<(), ClientError> {
    // CMSG_SPACE for up to 2 fds (matches broker's read_request cap).
    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE((2 * size_of::<i32>()) as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    assert!(
        fds.len() <= 2,
        "send_frame_with_fds: at most 2 fds supported, got {}",
        fds.len()
    );

    let mut bytes = frame.encode().map_err(ClientError::Protocol)?;
    // Phase F.5+ PE.1 Step C: stamp the encoded frame's caller_pid
    // header field (bytes 12-15) from the thread-local set by the
    // shim before invoking any FdTokenClient method. If the
    // thread-local is unset, caller_pid stays at the value the
    // builder used (typically 0 = unspecified), preserving today's
    // behaviour for callers that have not yet been ported to set
    // CALLER_PID (notification ring registration, response paths,
    // etc.).
    let stamp = CALLER_PID.with(std::cell::Cell::get);
    if stamp != 0 && bytes.len() >= CTRL_HEADER_LEN {
        bytes[12..16].copy_from_slice(&stamp.to_le_bytes());
    }

    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
        // fds.len() ≤ 2 (the leading assert), so the multiplication
        // fits trivially in a u32; explicit truncation is sound.
        #[allow(clippy::cast_possible_truncation)]
        let cmsg_data_len = (fds.len() * size_of::<i32>()) as u32;
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = unsafe { libc::CMSG_SPACE(cmsg_data_len) as _ };
        }
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        debug_assert!(!cmsg.is_null());
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            #[allow(clippy::cast_possible_truncation)]
            {
                (*cmsg).cmsg_len = libc::CMSG_LEN(cmsg_data_len) as _;
            }
            #[allow(clippy::cast_ptr_alignment)]
            let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
            for (i, fd) in fds.iter().enumerate() {
                std::ptr::write_unaligned(data_ptr.add(i), fd.as_raw_fd());
            }
        }
    }

    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    #[allow(clippy::cast_sign_loss)]
    if (n as usize) != bytes.len() {
        return Err(ClientError::Io(io::Error::other(format!(
            "short sendmsg on broker control socket: wrote {n}/{}",
            bytes.len()
        ))));
    }
    Ok(())
}

/// Reads one complete frame plus optional fd, returning the
/// (encoded-bytes, optional-fd) pair. The bytes can then be decoded
/// via `proto::decode`.
fn recv_frame(stream: &UnixStream) -> Result<(Vec<u8>, Option<OwnedFd>), ClientError> {
    // First recvmsg pulls the 16-byte header plus any cmsg.
    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
    }

    let mut header = [0u8; CTRL_HEADER_LEN];
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: CTRL_HEADER_LEN,
    };
    let mut cmsg_buf = CmsgBuf {
        buf: [0u8; CMSG_SPACE],
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
    #[allow(clippy::cast_possible_truncation)]
    {
        msg.msg_controllen = CMSG_SPACE as _;
    }

    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error().into());
    }
    #[allow(clippy::cast_sign_loss)]
    let header_read = n as usize;
    if header_read == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    if header_read != CTRL_HEADER_LEN {
        return Err(ClientError::ShortRead {
            got: header_read,
            need: CTRL_HEADER_LEN,
        });
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(ClientError::CmsgTruncated);
    }

    // Extract SCM_RIGHTS fd if present.
    let received_fd = extract_fd(&msg);

    // Peek at body_len in the header (bytes 8..12) to decide if we need a follow-up read.
    let body_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if body_len > BODY_MAX {
        return Err(ClientError::Protocol(ProtocolError::BodyTooLarge {
            body_len,
            max: BODY_MAX,
        }));
    }

    let mut full = Vec::with_capacity(CTRL_HEADER_LEN + body_len as usize);
    full.extend_from_slice(&header);
    if body_len > 0 {
        // Read body bytes with plain recv (no cmsg expected on the body).
        let mut remaining = body_len as usize;
        let mut body_buf = vec![0u8; body_len as usize];
        let mut offset = 0;
        while remaining > 0 {
            let r = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    body_buf.as_mut_ptr().add(offset).cast(),
                    remaining,
                    libc::MSG_WAITALL,
                )
            };
            if r < 0 {
                return Err(io::Error::last_os_error().into());
            }
            #[allow(clippy::cast_sign_loss)]
            let r_usize = r as usize;
            if r_usize == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            offset += r_usize;
            remaining -= r_usize;
        }
        full.extend_from_slice(&body_buf);
    }

    Ok((full, received_fd))
}

fn extract_fd(msg: &libc::msghdr) -> Option<OwnedFd> {
    let mut received_fd: Option<OwnedFd> = None;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            #[allow(clippy::cast_ptr_alignment)]
            let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>()) };
            received_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    received_fd
}

// -- Process-global accessor (unchanged from Phase 3c-i.3) -----------------

static GLOBAL_CLIENT: OnceLock<Arc<FdTokenClient>> = OnceLock::new();

/// Sets the process-global [`FdTokenClient`]. Called exactly once at
/// runner bootstrap. Returns `Err(client)` if already set.
pub fn set_global_client(client: Arc<FdTokenClient>) -> Result<(), Arc<FdTokenClient>> {
    GLOBAL_CLIENT.set(client)
}

/// Returns the process-global [`FdTokenClient`] if one has been set.
pub fn global_client() -> Option<Arc<FdTokenClient>> {
    GLOBAL_CLIENT.get().cloned()
}

#[cfg(test)]
mod global_tests {
    use super::*;

    #[test]
    fn global_client_is_none_or_some_without_panic() {
        let _ = global_client();
    }
}
