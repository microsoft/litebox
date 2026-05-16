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

use crate::fd_token_protocol::{
    self as proto, BODY_MAX, CTRL_HEADER_LEN, Frame, Opcode, ProtocolError, PtyIoctlOp, StatusCode,
    build_create_eventfd_request, build_create_pidfd_request, build_create_pipe_request,
    build_create_pty_request, build_create_signalfd_request, build_create_socketpair_request,
    build_mark_process_exited_request, build_materialize_request, build_pidfd_exited_request,
    build_pty_ioctl_request, build_pty_read_request, build_pty_write_request,
    build_read_eventfd_request, build_read_pipe_request, build_read_siginfo_request,
    build_read_socketpair_request, build_register_notification_ring_request,
    build_register_process_request, build_register_request, build_release_request,
    build_subscribe_eventfd_request, build_subscribe_process_exit_request,
    build_subscribe_pty_request, build_unsubscribe_request, build_write_eventfd_request,
    build_write_pipe_request, build_write_socketpair_request, decode,
    parse_create_pidfd_response_ok, parse_create_pty_response_ok,
    parse_create_socketpair_response_body, parse_handle_body, parse_pidfd_exited_response_ok,
    parse_pty_ioctl_response_body, parse_pty_read_response_body, parse_pty_write_response_ok,
    parse_read_pipe_response_body, parse_read_siginfo_response_body,
    parse_read_socketpair_response_body, parse_subscribe_process_exit_response_ok,
    parse_write_pipe_response_ok, parse_write_socketpair_response_ok,
};
use std::format;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
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

    #[error("broker internal error for opcode {opcode:?}")]
    BrokerInternal { opcode: Opcode },

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
        s => ClientError::OtherStatus { opcode, status: s },
    }
}

fn map_status_with_handle(opcode: Opcode, status: StatusCode, _handle: u64) -> ClientError {
    match status {
        StatusCode::Protocol => ClientError::BrokerRejectedProtocol,
        StatusCode::Internal => ClientError::BrokerInternal { opcode },
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

    let bytes = frame.encode().map_err(ClientError::Protocol)?;

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
