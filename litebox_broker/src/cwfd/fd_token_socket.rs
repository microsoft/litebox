// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker control-socket I/O.
//!
//! Reads variable-length [`Frame`]s with optional `SCM_RIGHTS` fd
//! attachment, dispatches to the matching handler in
//! [`crate::fd_token_service`] (host-fd ops) and — once Phase B-Step6
//! lands — `crate::state_service` (eventfd and other state-object ops).

use crate::fd_token_service::{HandlerFatal, handle_request as host_fd_handle_request};
use crate::fd_tokens::BrokerFdTokenRegistry;
use crate::state_registry::{BrokerStateRegistry, StateHandle};
use crate::state_service::{ConnState, handle_request as state_handle_request};
use litebox_common_linux::fd_token_protocol::{
    BODY_MAX, CTRL_HEADER_LEN, Opcode, OwnedFrame, ProtocolError, StatusCode, decode,
    parse_create_pidfd_response_ok, parse_create_pty_response_ok, parse_handle_body,
};
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tracing::{debug, info, warn};

/// Per-connection record of how many refs this connection has
/// contributed to each handle's registry refcount. On clean
/// disconnect the worker should have released them all; on
/// unclean disconnect (e.g., worker SIGKILL'd before its shim
/// could run `on_close` on inherited fds), `cleanup_on_disconnect`
/// force-releases each entry by its tracked count so the
/// underlying `StateObject` Drop fires (e.g.,
/// `PipeWriteEnd::drop` → reader sees EOF).
///
/// Without this, a SIGKILL'd worker leaks broker pipe/eventfd/etc.
/// refcounts and the peer worker stalls forever waiting on EOF.
#[derive(Default)]
struct ConnRefTracker {
    state_refs: HashMap<u64, u32>,
    process_refs: HashMap<u64, u32>,
}

impl ConnRefTracker {
    fn new() -> Self {
        Self::default()
    }

    fn record_state(&mut self, id: u64) {
        *self.state_refs.entry(id).or_insert(0) += 1;
    }

    fn record_process(&mut self, id: u64) {
        *self.process_refs.entry(id).or_insert(0) += 1;
    }

    /// Worker called Release on `id`. We don't know which registry
    /// without round-tripping the cascade, so decrement whichever
    /// map has a positive count for it (state first, then process).
    fn record_release(&mut self, id: u64) {
        if let Some(c) = self.state_refs.get_mut(&id) {
            if *c > 0 {
                *c -= 1;
                return;
            }
        }
        if let Some(c) = self.process_refs.get_mut(&id) {
            if *c > 0 {
                *c -= 1;
            }
        }
    }

    fn cleanup_on_disconnect(
        self,
        state_registry: &BrokerStateRegistry,
        process_registry: &BrokerStateRegistry,
    ) {
        let mut total_state = 0usize;
        let mut total_process = 0usize;
        for (id, count) in self.state_refs {
            for _ in 0..count {
                let _ = state_registry.release(StateHandle::from_id(id));
                total_state += 1;
            }
        }
        for (id, count) in self.process_refs {
            for _ in 0..count {
                let _ = process_registry.release(StateHandle::from_id(id));
                total_process += 1;
            }
        }
        if total_state + total_process > 0 {
            info!(
                state_releases = total_state,
                process_releases = total_process,
                "fd-token control: per-connection cleanup released leaked broker refs after disconnect"
            );
        }
        // C.5l follow-up: leak-detection breadcrumb. After this
        // connection's cleanup, report the post-cleanup registry
        // sizes. In a healthy system these should drop to zero
        // once all clients disconnect; a non-zero size here when
        // no other connections are active is a leak signal.
        //
        // We log at info! so the line shows up in default broker
        // logs (LITEBOX_KEEP_CONTAINER=1) without needing a
        // dedicated env-filter, and so tests can grep
        // `*.broker.log` for "registry post-cleanup state".
        let state_remaining = state_registry.len();
        let process_remaining = process_registry.len();
        info!(
            state_remaining,
            process_remaining,
            "fd-token control: registry post-cleanup state (non-zero after last connection = leak)"
        );
        if state_remaining > 0 {
            let dump = state_registry.diagnostic_snapshot();
            // Cap to first 16 entries to bound log volume.
            let preview: Vec<_> = dump.iter().take(16).collect();
            info!(
                state_remaining,
                truncated_to = preview.len(),
                ?preview,
                "fd-token control: state-registry leak preview"
            );
        }
    }
}

/// Inspect a successful response frame and record this connection's
/// net contribution to broker registry refcounts. Called once per
/// request/response round on the socket loop.
fn update_tracker_from_response(
    tracker: &mut ConnRefTracker,
    request_opcode: Opcode,
    request_body: &[u8],
    response: &OwnedFrame,
) {
    if response.status != StatusCode::Ok {
        return;
    }
    match request_opcode {
        // State-registry creators: response body is one or two handle ids.
        Opcode::CreateEventfd | Opcode::CreatePidfd | Opcode::CreateSignalfd => {
            if let Ok(id) = parse_handle_body(&response.body, response.opcode) {
                tracker.record_state(id);
            }
        }
        Opcode::CreatePipe => {
            // build_create_pipe_response_ok packs (read_id, write_id) as 2 u64 LE.
            if response.body.len() >= 16 {
                let r = u64::from_le_bytes(response.body[..8].try_into().unwrap());
                let w = u64::from_le_bytes(response.body[8..16].try_into().unwrap());
                tracker.record_state(r);
                tracker.record_state(w);
            }
        }
        Opcode::CreateSocketPair => {
            // Phase F: response is (endpoint_a_id, endpoint_b_id) as 2 u64 LE.
            if response.body.len() >= 16 {
                let a = u64::from_le_bytes(response.body[..8].try_into().unwrap());
                let b = u64::from_le_bytes(response.body[8..16].try_into().unwrap());
                tracker.record_state(a);
                tracker.record_state(b);
            }
        }
        Opcode::CreatePty => {
            if let Ok((master, slave, _flags)) = parse_create_pty_response_ok(&response.body) {
                tracker.record_state(master);
                tracker.record_state(slave);
            }
        }
        // Process-registry creator.
        Opcode::RegisterProcess => {
            if let Ok(id) = parse_handle_body(&response.body, response.opcode) {
                tracker.record_process(id);
            }
        }
        // DupHandle: request body is one u64 handle id; response is empty.
        // The +1 goes on whichever registry holds it (try state first via
        // record_release symmetry — actually we want the inverse: record_state
        // by default since state is checked first elsewhere).
        Opcode::DupHandle => {
            if request_body.len() >= 8 {
                let id = u64::from_le_bytes(request_body[..8].try_into().unwrap());
                // We don't know which registry without resolve. Pick state
                // (statistically dominant for pipe/eventfd workloads).
                // Worst case: a process-registry DupHandle is tracked as
                // state — on disconnect we try state.release first, which
                // fails with UnknownHandle and falls through to process.
                tracker.record_state(id);
            }
        }
        // Release: -1 on whichever registry.
        Opcode::Release => {
            if request_body.len() >= 8 {
                let id = u64::from_le_bytes(request_body[..8].try_into().unwrap());
                tracker.record_release(id);
            }
        }
        _ => {}
    }
    let _ = parse_create_pidfd_response_ok;
}

/// Errors observed while reading or writing one control-frame round.
/// All variants close the connection.
#[derive(Debug, thiserror::Error)]
enum ConnError {
    #[error("client closed control connection")]
    PeerClosed,

    #[error("io error on control socket: {0}")]
    Io(#[from] std::io::Error),

    #[error("control header short-read: got {got} bytes, expected {CTRL_HEADER_LEN}")]
    HeaderShortRead { got: usize },

    #[error("control body short-read: got {got} bytes, expected {need}")]
    BodyShortRead { got: usize, need: usize },

    #[error("control frame had truncated SCM_RIGHTS payload")]
    CmsgTruncated,

    #[error("control frame had {count} attached fds; at most 1 supported")]
    TooManyFds { count: usize },

    #[error("malformed SCM_RIGHTS cmsg header")]
    MalformedCmsg,

    #[error("protocol decode error: {0}")]
    Decode(ProtocolError),

    #[error("handler reported fatal protocol violation: {0}")]
    HandlerFatal(#[from] HandlerFatal),
}

/// Reads one complete frame plus zero, one, or two `SCM_RIGHTS` fds.
/// Returns `(encoded_bytes, attached_fds)`. Bytes can then be `decode`d.
///
/// The cap of 2 attached fds matches the maximum any current opcode
/// expects (`RegisterNotificationRing` carries the two memfds of a
/// `ShmemRingPair`).
fn read_request(stream: &UnixStream) -> Result<(Vec<u8>, Vec<OwnedFd>), ConnError> {
    // CMSG_SPACE for up to 2 fds.
    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE((2 * size_of::<i32>()) as u32) as usize };
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

    let raw_fd = stream.as_raw_fd();
    let n = unsafe { libc::recvmsg(raw_fd, &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if n == 0 {
        return Err(ConnError::PeerClosed);
    }
    #[allow(clippy::cast_sign_loss)]
    let n_usize = n as usize;
    if n_usize != CTRL_HEADER_LEN {
        return Err(ConnError::HeaderShortRead { got: n_usize });
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(ConnError::CmsgTruncated);
    }

    // Extract SCM_RIGHTS fds. Up to 2 supported.
    let mut received_fds: Vec<OwnedFd> = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
            if (hdr.cmsg_len as usize) < header_len {
                return Err(ConnError::MalformedCmsg);
            }
            let fd_count = ((hdr.cmsg_len as usize) - header_len) / size_of::<i32>();
            if received_fds.len() + fd_count > 2 {
                for i in 0..fd_count {
                    #[allow(clippy::cast_ptr_alignment)]
                    let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(i)) };
                    drop(unsafe { OwnedFd::from_raw_fd(raw) });
                }
                return Err(ConnError::TooManyFds {
                    count: received_fds.len() + fd_count,
                });
            }
            for i in 0..fd_count {
                #[allow(clippy::cast_ptr_alignment)]
                let raw = unsafe { std::ptr::read_unaligned(data_ptr.cast::<i32>().add(i)) };
                received_fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&raw const msg, cmsg) };
    }

    // Read body bytes if any.
    let body_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if body_len > BODY_MAX {
        return Err(ConnError::Decode(ProtocolError::BodyTooLarge {
            body_len,
            max: BODY_MAX,
        }));
    }
    let mut full = Vec::with_capacity(CTRL_HEADER_LEN + body_len as usize);
    full.extend_from_slice(&header);
    if body_len > 0 {
        let mut remaining = body_len as usize;
        let mut body_buf = vec![0u8; body_len as usize];
        let mut offset = 0;
        while remaining > 0 {
            let r = unsafe {
                libc::recv(
                    raw_fd,
                    body_buf.as_mut_ptr().add(offset).cast(),
                    remaining,
                    libc::MSG_WAITALL,
                )
            };
            if r < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            #[allow(clippy::cast_sign_loss)]
            let r_usize = r as usize;
            if r_usize == 0 {
                return Err(ConnError::BodyShortRead {
                    got: offset,
                    need: body_len as usize,
                });
            }
            offset += r_usize;
            remaining -= r_usize;
        }
        full.extend_from_slice(&body_buf);
    }

    Ok((full, received_fds))
}

/// Sends an [`OwnedFrame`] plus an optional fd via `sendmsg`.
fn write_response(
    stream: &UnixStream,
    frame: OwnedFrame,
    out_fd: Option<OwnedFd>,
) -> Result<(), ConnError> {
    let bytes = frame.encode().map_err(ConnError::Decode)?;

    #[allow(clippy::cast_possible_truncation)]
    const CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) as usize };
    #[repr(C)]
    union CmsgBuf {
        _align: libc::cmsghdr,
        buf: [u8; CMSG_SPACE],
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

    if let Some(f) = &out_fd {
        msg.msg_control = unsafe { cmsg_buf.buf.as_mut_ptr().cast() };
        #[allow(clippy::cast_possible_truncation)]
        {
            msg.msg_controllen = CMSG_SPACE as _;
        }
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
        debug_assert!(!cmsg.is_null());
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            #[allow(clippy::cast_possible_truncation)]
            {
                (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as _;
            }
            #[allow(clippy::cast_ptr_alignment)]
            let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
            std::ptr::write_unaligned(data_ptr, f.as_raw_fd());
        }
    }

    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    #[allow(clippy::cast_sign_loss)]
    if (n as usize) != bytes.len() {
        return Err(ConnError::Io(std::io::Error::other(format!(
            "short sendmsg: wrote {n}/{} bytes",
            bytes.len()
        ))));
    }

    drop(out_fd);
    Ok(())
}

/// Runs the per-connection request/response loop until the peer
/// closes or an error is observed.
pub fn handle_control_connection(
    stream: UnixStream,
    fd_registry: Arc<BrokerFdTokenRegistry>,
    state_registry: Arc<BrokerStateRegistry>,
    process_registry: Arc<BrokerStateRegistry>,
) {
    let mut conn_state = ConnState::new();
    let mut tracker = ConnRefTracker::new();
    let result = handle_control_connection_inner(
        stream,
        &fd_registry,
        &state_registry,
        &process_registry,
        &mut conn_state,
        &mut tracker,
    );
    // Force-release any broker-registry refs this connection contributed
    // but did not release before disconnect. Critical for SIGKILL'd
    // workers whose shim never got to run `on_close` on inherited
    // broker-backed fds.
    let final_tracker = std::mem::take(&mut tracker);
    final_tracker.cleanup_on_disconnect(&state_registry, &process_registry);
    let _ = result;
}

fn handle_control_connection_inner(
    stream: UnixStream,
    fd_registry: &Arc<BrokerFdTokenRegistry>,
    state_registry: &Arc<BrokerStateRegistry>,
    process_registry: &Arc<BrokerStateRegistry>,
    conn_state: &mut ConnState,
    tracker: &mut ConnRefTracker,
) {
    loop {
        match read_request(&stream) {
            Ok((bytes, in_fds)) => {
                let frame = match decode(&bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = ?e, "fd-token control: decode failed; closing");
                        return;
                    }
                };
                let request_opcode = frame.opcode;
                let request_body = frame.body.to_vec();
                let result = match frame.opcode {
                    Opcode::Register | Opcode::Materialize => {
                        // Host-fd opcodes: route to fd_token_service.
                        // It expects Option<OwnedFd>; collapse Vec → Option.
                        let mut fds: Vec<OwnedFd> = in_fds;
                        if fds.len() > 1 {
                            warn!("fd-token control: host-fd opcode with >1 fds; closing");
                            return;
                        }
                        let in_fd = fds.pop();
                        let host_result = match host_fd_handle_request(fd_registry, &frame, in_fd) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!(error = %e, "fd-token control: fatal handler error");
                                return;
                            }
                        };
                        SocketHandlerResult {
                            frame: host_result.frame,
                            out_fd: host_result.out_fd,
                        }
                    }
                    Opcode::Release => {
                        // Release: cascade host-fd registry → state registry → process registry.
                        // All three registries use independent monotonic id spaces, so an id
                        // will never be in more than one. Easy disambiguation by UnknownHandle.
                        let fds: Vec<OwnedFd> = in_fds;
                        if !fds.is_empty() {
                            warn!("fd-token control: Release with attached fds; closing");
                            return;
                        }
                        let host_result = match host_fd_handle_request(fd_registry, &frame, None) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!(error = %e, "fd-token control: fatal handler error");
                                return;
                            }
                        };
                        if host_result.frame.status
                            == litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle
                        {
                            let state_result = state_handle_request(
                                state_registry,
                                conn_state,
                                &frame,
                                Vec::new(),
                            );
                            if state_result.frame.status
                                == litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle
                            {
                                let proc_result = state_handle_request(
                                    process_registry,
                                    conn_state,
                                    &frame,
                                    Vec::new(),
                                );
                                SocketHandlerResult {
                                    frame: proc_result.frame,
                                    out_fd: proc_result.out_fd,
                                }
                            } else {
                                SocketHandlerResult {
                                    frame: state_result.frame,
                                    out_fd: state_result.out_fd,
                                }
                            }
                        } else {
                            SocketHandlerResult {
                                frame: host_result.frame,
                                out_fd: host_result.out_fd,
                            }
                        }
                    }
                    Opcode::Unsubscribe => {
                        // Unsubscribe is kind-agnostic: try fd-state first, then process-state.
                        let state_result =
                            state_handle_request(state_registry, conn_state, &frame, in_fds);
                        if state_result.frame.status
                            == litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle
                        {
                            let proc_result = state_handle_request(
                                process_registry,
                                conn_state,
                                &frame,
                                Vec::new(),
                            );
                            SocketHandlerResult {
                                frame: proc_result.frame,
                                out_fd: proc_result.out_fd,
                            }
                        } else {
                            SocketHandlerResult {
                                frame: state_result.frame,
                                out_fd: state_result.out_fd,
                            }
                        }
                    }
                    Opcode::RegisterNotificationRing
                    | Opcode::CreateEventfd
                    | Opcode::ReadEventfd
                    | Opcode::WriteEventfd
                    | Opcode::CreateSignalfd
                    | Opcode::ReadSiginfo
                    | Opcode::CreatePipe
                    | Opcode::ReadPipe
                    | Opcode::WritePipe
                    | Opcode::CreateSocketPair
                    | Opcode::ReadSocketPair
                    | Opcode::WriteSocketPair
                    | Opcode::CreatePty
                    | Opcode::PtyRead
                    | Opcode::PtyWrite
                    | Opcode::SubscribePty
                    | Opcode::PtyIoctl
                    | Opcode::SubscribeEventfd
                    | Opcode::DupHandle => {
                        // State-object opcodes: route to state_service on the fd-state registry.
                        let state_result =
                            state_handle_request(state_registry, conn_state, &frame, in_fds);
                        SocketHandlerResult {
                            frame: state_result.frame,
                            out_fd: state_result.out_fd,
                        }
                    }
                    Opcode::RegisterProcess
                    | Opcode::SubscribeProcessExit
                    | Opcode::MarkProcessExited => {
                        // Process operations: route to state_service on the *process*
                        // registry. RegisterProcess allocates the process handle; Phase G
                        // exit-state RPCs resolve that same handle id (guest pid).
                        let proc_result =
                            state_handle_request(process_registry, conn_state, &frame, in_fds);
                        SocketHandlerResult {
                            frame: proc_result.frame,
                            out_fd: proc_result.out_fd,
                        }
                    }
                    other => {
                        warn!(opcode = ?other, "fd-token control: response opcode received as request; closing");
                        return;
                    }
                };
                update_tracker_from_response(tracker, request_opcode, &request_body, &result.frame);
                if let Err(e) = write_response(&stream, result.frame, result.out_fd) {
                    warn!(error = %e, "fd-token control: write error");
                    return;
                }
            }
            Err(ConnError::PeerClosed) => {
                debug!("fd-token control: peer closed");
                return;
            }
            Err(e) => {
                warn!(error = %e, "fd-token control: read error");
                return;
            }
        }
    }
}

struct SocketHandlerResult {
    frame: OwnedFrame,
    out_fd: Option<OwnedFd>,
}

/// Spawns a thread that listens on `path` and handles each accepted
/// connection on its own thread, with all three registries available.
pub fn spawn_control_listener(
    path: &Path,
    fd_registry: Arc<BrokerFdTokenRegistry>,
    state_registry: Arc<BrokerStateRegistry>,
    process_registry: Arc<BrokerStateRegistry>,
) -> std::io::Result<JoinHandle<()>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!(path = %path.display(), "fd-token control listener bound");
    let path_owned = path.to_owned();
    thread::Builder::new()
        .name("fd-token-listener".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let fd_registry = Arc::clone(&fd_registry);
                        let state_registry = Arc::clone(&state_registry);
                        let process_registry = Arc::clone(&process_registry);
                        if let Err(e) =
                            thread::Builder::new()
                                .name("fd-token-conn".into())
                                .spawn(move || {
                                    handle_control_connection(
                                        stream,
                                        fd_registry,
                                        state_registry,
                                        process_registry,
                                    )
                                })
                        {
                            warn!(error = %e, "failed to spawn fd-token connection thread");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, path = %path_owned.display(), "fd-token accept error");
                    }
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_common_linux::fd_token_client::{ClientError, FdTokenClient};
    use std::io::{Read, Write};
    use std::thread;
    use tempfile::tempdir;

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        })
    }

    fn spawn_test_listener() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        Arc<BrokerFdTokenRegistry>,
        Arc<BrokerStateRegistry>,
        Arc<BrokerStateRegistry>,
    ) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("fd-token.sock");
        let fd_registry = Arc::new(BrokerFdTokenRegistry::new());
        let state_registry = Arc::new(BrokerStateRegistry::new());
        let process_registry = Arc::new(BrokerStateRegistry::new());
        let _ = spawn_control_listener(
            &path,
            Arc::clone(&fd_registry),
            Arc::clone(&state_registry),
            Arc::clone(&process_registry),
        )
        .expect("spawn");
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        (dir, path, fd_registry, state_registry, process_registry)
    }

    #[test]
    fn end_to_end_host_fd_lifecycle() {
        let (_dir, path, registry, _state, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        let (r, w) = pipe_pair();
        let handle_id = client.register(r).expect("register");
        assert!(handle_id > 0);
        assert_eq!(registry.live_token_count(), 1);

        let mat_fd = client.materialize(handle_id).expect("materialize");
        let mut writer = std::fs::File::from(w);
        writer.write_all(b"crossworker").unwrap();
        drop(writer);
        let mut reader = std::fs::File::from(mat_fd);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"crossworker");

        client.release(handle_id).expect("release");
        assert_eq!(registry.live_token_count(), 0);
    }

    #[test]
    fn unknown_handle_returns_typed_error() {
        let (_dir, path, _registry, _state, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        match client.materialize(99_999) {
            Err(ClientError::UnknownHandle { handle_id }) => assert_eq!(handle_id, 99_999),
            other => panic!("expected UnknownHandle, got {other:?}"),
        }

        match client.release(99_999) {
            Err(ClientError::UnknownHandle { handle_id }) => assert_eq!(handle_id, 99_999),
            other => panic!("expected UnknownHandle, got {other:?}"),
        }
    }

    #[test]
    fn many_requests_over_one_connection() {
        let (_dir, path, registry, _state, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");
        for _ in 0..50 {
            let (r, _w) = pipe_pair();
            let id = client.register(r).expect("register");
            client.release(id).expect("release");
        }
        assert_eq!(registry.live_token_count(), 0);
    }

    #[test]
    fn register_process_allocates_sequential_pids() {
        let (_dir, path, _fd, _state, process_registry) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        let pid1 = client.register_process().expect("register_process 1");
        let pid2 = client.register_process().expect("register_process 2");
        let pid3 = client.register_process().expect("register_process 3");

        // BrokerStateRegistry monotonically allocates ids starting at 1.
        // The process_registry is dedicated to processes (no other
        // SubsystemTag uses it), so allocations are sequential and
        // small u32-sized.
        assert_eq!(pid1, 1);
        assert_eq!(pid2, 2);
        assert_eq!(pid3, 3);
        assert_eq!(process_registry.live_handle_count(), 3);

        // Release flows through the cascading Release dispatcher to the
        // process registry.
        client.release(pid1).expect("release pid1");
        client.release(pid2).expect("release pid2");
        client.release(pid3).expect("release pid3");
        assert_eq!(process_registry.live_handle_count(), 0);
    }

    #[test]
    fn end_to_end_eventfd_via_client() {
        use litebox_common_linux::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
        use litebox_common_linux::notification_ring::NotificationReceiver;
        use litebox_common_linux::shmem_ring::ShmemRingPair;

        let (_dir, path, _fd_registry, state_registry, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        // Set up the notification ring. Worker creates the pair; broker
        // takes the writer half via SCM_RIGHTS.
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        let (_worker_writer_unused, worker_reader) = pair.into_parts();
        client
            .register_notification_ring(tx_fd, rx_fd)
            .expect("register_notification_ring");
        let mut receiver = NotificationReceiver::new(worker_reader);

        // Create an eventfd.
        let handle = client.create_eventfd(0, false).expect("create_eventfd");
        assert!(handle > 0);
        assert_eq!(state_registry.live_handle_count(), 1);

        // Subscribe with IN+OUT, expect priming notification for OUT.
        client
            .subscribe_eventfd(handle, 42, NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT)
            .expect("subscribe");
        let priming = receiver.recv().expect("recv priming");
        assert_eq!(priming.subscription_id(), 42);
        assert_eq!(priming.events(), NOTIFY_EVENT_OUT);

        // Write a value; expect notification for IN+OUT.
        client.write_eventfd(handle, 7).expect("write");
        let notif = receiver.recv().expect("recv after write");
        assert_eq!(notif.subscription_id(), 42);
        assert_eq!(notif.events(), NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT);

        // Read; expect 7 + notification for OUT only.
        let value = client.read_eventfd(handle).expect("read");
        assert_eq!(value, 7);
        let notif = receiver.recv().expect("recv after read");
        assert_eq!(notif.events(), NOTIFY_EVENT_OUT);

        // Read on empty: WouldBlock.
        match client.read_eventfd(handle) {
            Err(litebox_common_linux::fd_token_client::ClientError::WouldBlock) => {}
            other => panic!("expected WouldBlock, got {other:?}"),
        }

        // Unsubscribe.
        client.unsubscribe(handle, 42).expect("unsubscribe");

        // Release the eventfd handle.
        client.release(handle).expect("release");
        assert_eq!(state_registry.live_handle_count(), 0);
    }

    #[test]
    fn end_to_end_broker_eventfd_facade() {
        // Uses BrokerEventfd + NotificationDispatcher — the full
        // worker-side experience workers will eventually use through
        // the shim once Step 7b lands the Platform-trait indirection.
        use litebox_common_linux::broker_eventfd::{
            BrokerEventfd, NotificationCallback, NotificationDispatcher,
        };
        use litebox_common_linux::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
        use litebox_common_linux::notification_ring::NotificationReceiver;
        use litebox_common_linux::shmem_ring::ShmemRingPair;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct AccumCallback(AtomicU32);
        impl NotificationCallback for AccumCallback {
            fn on_events(&self, events: u32) {
                self.0.fetch_or(events, Ordering::SeqCst);
            }
        }

        let (_dir, path, _fd_registry, state_registry, _proc) = spawn_test_listener();
        let client = Arc::new(FdTokenClient::connect(&path).expect("connect"));

        // Set up the notification ring.
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().expect("ring create");
        let (_worker_writer_unused, worker_reader) = pair.into_parts();
        client
            .register_notification_ring(tx_fd, rx_fd)
            .expect("register_notification_ring");
        let dispatcher = NotificationDispatcher::start(NotificationReceiver::new(worker_reader));

        // Create eventfd via BrokerEventfd facade.
        let efd = BrokerEventfd::create(Arc::clone(&client), 0, false).expect("create");

        // Subscribe with a callback that ORs together all observed events.
        let cb = Arc::new(AccumCallback(AtomicU32::new(0)));
        let sub_id = efd
            .subscribe(
                &dispatcher,
                NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT,
                Arc::clone(&cb) as Arc<dyn NotificationCallback>,
            )
            .expect("subscribe");

        // Write 1 → expect IN+OUT events (after counter changes).
        efd.write(1).expect("write");

        // Wait for the IN bit to appear in the callback (initially OUT
        // arrives via priming, then IN+OUT arrives after write).
        for _ in 0..50 {
            let e = cb.0.load(Ordering::SeqCst);
            if e & NOTIFY_EVENT_IN != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let observed = cb.0.load(Ordering::SeqCst);
        assert!(
            observed & NOTIFY_EVENT_IN != 0,
            "expected IN bit in observed events, got 0x{observed:x}"
        );
        assert!(
            observed & NOTIFY_EVENT_OUT != 0,
            "expected OUT bit (from priming) in observed events, got 0x{observed:x}"
        );

        // Read returns 1.
        let value = efd.read().expect("read");
        assert_eq!(value, 1);

        // Unsubscribe + close.
        efd.unsubscribe(&dispatcher, sub_id).expect("unsubscribe");
        efd.close().expect("close");
        assert_eq!(state_registry.live_handle_count(), 0);
    }
}
