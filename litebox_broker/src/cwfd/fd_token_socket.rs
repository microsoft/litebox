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
use crate::inotify_dispatcher::InotifyDispatcher;
use crate::pgrp_signal_inbox::PgrpSignalInbox;
use crate::process_state::ProcessState;
use crate::state_registry::{
    BrokerStateRegistry, StateHandle, StateObjectEnum, StateRegistryError,
};
use crate::state_service::{
    ConnState, SubscriptionRegistry, handle_deliver_signal_inbox, handle_pty_ioctl,
    handle_pty_write, handle_request as state_handle_request, handle_set_pgid, handle_set_sid,
    handle_subscribe_signal_inbox, handle_unsubscribe_signal_inbox,
};
use litebox_common_linux::fd_token_protocol::{
    BODY_MAX, CTRL_HEADER_LEN, Opcode, OwnedFrame, ProtocolError, StatusCode, build_error_response,
    build_release_response_ok, decode, parse_create_pidfd_response_ok,
    parse_create_pty_response_ok, parse_handle_body, parse_inet_listener_accept_response_ok,
    parse_open_pty_slave_response_ok,
};
use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::num::NonZeroU32;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tracing::{debug, info, warn};

/// Per-connection ledger of broker-held resources owned by the
/// guest process(es) served by this connection.
///
/// # Ownership model
///
/// Each broker-held resource (eventfd state, pipe state, socketpair
/// state, etc.) has a registry-side refcount. A "reference" to that
/// resource is held by a guest process. The broker tracks references
/// at the connection granularity — for now, a connection is a proxy
/// for the guest process(es) it serves (in the simple case: one
/// worker process = one connection = one or more guest pids).
///
/// **Protocol invariants** (these are STRICT — violations close the
/// connection with a loud log):
///
/// * `Release(handle)` MUST be matched by a prior acquire
///   (`Create*` response or `DupHandle`) on the SAME connection.
///   A release from a connection that hasn't acquired the handle
///   is a shim-side bug — typically a fork-inherited fd-table
///   entry whose `on_close` is firing release on the parent's
///   broker connection without the child having ever issued
///   `DupHandle` for that handle.
///
/// * `Release` is NOT idempotent — calling it without a matching
///   acquire is the same protocol error.
///
/// # Crash cleanup
///
/// On unclean disconnect (e.g., worker SIGKILL'd before its shim
/// could run `on_close` on inherited fds), `cleanup_on_disconnect`
/// force-releases each entry by its tracked count so the underlying
/// `StateObject` Drop fires (e.g., `PipeWriteEnd::drop` → reader
/// sees EOF). Without this, a SIGKILL'd worker leaks broker
/// pipe/eventfd/etc. refcounts and the peer worker stalls forever
/// waiting on EOF.
#[derive(Clone, Copy)]
struct PeerCred {
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallerScope {
    /// Syscall-stamped guest pid; non-zero by construction.
    Owned(NonZeroU32),
    /// Async-Drop / unscoped release path; falls back to "any pid on this conn".
    Ambient,
}

impl Hash for CallerScope {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Preserve the old `(caller_pid: u32, id)` HashMap bucket order so
        // Ambient release keeps choosing the same arbitrary bucket.
        self.to_wire().hash(state);
    }
}

impl CallerScope {
    fn from_wire(pid: u32) -> Self {
        match NonZeroU32::new(pid) {
            Some(pid) => Self::Owned(pid),
            None => Self::Ambient,
        }
    }

    fn to_wire(self) -> u32 {
        match self {
            Self::Owned(pid) => pid.get(),
            Self::Ambient => 0,
        }
    }

    fn assert_or_diagnose(&mut self, seen_owned_caller_pid: &mut bool) -> Self {
        match *self {
            Self::Owned(_) => *seen_owned_caller_pid = true,
            Self::Ambient if *seen_owned_caller_pid => {
                // TODO: future hardening — flip this diagnostic to Err once
                // async-Drop / unscoped release paths have explicit ownership.
                warn!(
                    "fd-token control: PE.9 PER-PID GAP: caller_pid=0 on a conn that \
                     previously sent non-zero pids — shim has an unscoped release \
                     path. Operation continues via ambient fallback."
                );
            }
            Self::Ambient => {}
        }
        *self
    }
}

#[derive(Default)]
struct ConnRefTracker {
    /// Per-(caller scope, handle_id) refcount. Wire caller_pid=0 decodes
    /// to [`CallerScope::Ambient`], preserving the historical `(0, id)`
    /// bucket for genuinely unscoped creates while making ambient fallback
    /// explicit at type level.
    state_refs: HashMap<(CallerScope, u64), u32>,
    process_refs: HashMap<(CallerScope, u64), u32>,
    /// PE.9 diagnostic: set to true the first time this conn sends a
    /// non-zero caller_pid frame. Once set, every subsequent
    /// caller_pid=0 frame from this conn is suspicious — it means
    /// the shim stamps caller_pid in some paths but not others on
    /// the same worker. That's a bug class (shim async-drop or
    /// otherwise-unscoped code path). Logged loudly so the gap is
    /// hunted down. Future: caller_pid=0 should be promoted to a
    /// hard protocol violation once async-drop paths are audited.
    seen_nonzero_caller_pid: bool,
    /// PE.12 diagnostic: stable per-conn ID used to correlate frames
    /// across the broker log. Set by `handle_control_connection`.
    conn_id: u64,
    /// Host credentials of the worker process connected to this socket.
    peer_cred: Option<PeerCred>,
}

impl ConnRefTracker {
    fn new() -> Self {
        Self::default()
    }

    /// PE.9 diagnostic: called from every opcode entrypoint that
    /// carries a caller_pid in the frame header, before tracker
    /// mutations. Trips the conn into "gate-on" mode on first
    /// non-zero pid; subsequent caller_pid=0 ops then warn.
    fn note_caller_scope(&mut self, mut caller_scope: CallerScope) -> CallerScope {
        caller_scope.assert_or_diagnose(&mut self.seen_nonzero_caller_pid)
    }

    fn record_state(&mut self, caller_scope: CallerScope, id: u64) {
        *self.state_refs.entry((caller_scope, id)).or_insert(0) += 1;
    }

    fn record_process(&mut self, caller_scope: CallerScope, id: u64) {
        *self.process_refs.entry((caller_scope, id)).or_insert(0) += 1;
    }

    /// Returns true iff this connection has a positive reference
    /// count for `id` from `caller_scope` in the state registry.
    ///
    /// [`CallerScope::Ambient`] falls back to "owned by ANY scope on
    /// this conn" (including an Ambient bucket from an unscoped acquire).
    /// [`CallerScope::Owned`] also accepts an Ambient bucket for state refs:
    /// bridge installs can acquire before the syscall loop has a pid scope,
    /// while the later fd close is pid-scoped.
    fn owns_state(&self, caller_scope: CallerScope, id: u64) -> bool {
        match caller_scope {
            CallerScope::Ambient => self.state_refs.iter().any(|((_, h), c)| *h == id && *c > 0),
            CallerScope::Owned(_) => {
                self.state_refs
                    .get(&(caller_scope, id))
                    .copied()
                    .unwrap_or(0)
                    > 0
                    || self
                        .state_refs
                        .get(&(CallerScope::Ambient, id))
                        .copied()
                        .unwrap_or(0)
                        > 0
            }
        }
    }

    fn owns_process(&self, caller_scope: CallerScope, id: u64) -> bool {
        match caller_scope {
            CallerScope::Ambient => self
                .process_refs
                .iter()
                .any(|((_, h), c)| *h == id && *c > 0),
            CallerScope::Owned(_) => {
                self.process_refs
                    .get(&(caller_scope, id))
                    .copied()
                    .unwrap_or(0)
                    > 0
            }
        }
    }

    /// Worker called Release on `id`. Decrement the matching
    /// (caller scope, id) bucket; try state first, then process.
    /// Removes the entry entirely when its count drops to 0 so
    /// the invariant "key present ⇒ count > 0" holds.
    ///
    /// [`CallerScope::Ambient`] falls back to "decrement an arbitrary
    /// scope bucket holding this id" (see [`owns_state`]). Owned state
    /// releases first use their exact pid bucket, then an Ambient bridge
    /// bucket if one exists for the same handle on this connection.
    fn record_release(&mut self, caller_scope: CallerScope, id: u64) {
        if caller_scope == CallerScope::Ambient {
            // Ambient release: preserve the historical HashMap iteration
            // behavior by picking the first positive bucket for this id,
            // including an Ambient bucket if the acquire was also unscoped.
            let state_key = self
                .state_refs
                .iter()
                .find(|((_, h), c)| *h == id && **c > 0)
                .map(|(k, _)| *k);
            if let Some(key) = state_key {
                if let Some(c) = self.state_refs.get_mut(&key) {
                    *c -= 1;
                    if *c == 0 {
                        self.state_refs.remove(&key);
                    }
                }
                return;
            }
            let proc_key = self
                .process_refs
                .iter()
                .find(|((_, h), c)| *h == id && **c > 0)
                .map(|(k, _)| *k);
            if let Some(key) = proc_key {
                if let Some(c) = self.process_refs.get_mut(&key) {
                    *c -= 1;
                    if *c == 0 {
                        self.process_refs.remove(&key);
                    }
                }
            }
            return;
        }
        if let Some(c) = self.state_refs.get_mut(&(caller_scope, id)) {
            debug_assert!(
                *c > 0,
                "ConnRefTracker invariant: zero-count state_refs entry present for (scope={caller_scope:?}, id={id})"
            );
            if *c > 0 {
                *c -= 1;
                if *c == 0 {
                    self.state_refs.remove(&(caller_scope, id));
                }
                return;
            }
        }
        if let Some(c) = self.state_refs.get_mut(&(CallerScope::Ambient, id)) {
            debug_assert!(
                *c > 0,
                "ConnRefTracker invariant: zero-count ambient state_refs entry present for id={id}"
            );
            if *c > 0 {
                *c -= 1;
                if *c == 0 {
                    self.state_refs.remove(&(CallerScope::Ambient, id));
                }
                return;
            }
        }
        if let Some(c) = self.process_refs.get_mut(&(caller_scope, id)) {
            debug_assert!(
                *c > 0,
                "ConnRefTracker invariant: zero-count process_refs entry present for (scope={caller_scope:?}, id={id})"
            );
            if *c > 0 {
                *c -= 1;
                if *c == 0 {
                    self.process_refs.remove(&(caller_scope, id));
                }
            }
        }
    }

    /// Phase F.5+ PE.1 Step D: release every (pid, id) entry for
    /// the given `pid`. Called from the broker's ReleaseAllForPid
    /// handler when a guest process exits cleanly. Returns the
    /// total number of refs decremented across both registries.
    fn release_all_for_pid(
        &mut self,
        pid: u32,
        state_registry: &BrokerStateRegistry,
        process_registry: &BrokerStateRegistry,
    ) -> u32 {
        let mut released = 0u32;
        let target_scope = CallerScope::from_wire(pid);
        let state_keys: Vec<(CallerScope, u64)> = self
            .state_refs
            .keys()
            .filter(|(scope, _)| *scope == target_scope)
            .copied()
            .collect();
        for key in state_keys {
            if let Some(count) = self.state_refs.remove(&key) {
                for _ in 0..count {
                    let _ = state_registry.release(StateHandle::from_id(key.1));
                    released = released.saturating_add(1);
                }
            }
        }
        let process_keys: Vec<(CallerScope, u64)> = self
            .process_refs
            .keys()
            .filter(|(scope, _)| *scope == target_scope)
            .copied()
            .collect();
        for key in process_keys {
            if let Some(count) = self.process_refs.remove(&key) {
                for _ in 0..count {
                    let _ = process_registry.release(StateHandle::from_id(key.1));
                    released = released.saturating_add(1);
                }
            }
        }
        // P3 invariant: after release_all_for_pid, no (pid, *) entry
        // remains in either tracker. Cheap to check (linear in tracker
        // size, debug-only). A failure here indicates a concurrent
        // insertion or a bug in the removal loop above.
        debug_assert!(
            !self
                .state_refs
                .keys()
                .any(|(scope, _)| *scope == target_scope),
            "P3: state_refs still has entries for released pid {pid}"
        );
        debug_assert!(
            !self
                .process_refs
                .keys()
                .any(|(scope, _)| *scope == target_scope),
            "P3: process_refs still has entries for released pid {pid}"
        );
        released
    }

    /// Force-release every (pid, id) entry. Used on disconnect.
    /// Returns (state_total, process_total) for diagnostics.
    fn cleanup_on_disconnect(
        self,
        state_registry: &BrokerStateRegistry,
        process_registry: &BrokerStateRegistry,
    ) {
        let mut total_state = 0usize;
        let mut total_process = 0usize;
        for ((_scope, id), count) in self.state_refs {
            for _ in 0..count {
                let _ = state_registry.release(StateHandle::from_id(id));
                total_state += 1;
            }
        }
        for ((_scope, id), count) in self.process_refs {
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

fn peer_cred(stream: &UnixStream) -> Option<PeerCred> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` points to writable storage of `len` bytes, `len` points to
    // initialized socklen_t storage, and `stream.as_raw_fd()` is a valid socket fd.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc == 0 && len as usize >= std::mem::size_of::<libc::ucred>() {
        // SAFETY: getsockopt returned success and reported a complete ucred.
        let cred = unsafe { cred.assume_init() };
        Some(PeerCred {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
        })
    } else {
        None
    }
}

fn peer_cred_fields(peer_cred: Option<PeerCred>) -> String {
    match peer_cred {
        Some(cred) => format!(
            "peer_pid={} peer_uid={} peer_gid={}",
            cred.pid, cred.uid, cred.gid
        ),
        None => "peer_pid=? peer_uid=? peer_gid=?".to_string(),
    }
}

fn caller_process_exited_or_gone(
    process_registry: &BrokerStateRegistry,
    caller_scope: CallerScope,
) -> bool {
    let CallerScope::Owned(pid) = caller_scope else {
        return false;
    };
    let handle = StateHandle::from_id(u64::from(pid.get()));
    match process_registry.resolve(handle, SubsystemTag::Process) {
        Ok(state) => {
            let StateObjectEnum::Process(process) = state.as_ref() else {
                return false;
            };
            process.exit_state().is_some()
        }
        Err(StateRegistryError::UnknownHandle(_)) => true,
        Err(StateRegistryError::TagMismatch { .. })
        | Err(StateRegistryError::RefcountOverflow(_)) => false,
    }
}

fn ensure_process_registered_for_caller(
    process_registry: &BrokerStateRegistry,
    tracker: &mut ConnRefTracker,
    caller_scope: CallerScope,
) {
    let CallerScope::Owned(pid) = caller_scope else {
        return;
    };
    let id = u64::from(pid.get());
    if tracker.owns_process(caller_scope, id) {
        return;
    }

    let handle = StateHandle::from_id(id);
    match process_registry.resolve(handle, SubsystemTag::Process) {
        Ok(_) => match process_registry.dup(handle) {
            Ok(_) => tracker.record_process(caller_scope, id),
            Err(err) => {
                warn!(pid = pid.get(), error = ?err, "fd-token control: failed to dup caller process handle")
            }
        },
        Err(StateRegistryError::UnknownHandle(_)) => {
            match process_registry.register_with_id(id, ProcessState::arc()) {
                Ok(registered) => {
                    debug_assert_eq!(registered.id(), id);
                    tracker.record_process(caller_scope, id);
                }
                Err(err) => {
                    warn!(pid = pid.get(), error = ?err, "fd-token control: failed to auto-register caller process handle")
                }
            }
        }
        Err(StateRegistryError::TagMismatch { .. }) => {
            warn!(
                pid = pid.get(),
                "fd-token control: caller pid handle is not a Process"
            );
        }
        Err(err) => {
            warn!(pid = pid.get(), error = ?err, "fd-token control: failed to resolve caller process handle")
        }
    }
}

/// Inspect a successful response frame and record this connection's
/// net contribution to broker registry refcounts. Called once per
/// request/response round on the socket loop.
fn update_tracker_from_response(
    tracker: &mut ConnRefTracker,
    caller_scope: CallerScope,
    request_opcode: Opcode,
    request_body: &[u8],
    response: &OwnedFrame,
) {
    if response.status != StatusCode::Ok {
        return;
    }
    // reason: unsupported variants intentionally share this fallback path.
    #[allow(clippy::wildcard_enum_match_arm)]
    match request_opcode {
        // State-registry creators: response body is one or two handle ids.
        Opcode::CreateEventfd
        | Opcode::CreatePidfd
        | Opcode::CreateTimerfd
        | Opcode::CreateSignalfd
        | Opcode::InotifyInit1
        | Opcode::InetListenerCreate
        | Opcode::InetTcpConnCreate
        | Opcode::InetDgramCreate
        | Opcode::InetRawCreate
        | Opcode::AttachHostFd => {
            if let Ok(id) = parse_handle_body(&response.body, response.opcode) {
                tracker.record_state(caller_scope, id);
            }
        }
        Opcode::CreatePipe => {
            // build_create_pipe_response_ok packs (read_id, write_id) as 2 u64 LE.
            if response.body.len() >= 16 {
                let r = u64::from_le_bytes(response.body[..8].try_into().unwrap());
                let w = u64::from_le_bytes(response.body[8..16].try_into().unwrap());
                tracker.record_state(caller_scope, r);
                tracker.record_state(caller_scope, w);
            }
        }
        Opcode::CreateSocketPair => {
            // Phase F: response is (endpoint_a_id, endpoint_b_id) as 2 u64 LE.
            if response.body.len() >= 16 {
                let a = u64::from_le_bytes(response.body[..8].try_into().unwrap());
                let b = u64::from_le_bytes(response.body[8..16].try_into().unwrap());
                tracker.record_state(caller_scope, a);
                tracker.record_state(caller_scope, b);
            }
        }
        Opcode::CreatePty => {
            if let Ok((master, slave, _flags)) = parse_create_pty_response_ok(&response.body) {
                tracker.record_state(caller_scope, master);
                tracker.record_state(caller_scope, slave);
            }
        }
        Opcode::OpenPtySlave => {
            if let Ok((slave, _pty_id)) = parse_open_pty_slave_response_ok(&response.body) {
                tracker.record_state(caller_scope, slave);
            }
        }
        Opcode::InetListenerAccept => {
            if let Ok((conn, _peer)) = parse_inet_listener_accept_response_ok(&response.body) {
                tracker.record_state(caller_scope, conn);
            }
        }
        // Process-registry creator.
        Opcode::RegisterProcess => {
            if let Ok(id) = parse_handle_body(&response.body, response.opcode) {
                tracker.record_process(caller_scope, id);
            }
        }
        // DupHandle: request body is one u64 handle id; response is empty.
        Opcode::DupHandle => {
            if request_body.len() >= 8 {
                let id = u64::from_le_bytes(request_body[..8].try_into().unwrap());
                tracker.record_state(caller_scope, id);
            }
        }
        // Release: -1 on whichever registry.
        Opcode::Release => {
            if request_body.len() >= 8 {
                let id = u64::from_le_bytes(request_body[..8].try_into().unwrap());
                tracker.record_release(caller_scope, id);
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
    inotify_dispatcher: Arc<InotifyDispatcher>,
    pgrp_signal_inbox: Arc<PgrpSignalInbox>,
) {
    // PE.12 diag: assign a per-conn id so we can correlate frames
    // across the broker log. Counter is process-global, monotonic.
    static CONN_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let conn_id = CONN_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let peer_cred = peer_cred(&stream);
    if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/rst-diag.log")
        {
            let _ = writeln!(
                f,
                "[PE.12-diag] CONN OPEN: conn_id={conn_id} {}",
                peer_cred_fields(peer_cred)
            );
        }
    }
    let mut conn_state = ConnState::with_conn_id(conn_id);
    let mut tracker = ConnRefTracker::new();
    tracker.conn_id = conn_id;
    tracker.peer_cred = peer_cred;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_control_connection_inner(
            stream,
            &fd_registry,
            &state_registry,
            &process_registry,
            &inotify_dispatcher,
            &pgrp_signal_inbox,
            &mut conn_state,
            &mut tracker,
        )
    }));
    // PE.14 diag: if the inner handler panicked, log the payload.
    // A panic here typically poisons one of the global registries'
    // mutexes; subsequent conns' RPC handlers will then panic at
    // `.expect("...poisoned")` and drop their UnixStreams,
    // surfacing as "BrokenPipe" on the runner side.
    if let Err(payload) = &result {
        let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            format!("non-string panic payload (type_id={:?})", payload.type_id())
        };
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
                "[PE.14-diag] ts={ts} BROKER CONN HANDLER PANIC conn_id={conn_id} {}: {msg}",
                peer_cred_fields(peer_cred)
            );
        }
    }
    // PE.9 fix: BEFORE releasing tracked state refs, force-unsubscribe
    // every subscription this conn issued. If we release first, a
    // state might Drop with our subscription still in its
    // SubscriptionList — a leak (the subscribe-doesn't-bump-rc
    // gap documented in the PE.9 fix commit). Doing the unsubscribe
    // pass first ensures the SubscriptionList is empty before the
    // state's refcount can hit zero from our release.
    pgrp_signal_inbox.cleanup_connection(conn_id);
    for (registry_kind, handle_id, subscription_id) in conn_state.drain_tracked_subscriptions() {
        let handle = StateHandle::from_id(handle_id);
        let registry = match registry_kind {
            SubscriptionRegistry::State => state_registry.as_ref(),
            SubscriptionRegistry::Process => process_registry.as_ref(),
        };
        if let Ok(obj) = registry.resolve_untyped(handle) {
            let _ = obj.unsubscribe(subscription_id);
            if registry_kind == SubscriptionRegistry::Process {
                let _ = registry.release(handle);
            }
        }
    }
    // Force-release any broker-registry refs this connection contributed
    // but did not release before disconnect. Critical for SIGKILL'd
    // workers whose shim never got to run `on_close` on inherited
    // broker-backed fds.
    //
    // PE.14 experiment: optional pre-cleanup delay to test the
    // hypothesis that `cleanup_on_disconnect` racing with concurrent
    // RPCs on sibling conns is the bug. Set
    // `LITEBOX_CLEANUP_DELAY_MS=N` to inject N ms before cleanup.
    if let Ok(s) = std::env::var("LITEBOX_CLEANUP_DELAY_MS")
        && let Ok(ms) = s.parse::<u64>()
        && ms > 0
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    let final_tracker = std::mem::take(&mut tracker);
    final_tracker.cleanup_on_disconnect(&state_registry, &process_registry);
    let _ = result;
}

fn handle_control_connection_inner(
    stream: UnixStream,
    fd_registry: &Arc<BrokerFdTokenRegistry>,
    state_registry: &Arc<BrokerStateRegistry>,
    process_registry: &Arc<BrokerStateRegistry>,
    inotify_dispatcher: &Arc<InotifyDispatcher>,
    pgrp_signal_inbox: &Arc<PgrpSignalInbox>,
    conn_state: &mut ConnState,
    tracker: &mut ConnRefTracker,
) {
    // PE.14 diag: RAII guard that fires when this function returns
    // OR panics. Captures the FINAL return path. Tag each CONN CLOSE
    // log line with a high-resolution monotonic timestamp so we can
    // reconstruct chronology vs runner-side diag lines from the same
    // /tmp/rst-diag.log file (multi-process appends arrive out of
    // order).
    struct CloseGuard {
        conn_id: u64,
        fd: i32,
        peer_cred: Option<PeerCred>,
    }
    impl Drop for CloseGuard {
        fn drop(&mut self) {
            use std::io::Write;
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let bt = std::backtrace::Backtrace::force_capture();
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/rst-diag.log")
            {
                let _ = writeln!(
                    f,
                    "[PE.14-diag] ts={ts} CONN HANDLER EXIT conn_id={} fd={} {} (UnixStream about to drop)\nbacktrace:\n{bt}",
                    self.conn_id,
                    self.fd,
                    peer_cred_fields(self.peer_cred)
                );
            }
        }
    }
    let _close_guard = CloseGuard {
        conn_id: tracker.conn_id,
        fd: {
            use std::os::unix::io::AsRawFd;
            stream.as_raw_fd()
        },
        peer_cred: tracker.peer_cred,
    };
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
                let caller_pid = frame.caller_pid;
                let caller_scope = tracker.note_caller_scope(CallerScope::from_wire(caller_pid));
                if matches!(
                    request_opcode,
                    Opcode::SetSid
                        | Opcode::SetPgid
                        | Opcode::SubscribeProcessExit
                        | Opcode::MarkProcessExited
                ) {
                    ensure_process_registered_for_caller(process_registry, tracker, caller_scope);
                }
                // PE.12 diag: log every frame received, gated on
                // LITEBOX_PE10_DIAG. Tracker state pid_count helps
                // identify which conn (by tracker fingerprint) the
                // frame belongs to.
                if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("/tmp/rst-diag.log")
                    {
                        let tracker_size = tracker.state_refs.len() + tracker.process_refs.len();
                        let body_first = request_body
                            .iter()
                            .take(8)
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join("");
                        let _ = writeln!(
                            f,
                            "[PE.12-diag] FRAME conn_id={} opcode={request_opcode:?} caller_pid={caller_pid} \
                             body[..8]={body_first} tracker_size={tracker_size}",
                            tracker.conn_id
                        );
                    }
                }
                // reason: unsupported protocol opcodes intentionally close the control connection.
                #[allow(clippy::wildcard_enum_match_arm)]
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
                        //
                        // Phase F follow-up: STRICT OWNERSHIP CHECK. A Release of a handle that
                        // EXISTS but is not owned by this connection is a protocol violation
                        // (typically a fork-inherited fd-table entry whose on_close fires
                        // release on the parent's broker connection without a matching
                        // DupHandle). We close the connection in that case so the bug
                        // surfaces loudly. A Release of a handle that doesn't exist anywhere
                        // is just an unknown-handle error (existing behavior).
                        let fds: Vec<OwnedFd> = in_fds;
                        if !fds.is_empty() {
                            warn!("fd-token control: Release with attached fds; closing");
                            return;
                        }
                        let release_id = match parse_handle_body(frame.body, frame.opcode) {
                            Ok(id) => id,
                            Err(_) => {
                                warn!("fd-token control: Release with malformed body; closing");
                                return;
                            }
                        };
                        // Host-fd registry: it has its own per-conn ownership inside
                        // BrokerFdTokenRegistry. Let it speak for itself.
                        let host_result = match host_fd_handle_request(fd_registry, &frame, None) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!(error = %e, "fd-token control: fatal handler error");
                                return;
                            }
                        };
                        if host_result.frame.status
                            != litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle
                        {
                            // Host-fd handled it (success or other status).
                            SocketHandlerResult {
                                frame: host_result.frame,
                                out_fd: host_result.out_fd,
                            }
                        } else if tracker.owns_state(caller_scope, release_id) {
                            // State-registry release. Owner-gated.
                            let state_result = state_handle_request(
                                state_registry,
                                inotify_dispatcher,
                                conn_state,
                                &frame,
                                Vec::new(),
                            );
                            SocketHandlerResult {
                                frame: state_result.frame,
                                out_fd: state_result.out_fd,
                            }
                        } else if tracker.owns_process(caller_scope, release_id) {
                            // Process-registry release. Owner-gated.
                            let proc_result = state_handle_request(
                                process_registry,
                                inotify_dispatcher,
                                conn_state,
                                &frame,
                                Vec::new(),
                            );
                            SocketHandlerResult {
                                frame: proc_result.frame,
                                out_fd: proc_result.out_fd,
                            }
                        } else if state_registry
                            .resolve(StateHandle::from_id(release_id), SubsystemTag::TcpSocket)
                            .is_ok()
                        {
                            // Broker TCP accept currently registers the accepted stream from
                            // the network proxy before the worker control connection owns it.
                            // Let the accepting worker's close consume that handoff ref.
                            let state_result = state_handle_request(
                                state_registry,
                                inotify_dispatcher,
                                conn_state,
                                &frame,
                                Vec::new(),
                            );
                            SocketHandlerResult {
                                frame: state_result.frame,
                                out_fd: state_result.out_fd,
                            }
                        } else {
                            // This conn doesn't own a state or process ref. Is the handle
                            // even known to the broker, or is it just bogus?
                            let state_exists = state_registry
                                .resolve_untyped(StateHandle::from_id(release_id))
                                .is_ok();
                            let process_exists = process_registry
                                .resolve_untyped(StateHandle::from_id(release_id))
                                .is_ok();
                            if state_exists || process_exists {
                                // Per-pid ReleaseAllForPid is a teardown sweep, not a
                                // replacement for every later fd Drop. If a state object
                                // is still live but this conn's per-pid bucket was already
                                // drained, treat the late fd close as an idempotent no-op
                                // rather than killing the shared control socket.
                                if state_exists
                                    && (!process_exists
                                        || caller_process_exited_or_gone(
                                            process_registry,
                                            caller_scope,
                                        ))
                                {
                                    debug!(
                                        handle_id = release_id,
                                        caller_pid,
                                        "fd-token control: tolerating late Release after per-pid deregistration"
                                    );
                                    SocketHandlerResult {
                                        frame: build_release_response_ok(),
                                        out_fd: None,
                                    }
                                } else {
                                    // Handle exists but THIS conn isn't an owner. Loud bug.
                                    warn!(
                                        handle_id = release_id,
                                        state_exists,
                                        process_exists,
                                        caller_pid,
                                        "fd-token control: PROTOCOL VIOLATION: Release of \
                                         broker-held resource not owned by this connection; \
                                         closing. Likely a shim-side bug — a fork-inherited \
                                         fd-table entry's on_close firing release without a \
                                         matching DupHandle."
                                    );
                                    // PE.5 diag: also write to the runner-side
                                    // diagnostic file so it's visible in
                                    // LITEBOX_KEEP_CONTAINER inspections.
                                    // Includes tracker state dump for the
                                    // current conn so we can see which
                                    // (pid, id) buckets exist when the
                                    // violation fires.
                                    use std::io::Write;
                                    if let Ok(mut f) = std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open("/tmp/rst-diag.log")
                                    {
                                        let state_entries: Vec<((u32, u64), u32)> = tracker
                                            .state_refs
                                            .iter()
                                            .map(|((scope, id), count)| {
                                                (((*scope).to_wire(), *id), *count)
                                            })
                                            .collect();
                                        let proc_entries: Vec<((u32, u64), u32)> = tracker
                                            .process_refs
                                            .iter()
                                            .map(|((scope, id), count)| {
                                                (((*scope).to_wire(), *id), *count)
                                            })
                                            .collect();
                                        let _ = writeln!(
                                            f,
                                            "[PE.5-diag] BROKER PROTOCOL VIOLATION conn_id={}: Release \
                                         handle_id={release_id} caller_pid={caller_pid} \
                                         state_exists={state_exists} process_exists={process_exists}\n  \
                                         conn state_refs: {state_entries:?}\n  \
                                         conn process_refs: {proc_entries:?}",
                                            tracker.conn_id
                                        );
                                    }
                                    return;
                                }
                            } else {
                                // Handle is truly unknown to the broker — preserve existing
                                // semantics by returning UnknownHandle to the client.
                                SocketHandlerResult {
                                    frame: build_error_response(
                                        Opcode::ReleaseResponse,
                                        litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle,
                                    ),
                                    out_fd: None,
                                }
                            }
                        }
                    }
                    Opcode::SubscribeSignalInbox => {
                        let result = handle_subscribe_signal_inbox(
                            pgrp_signal_inbox,
                            conn_state,
                            &frame,
                            in_fds,
                        );
                        SocketHandlerResult {
                            frame: result.frame,
                            out_fd: result.out_fd,
                        }
                    }
                    Opcode::DeliverSignalInbox => {
                        let result = handle_deliver_signal_inbox(pgrp_signal_inbox, &frame, in_fds);
                        SocketHandlerResult {
                            frame: result.frame,
                            out_fd: result.out_fd,
                        }
                    }
                    Opcode::UnsubscribeSignalInbox => {
                        let result = handle_unsubscribe_signal_inbox(
                            pgrp_signal_inbox,
                            conn_state,
                            &frame,
                            in_fds,
                        );
                        SocketHandlerResult {
                            frame: result.frame,
                            out_fd: result.out_fd,
                        }
                    }
                    Opcode::SetPgid => {
                        let result = handle_set_pgid(
                            process_registry,
                            pgrp_signal_inbox,
                            conn_state,
                            &frame,
                            in_fds,
                        );
                        SocketHandlerResult {
                            frame: result.frame,
                            out_fd: result.out_fd,
                        }
                    }
                    Opcode::SetSid => {
                        let result = handle_set_sid(
                            process_registry,
                            pgrp_signal_inbox,
                            conn_state,
                            &frame,
                            in_fds,
                        );
                        SocketHandlerResult {
                            frame: result.frame,
                            out_fd: result.out_fd,
                        }
                    }
                    Opcode::Unsubscribe => {
                        // Unsubscribe is kind-agnostic: try fd-state first, then process-state.
                        let state_result = state_handle_request(
                            state_registry,
                            inotify_dispatcher,
                            conn_state,
                            &frame,
                            in_fds,
                        );
                        if matches!(
                            state_result.frame.status,
                            litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle
                                | litebox_common_linux::fd_token_protocol::StatusCode::UnknownSubscription
                        ) {
                            let proc_result = state_handle_request(
                                process_registry,
                                inotify_dispatcher,
                                conn_state,
                                &frame,
                                Vec::new(),
                            );
                            if proc_result.frame.status
                                != litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle
                            {
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
                                frame: state_result.frame,
                                out_fd: state_result.out_fd,
                            }
                        }
                    }
                    Opcode::RegisterNotificationRing
                    | Opcode::CreateEventfd
                    | Opcode::ReadEventfd
                    | Opcode::WriteEventfd
                    | Opcode::CreateTimerfd
                    | Opcode::ReadTimerfd
                    | Opcode::SetTimerfd
                    | Opcode::GetTimerfd
                    | Opcode::CreateSignalfd
                    | Opcode::ReadSiginfo
                    | Opcode::PushSiginfo
                    | Opcode::InotifyInit1
                    | Opcode::InotifyAddWatch
                    | Opcode::InotifyRmWatch
                    | Opcode::InotifyRead
                    | Opcode::InotifyQueryEvents
                    | Opcode::InetListenerCreate
                    | Opcode::InetListenerBind
                    | Opcode::InetListenerListen
                    | Opcode::InetListenerAccept
                    | Opcode::InetListenerQueryEvents
                    | Opcode::InetListenerSetSockOpt
                    | Opcode::InetListenerGetSockName
                    | Opcode::InetListenerGetSockOpt
                    | Opcode::InetRawCreate
                    | Opcode::InetRawSendTo
                    | Opcode::InetRawRecvFrom
                    | Opcode::InetRawQueryEvents
                    | Opcode::InetTcpConnCreate
                    | Opcode::InetTcpConnConnect
                    | Opcode::InetTcpConnQueryEvents
                    | Opcode::InetTcpConnGetSockName
                    | Opcode::InetTcpConnGetPeerName
                    | Opcode::InetDgramCreate
                    | Opcode::InetDgramBind
                    | Opcode::InetDgramConnect
                    | Opcode::InetDgramSendTo
                    | Opcode::InetDgramRecvFrom
                    | Opcode::InetDgramShutdown
                    | Opcode::InetDgramGetSockName
                    | Opcode::InetDgramGetPeerName
                    | Opcode::InetDgramSetSockOpt
                    | Opcode::InetDgramGetSockOpt
                    | Opcode::InetDgramQueryEvents
                    | Opcode::InetTcpConnSetSockOpt
                    | Opcode::InetTcpConnGetSockOpt
                    | Opcode::CreatePipe
                    | Opcode::ReadPipe
                    | Opcode::WritePipe
                    | Opcode::AttachHostFd
                    | Opcode::CreateSocketDgram
                    | Opcode::SocketDgramBind
                    | Opcode::SocketDgramConnect
                    | Opcode::SocketDgramSendTo
                    | Opcode::SocketDgramRecvFrom
                    | Opcode::SocketDgramShutdown
                    | Opcode::SocketDgramGetSockName
                    | Opcode::SocketDgramGetPeerName
                    | Opcode::CreateSocketSeqPacket
                    | Opcode::SocketSeqPacketBind
                    | Opcode::SocketSeqPacketListen
                    | Opcode::SocketSeqPacketAccept
                    | Opcode::SocketSeqPacketConnect
                    | Opcode::SocketSeqPacketSend
                    | Opcode::SocketSeqPacketRecv
                    | Opcode::SocketSeqPacketShutdown
                    | Opcode::SocketSeqPacketGetSockName
                    | Opcode::SocketSeqPacketGetPeerName
                    | Opcode::CreateSocketPair
                    | Opcode::ReadSocketPair
                    | Opcode::WriteSocketPair
                    | Opcode::ShutdownSocketPairWrite
                    | Opcode::CreatePty
                    | Opcode::OpenPtySlave
                    | Opcode::PtyRead
                    | Opcode::SubscribePty
                    | Opcode::SubscribeEventfd
                    | Opcode::ReadTcpConn
                    | Opcode::WriteTcpConn
                    | Opcode::ShutdownTcpConn
                    | Opcode::PollTcpConnEvents
                    | Opcode::DupHandle
                    | Opcode::BindNinePSession
                    | Opcode::RegisterOfd
                    | Opcode::CloneOfd => {
                        // State-object opcodes: route to state_service on the fd-state registry.
                        let state_result = state_handle_request(
                            state_registry,
                            inotify_dispatcher,
                            conn_state,
                            &frame,
                            in_fds,
                        );
                        SocketHandlerResult {
                            frame: state_result.frame,
                            out_fd: state_result.out_fd,
                        }
                    }
                    Opcode::QueryEvents => {
                        // QueryEvents is registry-agnostic: handles can live in
                        // state_registry (Pty / Eventfd / Pipe / SocketPair / Tcp /
                        // Signalfd / Pidfd) or process_registry (Process). Try
                        // state first; on UnknownHandle fall back to process. Same
                        // cross-registry shape as Opcode::Release.
                        let state_result = state_handle_request(
                            state_registry,
                            inotify_dispatcher,
                            conn_state,
                            &frame,
                            in_fds,
                        );
                        if state_result.frame.status
                            == litebox_common_linux::fd_token_protocol::StatusCode::UnknownHandle
                        {
                            let proc_result = state_handle_request(
                                process_registry,
                                inotify_dispatcher,
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
                    Opcode::PtyWrite => {
                        let state_result = handle_pty_write(
                            state_registry,
                            Some(pgrp_signal_inbox.as_ref()),
                            &frame,
                            in_fds,
                        );
                        SocketHandlerResult {
                            frame: state_result.frame,
                            out_fd: state_result.out_fd,
                        }
                    }
                    Opcode::PtyIoctl => {
                        let state_result = handle_pty_ioctl(
                            state_registry,
                            Some(pgrp_signal_inbox.as_ref()),
                            &frame,
                            in_fds,
                        );
                        SocketHandlerResult {
                            frame: state_result.frame,
                            out_fd: state_result.out_fd,
                        }
                    }
                    Opcode::ReleaseAllForPid => {
                        // Phase F.5+ PE.1 Step D: parse pid, release every
                        // (pid, *) entry tracked on this connection across
                        // both registries, and return the count.
                        // reason: unsupported variants intentionally share this fallback path.
                        #[allow(clippy::wildcard_enum_match_arm)]
                        match litebox_common_linux::fd_token_protocol::parse_release_all_for_pid_body(
                            &request_body,
                        ) {
                            Ok(target_pid) => {
                                let released = tracker.release_all_for_pid(
                                    target_pid,
                                    state_registry,
                                    process_registry,
                                );
                                // PE.5 diag (gated): trace every
                                // ReleaseAllForPid invocation when
                                // LITEBOX_PE5_DIAG=1. Useful when
                                // chasing premature-release / read-empty
                                // patterns; spammy in normal use.
                                if std::env::var_os("LITEBOX_PE5_DIAG").is_some() {
                                    use std::io::Write;
                                    if let Ok(mut f) = std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open("/tmp/rst-diag.log")
                                    {
                                        let _ = writeln!(
                                            f,
                                            "[PE.5-diag] ReleaseAllForPid target_pid={target_pid} released={released}"
                                        );
                                    }
                                }
                                if released > 0 {
                                    debug!(
                                        target_pid,
                                        released,
                                        "fd-token control: ReleaseAllForPid"
                                    );
                                }
                                SocketHandlerResult {
                                    frame: litebox_common_linux::fd_token_protocol::build_release_all_for_pid_response_ok(
                                        released,
                                    ),
                                    out_fd: None,
                                }
                            }
                            Err(_) => {
                                warn!("fd-token control: malformed ReleaseAllForPid body; closing");
                                return;
                            }
                        }
                    }
                    Opcode::RegisterProcess
                    | Opcode::SubscribeProcessExit
                    | Opcode::MarkProcessExited => {
                        // Process operations: route to state_service on the *process*
                        // registry. RegisterProcess allocates the process handle; Phase G
                        // exit-state RPCs resolve that same handle id (guest pid).
                        let proc_result = state_handle_request(
                            process_registry,
                            inotify_dispatcher,
                            conn_state,
                            &frame,
                            in_fds,
                        );
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
                update_tracker_from_response(
                    tracker,
                    caller_scope,
                    request_opcode,
                    &request_body,
                    &result.frame,
                );
                if let Err(e) = write_response(&stream, result.frame, result.out_fd) {
                    warn!(error = %e, "fd-token control: write error");
                    // PE.14 diag: persistent log of conn-close reasons.
                    if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("/tmp/rst-diag.log")
                        {
                            let _ = writeln!(
                                f,
                                "[PE.14-diag] CONN CLOSE conn_id={} {} reason=write_error: {e}",
                                tracker.conn_id,
                                peer_cred_fields(tracker.peer_cred)
                            );
                        }
                    }
                    return;
                }
            }
            Err(ConnError::PeerClosed) => {
                debug!("fd-token control: peer closed");
                if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("/tmp/rst-diag.log")
                    {
                        let _ = writeln!(
                            f,
                            "[PE.14-diag] CONN CLOSE conn_id={} {} reason=peer_closed",
                            tracker.conn_id,
                            peer_cred_fields(tracker.peer_cred)
                        );
                    }
                }
                return;
            }
            Err(e) => {
                warn!(error = %e, "fd-token control: read error");
                if std::env::var_os("LITEBOX_PE10_DIAG").is_some() {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("/tmp/rst-diag.log")
                    {
                        let _ = writeln!(
                            f,
                            "[PE.14-diag] CONN CLOSE conn_id={} {} reason=read_error: {e}",
                            tracker.conn_id,
                            peer_cred_fields(tracker.peer_cred)
                        );
                    }
                }
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
    inotify_dispatcher: Arc<InotifyDispatcher>,
) -> std::io::Result<JoinHandle<()>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!(path = %path.display(), "fd-token control listener bound");
    let pgrp_signal_inbox = Arc::new(PgrpSignalInbox::new());
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
                        let pgrp_signal_inbox = Arc::clone(&pgrp_signal_inbox);
                        let inotify_dispatcher = Arc::clone(&inotify_dispatcher);
                        if let Err(e) =
                            thread::Builder::new()
                                .name("fd-token-conn".into())
                                .spawn(move || {
                                    handle_control_connection(
                                        stream,
                                        fd_registry,
                                        state_registry,
                                        process_registry,
                                        inotify_dispatcher,
                                        pgrp_signal_inbox,
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
        let inotify_dispatcher = Arc::new(InotifyDispatcher::new());
        let _ = spawn_control_listener(
            &path,
            Arc::clone(&fd_registry),
            Arc::clone(&state_registry),
            Arc::clone(&process_registry),
            inotify_dispatcher,
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

    #[test]
    fn release_all_for_pid_drains_per_pid_bucket() {
        // Phase F.5+ PE.1 Step D: when the shim sends caller_pid != 0
        // on resource creation, the broker tracks per-(pid, id), and
        // ReleaseAllForPid(pid) drains every entry for that pid
        // without touching entries owned by other pids.
        use litebox_common_linux::fd_token_client::set_caller_pid_scope;

        let (_dir, path, _fdr, state_registry, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        // Pid 7 creates two eventfds.
        let (h7a, h7b) = {
            let _guard = set_caller_pid_scope(7);
            let a = client.create_eventfd(0, false).expect("create eventfd a");
            let b = client.create_eventfd(0, false).expect("create eventfd b");
            (a, b)
        };
        // Pid 8 creates one eventfd.
        let h8 = {
            let _guard = set_caller_pid_scope(8);
            client.create_eventfd(0, false).expect("create eventfd c")
        };
        assert_eq!(state_registry.live_handle_count(), 3);

        // ReleaseAllForPid(7) drops both pid-7 handles, keeps pid-8.
        let released = {
            let _guard = set_caller_pid_scope(7);
            client.release_all_for_pid(7).expect("release_all_for_pid")
        };
        assert_eq!(released, 2, "should release exactly the two pid-7 refs");
        assert_eq!(
            state_registry.live_handle_count(),
            1,
            "pid-8 eventfd must remain"
        );

        // ReleaseAllForPid(7) again — nothing left to release.
        let released_again = {
            let _guard = set_caller_pid_scope(7);
            client
                .release_all_for_pid(7)
                .expect("release_all_for_pid 2")
        };
        assert_eq!(released_again, 0);

        // ReleaseAllForPid(8) drains the remaining handle.
        let released_8 = {
            let _guard = set_caller_pid_scope(8);
            client
                .release_all_for_pid(8)
                .expect("release_all_for_pid 8")
        };
        assert_eq!(released_8, 1);
        assert_eq!(state_registry.live_handle_count(), 0);

        let _ = (h7a, h7b, h8);
    }

    #[test]
    fn owned_release_can_close_ambient_bridge_ref() {
        use litebox_common_linux::fd_token_client::set_caller_pid_scope;

        let (_dir, path, _fdr, state_registry, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        let handle = client.create_eventfd(0, false).expect("create ambient");
        assert_eq!(state_registry.live_handle_count(), 1);

        {
            let _guard = set_caller_pid_scope(7);
            client.release(handle).expect("release ambient under pid");
        }

        assert_eq!(state_registry.live_handle_count(), 0);
    }

    #[test]
    fn release_after_process_exit_is_tolerated_when_state_still_exists() {
        use litebox_common_linux::fd_token_client::set_caller_pid_scope;

        let (_dir, path, _fdr, state_registry, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        let (read_handle, _write_handle) = {
            let _guard = set_caller_pid_scope(7);
            client.create_pipe(65_536, 4_096).expect("create pipe")
        };
        {
            let _guard = set_caller_pid_scope(8);
            client.dup_handle(read_handle).expect("pid 8 dup read end");
        }
        assert_eq!(state_registry.live_handle_count(), 2);

        {
            let _guard = set_caller_pid_scope(7);
            client.mark_process_exited(7, 0).expect("mark pid 7 exited");
            assert_eq!(client.release_all_for_pid(7).expect("release all pid 7"), 3);
            assert_eq!(state_registry.live_handle_count(), 1);
            client
                .release(read_handle)
                .expect("late fd close after process release-all");
        }

        assert_eq!(state_registry.live_handle_count(), 1);
        {
            let _guard = set_caller_pid_scope(8);
            client.release(read_handle).expect("pid 8 release read end");
        }
        assert_eq!(state_registry.live_handle_count(), 0);
    }

    #[test]
    fn caller_pid_zero_is_distinct_bucket() {
        use litebox_common_linux::fd_token_client::set_caller_pid_scope;

        let (_dir, path, _fdr, state_registry, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        // Default (caller_pid=0) creates one.
        let _h0 = client.create_eventfd(0, false).expect("create");
        // pid=5 creates one.
        let _h5 = {
            let _guard = set_caller_pid_scope(5);
            client.create_eventfd(0, false).expect("create")
        };
        assert_eq!(state_registry.live_handle_count(), 2);

        // ReleaseAllForPid(0) drains the legacy bucket only.
        let n = client.release_all_for_pid(0).expect("release_all 0");
        assert_eq!(n, 1);
        assert_eq!(state_registry.live_handle_count(), 1);

        let n = {
            let _guard = set_caller_pid_scope(5);
            client.release_all_for_pid(5).expect("release_all 5")
        };
        assert_eq!(n, 1);
        assert_eq!(state_registry.live_handle_count(), 0);
    }

    // ---------- D2.3: client-side attach_host_fd integration tests --------

    #[test]
    fn attach_host_fd_round_trip_read() {
        use litebox_common_linux::fd_token_protocol::host_fd_direction;

        let (_dir, path, _fd_reg, state, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        // Pipe pair: hand the READ end to the broker via SCM_RIGHTS;
        // worker writes into the WRITE end out-of-band and then
        // `read_pipe`s through the broker.
        let (r, w) = pipe_pair();
        let handle = client
            .attach_host_fd(r, host_fd_direction::READ)
            .expect("attach READ");
        assert!(handle > 0);
        assert_eq!(state.live_handle_count(), 1);

        let mut writer = std::fs::File::from(w);
        writer.write_all(b"hello-attach").expect("host write");
        drop(writer); // closes WRITE end → EOF on broker side eventually

        // Drain by repeated read_pipe (returns up to max_len; EOF
        // surfaces as Ok(empty Vec) per HostFdState semantics).
        let mut got = Vec::new();
        for _ in 0..50 {
            match client.read_pipe(handle, 1024) {
                Ok(chunk) if chunk.is_empty() => break,
                Ok(chunk) => got.extend_from_slice(&chunk),
                Err(ClientError::WouldBlock) => {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("unexpected error reading attached host fd: {e:?}"),
            }
        }
        assert_eq!(&got, b"hello-attach");

        client.release(handle).expect("release");
        assert_eq!(state.live_handle_count(), 0);
    }

    #[test]
    fn attach_host_fd_round_trip_write() {
        use litebox_common_linux::fd_token_protocol::host_fd_direction;

        let (_dir, path, _fd_reg, state, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        // Hand the WRITE end to the broker; out-of-band reader on R.
        let (r, w) = pipe_pair();
        let handle = client
            .attach_host_fd(w, host_fd_direction::WRITE)
            .expect("attach WRITE");
        assert_eq!(state.live_handle_count(), 1);

        let n = client.write_pipe(handle, b"abcde").expect("write_pipe");
        assert_eq!(n, 5);

        let mut reader = std::fs::File::from(r);
        let mut buf = [0u8; 16];
        let got = reader.read(&mut buf).expect("host read");
        assert_eq!(&buf[..got], b"abcde");

        client.release(handle).expect("release");
        assert_eq!(state.live_handle_count(), 0);
    }

    #[test]
    fn attach_host_fd_direction_enforcement() {
        use litebox_common_linux::fd_token_protocol::host_fd_direction;

        let (_dir, path, _fd_reg, _state, _proc) = spawn_test_listener();
        let client = FdTokenClient::connect(&path).expect("connect");

        // READ-only attach rejects write_pipe.
        let (r, _w) = pipe_pair();
        let handle = client
            .attach_host_fd(r, host_fd_direction::READ)
            .expect("attach READ");
        match client.write_pipe(handle, b"nope") {
            Err(_) => {} // any error is acceptable; broker maps SubsystemMismatch
            Ok(n) => panic!("write_pipe should fail on READ-only attached host fd, got n={n}"),
        }
        client.release(handle).expect("release");

        // WRITE-only attach rejects read_pipe.
        let (_r, w) = pipe_pair();
        let handle = client
            .attach_host_fd(w, host_fd_direction::WRITE)
            .expect("attach WRITE");
        match client.read_pipe(handle, 16) {
            Err(_) => {}
            Ok(b) => panic!("read_pipe should fail on WRITE-only attached host fd, got {b:?}"),
        }
        client.release(handle).expect("release");
    }
}
