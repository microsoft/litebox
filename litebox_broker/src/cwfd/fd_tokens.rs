// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-global file-descriptor token registry.
//!
//! # Why this exists
//!
//! The cross-worker fd-transport architecture (see
//! `docs/design/cross-worker-fd-transport.md`) requires the broker to hold
//! transferable handles to host kernel objects on behalf of guest processes
//! that may live on different worker processes. A worker can hand a host fd
//! to the broker and receive an opaque [`BrokerFdToken`] in return; the token
//! can then travel through any byte-stream IPC (the existing shm ring or a
//! `UnixTransport::Tcp` byte stream) to reach a peer worker on a different
//! host process. The peer worker presents the token back to the broker,
//! which materializes a fresh host fd aliasing the same kernel object.
//!
//! This decouples *fd identity* (the kernel object the receiver must observe)
//! from *fd location* (the worker process that currently owns a host fd
//! pointing at it). The existing transports (mux mesh pipe bridging, 9P paths)
//! carry bytes or path-identified resources; none can carry an opaque
//! kernel-object handle. This registry fills that gap.
//!
//! # Concurrency
//!
//! The registry is internally synchronized via a single [`std::sync::Mutex`].
//! Operations are short — table insert/lookup and (on final release) a host
//! `close(2)` — so contention is not expected to be a hot path. If profiling
//! later shows otherwise the table can be sharded.
//!
//! # Aliasing semantics
//!
//! When two callers ([`BrokerFdTokenRegistry::register`] twice on
//! independently-opened fds for the same kernel object, or
//! [`BrokerFdTokenRegistry::dup`] on an existing token), the resulting tokens
//! all keep the underlying host fd alive. [`BrokerFdTokenRegistry::materialize`]
//! returns a fresh `OwnedFd` (via `dup(2)`) that aliases the same kernel
//! object as the registered fd, matching `SCM_RIGHTS` semantics: each
//! materialization is an independent fd, but all alias one kernel object.
//!
//! # Phase boundary
//!
//! This module is the **Phase 2** deliverable for the cross-worker fd
//! transport plan: a self-contained, fully-tested registry. It is not yet
//! wired into any IPC path. **Phase 3** will extend `IpcStream` /
//! `UnixTransport::Tcp` with control-message framing that carries
//! `BrokerFdToken` IDs in place of the dropped `passed_fds` payload at
//! `litebox_shim_linux/src/syscalls/unix.rs:704-734`. **Phase 4** will use
//! the registry to fix the `commit_delayed_fork` SCM-buffered ENOSYS gap at
//! `litebox_shim_linux/src/syscalls/process.rs:5391-5400`.

use std::collections::HashMap;
use std::os::unix::io::OwnedFd;
use std::sync::Mutex;

/// An opaque, broker-global handle to a host kernel object held by the
/// broker on behalf of one or more guest workers.
///
/// Token IDs are monotonically allocated and are never reused once released.
/// Tokens are safe to serialize over any byte-stream IPC; a stale or forged
/// token simply yields [`BrokerFdTokenError::UnknownToken`] when presented
/// back to the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BrokerFdToken(u64);

impl BrokerFdToken {
    /// Returns the raw token id, intended for serialization onto IPC byte
    /// streams. The id has no meaning outside its issuing registry.
    #[inline]
    pub fn id(self) -> u64 {
        self.0
    }

    /// Reconstructs a token from a raw id received over IPC. The caller is
    /// responsible for validating the id against a registry; this constructor
    /// performs no validation.
    #[inline]
    pub fn from_id(id: u64) -> Self {
        Self(id)
    }
}

/// Kind tag carried alongside each registered token.
///
/// Receiver-side SCM_RIGHTS materialization must construct the right
/// shim variant for the kind of kernel object the token refers to —
/// an eventfd token materializes into `EventFile::BrokerBacked`, a
/// pidfd token into `PidfdState::BrokerBacked`, etc. The kind is
/// recorded at register time (the registering worker knows the
/// kind), travels alongside the token over IPC, and is queried at
/// materialize time.
///
/// `FdKind::Eventfd` is the default for legacy callers that
/// registered tokens before this tag existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FdKind {
    /// Plain host fd (no broker-managed state object). Used by the
    /// original Phase 2/3 SCM_RIGHTS path that just shipped a raw fd
    /// alias through the registry.
    Raw,
    /// Eventfd state hosted by the broker (`EventfdState`).
    Eventfd,
    /// AF_UNIX socket state hosted by the broker
    /// (`UnixSocketState`, P2.A).
    UnixSocket,
    /// pidfd state hosted by the broker (`PidfdState`, P2.B).
    Pidfd,
    /// signalfd state hosted by the broker (`SignalfdState`, P2.C).
    Signalfd,
    /// timerfd state hosted by the broker (future).
    Timerfd,
    /// inotify state hosted by the broker (future).
    Inotify,
}

impl FdKind {
    /// Wire encoding of an `FdKind` as a single byte for transport
    /// over the fd-transfer / SCM bridge protocols.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::Eventfd => 1,
            Self::UnixSocket => 2,
            Self::Pidfd => 3,
            Self::Signalfd => 4,
            Self::Timerfd => 5,
            Self::Inotify => 6,
        }
    }

    /// Inverse of [`as_u8`]. Returns `None` for unrecognised tags so
    /// receiver code can reject forged frames cleanly.
    ///
    /// [`as_u8`]: FdKind::as_u8
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Raw,
            1 => Self::Eventfd,
            2 => Self::UnixSocket,
            3 => Self::Pidfd,
            4 => Self::Signalfd,
            5 => Self::Timerfd,
            6 => Self::Inotify,
            _ => return None,
        })
    }
}

/// Errors returned by [`BrokerFdTokenRegistry`] operations.
#[derive(Debug, thiserror::Error)]
pub enum BrokerFdTokenError {
    /// The presented token id was not present in the registry. Either it was
    /// already fully released, was never registered with this registry, or is
    /// a forged value.
    #[error("unknown broker fd token: {0:?}")]
    UnknownToken(BrokerFdToken),

    /// Refcount overflow on [`BrokerFdTokenRegistry::dup`]. In practice this
    /// can only occur after `u32::MAX` outstanding duplications of a single
    /// token, which is not expected during normal operation but is reported
    /// rather than panicked to keep the broker resilient against worker bugs.
    #[error("broker fd token refcount overflow for {0:?}")]
    RefcountOverflow(BrokerFdToken),

    /// `dup(2)` failed while materializing a fresh host fd from a registry
    /// entry. Wraps the underlying [`std::io::Error`].
    #[error("failed to materialize broker fd token {token:?}: {source}")]
    Materialize {
        token: BrokerFdToken,
        #[source]
        source: std::io::Error,
    },
}

struct Entry {
    fd: OwnedFd,
    refcount: u32,
    kind: FdKind,
}

struct State {
    next_id: u64,
    table: HashMap<u64, Entry>,
}

/// Broker-global registry of host fds reachable by opaque [`BrokerFdToken`]
/// handles. See module-level documentation for design rationale.
pub struct BrokerFdTokenRegistry {
    state: Mutex<State>,
}

impl Default for BrokerFdTokenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerFdTokenRegistry {
    /// Creates an empty registry. Token ids start at 1; the value `0` is
    /// reserved as a sentinel "no token" for callers that want to encode an
    /// absent token in the wire format.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                next_id: 1,
                table: HashMap::new(),
            }),
        }
    }

    /// Takes ownership of `fd` and returns a fresh token referring to it
    /// with refcount 1. The caller must arrange for [`Self::release`] to be
    /// invoked exactly once per outstanding reference (the initial register
    /// counts as one reference).
    ///
    /// Equivalent to [`Self::register_with_kind`] with [`FdKind::Raw`]; use
    /// the latter when the token refers to a broker-managed kernel-object
    /// state (eventfd / pidfd / unix-socket / signalfd / …) so receiver
    /// workers can materialize the correct shim variant.
    pub fn register(&self, fd: OwnedFd) -> BrokerFdToken {
        self.register_with_kind(fd, FdKind::Raw)
    }

    /// Variant of [`Self::register`] that also records the kind of
    /// kernel object the fd refers to. The kind travels with the
    /// token through every subsequent dup / materialize call.
    pub fn register_with_kind(&self, fd: OwnedFd, kind: FdKind) -> BrokerFdToken {
        let mut state = self.state.lock().expect("BrokerFdTokenRegistry poisoned");
        let id = state.next_id;
        // Token allocation is a u64 monotonic counter. At one allocation per
        // nanosecond it would take 584 years to wrap; nevertheless guard
        // against the theoretical boundary rather than allowing reuse.
        state.next_id = state
            .next_id
            .checked_add(1)
            .expect("BrokerFdTokenRegistry id space exhausted");
        state.table.insert(
            id,
            Entry {
                fd,
                refcount: 1,
                kind,
            },
        );
        BrokerFdToken(id)
    }

    /// Returns the [`FdKind`] recorded at register time for the token.
    /// `None` if the token is unknown (e.g. already fully released).
    pub fn kind_of(&self, token: BrokerFdToken) -> Option<FdKind> {
        let state = self.state.lock().expect("BrokerFdTokenRegistry poisoned");
        state.table.get(&token.0).map(|e| e.kind)
    }

    /// Increments the refcount of an existing token, returning the same
    /// token on success. Used when a worker passes the same fd through more
    /// than one transport, or when the broker itself needs to retain a
    /// reference beyond the worker's lifetime.
    pub fn dup(&self, token: BrokerFdToken) -> Result<BrokerFdToken, BrokerFdTokenError> {
        let mut state = self.state.lock().expect("BrokerFdTokenRegistry poisoned");
        let entry = state
            .table
            .get_mut(&token.0)
            .ok_or(BrokerFdTokenError::UnknownToken(token))?;
        entry.refcount = entry
            .refcount
            .checked_add(1)
            .ok_or(BrokerFdTokenError::RefcountOverflow(token))?;
        Ok(token)
    }

    /// Decrements the refcount of an existing token. When the refcount
    /// reaches zero the underlying host fd is closed (via `OwnedFd`'s `Drop`)
    /// and the token id is permanently retired.
    pub fn release(&self, token: BrokerFdToken) -> Result<(), BrokerFdTokenError> {
        let mut state = self.state.lock().expect("BrokerFdTokenRegistry poisoned");
        let entry = state
            .table
            .get_mut(&token.0)
            .ok_or(BrokerFdTokenError::UnknownToken(token))?;
        // Refcount can never reach zero except via this branch, because
        // `register` initializes to 1 and `dup` only increments. An
        // underflow here would mean a release after the entry was already
        // removed, which the `get_mut` above already rejects.
        entry.refcount -= 1;
        if entry.refcount == 0 {
            // OwnedFd drops here, which closes the host fd.
            state.table.remove(&token.0);
        }
        Ok(())
    }

    /// Materializes a fresh host fd that aliases the same kernel object as
    /// the registered fd. This is what the *receiver* worker invokes when
    /// it observes a token on a Phase 3 byte-stream IPC and needs a real
    /// host fd to install in its guest fd table.
    ///
    /// Does not change the registry refcount; the caller is still expected
    /// to invoke [`Self::release`] when its reference is no longer needed.
    pub fn materialize(&self, token: BrokerFdToken) -> Result<OwnedFd, BrokerFdTokenError> {
        let state = self.state.lock().expect("BrokerFdTokenRegistry poisoned");
        let entry = state
            .table
            .get(&token.0)
            .ok_or(BrokerFdTokenError::UnknownToken(token))?;
        entry
            .fd
            .try_clone()
            .map_err(|source| BrokerFdTokenError::Materialize { token, source })
    }

    /// Returns the current number of live (registered, not fully released)
    /// tokens. Intended for tests and broker telemetry; not part of the
    /// production wire protocol.
    pub fn live_token_count(&self) -> usize {
        self.state
            .lock()
            .expect("BrokerFdTokenRegistry poisoned")
            .table
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::sync::Arc;
    use std::thread;

    /// Creates a external fd and returns its (read, write) ends as `OwnedFd`s.
    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe(2) failed: {}", std::io::Error::last_os_error());
        let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let w = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        (r, w)
    }

    /// Writes `bytes` to a pipe write end and closes it (so the reader
    /// observes EOF after consuming the data).
    fn write_and_close(w: OwnedFd, bytes: &[u8]) {
        let mut f = std::fs::File::from(w);
        f.write_all(bytes).expect("write to pipe");
    }

    /// Returns true if the given fd is still open at the kernel level.
    fn fd_is_open(raw: i32) -> bool {
        unsafe { libc::fcntl(raw, libc::F_GETFD) != -1 }
    }

    #[test]
    fn register_returns_unique_tokens() {
        let reg = BrokerFdTokenRegistry::new();
        let (r1, _w1) = pipe_pair();
        let (r2, _w2) = pipe_pair();
        let t1 = reg.register(r1);
        let t2 = reg.register(r2);
        assert_ne!(t1.id(), t2.id());
        assert_eq!(reg.live_token_count(), 2);
    }

    #[test]
    fn release_closes_fd_on_final_ref() {
        let reg = BrokerFdTokenRegistry::new();
        let (r, w) = pipe_pair();
        let r_raw = r.as_raw_fd();
        let token = reg.register(r);
        // Still open while held by registry.
        assert!(fd_is_open(r_raw));
        reg.release(token).expect("release should succeed");
        // Writer side observes EOF once the read end is closed and we drop the writer.
        drop(w);
        assert_eq!(reg.live_token_count(), 0);
    }

    #[test]
    fn dup_increments_refcount_release_balances() {
        let reg = BrokerFdTokenRegistry::new();
        let (r, _w) = pipe_pair();
        let r_raw = r.as_raw_fd();
        let t1 = reg.register(r);
        let t2 = reg.dup(t1).expect("dup should succeed");
        assert_eq!(t1, t2, "dup returns the same token id");
        assert_eq!(reg.live_token_count(), 1);

        // First release: refcount drops to 1, fd still open.
        reg.release(t1).expect("first release");
        assert!(
            fd_is_open(r_raw),
            "fd must remain open after partial release"
        );
        assert_eq!(reg.live_token_count(), 1);

        // Second release: refcount drops to 0, entry removed, fd closed.
        reg.release(t2).expect("second release");
        assert_eq!(reg.live_token_count(), 0);
    }

    #[test]
    fn release_unknown_token_returns_err() {
        let reg = BrokerFdTokenRegistry::new();
        let bogus = BrokerFdToken::from_id(999);
        match reg.release(bogus) {
            Err(BrokerFdTokenError::UnknownToken(t)) => assert_eq!(t, bogus),
            other => panic!("expected UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn dup_unknown_token_returns_err() {
        let reg = BrokerFdTokenRegistry::new();
        let bogus = BrokerFdToken::from_id(999);
        match reg.dup(bogus) {
            Err(BrokerFdTokenError::UnknownToken(t)) => assert_eq!(t, bogus),
            other => panic!("expected UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn double_release_after_zero_returns_err() {
        let reg = BrokerFdTokenRegistry::new();
        let (r, _w) = pipe_pair();
        let token = reg.register(r);
        reg.release(token).expect("first release");
        match reg.release(token) {
            Err(BrokerFdTokenError::UnknownToken(t)) => assert_eq!(t, token),
            other => panic!("expected UnknownToken on stale release, got {other:?}"),
        }
    }

    #[test]
    fn materialize_aliases_kernel_object() {
        // Registers the read end; materialize() must yield an independent fd
        // that observes the bytes written through the original write end —
        // proving they alias the same kernel pipe.
        let reg = BrokerFdTokenRegistry::new();
        let (r, w) = pipe_pair();
        let token = reg.register(r);

        let materialized = reg.materialize(token).expect("materialize should succeed");
        let mat_raw = materialized.as_raw_fd();

        // Write through the original write end and close it.
        write_and_close(w, b"phase2");

        // Read through the materialized fd.
        let mut std_file = unsafe { std::fs::File::from_raw_fd(mat_raw) };
        std::mem::forget(materialized); // ownership transferred to std_file
        let mut buf = Vec::new();
        std_file.read_to_end(&mut buf).expect("read");
        assert_eq!(&buf, b"phase2");

        reg.release(token).expect("release");
    }

    #[test]
    fn materialize_unknown_token_returns_err() {
        let reg = BrokerFdTokenRegistry::new();
        let bogus = BrokerFdToken::from_id(42);
        match reg.materialize(bogus) {
            Err(BrokerFdTokenError::UnknownToken(t)) => assert_eq!(t, bogus),
            other => panic!("expected UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn materialize_after_partial_release_still_works() {
        // Materialization works as long as at least one reference is live.
        let reg = BrokerFdTokenRegistry::new();
        let (r, _w) = pipe_pair();
        let t1 = reg.register(r);
        let t2 = reg.dup(t1).expect("dup");
        reg.release(t1).expect("release one ref");
        let _fd = reg.materialize(t2).expect("materialize remaining ref");
        reg.release(t2).expect("release final ref");
    }

    #[test]
    fn token_ids_are_never_reused() {
        let reg = BrokerFdTokenRegistry::new();
        let (r1, _w1) = pipe_pair();
        let t1 = reg.register(r1);
        reg.release(t1).expect("release t1");

        let (r2, _w2) = pipe_pair();
        let t2 = reg.register(r2);
        assert_ne!(t1.id(), t2.id(), "token ids must not be reused");
        assert!(t2.id() > t1.id(), "token ids must monotonically increase");
        reg.release(t2).expect("release t2");
    }

    #[test]
    fn concurrent_register_release_is_safe() {
        // Stress the Mutex with parallel register/release cycles. Not a
        // performance test — a soundness smoke test.
        let reg = Arc::new(BrokerFdTokenRegistry::new());
        let n_threads = 4;
        let n_iters = 256;
        let mut handles = Vec::with_capacity(n_threads);
        for _ in 0..n_threads {
            let reg = Arc::clone(&reg);
            handles.push(thread::spawn(move || {
                for _ in 0..n_iters {
                    let (r, _w) = pipe_pair();
                    let token = reg.register(r);
                    let dup = reg.dup(token).expect("dup");
                    let _fd = reg.materialize(token).expect("materialize");
                    reg.release(dup).expect("release dup");
                    reg.release(token).expect("release original");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }
        assert_eq!(reg.live_token_count(), 0);
    }
}
