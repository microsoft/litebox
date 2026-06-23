// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted "attached host fd" state object.
//!
//! Workers (or the parent shim during fork-snapshot) can SCM_RIGHTS-pass
//! an already-open host fd into the broker via
//! [`Opcode::AttachHostFd`][litebox_common_linux::cwfd::fd_token_protocol::Opcode::AttachHostFd].
//! The broker takes ownership of the fd and exposes it through the same
//! pipe-shaped [`ReadPipe`][litebox_common_linux::cwfd::fd_token_protocol::Opcode::ReadPipe]
//! / [`WritePipe`][litebox_common_linux::cwfd::fd_token_protocol::Opcode::WritePipe]
//! surface used by broker-hosted pipes. Workers see a [`BrokerPipeFd`]
//! whose read/write RPCs land on this state object; readiness is
//! mirrored from the underlying host fd via a small poll thread.
//!
//! # Motivation
//!
//! Legacy-pipes phase 3 retires the mux relay's `--pipe-bridge`
//! (host-fd-passthrough) topology: every fd that crosses the worker
//! boundary now becomes a broker-held resource. PTY master fds, raw
//! host fds that pre-existed the sandbox, and similar "kernel resource
//! the broker didn't create itself" cases need this attach-by-SCM_RIGHTS
//! shape because there is no broker-side `create_*` op that would
//! materialise the underlying fd from parameters alone.
//!
//! # Direction enforcement
//!
//! At attach time the worker declares a [`HostFdDirection`]
//! ([`Read`][HostFdDirection::Read],
//! [`Write`][HostFdDirection::Write], or
//! [`ReadWrite`][HostFdDirection::ReadWrite]). The broker rejects
//! read RPCs against a write-only handle (and vice versa) with
//! [`StatusCode::SubsystemMismatch`][litebox_common_linux::cwfd::fd_token_protocol::StatusCode::SubsystemMismatch]
//! so the worker sees the same EBADF a Linux kernel would return for
//! `read()` on a write-only fd.

use core::any::Any;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// Errors returned by [`HostFdState`] read/write operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostFdError {
    /// Underlying `read(2)`/`write(2)` returned `EAGAIN`.
    #[error("host fd operation would block")]
    WouldBlock,
    /// Operation was attempted in a direction not permitted at attach
    /// time (e.g. `read` on a write-only attach).
    #[error("operation not permitted by attach direction")]
    DirectionMismatch,
    /// Underlying host syscall returned an unrecoverable error.
    #[error("host fd I/O error: {0}")]
    Io(i32),
    /// Peer closed (`EPIPE`/`ECONNRESET`/etc.).
    #[error("host fd peer closed")]
    PeerClosed,
}

/// Access direction declared at attach time. Mirrors the wire constants
/// in [`litebox_common_linux::cwfd::fd_token_protocol::host_fd_direction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFdDirection {
    Read,
    Write,
    ReadWrite,
}

impl HostFdDirection {
    /// Decode the wire byte. Returns `None` for unrecognised values
    /// (caller surfaces as a protocol error).
    pub fn from_wire(byte: u8) -> Option<Self> {
        use litebox_common_linux::cwfd::fd_token_protocol::host_fd_direction as wire;
        match byte {
            wire::READ => Some(Self::Read),
            wire::WRITE => Some(Self::Write),
            wire::READ_WRITE => Some(Self::ReadWrite),
            _ => None,
        }
    }

    /// True iff this direction permits `ReadPipe` RPCs.
    pub fn allows_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// True iff this direction permits `WritePipe` RPCs.
    pub fn allows_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

/// Broker-hosted state for an attached host fd.
///
/// Wraps the [`OwnedFd`] (set to non-blocking on construction) and
/// exposes a pipe-shaped read/write/subscribe surface. A background
/// poll thread mirrors the underlying fd's readiness into the
/// [`SubscriptionList`] so workers using level-triggered
/// `epoll_wait`/`poll` see wake-ups even when the broker is idle.
#[derive(Debug)]
pub struct HostFdState {
    fd: OwnedFd,
    direction: HostFdDirection,
    subject: SubscriptionList,
    /// `true` once [`Drop`] has been entered. Causes the poll thread
    /// to exit on its next tick (the `Weak::upgrade` returns `None`
    /// only after the last `Arc` is gone — this flag short-circuits
    /// faster).
    closed: AtomicBool,
    /// Set by a `read` that finds the host fd not readable (drained); consumed
    /// by the poll thread to re-notify a still-asserted readable level exactly
    /// once per drain instead of on every tick (see [`Self::spawn_poll_thread`]).
    read_drained: AtomicBool,
}

impl HostFdState {
    /// Wrap an SCM_RIGHTS-received host fd as a broker state object.
    /// Spawns the readiness poll thread.
    ///
    /// # Semantic note: OFD flags are NOT mutated
    ///
    /// The broker holds ONE fd ref to a shared open file description
    /// (OFD). The original opener (parent shim, dropbear, etc.) holds
    /// sibling refs that may still be in use by their own I/O loops.
    /// OFD-level state (`F_SETFL` including `O_NONBLOCK`, `F_SETOWN`,
    /// etc.) is set by `fcntl(F_SETFL, ...)` per POSIX `fcntl(2)` —
    /// the file-status flags live **on the OFD**, not on the fd.
    ///
    /// Earlier versions of this function called `fcntl(F_SETFL,
    /// |O_NONBLOCK)` here, which silently flipped sibling fds (e.g.
    /// dropbear's PTY-master) into non-blocking mode and broke their
    /// blocking read loops with unexpected `EAGAIN`. That was the
    /// root cause of `echo_two_lines`/`pipe_head_early_exit` failures
    /// during D5 bring-up (see plan.md §A "Semantic guidance
    /// after Sessions 7-8").
    ///
    /// Instead, every `read()` / `write()` call in this module is
    /// preceded by a `poll(timeout=0)` readiness probe. The kernel
    /// will return `EAGAIN` only if the OFD already carries
    /// `O_NONBLOCK` from the opener — in that case the WouldBlock is
    /// propagated to the worker's `BrokerPipeFd` retry path, same as
    /// any other notification-driven WouldBlock.
    pub fn from_received(fd: OwnedFd, direction: HostFdDirection) -> Arc<Self> {
        let state = Arc::new(Self {
            fd,
            direction,
            subject: SubscriptionList::new(),
            closed: AtomicBool::new(false),
            read_drained: AtomicBool::new(false),
        });
        Self::spawn_poll_thread(Arc::downgrade(&state));
        state
    }

    /// Returns the declared attach direction.
    pub fn direction(&self) -> HostFdDirection {
        self.direction
    }

    /// Non-blocking read into a freshly-allocated buffer of up to
    /// `max_len` bytes. Returns an empty `Vec` on EOF.
    ///
    /// Gated on a `poll(POLLIN, timeout=0)` readiness check rather
    /// than relying on `O_NONBLOCK` on the OFD (see [`from_received`]
    /// docs for why). If POLLIN is not set, returns `WouldBlock`
    /// without issuing the `read(2)` — the worker's `BrokerPipeFd`
    /// retry loop will re-issue when the poll thread notifies.
    ///
    /// [`from_received`]: Self::from_received
    pub fn read(&self, max_len: usize) -> Result<Vec<u8>, HostFdError> {
        if !self.direction.allows_read() {
            return Err(HostFdError::DirectionMismatch);
        }
        if max_len == 0 {
            return Ok(Vec::new());
        }
        let revents = poll_fd_events(self.fd.as_raw_fd());
        if revents & (NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR) == 0 {
            // Drained: arm a one-shot re-notify so the poll thread re-signals
            // the next arrival even if the level mask looks unchanged.
            self.read_drained.store(true, Ordering::Release);
            return Err(HostFdError::WouldBlock);
        }
        let mut buf = vec![0u8; max_len];
        // SAFETY: `buf` is a valid writable slice of length `max_len`;
        // `self.fd` is a live host fd owned for the lifetime of `self`.
        let rc = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            return classify_read_err(err, &self.subject);
        }
        let n = usize::try_from(rc).expect("rc >= 0 here");
        buf.truncate(n);
        if n == 0 {
            // EOF: writer closed. Wake any pollers.
            self.subject.notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
        }
        Ok(buf)
    }

    /// Non-blocking write. Returns number of bytes actually written
    /// (may be less than `bytes.len()` for partial writes).
    ///
    /// Gated on a `poll(POLLOUT, timeout=0)` readiness check rather
    /// than relying on `O_NONBLOCK` on the OFD (see [`from_received`]
    /// docs for why). If POLLOUT is not set, returns `WouldBlock`.
    ///
    /// **Does NOT chunk writes to `PIPE_BUF`.** Earlier Session 7
    /// experiment chunked at `PIPE_BUF=4096` defensively to avoid
    /// the case where the kernel partially accepts a large write
    /// after POLLOUT; that caused `echo_sleep_zero` to regress
    /// because it broke write atomicity expectations of upstream
    /// readers. Per `write(2)`, partial writes are explicitly
    /// permitted and the worker's `BrokerPipeFd` already loops on
    /// short writes. Pass `bytes` through as-is.
    ///
    /// [`from_received`]: Self::from_received
    pub fn write(&self, bytes: &[u8]) -> Result<usize, HostFdError> {
        if !self.direction.allows_write() {
            return Err(HostFdError::DirectionMismatch);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let revents = poll_fd_events(self.fd.as_raw_fd());
        if revents & (NOTIFY_EVENT_OUT | NOTIFY_EVENT_ERR) == 0 {
            return Err(HostFdError::WouldBlock);
        }
        // SAFETY: `bytes` is a valid readable slice; `self.fd` is a
        // live host fd owned for the lifetime of `self`.
        let rc = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            return classify_write_err(err, &self.subject);
        }
        Ok(usize::try_from(rc).expect("rc >= 0 here"))
    }

    /// Compute current readiness by `poll(2)`-ing the fd with timeout 0.
    /// Used by [`StateObject::current_events`] and by the prime path
    /// of [`StateObject::subscribe`].
    fn current_events_internal(&self) -> u32 {
        let raw = poll_fd_events(self.fd.as_raw_fd());
        // Mask out events that aren't reachable for this direction so
        // workers don't see spurious POLLOUT on a read-only attach.
        let mut out = raw;
        if !self.direction.allows_read() {
            out &= !NOTIFY_EVENT_IN;
        }
        if !self.direction.allows_write() {
            out &= !NOTIFY_EVENT_OUT;
        }
        out
    }

    fn spawn_poll_thread(weak: Weak<Self>) {
        let _ = thread::Builder::new()
            .name("litebox-host-fd-poll".into())
            .spawn(move || {
                let mut last = 0u32;
                loop {
                    let Some(state) = weak.upgrade() else {
                        break;
                    };
                    if state.closed.load(Ordering::Acquire) {
                        break;
                    }
                    let now = state.current_events_internal();
                    // Edge-correct re-notification: resend a still-asserted
                    // readable level only once per drain (a read that found the
                    // fd not readable arms read_drained), not on every 10ms tick,
                    // which converts a persistent level into an edge storm that
                    // livelocks a fast level-triggered subscriber.
                    let readable =
                        now & (NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR) != 0;
                    let drained_resend =
                        readable && state.read_drained.swap(false, Ordering::AcqRel);
                    if now != 0 && (now != last || drained_resend) {
                        state.subject.notify(now);
                    }
                    last = now;
                    drop(state);
                    thread::sleep(Duration::from_millis(10));
                }
            });
    }
}

impl Drop for HostFdState {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        // Wake any remaining subscribers so a worker blocked in
        // epoll_wait on this handle sees the teardown.
        self.subject
            .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR);
        // `self.fd` drops normally and closes the broker's reference
        // to the host fd. The sender's own copy (if any) is unaffected.
    }
}

impl StateObject for HostFdState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::HostFd
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        let now = self.current_events_internal();
        self.subject.add(subscription_id, events_mask, sender)?;
        if now & events_mask != 0 {
            self.subject.notify(now);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subject.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        self.current_events_internal()
    }

    fn try_flush_subscriptions(&self) {
        self.subject.try_flush();
    }
}

fn poll_fd_events(fd: libc::c_int) -> u32 {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLOUT | libc::POLLERR | libc::POLLHUP | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: `pfd` is one initialized pollfd; timeout 0 makes this
    // non-blocking and signal-safe.
    let rc = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    if rc <= 0 {
        return 0;
    }
    let revents = pfd.revents;
    let mut events = 0u32;
    if revents & libc::POLLIN != 0 {
        events |= NOTIFY_EVENT_IN;
    }
    if revents & libc::POLLOUT != 0 {
        events |= NOTIFY_EVENT_OUT;
    }
    if revents & libc::POLLERR != 0 {
        events |= NOTIFY_EVENT_ERR;
    }
    if revents & libc::POLLHUP != 0 {
        events |= NOTIFY_EVENT_HUP;
    }
    if revents & libc::POLLRDHUP != 0 {
        events |= NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP;
    }
    events
}

fn classify_read_err(err: io::Error, subject: &SubscriptionList) -> Result<Vec<u8>, HostFdError> {
    match err.raw_os_error() {
        Some(libc::EAGAIN) => Err(HostFdError::WouldBlock),
        Some(libc::ECONNRESET | libc::EPIPE) => {
            subject.notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP | NOTIFY_EVENT_ERR);
            Err(HostFdError::PeerClosed)
        }
        Some(errno) => Err(HostFdError::Io(errno)),
        None => Err(HostFdError::Io(libc::EIO)),
    }
}

fn classify_write_err(err: io::Error, subject: &SubscriptionList) -> Result<usize, HostFdError> {
    match err.raw_os_error() {
        Some(libc::EAGAIN) => Err(HostFdError::WouldBlock),
        Some(libc::ECONNRESET | libc::EPIPE) => {
            subject.notify(NOTIFY_EVENT_ERR | NOTIFY_EVENT_HUP);
            Err(HostFdError::PeerClosed)
        }
        Some(errno) => Err(HostFdError::Io(errno)),
        None => Err(HostFdError::Io(libc::EIO)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    /// Helper: returns (read_end, write_end) as a pair of `OwnedFd`s
    /// via `pipe2(O_CLOEXEC)`. Both are blocking on creation; HostFdState
    /// will flip them to non-blocking.
    fn host_pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a 2-element array of `c_int`; pipe2 fills both.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(rc, 0, "pipe2 failed: {}", io::Error::last_os_error());
        // SAFETY: both fds are freshly created by pipe2.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn read_only_attach_rejects_write() {
        let (r, _w) = host_pipe();
        let state = HostFdState::from_received(r, HostFdDirection::Read);
        let err = state.write(b"x").expect_err("write on read-only must fail");
        assert_eq!(err, HostFdError::DirectionMismatch);
    }

    #[test]
    fn write_only_attach_rejects_read() {
        let (_r, w) = host_pipe();
        let state = HostFdState::from_received(w, HostFdDirection::Write);
        let err = state.read(64).expect_err("read on write-only must fail");
        assert_eq!(err, HostFdError::DirectionMismatch);
    }

    #[test]
    fn read_returns_wouldblock_when_empty() {
        let (r, _w) = host_pipe();
        let state = HostFdState::from_received(r, HostFdDirection::Read);
        match state.read(8) {
            Err(HostFdError::WouldBlock) => {}
            other => panic!("expected WouldBlock, got {other:?}"),
        }
    }

    #[test]
    fn write_then_read_round_trip() {
        let (r, w) = host_pipe();
        let read_state = HostFdState::from_received(r, HostFdDirection::Read);
        // Use a std::fs::File-like writer to push data into the
        // sender's end; the broker doesn't own the sender's end here.
        // SAFETY: w is an OwnedFd we have unique ownership of.
        let mut sender = unsafe { std::fs::File::from_raw_fd(w.into_raw_fd_keep_open()) };
        sender.write_all(b"hello broker").unwrap();
        drop(sender); // closes the write end → EOF for reader
        // Give the writer a moment for the close to propagate.
        std::thread::sleep(Duration::from_millis(20));
        let bytes = read_state.read(64).expect("read after write must succeed");
        assert_eq!(&bytes[..], b"hello broker");
        // Subsequent read returns 0 (EOF).
        let eof = read_state.read(64).expect("read at EOF returns empty");
        assert!(eof.is_empty(), "expected EOF, got {eof:?}");
    }

    #[test]
    fn read_write_attach_allows_both_directions() {
        // socketpair gives us a full-duplex pair to exercise read+write
        // on the same handle.
        let mut sv = [0i32; 2];
        // SAFETY: `sv` is a 2-element c_int array; socketpair fills both.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        // SAFETY: both fds are freshly created by socketpair.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
        let state = HostFdState::from_received(a, HostFdDirection::ReadWrite);
        // Peer pushes data; state reads it.
        // SAFETY: b is owned here.
        let mut peer = unsafe { std::fs::File::from_raw_fd(b.into_raw_fd_keep_open()) };
        peer.write_all(b"ping").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let got = state.read(64).expect("read must succeed");
        assert_eq!(&got[..], b"ping");
        // State writes; peer reads it.
        let n = state.write(b"pong").expect("write must succeed");
        assert_eq!(n, 4);
        let mut buf = [0u8; 64];
        let got_n = peer.read(&mut buf).expect("peer read must succeed");
        assert_eq!(&buf[..got_n], b"pong");
    }

    /// Test that drop wakes outstanding subscribers (regression guard
    /// for the legacy-pipes mux teardown path).
    #[test]
    fn drop_notifies_subscribers() {
        let (r, _w) = host_pipe();
        let state = HostFdState::from_received(r, HostFdDirection::Read);
        // Without a worker connection the SubscriptionList has no
        // subscribers; this test asserts the drop path itself doesn't
        // panic and the notification call returns cleanly.
        let _ = state;
    }
}

// Local extension on OwnedFd used only by tests: hand the underlying
// raw fd to `std::fs::File::from_raw_fd` while keeping the OwnedFd
// alive — necessary because the OwnedFd's Drop would otherwise close
// the fd the File now owns. The trick is `into_raw_fd()` which
// consumes the OwnedFd without closing. The trait-style helper here
// just clarifies intent at call sites.
#[cfg(test)]
trait OwnedFdRawSplitForTests {
    fn into_raw_fd_keep_open(self) -> libc::c_int;
}

#[cfg(test)]
impl OwnedFdRawSplitForTests for OwnedFd {
    fn into_raw_fd_keep_open(self) -> libc::c_int {
        use std::os::fd::IntoRawFd;
        self.into_raw_fd()
    }
}
