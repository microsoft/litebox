// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted AF_UNIX SOCK_STREAM socketpair state.
//!
//! A socketpair is modeled as TWO state-registry entries that share an
//! [`Arc<SocketPairInner>`]: one [`SocketPairEnd`] per endpoint
//! (A and B). Each end is an independent [`StateObject`] with its own
//! registry refcount and its own subscription list. Unlike pipes, both
//! endpoints are bidirectional — each can read AND write.
//!
//! `SocketPairInner` holds two byte buffers:
//! * `buffer_ab`: data flowing A → B (B reads from this, A writes to it)
//! * `buffer_ba`: data flowing B → A (A reads from this, B writes to it)
//!
//! Scope: Phase F initial cut handles `AF_UNIX + SOCK_STREAM` only.
//! Messages with `SCM_RIGHTS` / `SCM_CREDENTIALS`, `SOCK_SEQPACKET`,
//! and `SOCK_DGRAM` are intentionally out of scope for this iteration.
//! The shim should not promote non-stream AF_UNIX pairs to the broker
//! until those are modeled.

use core::any::Any;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use litebox_common_linux::fd_transfer_frame::SubsystemTag;
use litebox_common_linux::notification_frame::{
    NOTIFY_EVENT_ERR, NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT,
};
use litebox_common_linux::notification_ring::NotificationSender;

use crate::state_registry::StateObject;
use crate::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// Errors returned by socketpair operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SocketPairError {
    #[error("socketpair operation would block")]
    WouldBlock,
    #[error("socketpair peer is closed")]
    PeerClosed,
}

/// Which end of the pair an operation refers to. Encoded on the wire
/// as the same byte position as `FdKind::pipe_direction`
/// (per-kind interpretation): 1 = A, 2 = B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPairEndpoint {
    A,
    B,
}

#[derive(Debug)]
struct SocketPairBuffer {
    buf: VecDeque<u8>,
    capacity: usize,
}

/// State shared between the two ends of one socketpair.
///
/// Owned by both [`SocketPairEnd`] instances via `Arc`. Each end's
/// [`Drop`] flips its corresponding `*_open` flag and notifies the
/// peer end's subscribers — that's how cross-worker peer-close
/// propagation works.
#[derive(Debug)]
pub struct SocketPairInner {
    /// Bytes flowing A → B. B reads from here; A writes to here.
    buffer_ab: Mutex<SocketPairBuffer>,
    /// Bytes flowing B → A. A reads from here; B writes to here.
    buffer_ba: Mutex<SocketPairBuffer>,
    /// `false` once A's registry entry has been dropped (last worker
    /// released its A handle). Surfaces on B's subject as
    /// `NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN` (peer closed) plus
    /// `NOTIFY_EVENT_ERR` (writes would EPIPE).
    a_open: AtomicBool,
    b_open: AtomicBool,
    /// True while endpoint A/B may still send bytes to its peer.
    /// `shutdown(SHUT_WR)` clears only the caller's write-open flag;
    /// dropping the endpoint clears both liveness and write-open.
    a_write_open: AtomicBool,
    b_write_open: AtomicBool,
    /// Linux `PIPE_BUF`-equivalent for atomicity. Writes whose
    /// `len <= atomic_write_size` are atomic: they either fit entirely
    /// or return `WouldBlock`. Larger writes may produce partial
    /// successes.
    atomic_write_size: usize,
    /// Subscribers attached to endpoint A (notified about events
    /// observable from A: data arriving in `buffer_ba`, space freeing
    /// in `buffer_ab`, B's close).
    subject_a: SubscriptionList,
    subject_b: SubscriptionList,
    /// PE.14 invariant counters (mirrors PE.14 PIPE READ-END DATA LOSS
    /// in pipe_state.rs). Track per-direction successful (non-zero-byte)
    /// reads and writes so SocketPairEnd::drop can distinguish real
    /// data loss (writes>0 AND reads>0 AND unread>0) from legitimate
    /// non-drain (reader never tried).
    /// `_ab_*` = direction A→B (A writes, B reads).
    /// `_ba_*` = direction B→A (B writes, A reads).
    ab_writes: AtomicU64,
    ab_reads: AtomicU64,
    ba_writes: AtomicU64,
    ba_reads: AtomicU64,
}

impl SocketPairInner {
    fn new(capacity: usize, atomic_write_size: usize) -> Self {
        Self {
            buffer_ab: Mutex::new(SocketPairBuffer {
                buf: VecDeque::with_capacity(capacity),
                capacity,
            }),
            buffer_ba: Mutex::new(SocketPairBuffer {
                buf: VecDeque::with_capacity(capacity),
                capacity,
            }),
            a_open: AtomicBool::new(true),
            b_open: AtomicBool::new(true),
            a_write_open: AtomicBool::new(true),
            b_write_open: AtomicBool::new(true),
            atomic_write_size,
            subject_a: SubscriptionList::new(),
            subject_b: SubscriptionList::new(),
            ab_writes: AtomicU64::new(0),
            ab_reads: AtomicU64::new(0),
            ba_writes: AtomicU64::new(0),
            ba_reads: AtomicU64::new(0),
        }
    }

    fn a_open(&self) -> bool {
        self.a_open.load(Ordering::Acquire)
    }

    fn b_open(&self) -> bool {
        self.b_open.load(Ordering::Acquire)
    }

    fn a_write_open(&self) -> bool {
        self.a_write_open.load(Ordering::Acquire)
    }

    fn b_write_open(&self) -> bool {
        self.b_write_open.load(Ordering::Acquire)
    }

    /// Read up to `max_len` bytes destined for `endpoint`.
    fn read(
        &self,
        endpoint: SocketPairEndpoint,
        max_len: usize,
    ) -> Result<Vec<u8>, SocketPairError> {
        if max_len == 0 {
            return Ok(Vec::new());
        }
        // A reads from buffer_ba (data sent by B). EOF when the peer
        // endpoint is gone or has shut down its write side.
        let (buf_mutex, peer_can_write, peer_subject) = match endpoint {
            SocketPairEndpoint::A => (
                &self.buffer_ba,
                self.b_open() && self.b_write_open(),
                &self.subject_b,
            ),
            SocketPairEndpoint::B => (
                &self.buffer_ab,
                self.a_open() && self.a_write_open(),
                &self.subject_a,
            ),
        };
        let mut buf = buf_mutex.lock().expect("SocketPairInner poisoned");
        if buf.buf.is_empty() {
            if !peer_can_write {
                // PE.10 diag: log first time we report EOF to a reader
                // — this is the case that surfaces tokio's "EOF on
                // self-pipe" panic when broker socketpair rc accounting
                // drops the peer-end early. Helps debug the residual
                // F.8 flip blocker.
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("/tmp/rst-diag.log")
                {
                    let _ = writeln!(
                        f,
                        "[PE.10-diag] BrokerSocketPair read EOF: endpoint={endpoint:?}"
                    );
                }
                // Peer-end closed and no data → EOF (zero-length read).
                return Ok(Vec::new());
            }
            return Err(SocketPairError::WouldBlock);
        }
        let n = core::cmp::min(max_len, buf.buf.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(buf.buf.pop_front().expect("length checked"));
        }
        let writable = buf.buf.len() < buf.capacity;
        drop(buf);
        // Notify peer that its outbound buffer now has more room.
        if writable && peer_can_write {
            peer_subject.notify(NOTIFY_EVENT_OUT);
        }
        if n > 0 {
            match endpoint {
                SocketPairEndpoint::A => self.ba_reads.fetch_add(1, Ordering::Relaxed),
                SocketPairEndpoint::B => self.ab_reads.fetch_add(1, Ordering::Relaxed),
            };
        }
        Ok(out)
    }

    /// Write `bytes` from `endpoint`. Returns bytes accepted.
    fn write(&self, endpoint: SocketPairEndpoint, bytes: &[u8]) -> Result<usize, SocketPairError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // A writes to buffer_ab. EPIPE if this end has been write-shut
        // or if peer (B) closed.
        let (buf_mutex, this_write_open, peer_open, peer_subject) = match endpoint {
            SocketPairEndpoint::A => (
                &self.buffer_ab,
                self.a_write_open(),
                self.b_open(),
                &self.subject_b,
            ),
            SocketPairEndpoint::B => (
                &self.buffer_ba,
                self.b_write_open(),
                self.a_open(),
                &self.subject_a,
            ),
        };
        if !this_write_open || !peer_open {
            return Err(SocketPairError::PeerClosed);
        }
        let mut buf = buf_mutex.lock().expect("SocketPairInner poisoned");
        let vacant = buf.capacity.saturating_sub(buf.buf.len());
        if vacant == 0 || (bytes.len() <= self.atomic_write_size && vacant < bytes.len()) {
            return Err(SocketPairError::WouldBlock);
        }
        let n = core::cmp::min(vacant, bytes.len());
        buf.buf.extend(bytes[..n].iter().copied());
        let has_data = !buf.buf.is_empty();
        drop(buf);
        if has_data {
            // Wake peer's IN subscribers (data now available to them).
            peer_subject.notify(NOTIFY_EVENT_IN);
        }
        if n > 0 {
            match endpoint {
                SocketPairEndpoint::A => self.ab_writes.fetch_add(1, Ordering::Relaxed),
                SocketPairEndpoint::B => self.ba_writes.fetch_add(1, Ordering::Relaxed),
            };
        }
        Ok(n)
    }

    fn current_events(&self, endpoint: SocketPairEndpoint) -> u32 {
        let (in_buf_mutex, out_buf_mutex, peer_open, peer_can_write) = match endpoint {
            SocketPairEndpoint::A => (
                &self.buffer_ba,
                &self.buffer_ab,
                self.b_open(),
                self.b_open() && self.b_write_open(),
            ),
            SocketPairEndpoint::B => (
                &self.buffer_ab,
                &self.buffer_ba,
                self.a_open(),
                self.a_open() && self.a_write_open(),
            ),
        };
        let mut events = 0;
        let in_buf = in_buf_mutex.lock().expect("SocketPairInner poisoned");
        if !in_buf.buf.is_empty() {
            events |= NOTIFY_EVENT_IN;
        }
        drop(in_buf);
        let out_buf = out_buf_mutex.lock().expect("SocketPairInner poisoned");
        if peer_open && out_buf.buf.len() < out_buf.capacity {
            events |= NOTIFY_EVENT_OUT;
        }
        drop(out_buf);
        if !peer_can_write {
            // Peer write-half close: deliver HUP + IN so blocked readers
            // wake to EOF after draining any buffered data. Only a full
            // peer close sets ERR, because half-close still permits the
            // peer to receive our writes.
            events |= NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN;
        }
        if !peer_open {
            events |= NOTIFY_EVENT_ERR;
        }
        events
    }

    fn shutdown_write(&self, endpoint: SocketPairEndpoint) {
        match endpoint {
            SocketPairEndpoint::A => {
                if self.a_write_open.swap(false, Ordering::AcqRel) {
                    self.subject_b.notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN);
                }
            }
            SocketPairEndpoint::B => {
                if self.b_write_open.swap(false, Ordering::AcqRel) {
                    self.subject_a.notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN);
                }
            }
        }
    }
}

/// Create a new socketpair and return its two endpoints. Each end is
/// meant to be registered into the [`BrokerStateRegistry`]
/// independently — the registry refcount of each end represents the
/// number of worker `BrokerSocketPairFd` instances referring to it.
pub fn new_socketpair(
    capacity: usize,
    atomic_write_size: usize,
) -> (Arc<SocketPairEnd>, Arc<SocketPairEnd>) {
    let inner = Arc::new(SocketPairInner::new(capacity, atomic_write_size));
    let end_a = Arc::new(SocketPairEnd {
        inner: Arc::clone(&inner),
        endpoint: SocketPairEndpoint::A,
        handle_id: AtomicU64::new(0),
    });
    let end_b = Arc::new(SocketPairEnd {
        inner,
        endpoint: SocketPairEndpoint::B,
        handle_id: AtomicU64::new(0),
    });
    (end_a, end_b)
}

/// Broker-hosted endpoint of a socketpair. Holds an `Arc` to the
/// shared `SocketPairInner` and identifies which side of the pair it
/// represents. Independent [`StateObject`]: the registry tracks its
/// refcount, and when that refcount hits zero the underlying entry is
/// dropped — [`SocketPairEnd::drop`] flips the matching `*_open` flag
/// and wakes the peer's subscribers.
#[derive(Debug)]
pub struct SocketPairEnd {
    pub(crate) inner: Arc<SocketPairInner>,
    pub endpoint: SocketPairEndpoint,
    /// PE.14: the registry handle id this endpoint was registered under.
    /// Set by the call site immediately after register. Used in the
    /// SOCKETPAIR DATA LOSS invariant log for cross-reference with the
    /// shim's per-slot diagnostics.
    pub(crate) handle_id: AtomicU64,
}

impl SocketPairEnd {
    pub fn read(&self, max_len: usize) -> Result<Vec<u8>, SocketPairError> {
        self.inner.read(self.endpoint, max_len)
    }

    pub fn write(&self, bytes: &[u8]) -> Result<usize, SocketPairError> {
        self.inner.write(self.endpoint, bytes)
    }

    pub fn shutdown_write(&self) {
        self.inner.shutdown_write(self.endpoint);
    }
}

impl Drop for SocketPairEnd {
    fn drop(&mut self) {
        // PE.10 diag: log every Drop so we can correlate broker-side
        // peer-close events with read-EOF observations.
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/rst-diag.log")
        {
            let _ = writeln!(
                f,
                "[PE.10-diag] BrokerSocketPair Drop: endpoint={:?} a_open={} b_open={}",
                self.endpoint,
                self.inner.a_open.load(Ordering::Acquire),
                self.inner.b_open.load(Ordering::Acquire)
            );
        }
        // PE.14 invariant (mirrors PIPE READ-END DATA LOSS):
        // FUNDAMENTALLY LOSSY predicate — matches real bugs AND
        // legitimate process-crash / early-close. Log loudly, don't
        // panic (a broker panic on every worker crash is worse than
        // missing diagnostic). See pipe_state.rs Drop for full
        // rationale.
        let (inbound_buf_mutex, writes_into_x, reads_by_x, dir_label) = match self.endpoint {
            // A's inbound = buffer_ba; B wrote into it (ba_writes); A read from it (ba_reads).
            SocketPairEndpoint::A => (
                &self.inner.buffer_ba,
                &self.inner.ba_writes,
                &self.inner.ba_reads,
                "B->A",
            ),
            // B's inbound = buffer_ab; A wrote into it (ab_writes); B read from it (ab_reads).
            SocketPairEndpoint::B => (
                &self.inner.buffer_ab,
                &self.inner.ab_writes,
                &self.inner.ab_reads,
                "A->B",
            ),
        };
        let unread = inbound_buf_mutex
            .lock()
            .expect("SocketPairInner poisoned")
            .buf
            .len();
        let writes = writes_into_x.load(Ordering::Relaxed);
        let reads = reads_by_x.load(Ordering::Relaxed);
        if unread > 0 && writes > 0 && reads > 0 {
            let handle_id = self.handle_id.load(Ordering::Relaxed);
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
                    "[PE.14-invariant] ts={ts} SOCKETPAIR DATA LOSS direction={dir_label} \
                     endpoint={:?} handle={handle_id}: unread={unread} writes={writes} reads={reads} \
                     (reader partially drained then closed; could be litebox bug, crash, or legit close)",
                    self.endpoint
                );
            }
            // NO PANIC: see pipe_state.rs Drop rationale.
        } else if unread > 0 && writes > 0 {
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
                    "[PE.14-diag] ts={ts} SOCKETPAIR soft-unread direction={dir_label} endpoint={:?}: unread={unread} writes={writes} reads=0 (reader never tried)",
                    self.endpoint
                );
            }
        }
        match self.endpoint {
            SocketPairEndpoint::A => {
                // Invariant B6: Drop fires when registry rc=0.
                // a_open must be true (else double-Drop).
                debug_assert!(
                    self.inner.a_open.load(Ordering::Acquire),
                    "SocketPairEnd::drop endpoint=A with a_open=false (double-Drop?)"
                );
                self.inner.a_open.store(false, Ordering::Release);
                self.inner.a_write_open.store(false, Ordering::Release);
                // Wake B: peer close = IN (read EOF) + HUP + ERR (write EPIPE).
                self.inner
                    .subject_b
                    .notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN | NOTIFY_EVENT_ERR);
            }
            SocketPairEndpoint::B => {
                debug_assert!(
                    self.inner.b_open.load(Ordering::Acquire),
                    "SocketPairEnd::drop endpoint=B with b_open=false (double-Drop?)"
                );
                self.inner.b_open.store(false, Ordering::Release);
                self.inner.b_write_open.store(false, Ordering::Release);
                self.inner
                    .subject_a
                    .notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN | NOTIFY_EVENT_ERR);
            }
        }
    }
}

impl StateObject for SocketPairEnd {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::UnixSocket
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
        let now = self.inner.current_events(self.endpoint);
        let subject = match self.endpoint {
            SocketPairEndpoint::A => &self.inner.subject_a,
            SocketPairEndpoint::B => &self.inner.subject_b,
        };
        subject.add(subscription_id, events_mask, sender)?;
        if now & events_mask != 0 {
            subject.notify(now);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        let subject = match self.endpoint {
            SocketPairEndpoint::A => &self.inner.subject_a,
            SocketPairEndpoint::B => &self.inner.subject_b,
        };
        subject.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        self.inner.current_events(self.endpoint)
    }

    fn try_flush_subscriptions(&self) {
        let subject = match self.endpoint {
            SocketPairEndpoint::A => &self.inner.subject_a,
            SocketPairEndpoint::B => &self.inner.subject_b,
        };
        subject.try_flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Arc<SocketPairEnd>, Arc<SocketPairEnd>) {
        new_socketpair(4096, 512)
    }

    #[test]
    fn write_a_read_b_roundtrip() {
        let (a, b) = pair();
        assert_eq!(a.write(b"hello").unwrap(), 5);
        let got = b.read(64).unwrap();
        assert_eq!(&got, b"hello");
    }

    #[test]
    fn write_b_read_a_roundtrip() {
        let (a, b) = pair();
        assert_eq!(b.write(b"world").unwrap(), 5);
        let got = a.read(64).unwrap();
        assert_eq!(&got, b"world");
    }

    #[test]
    fn bidirectional() {
        let (a, b) = pair();
        a.write(b"ping").unwrap();
        b.write(b"pong").unwrap();
        assert_eq!(b.read(64).unwrap(), b"ping");
        assert_eq!(a.read(64).unwrap(), b"pong");
    }

    #[test]
    fn empty_read_wouldblock() {
        let (a, _b) = pair();
        let err = a.read(64).unwrap_err();
        assert_eq!(err, SocketPairError::WouldBlock);
    }

    #[test]
    fn peer_close_eof_on_read() {
        let (a, b) = pair();
        drop(b);
        let got = a.read(64).unwrap();
        assert!(got.is_empty(), "expected EOF, got {got:?}");
    }

    #[test]
    fn peer_close_epipe_on_write() {
        let (a, b) = pair();
        drop(b);
        let err = a.write(b"x").unwrap_err();
        assert_eq!(err, SocketPairError::PeerClosed);
    }

    #[test]
    fn buffered_data_survives_peer_close() {
        let (a, b) = pair();
        b.write(b"queued").unwrap();
        drop(b);
        // A can still drain pre-buffered data, then sees EOF.
        let got = a.read(64).unwrap();
        assert_eq!(&got, b"queued");
        let next = a.read(64).unwrap();
        assert!(next.is_empty());
    }

    #[test]
    fn shutdown_write_preserves_reply_direction() {
        let (a, b) = pair();
        a.write(b"ping").unwrap();
        a.shutdown_write();
        assert_eq!(b.read(64).unwrap(), b"ping");
        assert!(b.read(64).unwrap().is_empty());
        b.write(b"pong").unwrap();
        assert_eq!(a.read(64).unwrap(), b"pong");
        assert_eq!(a.write(b"again").unwrap_err(), SocketPairError::PeerClosed);
    }

    #[test]
    fn full_buffer_wouldblock() {
        let (a, _b) = pair();
        // Fill A→B buffer. Atomic guarantee for writes <= 512; with
        // capacity 4096, a single 4096-byte write should fill exactly.
        let data = vec![0u8; 4096];
        let n = a.write(&data).unwrap();
        assert_eq!(n, 4096);
        let err = a.write(b"more").unwrap_err();
        assert_eq!(err, SocketPairError::WouldBlock);
    }

    #[test]
    fn subsystem_tag_is_unix_socket() {
        let (a, b) = pair();
        assert_eq!(a.subsystem_tag(), SubsystemTag::UnixSocket);
        assert_eq!(b.subsystem_tag(), SubsystemTag::UnixSocket);
    }

    #[test]
    fn endpoint_is_carried() {
        let (a, b) = pair();
        assert_eq!(a.endpoint, SocketPairEndpoint::A);
        assert_eq!(b.endpoint, SocketPairEndpoint::B);
    }
}
