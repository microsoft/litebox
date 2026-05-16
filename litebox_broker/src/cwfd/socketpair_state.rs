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
//! `SOCK_DGRAM`, and `shutdown()` semantics are intentionally out of
//! scope for this iteration. The shim should not promote non-stream
//! AF_UNIX pairs to the broker until those are modeled.

use core::any::Any;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
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
/// as the same byte position as `BrokerHandleSnapshot::pipe_direction`
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
            atomic_write_size,
            subject_a: SubscriptionList::new(),
            subject_b: SubscriptionList::new(),
        }
    }

    fn a_open(&self) -> bool {
        self.a_open.load(Ordering::Acquire)
    }

    fn b_open(&self) -> bool {
        self.b_open.load(Ordering::Acquire)
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
        // A reads from buffer_ba (data sent by B). Peer-close = !b_open.
        let (buf_mutex, peer_open, peer_subject) = match endpoint {
            SocketPairEndpoint::A => (&self.buffer_ba, self.b_open(), &self.subject_b),
            SocketPairEndpoint::B => (&self.buffer_ab, self.a_open(), &self.subject_a),
        };
        let mut buf = buf_mutex.lock().expect("SocketPairInner poisoned");
        if buf.buf.is_empty() {
            if !peer_open {
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
        if writable && peer_open {
            peer_subject.notify(NOTIFY_EVENT_OUT);
        }
        Ok(out)
    }

    /// Write `bytes` from `endpoint`. Returns bytes accepted.
    fn write(&self, endpoint: SocketPairEndpoint, bytes: &[u8]) -> Result<usize, SocketPairError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // A writes to buffer_ab. EPIPE if peer (B) closed.
        let (buf_mutex, peer_open, peer_subject) = match endpoint {
            SocketPairEndpoint::A => (&self.buffer_ab, self.b_open(), &self.subject_b),
            SocketPairEndpoint::B => (&self.buffer_ba, self.a_open(), &self.subject_a),
        };
        if !peer_open {
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
        Ok(n)
    }

    fn current_events(&self, endpoint: SocketPairEndpoint) -> u32 {
        let (in_buf_mutex, out_buf_mutex, peer_open) = match endpoint {
            SocketPairEndpoint::A => (&self.buffer_ba, &self.buffer_ab, self.b_open()),
            SocketPairEndpoint::B => (&self.buffer_ab, &self.buffer_ba, self.a_open()),
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
        if !peer_open {
            // Peer-close: deliver HUP + IN (so blocked readers wake to
            // EOF) and ERR (so blocked writers wake to EPIPE).
            events |= NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN | NOTIFY_EVENT_ERR;
        }
        events
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
    });
    let end_b = Arc::new(SocketPairEnd {
        inner,
        endpoint: SocketPairEndpoint::B,
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
}

impl SocketPairEnd {
    pub fn read(&self, max_len: usize) -> Result<Vec<u8>, SocketPairError> {
        self.inner.read(self.endpoint, max_len)
    }

    pub fn write(&self, bytes: &[u8]) -> Result<usize, SocketPairError> {
        self.inner.write(self.endpoint, bytes)
    }
}

impl Drop for SocketPairEnd {
    fn drop(&mut self) {
        match self.endpoint {
            SocketPairEndpoint::A => {
                self.inner.a_open.store(false, Ordering::Release);
                // Wake B: peer close = IN (read EOF) + HUP + ERR (write EPIPE).
                self.inner
                    .subject_b
                    .notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN | NOTIFY_EVENT_ERR);
            }
            SocketPairEndpoint::B => {
                self.inner.b_open.store(false, Ordering::Release);
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
