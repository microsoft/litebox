// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted pipe state.
//!
//! A pipe is modeled as TWO state-registry entries that share an
//! [`Arc<PipeInner>`]: a [`PipeReadEnd`] and a [`PipeWriteEnd`]. Each
//! end is an independent [`StateObject`] with its own registry
//! refcount and its own subscription list. The shim's `read fd` holds
//! a handle to the read end; the `write fd` holds a handle to the
//! write end. Read/write/subscribe/release operate on the specific
//! end's handle — no direction parameter on the wire.
//!
//! This shape eliminates the per-end direction byte from
//! `ClosePipeEnd` / `IncrefPipeEnd` / `SubscribePipe` /
//! `UnsubscribePipeEnd` (deleted in the same change) and prevents
//! cross-end subscription-id collisions: each end's subscription
//! ids live in its own SubscriptionList namespace, so worker A's
//! read sub id 1 and worker B's write sub id 1 don't share a
//! `PipeState` to confuse the broker.

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

/// Errors returned by pipe operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PipeError {
    #[error("pipe operation would block")]
    WouldBlock,
    #[error("pipe peer is closed")]
    PeerClosed,
    #[error("operation invalid for this pipe end")]
    InvalidEnd,
}

#[derive(Debug)]
struct PipeBuffer {
    buf: VecDeque<u8>,
    capacity: usize,
}

/// State shared between the two ends of one pipe.
///
/// Owned by both [`PipeReadEnd`] and [`PipeWriteEnd`] via `Arc`. Each
/// end's [`Drop`] flips its corresponding `*_open` flag and notifies
/// the *other* end's subscribers — that's how cross-worker EOF and
/// EPIPE propagate when the last handle to one end is released by
/// the state registry.
#[derive(Debug)]
pub struct PipeInner {
    buffer: Mutex<PipeBuffer>,
    /// `false` once the read end's registry entry has been dropped
    /// (the last worker released its read handle). Surfaces as
    /// `NOTIFY_EVENT_ERR` on the write end's subject.
    read_open: AtomicBool,
    /// `false` once the write end's registry entry has been dropped.
    /// Surfaces as `NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN` on the read
    /// end's subject (the `IN` bit is the EOF wake-up — readers
    /// blocked in `read` see a zero-byte read).
    write_open: AtomicBool,
    /// Linux `PIPE_BUF`. Writes whose `len <= atomic_write_size` are
    /// atomic: they either fit entirely or return `WouldBlock`. Larger
    /// writes may produce partial successes.
    atomic_write_size: usize,
    read_subject: SubscriptionList,
    write_subject: SubscriptionList,
    /// PE.14 invariant: count of read RPCs that returned at least one
    /// byte. Used to distinguish "real data loss" (reader started but
    /// didn't finish draining → bytes lost) from "legitimate non-drain"
    /// (reader never tried — fd inherited and ignored).
    successful_reads: AtomicU64,
    /// PE.14 invariant: count of write RPCs that buffered at least one
    /// byte. For symmetry with `successful_reads` (helps spot "all
    /// writes are zero-byte" edge cases that wouldn't be data loss).
    successful_writes: AtomicU64,
}

impl PipeInner {
    fn new(capacity: usize, atomic_write_size: usize) -> Self {
        Self {
            buffer: Mutex::new(PipeBuffer {
                buf: VecDeque::with_capacity(capacity),
                capacity,
            }),
            read_open: AtomicBool::new(true),
            write_open: AtomicBool::new(true),
            atomic_write_size,
            read_subject: SubscriptionList::new(),
            write_subject: SubscriptionList::new(),
            successful_reads: AtomicU64::new(0),
            successful_writes: AtomicU64::new(0),
        }
    }

    fn read_open(&self) -> bool {
        self.read_open.load(Ordering::Acquire)
    }

    fn write_open(&self) -> bool {
        self.write_open.load(Ordering::Acquire)
    }

    fn read(&self, max_len: usize) -> Result<Vec<u8>, PipeError> {
        if max_len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = self.buffer.lock().expect("PipeInner poisoned");
        if buf.buf.is_empty() {
            if !self.write_open() {
                return Ok(Vec::new());
            }
            return Err(PipeError::WouldBlock);
        }
        let n = core::cmp::min(max_len, buf.buf.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(buf.buf.pop_front().expect("length checked"));
        }
        let writable = buf.buf.len() < buf.capacity;
        drop(buf);
        if writable && self.write_open() {
            self.write_subject.notify(NOTIFY_EVENT_OUT);
        }
        if n > 0 {
            self.successful_reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(out)
    }

    fn write(&self, bytes: &[u8]) -> Result<usize, PipeError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if !self.read_open() {
            return Err(PipeError::PeerClosed);
        }
        let mut buf = self.buffer.lock().expect("PipeInner poisoned");
        let vacant = buf.capacity.saturating_sub(buf.buf.len());
        if vacant == 0 || (bytes.len() <= self.atomic_write_size && vacant < bytes.len()) {
            return Err(PipeError::WouldBlock);
        }
        let n = core::cmp::min(vacant, bytes.len());
        buf.buf.extend(bytes[..n].iter().copied());
        let has_data = !buf.buf.is_empty();
        drop(buf);
        if has_data {
            self.read_subject.notify(NOTIFY_EVENT_IN);
        }
        if n > 0 {
            self.successful_writes.fetch_add(1, Ordering::Relaxed);
        }
        Ok(n)
    }

    fn current_read_end_events(&self) -> u32 {
        let buf = self.buffer.lock().expect("PipeInner poisoned");
        let mut events = 0;
        if !buf.buf.is_empty() {
            events |= NOTIFY_EVENT_IN;
        }
        if !self.write_open() {
            events |= NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN;
        }
        events
    }

    fn current_write_end_events(&self) -> u32 {
        let buf = self.buffer.lock().expect("PipeInner poisoned");
        let mut events = 0;
        if !self.read_open() {
            events |= NOTIFY_EVENT_ERR;
        } else if buf.buf.len() < buf.capacity {
            events |= NOTIFY_EVENT_OUT;
        }
        events
    }
}

/// Creates a new pipe and returns its two ends. Each end is meant to
/// be registered into the [`BrokerStateRegistry`] independently — the
/// registry refcount of each end represents the number of worker
/// `BrokerPipeFd` instances referring to it.
pub fn new_pipe(
    capacity: usize,
    atomic_write_size: usize,
) -> (Arc<PipeReadEnd>, Arc<PipeWriteEnd>) {
    let inner = Arc::new(PipeInner::new(capacity, atomic_write_size));
    let read_end = Arc::new(PipeReadEnd {
        inner: Arc::clone(&inner),
        handle_id: AtomicU64::new(0),
    });
    let write_end = Arc::new(PipeWriteEnd { inner });
    (read_end, write_end)
}

/// Broker-hosted read end of one pipe. Independent [`StateObject`]:
/// the registry tracks its refcount, and when that refcount hits zero
/// the underlying entry is dropped — [`PipeReadEnd::drop`] flips
/// `read_open=false` on the shared [`PipeInner`] and wakes the write
/// end's subscribers with `NOTIFY_EVENT_ERR` (EPIPE).
#[derive(Debug)]
pub struct PipeReadEnd {
    pub(crate) inner: Arc<PipeInner>,
    /// PE.14: the registry handle id this read end was registered under.
    /// Set by the call site immediately after register so Drop can
    /// emit handle-tagged data-loss warnings. 0 = unset (legacy paths
    /// that didn't call set_handle_id; benign for invariant logs).
    pub(crate) handle_id: AtomicU64,
}

/// Broker-hosted write end. Symmetric to [`PipeReadEnd`]; drop fires
/// `NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN` on the read end's subject
/// (the `IN` bit is the EOF wake — readers blocked in `read` see a
/// zero-byte read returned).
#[derive(Debug)]
pub struct PipeWriteEnd {
    pub(crate) inner: Arc<PipeInner>,
}

impl PipeReadEnd {
    pub fn read(&self, max_len: usize) -> Result<Vec<u8>, PipeError> {
        self.inner.read(max_len)
    }
}

impl PipeWriteEnd {
    pub fn write(&self, bytes: &[u8]) -> Result<usize, PipeError> {
        self.inner.write(bytes)
    }
}

impl Drop for PipeReadEnd {
    fn drop(&mut self) {
        // Invariant B6: Drop fires exactly when registry rc=0, which
        // means no peer endpoint has registered a re-open. read_open
        // must have been true (or this is a double-Drop bug).
        debug_assert!(
            self.inner.read_open.load(Ordering::Acquire),
            "PipeReadEnd::drop with read_open=false (double-Drop?)"
        );
        // PE.14 invariant: data-loss check refined to fire only on
        // TRUE data loss (reader started reading but didn't finish):
        //   - unread bytes in buffer (writer wrote)
        //   - successful_writes > 0 (writer produced data)
        //   - successful_reads > 0 (reader started draining, then
        //     stopped → real loss)
        //
        // Note (user feedback 2026-05-19): this predicate is
        // FUNDAMENTALLY LOSSY. It matches both:
        //   (a) Real litebox bug: shim erroneously closed the reader's
        //       fd while data was buffered (e.g. the SIGCHLD-EINTR
        //       race that motivated PE.14 originally — commit e8316f5d).
        //   (b) Application crash: process died mid-read; kernel
        //       reaped fds; on_close fired with data still buffered.
        //       This is NOT a litebox bug.
        //   (c) Application chose to close early: legitimate user code
        //       deciding to discard remaining data.
        //
        // We can't distinguish these from broker side alone — the
        // broker only sees "rc hit 0". So this is a DIAGNOSTIC
        // (always-on file log) rather than a hard assertion. A real
        // bug (a) would manifest as a TEST FAILURE elsewhere; the
        // log helps the post-mortem.
        let unread = {
            let buf = self.inner.buffer.lock().expect("PipeInner poisoned");
            buf.buf.len()
        };
        let writes = self.inner.successful_writes.load(Ordering::Relaxed);
        let reads = self.inner.successful_reads.load(Ordering::Relaxed);
        if unread > 0 && writes > 0 && reads > 0 {
            let handle_id = self.handle_id.load(Ordering::Relaxed);
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
                    "[PE.14-invariant] ts={ts} PIPE READ-END DATA LOSS handle={handle_id}: \
                     unread={unread} writes={writes} reads={reads} \
                     (reader partially drained then closed; could be litebox bug, \
                     crash, or legitimate early-close — correlate with test result)"
                );
            }
            // NO PANIC: process crash + early-close are legitimate
            // scenarios indistinguishable from a real bug here.
            // The log is the diagnostic; a true litebox bug would
            // manifest as a separate test failure.
        } else if unread > 0 && writes > 0 {
            // Soft data-loss (reader never tried): still log but do
            // not assert. Often legitimate (inherited fds).
            let handle_id = self.handle_id.load(Ordering::Relaxed);
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
                    "[PE.14-diag] ts={ts} PIPE READ-END soft-unread handle={handle_id}: unread={unread} writes={writes} reads=0 (reader never tried — legitimate or potential leak)"
                );
            }
        }
        self.inner.read_open.store(false, Ordering::Release);
        self.inner.write_subject.notify(NOTIFY_EVENT_ERR);
    }
}

impl Drop for PipeWriteEnd {
    fn drop(&mut self) {
        debug_assert!(
            self.inner.write_open.load(Ordering::Acquire),
            "PipeWriteEnd::drop with write_open=false (double-Drop?)"
        );
        self.inner.write_open.store(false, Ordering::Release);
        self.inner
            .read_subject
            .notify(NOTIFY_EVENT_HUP | NOTIFY_EVENT_IN);
    }
}

impl StateObject for PipeReadEnd {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Pipe
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
        let now = self.inner.current_read_end_events();
        self.inner
            .read_subject
            .add(subscription_id, events_mask, sender)?;
        if now & events_mask != 0 {
            self.inner.read_subject.notify(now);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.inner.read_subject.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        self.inner.current_read_end_events()
    }
}

impl StateObject for PipeWriteEnd {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Pipe
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
        let now = self.inner.current_write_end_events();
        self.inner
            .write_subject
            .add(subscription_id, events_mask, sender)?;
        if now & events_mask != 0 {
            self.inner.write_subject.notify(now);
        }
        Ok(())
    }

    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.inner.write_subject.remove(subscription_id)
    }

    fn current_events(&self) -> u32 {
        self.inner.current_write_end_events()
    }
}
