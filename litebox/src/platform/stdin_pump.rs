// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bridges a real, blocking host stdin into a non-blocking, epoll-observable ring buffer.
//!
//! A platform that has a real interactive stdin (e.g. a userland platform reading from the
//! host's fd 0) spawns exactly one background host thread that performs blocking reads of the
//! real stdin and feeds whatever bytes arrive to [`StdinPump::push`]. The guest-facing,
//! non-blocking drain is [`StdinPump::try_read`], and this type's [`IOPollable`] implementation
//! is what `epoll`/`poll`/`select` observe for real stdin readiness -- reusing the same
//! [`Observer`]-based wakeup pattern already used by [`crate::pipes`] for pipe readiness, rather
//! than inventing a new one.
//!
//! Deliberately *not* generic over a `Platform`, unlike most of the rest of this crate: a
//! concrete platform (e.g. `MacOsUserland`) owns exactly one `StdinPump` as a field of itself,
//! and any type embedded that way that used this crate's `Platform`-generic sync primitives
//! (`litebox::sync::Mutex<Platform, _>`, and therefore also `Pollee<Platform>`) would make the
//! platform's own `Sync` impl depend on itself, which overflows trait-bound evaluation. A plain
//! `spin::Mutex` (already a dependency of this crate; see `crate::mm::allocator` and
//! `crate::sync::lock_tracing` for existing precedent) sidesteps that entirely.

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::sync::Weak;
use alloc::vec::Vec;
use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Observer as _, Producer as _, Split as _},
};

use crate::event::{Events, IOPollable, observer::Observer};

/// One registered observer and the event mask it's interested in.
type ObserverEntry = (Weak<dyn Observer<Events>>, Events);

/// A ring-buffer-backed bridge between a real, blocking host stdin and the guest-visible,
/// non-blocking/epoll-observable world.
pub struct StdinPump {
    prod: spin::Mutex<HeapProd<u8>>,
    cons: spin::Mutex<HeapCons<u8>>,
    observers: spin::Mutex<Vec<ObserverEntry>>,
    /// Set once the real host stdin has hit EOF (or been closed); once set, [`Self::try_read`]
    /// reports EOF (`Ok(0)`) after the buffer has been drained, matching real `read(2)` semantics.
    eof: AtomicBool,
}

/// Default capacity of the ring buffer backing a [`StdinPump`]. Generous enough to absorb a fast
/// piped producer (e.g. `yes | guest`) between guest drains without the background reader
/// thread's retry loop spinning excessively, while staying small relative to guest memory.
pub const DEFAULT_CAPACITY: usize = 64 * 1024;

impl StdinPump {
    /// Create a new pump with the given ring-buffer capacity in bytes.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (prod, cons) = HeapRb::<u8>::new(capacity).split();
        Self {
            prod: spin::Mutex::new(prod),
            cons: spin::Mutex::new(cons),
            observers: spin::Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
        }
    }

    /// Called by the platform's background reader thread with freshly read bytes from the real
    /// host stdin. Returns the number of bytes actually accepted into the ring buffer -- fewer
    /// than `data.len()` if it's currently full, in which case the caller is expected to retry
    /// the remainder (typically after a short backoff, since the guest is the only consumer).
    ///
    /// Never call this with an empty slice to signal EOF -- use [`Self::mark_eof`] instead, so
    /// that a legitimate zero-length host read (which does not happen for stdin, but would be an
    /// easy mistake to make) isn't confused with a real EOF condition.
    pub fn push(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        let n = self.prod.lock().push_slice(data);
        if n > 0 {
            self.notify(Events::IN);
        }
        n
    }

    /// Attempts to enqueue all of `data` without waiting for the consumer. Returns `false` and
    /// leaves the buffer unchanged if there is not enough room for the whole slice. This is useful
    /// for latency-sensitive producers such as an input-client reader: they must never stall behind
    /// a guest that has stopped draining stdin, and partially enqueuing a multi-byte terminal escape
    /// sequence would corrupt the next sequence the guest reads.
    pub fn try_push_all(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        let mut prod = self.prod.lock();
        if prod.vacant_len() < data.len() {
            return false;
        }
        let n = prod.push_slice(data);
        drop(prod);
        debug_assert_eq!(n, data.len());
        self.notify(Events::IN);
        true
    }

    /// Marks the real host stdin as closed/EOF. Idempotent; safe to call more than once (e.g. if
    /// the background reader thread sees repeated EOF reads).
    pub fn mark_eof(&self) {
        self.eof.store(true, Ordering::Release);
        self.notify(Events::IN);
    }

    /// Whether the real host stdin has hit EOF (all buffered bytes may not yet be drained).
    #[must_use]
    pub fn is_eof(&self) -> bool {
        self.eof.load(Ordering::Acquire)
    }

    /// Non-blocking drain into `buf`.
    ///
    /// * `Some(n)` with `n > 0`: `n` bytes were copied into `buf`.
    /// * `Some(0)`: the buffer is empty and the real stdin has hit EOF -- matches `read(2)`
    ///   returning `0`.
    /// * `None`: no data is available yet and stdin has not hit EOF -- the caller should treat
    ///   this the same as `EAGAIN`/`WouldBlock`.
    pub fn try_read(&self, buf: &mut [u8]) -> Option<usize> {
        let n = self.cons.lock().pop_slice(buf);
        if n > 0 {
            return Some(n);
        }
        if self.eof.load(Ordering::Acquire) {
            return Some(0);
        }
        None
    }

    /// Discards every byte currently sitting in the ring buffer, without waiting for the guest
    /// to read them. Backs `TCSETSF`/`TCSAFLUSH`'s "discard unread input" contract: a plain host
    /// `tcsetattr(TCSAFLUSH)` only flushes the host tty driver's own queue, not bytes this pump's
    /// background reader thread has already pulled off that queue and pushed into the ring, so
    /// callers must invoke this in addition to (after) the host-level flush.
    pub fn discard_buffered(&self) {
        let mut cons = self.cons.lock();
        let discarded = cons.occupied_len();
        if discarded > 0 {
            cons.clear();
        }
    }

    fn notify(&self, events: Events) {
        let mut observers = self.observers.lock();
        if observers.is_empty() {
            return;
        }
        observers.retain(|(weak, filter)| match weak.upgrade() {
            Some(observer) => {
                if filter.intersects(events) {
                    observer.on_events(&events);
                }
                true
            }
            None => false,
        });
    }
}

impl IOPollable for StdinPump {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.observers
            .lock()
            .push((observer, filter | Events::ALWAYS_POLLED));
    }

    fn unregister_observer(&self, observer: Weak<dyn Observer<Events>>) {
        self.observers
            .lock()
            .retain(|(registered, _)| !registered.ptr_eq(&observer));
    }

    fn check_io_events(&self) -> Events {
        let has_data = !self.cons.lock().is_empty();
        if has_data || self.eof.load(Ordering::Acquire) {
            Events::IN
        } else {
            Events::empty()
        }
    }
}
