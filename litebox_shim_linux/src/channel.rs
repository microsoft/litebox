// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A bounded, poll-integrated SPSC message channel: the transport under unix sockets (and any
//! other in-shim byte/message stream that pairs a writer with a reader).
//!
//! The queue is one `Mutex<VecDeque<T>>` shared by both ends. This deliberately replaced a
//! `ringbuf::HeapRb` split into that crate's *caching* producer/consumer handles: each caching
//! handle trusts a locally cached copy of the opposite index, which is only refreshed by the
//! handle's own push/pop operations. This module's peek-first consumption
//! ([`ReadEnd::peek_and_consume_one`]) observed the cached view without refreshing it, so a
//! consumer could see "empty" forever while the producer's side of the very same ring held
//! queued items -- observed live as an X client waiting on events the X server had already
//! written (the desktop-wide stall). One shared deque under one lock has no index caching to
//! go stale, and none of these paths are hot enough for the lock to matter.

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use litebox::{
    event::{Events, observer::Observer, polling::Pollee},
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_linux::errno::Errno;

use crate::ShimPlatform;

macro_rules! common_functions_for_channel {
    () => {
        pub(crate) fn is_shutdown(&self) -> bool {
            self.endpoint.is_shutdown()
        }

        /// Shuts the endpoint down. Returns `true` only on the call that
        /// effected the transition (idempotent thereafter — not a fallibility
        /// signal). The first transition also wakes the peer's pollee so a
        /// peer blocked in send/recv unblocks immediately.
        pub(crate) fn shutdown(&self) -> bool {
            if self.endpoint.shutdown() {
                if let Some(peer) = self.peer.upgrade() {
                    peer.pollee.notify_observers(litebox::event::Events::HUP);
                }
                true
            } else {
                false
            }
        }

        /// Has the peer (i.e., other end) been shut down?
        pub(crate) fn is_peer_shutdown(&self) -> bool {
            if let Some(peer) = self.peer.upgrade() {
                peer.is_shutdown()
            } else {
                true
            }
        }
    };
}

/// The queue both ends share, with its capacity bound.
struct SharedQueue<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    items: Mutex<Platform, VecDeque<T>>,
    capacity: usize,
}

/// One end's identity: its pollee (what the *other* end notifies) and its shutdown flag.
struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    pollee: Arc<Pollee<Platform>>,
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EndPointer<Platform> {
    fn new(pollee: Arc<Pollee<Platform>>) -> Self {
        Self {
            pollee,
            is_shutdown: AtomicBool::new(false),
        }
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::Acquire)
    }

    /// Returns `true` on the call that affected the transition so callers can
    /// gate one-shot side-effects (e.g. peer wake-ups); idempotent thereafter.
    /// The boolean reports newness, not fallibility — the state is always shut
    /// down after this call.
    fn shutdown(&self) -> bool {
        !self.is_shutdown.swap(true, Ordering::Release)
    }
}

pub(crate) struct ReadEnd<Platform: ShimPlatform, T> {
    queue: Arc<SharedQueue<Platform, T>>,
    endpoint: Arc<EndPointer<Platform>>,
    peer: Weak<EndPointer<Platform>>,
}

impl<Platform: ShimPlatform, T> ReadEnd<Platform, T> {
    fn update_pollee(&self) {
        if let Some(peer) = self.peer.upgrade() {
            peer.pollee.notify_observers(litebox::event::Events::OUT);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.items.lock().is_empty()
    }

    /// Peeks at the first item in the channel and conditionally consumes it.
    ///
    /// This method allows examining and potentially modifying the first item in the
    /// channel through a closure. The closure decides whether to consume the item
    /// by returning a boolean in its result tuple.
    pub(crate) fn peek_and_consume_one<R>(
        &self,
        mut f: impl FnMut(&mut T) -> Result<(bool, R), Errno>,
    ) -> Result<R, Errno> {
        // Linux preserves bytes already queued when the read side is shut down
        // (via shutdown(SHUT_RD) or peer close), so consult the buffer before
        // returning ESHUTDOWN; the caller observes EOF only once the queue drains.
        let is_shutdown = self.is_shutdown() || self.is_peer_shutdown();
        let mut guard = self.queue.items.lock();
        if let Some(item) = guard.front_mut() {
            let (should_consume, ret) = f(item)?;
            if should_consume {
                guard
                    .pop_front()
                    .expect("Guaranteed to have an element to consume");
                drop(guard);
                self.update_pollee();
            }
            return Ok(ret);
        }
        if is_shutdown {
            return Err(Errno::ESHUTDOWN);
        }

        Err(Errno::EAGAIN)
    }

    common_functions_for_channel!();
}

pub(crate) struct WriteEnd<Platform: ShimPlatform, T> {
    queue: Arc<SharedQueue<Platform, T>>,
    endpoint: Arc<EndPointer<Platform>>,
    peer: Weak<EndPointer<Platform>>,
}

impl<Platform: ShimPlatform, T> Clone for WriteEnd<Platform, T> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            endpoint: self.endpoint.clone(),
            peer: self.peer.clone(),
        }
    }
}

impl<Platform: ShimPlatform, T> WriteEnd<Platform, T> {
    pub(crate) fn try_write_one(&self, elem: T) -> Result<(), (T, Errno)> {
        if self.is_shutdown() || self.is_peer_shutdown() {
            return Err((elem, Errno::EPIPE));
        }

        {
            let mut guard = self.queue.items.lock();
            if guard.len() >= self.queue.capacity {
                return Err((elem, Errno::EAGAIN));
            }
            guard.push_back(elem);
        }
        if let Some(peer) = self.peer.upgrade() {
            peer.pollee.notify_observers(litebox::event::Events::IN);
        }
        Ok(())
    }

    pub(crate) fn is_full(&self) -> bool {
        self.queue.items.lock().len() >= self.queue.capacity
    }

    pub(crate) fn is_pair(&self, reader: &ReadEnd<Platform, T>) -> bool {
        Arc::ptr_eq(&self.queue, &reader.queue)
    }

    pub(crate) fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }

    common_functions_for_channel!();
}

pub(crate) struct Channel<Platform: ShimPlatform, T> {
    writer: WriteEnd<Platform, T>,
    reader: ReadEnd<Platform, T>,
}

impl<Platform: ShimPlatform, T> Channel<Platform, T> {
    pub(crate) fn new(
        capacity: usize,
        writer_pollee: Arc<Pollee<Platform>>,
        reader_pollee: Arc<Pollee<Platform>>,
    ) -> Self {
        let queue = Arc::new(SharedQueue {
            items: Mutex::new(VecDeque::new()),
            capacity,
        });
        let writer_end = Arc::new(EndPointer::new(writer_pollee));
        let reader_end = Arc::new(EndPointer::new(reader_pollee));

        let writer = WriteEnd {
            queue: queue.clone(),
            endpoint: writer_end.clone(),
            peer: Arc::downgrade(&reader_end),
        };
        let reader = ReadEnd {
            queue,
            endpoint: reader_end,
            peer: Arc::downgrade(&writer_end),
        };

        Self { writer, reader }
    }

    /// Turn the channel into a pair of its read and write ends.
    pub(crate) fn split(self) -> (WriteEnd<Platform, T>, ReadEnd<Platform, T>) {
        let Channel { writer, reader } = self;
        (writer, reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::tests::TestPlatform;
    use core::sync::atomic::{AtomicBool, Ordering};
    use litebox::event::observer::Observer;

    fn split_pair<T>() -> (WriteEnd<TestPlatform, T>, ReadEnd<TestPlatform, T>) {
        Channel::<TestPlatform, T>::new(4, Arc::new(Pollee::new()), Arc::new(Pollee::new())).split()
    }

    /// Test observer that flips a flag the first time it is notified.
    struct FlagOnNotify(Arc<AtomicBool>);
    impl Observer<Events> for FlagOnNotify {
        fn on_events(&self, _events: &Events) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn peek_and_consume_one_drains_queue_after_self_shutdown() {
        let (writer, reader) = split_pair::<u32>();
        writer.try_write_one(42).unwrap();
        reader.shutdown();
        // Queued bytes must remain readable after shutdown(SHUT_RD): we should
        // get the 42 first, ESHUTDOWN only once the buffer is empty.
        let got = reader
            .peek_and_consume_one(|x| Ok((true, *x)))
            .expect("queued item must be returned even after self shutdown");
        assert_eq!(got, 42);
        let err = reader
            .peek_and_consume_one(|x: &mut u32| Ok((true, *x)))
            .unwrap_err();
        assert_eq!(err, Errno::ESHUTDOWN);
    }

    #[test]
    fn peek_and_consume_one_drains_queue_after_peer_shutdown() {
        let (writer, reader) = split_pair::<u32>();
        writer.try_write_one(7).unwrap();
        writer.shutdown();
        let got = reader
            .peek_and_consume_one(|x| Ok((true, *x)))
            .expect("queued item must be returned even after peer shutdown");
        assert_eq!(got, 7);
        let err = reader
            .peek_and_consume_one(|x: &mut u32| Ok((true, *x)))
            .unwrap_err();
        assert_eq!(err, Errno::ESHUTDOWN);
    }

    #[test]
    fn peek_and_consume_one_returns_eagain_when_empty_and_alive() {
        let (_writer, reader) = split_pair::<u32>();
        let err = reader
            .peek_and_consume_one(|x: &mut u32| Ok((true, *x)))
            .unwrap_err();
        assert_eq!(err, Errno::EAGAIN);
    }

    #[test]
    fn try_write_one_returns_epipe_after_self_shutdown() {
        let (writer, _reader) = split_pair::<u32>();
        writer.shutdown();
        let (_val, err) = writer.try_write_one(1).unwrap_err();
        assert_eq!(err, Errno::EPIPE);
    }

    #[test]
    fn try_write_one_returns_epipe_after_peer_shutdown() {
        let (writer, reader) = split_pair::<u32>();
        reader.shutdown();
        let (_val, err) = writer.try_write_one(1).unwrap_err();
        assert_eq!(err, Errno::EPIPE);
    }

    /// The regression this module's rewrite exists for: an item pushed through the write end
    /// must be immediately visible to the read end's *peek* path (the ringbuf caching handles
    /// this replaced could report empty forever here).
    #[test]
    fn peek_sees_push_immediately() {
        let (writer, reader) = split_pair::<u32>();
        for i in 0..100u32 {
            writer.try_write_one(i).unwrap();
            let got = reader
                .peek_and_consume_one(|x| Ok((true, *x)))
                .expect("pushed item must be immediately peekable");
            assert_eq!(got, i);
        }
    }

    #[test]
    fn try_write_one_returns_eagain_when_full() {
        let (writer, _reader) = split_pair::<u32>();
        for i in 0..4 {
            writer.try_write_one(i).unwrap();
        }
        let (_val, err) = writer.try_write_one(99).unwrap_err();
        assert_eq!(err, Errno::EAGAIN);
    }

    /// Regression: `shutdown()` must wake observers on the peer's pollee so a peer blocked
    /// in send/recv notices the new state without waiting for an unrelated event. HUP is in
    /// `Events::ALWAYS_POLLED`, so any observer (even one registered with a different mask)
    /// must be notified.
    #[test]
    fn shutdown_notifies_peer_pollee_hup() {
        let writer_pollee = Arc::new(Pollee::new());
        let reader_pollee = Arc::new(Pollee::new());
        let (_writer, reader) =
            Channel::<TestPlatform, u32>::new(4, writer_pollee.clone(), reader_pollee).split();
        let flag = Arc::new(AtomicBool::new(false));
        let observer: Arc<FlagOnNotify> = Arc::new(FlagOnNotify(flag.clone()));
        // The peer of `reader` is the writer's endpoint, whose pollee is `writer_pollee`;
        // register the observer there to detect that `reader.shutdown()` reaches it.
        writer_pollee.register_observer(
            Arc::downgrade(&observer) as Weak<dyn Observer<Events>>,
            Events::OUT,
        );
        assert!(!flag.load(Ordering::Acquire), "observer must start cleared");
        reader.shutdown();
        assert!(
            flag.load(Ordering::Acquire),
            "shutdown(ReadEnd) must wake peer pollee observers"
        );
    }
}
