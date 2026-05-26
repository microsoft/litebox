// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::sync::{Arc, Weak};
use litebox::{
    event::{Events, observer::Observer, polling::Pollee},
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_linux::errno::Errno;
use ringbuf::traits::{Consumer as _, Observer as _, Producer as _};

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

struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    rb: Mutex<Platform, T>,
    pollee: Arc<Pollee<Platform>>,
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> EndPointer<Platform, T> {
    fn new(rb: T, pollee: Arc<Pollee<Platform>>) -> Self {
        Self {
            rb: Mutex::new(rb),
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

pub(crate) struct ReadEnd<T> {
    endpoint: alloc::sync::Arc<EndPointer<crate::Platform, ringbuf::HeapCons<T>>>,
    peer: alloc::sync::Weak<EndPointer<crate::Platform, ringbuf::HeapProd<T>>>,
}

impl<T> ReadEnd<T> {
    fn update_pollee(&self) {
        if let Some(peer) = self.peer.upgrade() {
            peer.pollee.notify_observers(litebox::event::Events::OUT);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.endpoint.rb.lock().is_empty()
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
        let mut guard = self.endpoint.rb.lock();
        if let Some(item) = guard.first_mut() {
            let (should_consume, ret) = f(item)?;
            if should_consume {
                guard
                    .try_pop()
                    .expect("Guaranteed to have an element to consume");
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

#[derive(Clone)]
pub(crate) struct WriteEnd<T> {
    endpoint: alloc::sync::Arc<EndPointer<crate::Platform, ringbuf::HeapProd<T>>>,
    peer: alloc::sync::Weak<EndPointer<crate::Platform, ringbuf::HeapCons<T>>>,
}

impl<T> WriteEnd<T> {
    pub(crate) fn try_write_one(&self, elem: T) -> Result<(), (T, Errno)> {
        if self.is_shutdown() || self.is_peer_shutdown() {
            return Err((elem, Errno::EPIPE));
        }

        let ret = self.endpoint.rb.lock().try_push(elem);
        match ret {
            Ok(()) => {
                if let Some(peer) = self.peer.upgrade() {
                    peer.pollee.notify_observers(litebox::event::Events::IN);
                }
                Ok(())
            }
            Err(e) => Err((e, Errno::EAGAIN)),
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.endpoint.rb.lock().is_full()
    }

    pub(crate) fn is_pair(&self, reader: &ReadEnd<T>) -> bool {
        if let Some(peer) = self.peer.upgrade() {
            Arc::ptr_eq(&peer, &reader.endpoint)
        } else {
            false
        }
    }

    pub(crate) fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }

    common_functions_for_channel!();
}

pub(crate) struct Channel<T> {
    writer: WriteEnd<T>,
    reader: ReadEnd<T>,
}

impl<T> Channel<T> {
    pub(crate) fn new(
        capacity: usize,
        writer_pollee: Arc<Pollee<crate::Platform>>,
        reader_pollee: Arc<Pollee<crate::Platform>>,
    ) -> Self {
        use ringbuf::traits::Split as _;
        let rb: ringbuf::HeapRb<T> = ringbuf::HeapRb::new(capacity);
        let (rb_prod, rb_cons) = rb.split();

        let mut writer = WriteEnd {
            endpoint: Arc::new(EndPointer::new(rb_prod, writer_pollee)),
            peer: alloc::sync::Weak::new(),
        };
        let mut reader = ReadEnd {
            endpoint: Arc::new(EndPointer::new(rb_cons, reader_pollee)),
            peer: alloc::sync::Weak::new(),
        };

        writer.peer = Arc::downgrade(&reader.endpoint);
        reader.peer = Arc::downgrade(&writer.endpoint);

        Self { writer, reader }
    }

    /// Turn the channel into a pair of its read and write ends.
    pub(crate) fn split(self) -> (WriteEnd<T>, ReadEnd<T>) {
        let Channel { writer, reader } = self;
        (writer, reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use litebox::event::observer::Observer;

    fn split_pair<T>() -> (WriteEnd<T>, ReadEnd<T>) {
        Channel::<T>::new(4, Arc::new(Pollee::new()), Arc::new(Pollee::new())).split()
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

    /// Regression: `shutdown()` must wake observers on the peer's pollee so a peer blocked
    /// in send/recv notices the new state without waiting for an unrelated event. HUP is in
    /// `Events::ALWAYS_POLLED`, so any observer (even one registered with a different mask)
    /// must be notified.
    #[test]
    fn shutdown_notifies_peer_pollee_hup() {
        let writer_pollee = Arc::new(Pollee::new());
        let reader_pollee = Arc::new(Pollee::new());
        let (_writer, reader) =
            Channel::<u32>::new(4, writer_pollee.clone(), reader_pollee).split();
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
