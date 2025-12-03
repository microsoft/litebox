use alloc::sync::Arc;
use litebox_common_linux::errno::Errno;
use ringbuf::traits::{Consumer as _, Producer as _};

macro_rules! common_functions_for_channel {
    () => {
        /// Has this been shut down?
        fn is_shutdown(&self) -> bool {
            self.endpoint.is_shutdown()
        }

        /// Shut this channel down.
        #[expect(dead_code)]
        fn shutdown(&self) {
            self.endpoint.shutdown();
        }

        /// Has the peer (i.e., other end) been shut down?
        fn is_peer_shutdown(&self) -> bool {
            if let Some(peer) = self.peer.upgrade() {
                peer.is_shutdown()
            } else {
                true
            }
        }
    };
}

pub(crate) struct ReadEnd<T> {
    endpoint: alloc::sync::Arc<litebox::pipes::EndPointer<crate::Platform, ringbuf::HeapCons<T>>>,
    peer: alloc::sync::Weak<litebox::pipes::EndPointer<crate::Platform, ringbuf::HeapProd<T>>>,
}

impl<T> ReadEnd<T> {
    fn update_pollee(&self) {
        if let Some(peer) = self.peer.upgrade() {
            peer.pollee.notify_observers(litebox::event::Events::OUT);
        }
    }

    pub(crate) fn peek_and_consume_one<R>(
        &self,
        mut f: impl FnMut(&mut T) -> Result<(bool, R), Errno>,
    ) -> Result<R, Errno> {
        if self.is_shutdown() {
            return Err(Errno::ESHUTDOWN);
        }

        let is_peer_shutdown = self.is_peer_shutdown();
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
        drop(guard);

        if is_peer_shutdown {
            return Err(Errno::ESHUTDOWN);
        }

        Err(Errno::EAGAIN)
    }

    common_functions_for_channel!();
}

pub(crate) struct WriteEnd<T> {
    endpoint: alloc::sync::Arc<litebox::pipes::EndPointer<crate::Platform, ringbuf::HeapProd<T>>>,
    peer: alloc::sync::Weak<litebox::pipes::EndPointer<crate::Platform, ringbuf::HeapCons<T>>>,
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

    common_functions_for_channel!();
}

pub(crate) struct Channel<T> {
    writer: WriteEnd<T>,
    reader: ReadEnd<T>,
}

impl<T> Channel<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        use ringbuf::traits::Split as _;
        let rb: ringbuf::HeapRb<T> = ringbuf::HeapRb::new(capacity);
        let (rb_prod, rb_cons) = rb.split();

        let mut writer = WriteEnd {
            endpoint: Arc::new(litebox::pipes::EndPointer::new(rb_prod, crate::litebox())),
            peer: alloc::sync::Weak::new(),
        };
        let mut reader = ReadEnd {
            endpoint: Arc::new(litebox::pipes::EndPointer::new(rb_cons, crate::litebox())),
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
