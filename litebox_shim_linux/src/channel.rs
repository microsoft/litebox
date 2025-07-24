//! This module implements a unidirectional communication channel, intended to implement IPC,
//! e.g., pipe, unix domain sockets, etc.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use alloc::sync::{Arc, Weak};
use litebox::{
    LiteBox,
    event::{
        Events,
        observer::Observer,
        polling::{Pollee, TryOpError},
    },
    fs::OFlags,
};
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;
use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Observer as _, Producer as _, Split as _},
};

use crate::syscalls::epoll::IOPollable;

/// The maximum number of bytes for atomic write.
///
/// See <https://man7.org/linux/man-pages/man7/pipe.7.html> for more details.
#[cfg(not(test))]
const PIPE_BUF: usize = 4096;
#[cfg(test)]
const PIPE_BUF: usize = 2;

struct EndPointer<T> {
    rb: litebox::sync::Mutex<Platform, T>,
    pollee: Pollee<Platform>,
    is_shutdown: AtomicBool,
}

impl<T> EndPointer<T> {
    pub fn new(rb: T, litebox: &LiteBox<Platform>) -> Self {
        Self {
            rb: litebox.sync().new_mutex(rb),
            pollee: Pollee::new(crate::litebox()),
            is_shutdown: AtomicBool::new(false),
        }
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::Acquire)
    }

    fn shutdown(&self) {
        self.is_shutdown.store(true, Ordering::Release);
    }
}

macro_rules! common_functions_for_channel {
    () => {
        pub fn is_shutdown(&self) -> bool {
            self.endpoint.is_shutdown()
        }

        pub fn shutdown(&self) {
            self.endpoint.shutdown();
        }

        pub fn is_peer_shutdown(&self) -> bool {
            if let Some(peer) = self.peer.upgrade() {
                peer.endpoint.is_shutdown()
            } else {
                true
            }
        }
    };
}

pub(crate) struct Producer<T> {
    endpoint: EndPointer<HeapProd<T>>,
    peer: Weak<Consumer<T>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
}

impl<T> Producer<T> {
    fn new(rb: HeapProd<T>, flags: OFlags, litebox: &LiteBox<Platform>) -> Self {
        Self {
            endpoint: EndPointer::new(rb, litebox),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::WRONLY).bits()),
        }
    }

    fn try_write(&self, buf: &[T]) -> Result<usize, TryOpError<Errno>>
    where
        T: Copy,
    {
        if self.is_shutdown() || self.is_peer_shutdown() {
            return Err(TryOpError::Other(Errno::EPIPE));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let write_len = {
            let mut rb = self.endpoint.rb.lock();
            let total_size = core::mem::size_of_val(buf);
            if rb.vacant_len() < total_size && total_size <= PIPE_BUF {
                // No sufficient space for an atomic write
                0
            } else {
                rb.push_slice(buf)
            }
        };
        if write_len > 0 {
            if let Some(peer) = self.peer.upgrade() {
                peer.endpoint.pollee.notify_observers(Events::IN);
            }
            Ok(write_len)
        } else {
            Err(TryOpError::TryAgain)
        }
    }

    pub(crate) fn write(&self, buf: &[T]) -> Result<usize, Errno>
    where
        T: Copy,
    {
        Ok(if self.get_status().contains(OFlags::NONBLOCK) {
            self.try_write(buf)
        } else {
            self.endpoint.pollee.wait_or_timeout(
                None,
                || self.try_write(buf),
                || {
                    self.check_io_events()
                        .intersects(Events::OUT | Events::ALWAYS_POLLED)
                },
            )
        }?)
    }

    common_functions_for_channel!();
    crate::syscalls::common_functions_for_file_status!();
}

impl<T> IOPollable for Producer<T> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let rb = self.endpoint.rb.lock();
        let mut events = Events::empty();
        if self.is_peer_shutdown() {
            events |= Events::ERR;
        }
        if !self.is_shutdown() && !rb.is_full() {
            events |= Events::OUT;
        }
        events
    }
}

impl<T> Drop for Producer<T> {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(peer) = self.peer.upgrade() {
            // when reading from a channel such as a pipe or a stream socket, this event
            // merely indicates that the peer closed its end of the channel.
            peer.endpoint.pollee.notify_observers(Events::HUP);
        }
    }
}

pub(crate) struct Consumer<T> {
    endpoint: EndPointer<HeapCons<T>>,
    peer: Weak<Producer<T>>,
    status: AtomicU32,
}

impl<T> IOPollable for Consumer<T> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let rb = self.endpoint.rb.lock();
        let mut events = Events::empty();
        if self.is_peer_shutdown() {
            events |= Events::HUP;
        }
        if !self.is_shutdown() && !rb.is_empty() {
            events |= Events::IN;
        }
        events
    }
}

impl<T> Consumer<T> {
    fn new(rb: HeapCons<T>, flags: OFlags, litebox: &LiteBox<Platform>) -> Self {
        Self {
            endpoint: EndPointer::new(rb, litebox),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::RDONLY).bits()),
        }
    }

    fn try_read(&self, buf: &mut [T]) -> Result<usize, TryOpError<Errno>>
    where
        T: Copy,
    {
        if self.is_shutdown() {
            return Err(TryOpError::Other(Errno::EPIPE));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let read_len = self.endpoint.rb.lock().pop_slice(buf);
        if read_len > 0 {
            if let Some(peer) = self.peer.upgrade() {
                peer.endpoint.pollee.notify_observers(Events::OUT);
            }
            Ok(read_len)
        } else {
            if self.is_peer_shutdown() {
                // Note: we need to read again to ensure no data sent between `pop_slice`
                // and `is_peer_shutdown` are lost.
                return Ok(self.endpoint.rb.lock().pop_slice(buf));
            }
            Err(TryOpError::TryAgain)
        }
    }

    pub(crate) fn read(&self, buf: &mut [T]) -> Result<usize, Errno>
    where
        T: Copy,
    {
        Ok(if self.get_status().contains(OFlags::NONBLOCK) {
            self.try_read(buf)
        } else {
            self.endpoint.pollee.wait_or_timeout(
                None,
                || self.try_read(buf),
                || {
                    self.check_io_events()
                        .intersects(Events::IN | Events::ALWAYS_POLLED)
                },
            )
        }?)
    }

    common_functions_for_channel!();
    crate::syscalls::common_functions_for_file_status!();
}

impl<T> Drop for Consumer<T> {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(peer) = self.peer.upgrade() {
            // This bit is also set for a file descriptor referring to the write end
            // of a pipe when the read end has been closed.
            peer.endpoint.pollee.notify_observers(Events::ERR);
        }
    }
}

/// A unidirectional communication channel, intended to implement IPC, e.g., pipe,
/// unix domain sockets, etc.
pub(crate) struct Channel<T> {
    prod: Arc<Producer<T>>,
    cons: Arc<Consumer<T>>,
}

impl<T> Channel<T> {
    /// Creates a new channel with the given capacity and flags.
    pub(crate) fn new(capacity: usize, flags: OFlags, litebox: &LiteBox<Platform>) -> Self {
        let rb: HeapRb<T> = HeapRb::new(capacity);
        let (rb_prod, rb_cons) = rb.split();

        // Create the producer and consumer, and set up cyclic references.
        let mut producer = Arc::new(Producer::new(rb_prod, flags, litebox));
        let consumer = Arc::new_cyclic(|weak_self| {
            // Producer has no other references as it is just created.
            // So we can safely get a mutable reference to it.
            Arc::get_mut(&mut producer).unwrap().peer = weak_self.clone();
            let mut consumer = Consumer::new(rb_cons, flags, litebox);
            consumer.peer = Arc::downgrade(&producer);
            consumer
        });

        Self {
            prod: producer,
            cons: consumer,
        }
    }

    /// Turn the channel into a pair of producer and consumer.
    pub(crate) fn split(self) -> (Arc<Producer<T>>, Arc<Consumer<T>>) {
        let Channel { prod, cons } = self;
        (prod, cons)
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::errno::Errno;

    extern crate std;

    #[test]
    fn test_blocking_channel() {
        crate::syscalls::tests::init_platform(None);

        let (prod, cons) =
            super::Channel::<u8>::new(2, litebox::fs::OFlags::empty(), crate::litebox()).split();
        std::thread::spawn(move || {
            let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut i = 0;
            while i < data.len() {
                let ret = prod.write(&data[i..]).unwrap();
                i += ret;
            }
            prod.shutdown();
            assert_eq!(i, data.len());
        });

        let mut buf = [0; 10];
        let mut i = 0;
        loop {
            let ret = cons.read(&mut buf[i..]).unwrap();
            if ret == 0 {
                cons.shutdown();
                break;
            }
            i += ret;
        }
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_nonblocking_channel() {
        crate::syscalls::tests::init_platform(None);

        let (prod, cons) =
            super::Channel::<u8>::new(2, litebox::fs::OFlags::NONBLOCK, crate::litebox()).split();
        std::thread::spawn(move || {
            let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut i = 0;
            while i < data.len() {
                match prod.write(&data[i..]) {
                    Ok(n) => {
                        i += n;
                    }
                    Err(Errno::EAGAIN) => {
                        // busy wait
                        // TODO: use poll rather than busy wait
                    }
                    Err(e) => {
                        panic!("Error writing to channel: {:?}", e);
                    }
                }
            }
            prod.shutdown();
            assert_eq!(i, data.len());
        });

        let mut buf = [0; 10];
        let mut i = 0;
        loop {
            match cons.read(&mut buf[i..]) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    i += n;
                }
                Err(Errno::EAGAIN) => {
                    // busy wait
                    // TODO: use poll rather than busy wait
                }
                Err(e) => {
                    panic!("Error reading from channel: {:?}", e);
                }
            }
        }
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }
}
