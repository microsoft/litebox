//! Unidirectional communication channels

use core::sync::atomic::{
    AtomicBool, AtomicU32,
    Ordering::{self, Relaxed},
};

use alloc::sync::{Arc, Weak};
use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Observer as _, Producer as _, Split as _},
};
use thiserror::Error;

use crate::{
    LiteBox,
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
    },
    fs::OFlags,
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};

/// The maximum number of bytes for atomic write.
///
/// See <https://man7.org/linux/man-pages/man7/pipe.7.html> for more details.
#[cfg(not(test))]
const PIPE_BUF: usize = 4096;
#[cfg(test)]
const PIPE_BUF: usize = 2;

struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    rb: Mutex<Platform, T>,
    pollee: Pollee<Platform>,
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> EndPointer<Platform, T> {
    fn new(rb: T, litebox: &LiteBox<Platform>) -> Self {
        Self {
            rb: litebox.sync().new_mutex(rb),
            pollee: Pollee::new(litebox),
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
        pub fn get_status(&self) -> OFlags {
            OFlags::from_bits(self.status.load(Relaxed)).unwrap() & OFlags::STATUS_FLAGS_MASK
        }

        pub fn set_status(&self, flag: OFlags, on: bool) {
            if on {
                self.status.fetch_or(flag.bits(), Relaxed);
            } else {
                self.status.fetch_and(flag.complement().bits(), Relaxed);
            }
        }

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

pub struct Producer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    endpoint: EndPointer<Platform, HeapProd<T>>,
    peer: Weak<Consumer<Platform, T>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PipeError {
    #[error("this pipe has been closed down")]
    Closed,
    #[error("this operation would block")]
    WouldBlock,
}

impl From<TryOpError<PipeError>> for PipeError {
    fn from(err: TryOpError<PipeError>) -> Self {
        match err {
            TryOpError::TryAgain => PipeError::WouldBlock,
            TryOpError::TimedOut => unreachable!(),
            TryOpError::Other(e) => e,
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> Producer<Platform, T> {
    fn new(rb: HeapProd<T>, flags: OFlags, litebox: &LiteBox<Platform>) -> Self {
        Self {
            endpoint: EndPointer::new(rb, litebox),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::WRONLY).bits()),
        }
    }

    fn try_write(&self, buf: &[T]) -> Result<usize, TryOpError<PipeError>>
    where
        T: Copy,
    {
        if self.is_shutdown() || self.is_peer_shutdown() {
            return Err(TryOpError::Other(PipeError::Closed));
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

    pub fn write(&self, buf: &[T]) -> Result<usize, PipeError>
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
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> IOPollable for Producer<Platform, T> {
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> Drop for Producer<Platform, T> {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(peer) = self.peer.upgrade() {
            // when reading from a channel such as a pipe or a stream socket, this event
            // merely indicates that the peer closed its end of the channel.
            peer.endpoint.pollee.notify_observers(Events::HUP);
        }
    }
}

pub struct Consumer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    endpoint: EndPointer<Platform, HeapCons<T>>,
    peer: Weak<Producer<Platform, T>>,
    status: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> IOPollable for Consumer<Platform, T> {
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> Consumer<Platform, T> {
    fn new(rb: HeapCons<T>, flags: OFlags, litebox: &LiteBox<Platform>) -> Self {
        Self {
            endpoint: EndPointer::new(rb, litebox),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::RDONLY).bits()),
        }
    }

    fn try_read(&self, buf: &mut [T]) -> Result<usize, TryOpError<PipeError>>
    where
        T: Copy,
    {
        if self.is_shutdown() {
            return Err(TryOpError::Other(PipeError::Closed));
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

    pub fn read(&self, buf: &mut [T]) -> Result<usize, PipeError>
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
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> Drop for Consumer<Platform, T> {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(peer) = self.peer.upgrade() {
            // This bit is also set for a file descriptor referring to the write end
            // of a pipe when the read end has been closed.
            peer.endpoint.pollee.notify_observers(Events::ERR);
        }
    }
}

/// Create a unidirectional communication channel that sending messages of (slices of) type `T`.
///
/// This function returns the sender and receiver halves.
///
/// `capacity` defines the maximum capacity of the channel, beyond which it will block or refuse to
/// write, depending on flags.
///
/// `flags` sets up the initial flags for the channel. An important flag is `OFlags::NONBLOCK` which
/// impacts what happens when the channel is full, and an attempt is made to write to it.
#[expect(
    clippy::type_complexity,
    reason = "clippy believes this result type to be complex, but factoring it out into a type def would not help readability in any way"
)]
pub fn new_channel<Platform: RawSyncPrimitivesProvider + TimeProvider, T>(
    litebox: &LiteBox<Platform>,
    capacity: usize,
    flags: OFlags,
) -> (Arc<Producer<Platform, T>>, Arc<Consumer<Platform, T>>) {
    let rb: HeapRb<T> = HeapRb::new(capacity);
    let (rb_prod, rb_cons) = rb.split();

    // Create the producer and consumer, and set up cyclic references.
    let mut producer = Arc::new(Producer::new(rb_prod, flags, litebox));
    let consumer = Arc::new_cyclic(|weak_self| {
        #[expect(
            clippy::missing_panics_doc,
            reason = "Producer has no other references as it is just created. So we can safely get a mutable reference to it."
        )]
        {
            Arc::get_mut(&mut producer).unwrap().peer = weak_self.clone();
        }
        let mut consumer = Consumer::new(rb_cons, flags, litebox);
        consumer.peer = Arc::downgrade(&producer);
        consumer
    });

    (producer, consumer)
}

#[cfg(test)]
mod tests {
    use crate::pipes::PipeError;

    extern crate std;

    #[test]
    fn test_blocking_channel() {
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = crate::LiteBox::new(platform);

        let (prod, cons) = super::new_channel(&litebox, 2, crate::fs::OFlags::empty());
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
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = crate::LiteBox::new(platform);

        let (prod, cons) = super::new_channel(&litebox, 2, crate::fs::OFlags::NONBLOCK);
        std::thread::spawn(move || {
            let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut i = 0;
            while i < data.len() {
                match prod.write(&data[i..]) {
                    Ok(n) => {
                        i += n;
                    }
                    Err(PipeError::WouldBlock) => {
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
                Err(PipeError::WouldBlock) => {
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
