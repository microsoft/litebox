//! Unidirectional communication channels

use core::{
    num::NonZeroUsize,
    sync::atomic::{
        AtomicBool, AtomicU32,
        Ordering::{self, Relaxed},
    },
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

struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    rb: Mutex<Platform, T>,
    pollee: Pollee<Platform>,
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> EndPointer<Platform, T> {
    fn new(litebox: &LiteBox<Platform>, rb: T) -> Self {
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

/// Potential errors when writing or reading from a pipe
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

/// The read [`EndType`]
pub struct Read {
    __private: (),
}
/// The write [`EndType`]
pub struct Write {
    /// Slice length that is guaranteed to be an atomic write (i.e., non-interleaved).
    atomic_slice_guarantee_size: usize,
}
/// Specifies the particular end of a pipe (see [`PipeEnd`]).
pub trait EndType {
    type Peer: EndType;
    const IS_READER_SIDE: bool;
    type EndTWrap<T>: ringbuf::traits::Observer;
}
impl EndType for Read {
    type Peer = Write;
    const IS_READER_SIDE: bool = true;
    type EndTWrap<T> = HeapCons<T>;
}
impl EndType for Write {
    type Peer = Read;
    const IS_READER_SIDE: bool = false;
    type EndTWrap<T> = HeapProd<T>;
}

/// One of the ends of a pipe produced by [`new_pipe`].
///
/// Which end of the pipe is specified by `ET` and impacts which side of the functionality is available.
pub struct PipeEnd<Platform: RawSyncPrimitivesProvider + TimeProvider, ET: EndType, T> {
    endpoint: EndPointer<Platform, ET::EndTWrap<T>>,
    peer: Weak<PipeEnd<Platform, ET::Peer, T>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    et_data: ET,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> PipeEnd<Platform, Write, T> {
    fn new(
        litebox: &LiteBox<Platform>,
        rb: HeapProd<T>,
        flags: OFlags,
        atomic_slice_guarantee_size: usize,
    ) -> Self {
        Self {
            endpoint: EndPointer::new(litebox, rb),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::WRONLY).bits()),
            et_data: Write {
                atomic_slice_guarantee_size,
            },
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
            let total_size = buf.len();
            if rb.vacant_len() < total_size
                && total_size <= self.et_data.atomic_slice_guarantee_size
            {
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

    /// Write the values in `buf` into the pipe, returning the number of elements written.
    ///
    /// See [`new_pipe`] for details on blocking and atomicity of writes.
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
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> PipeEnd<Platform, Read, T> {
    fn new(litebox: &LiteBox<Platform>, rb: HeapCons<T>, flags: OFlags) -> Self {
        Self {
            endpoint: EndPointer::new(litebox, rb),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::RDONLY).bits()),
            et_data: Read { __private: () },
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

    /// Read values in the pipe into `buf`, returning the number of elements read.
    ///
    /// See [`new_pipe`] for details on blocking behavior.
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
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, ET: EndType, T> PipeEnd<Platform, ET, T> {
    /// Get the status flags for this channel
    #[expect(
        clippy::missing_panics_doc,
        reason = "we only store values that are valid bits"
    )]
    pub fn get_status(&self) -> OFlags {
        OFlags::from_bits(self.status.load(Relaxed)).unwrap() & OFlags::STATUS_FLAGS_MASK
    }

    /// Update the status flags for `mask` to `on`.
    pub fn set_status(&self, mask: OFlags, on: bool) {
        if on {
            self.status.fetch_or(mask.bits(), Relaxed);
        } else {
            self.status.fetch_and(mask.complement().bits(), Relaxed);
        }
    }

    /// Has this been shut down?
    pub fn is_shutdown(&self) -> bool {
        self.endpoint.is_shutdown()
    }

    /// Shut this channel down.
    pub fn shutdown(&self) {
        self.endpoint.shutdown();
    }

    /// Has the peer (i.e., other end) been shut down?
    pub fn is_peer_shutdown(&self) -> bool {
        if let Some(peer) = self.peer.upgrade() {
            peer.endpoint.is_shutdown()
        } else {
            true
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, ET: EndType, T> IOPollable
    for PipeEnd<Platform, ET, T>
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let rb = self.endpoint.rb.lock();
        let mut events = Events::empty();
        events.set(
            if ET::IS_READER_SIDE {
                Events::HUP
            } else {
                Events::ERR
            },
            self.is_peer_shutdown(),
        );
        if !self.is_shutdown() {
            events.set(Events::IN, !rb.is_empty() && ET::IS_READER_SIDE);
            events.set(Events::OUT, !rb.is_full() && !ET::IS_READER_SIDE);
        }
        events
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, ET: EndType, T> Drop
    for PipeEnd<Platform, ET, T>
{
    fn drop(&mut self) {
        self.shutdown();
        if let Some(peer) = self.peer.upgrade() {
            let notification_event = if ET::Peer::IS_READER_SIDE {
                // The reader end must be told that the writing peer closed its end.
                Events::HUP
            } else {
                // The writing end must be told that the read end has been closed.
                Events::ERR
            };
            peer.endpoint.pollee.notify_observers(notification_event);
        }
    }
}

pub type Writer<Platform, T> = Arc<PipeEnd<Platform, Write, T>>;
pub type Reader<Platform, T> = Arc<PipeEnd<Platform, Read, T>>;

/// Create a unidirectional communication channel that sending messages of (slices of) type `T`.
///
/// This function returns the sender and receiver halves.
///
/// `capacity` defines the maximum capacity of the channel, beyond which it will block or refuse to
/// write, depending on flags.
///
/// `flags` sets up the initial flags for the channel. An important flag is `OFlags::NONBLOCK` which
/// impacts what happens when the channel is full, and an attempt is made to write to it.
///
/// `atomic_slice_guarantee_size` (if provided) is the number of elements that are guaranteed to be
/// written atomically (i.e., not interleaved with other writes) if a slice of those many (or fewer)
/// elements are passed at once. Slices longer than this length have no guarantees on atomicity of
/// writes and might be interleaved with other writes.
pub fn new_pipe<Platform: RawSyncPrimitivesProvider + TimeProvider, T>(
    litebox: &LiteBox<Platform>,
    capacity: usize,
    flags: OFlags,
    atomic_slice_guarantee_size: Option<NonZeroUsize>,
) -> (Writer<Platform, T>, Reader<Platform, T>) {
    let rb: HeapRb<T> = HeapRb::new(capacity);
    let (rb_prod, rb_cons) = rb.split();

    // Create the producer and consumer, and set up cyclic references.
    let mut producer = Arc::new(PipeEnd::<_, Write, _>::new(
        litebox,
        rb_prod,
        flags,
        atomic_slice_guarantee_size
            .map(NonZeroUsize::get)
            .unwrap_or_default(),
    ));
    let consumer = Arc::new_cyclic(|weak_self| {
        #[expect(
            clippy::missing_panics_doc,
            reason = "Producer has no other references as it is just created. So we can safely get a mutable reference to it."
        )]
        {
            Arc::get_mut(&mut producer).unwrap().peer = weak_self.clone();
        }
        let mut consumer = PipeEnd::<_, Read, _>::new(litebox, rb_cons, flags);
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

        let (prod, cons) = super::new_pipe(&litebox, 2, crate::fs::OFlags::empty(), None);
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

        let (prod, cons) = super::new_pipe(&litebox, 2, crate::fs::OFlags::NONBLOCK, None);
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
