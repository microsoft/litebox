// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unidirectional communication channels

use core::{
    num::NonZeroUsize,
    sync::atomic::{
        AtomicBool, AtomicU32, AtomicUsize,
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
        wait::{WaitContext, WaitError},
    },
    fs::OFlags,
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};

/// Support for unidirectional communication channels
pub struct Pipes<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    litebox: LiteBox<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Clone for Pipes<Platform> {
    fn clone(&self) -> Self {
        Self {
            litebox: self.litebox.clone(),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Pipes<Platform> {
    /// Construct a new `Pipes` instance.
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `Pipes` handle is expected to be shared across all usage over the system.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            litebox: litebox.clone(),
        }
    }

    /// Create a unidirectional communication channel for sending messages of (slices of) bytes.
    ///
    /// This function returns the sender and receiver halves respectively.
    ///
    /// `capacity` defines the maximum capacity of the channel, beyond which it will block or refuse to
    /// write, depending on flags.
    ///
    /// `flags` sets up the initial flags for the channel.
    ///
    /// `atomic_slice_guarantee_size` (if provided) is the number of elements that are guaranteed to be
    /// written atomically (i.e., not interleaved with other writes) if a slice of those many (or fewer)
    /// elements are passed at once. Slices longer than this length have no guarantees on atomicity of
    /// writes and might be interleaved with other writes.
    pub fn create_pipe(
        &self,
        capacity: usize,
        flags: Flags,
        atomic_slice_guarantee_size: Option<NonZeroUsize>,
    ) -> (PipeFd<Platform>, PipeFd<Platform>) {
        let (sender, receiver) =
            new_pipe::<Platform, u8>(capacity, OFlags::from(flags), atomic_slice_guarantee_size);
        let sender = PipeEnd::Sender(sender);
        let receiver = PipeEnd::Receiver(receiver);
        let mut dt = self.litebox.descriptor_table_mut();
        let sender = dt.insert(sender);
        let receiver = dt.insert(receiver);
        (sender, receiver)
    }

    /// Close the pipe at `fd`.
    ///
    /// Future operations on the `fd` will start to return `ClosedFd` errors.
    pub fn close(&self, fd: &PipeFd<Platform>) -> Result<(), errors::CloseError> {
        self.litebox.descriptor_table_mut().remove(fd);
        // Shutdowns are taken care of automatically by the drop implementations
        Ok(())
    }

    /// Read values in the pipe into `buf`, returning the number of elements read.
    ///
    /// See [`Self::create_pipe`] for details on blocking behavior.
    ///
    /// Note: currently, this function returns `Ok(0)` if the peer end has been shut down, this may
    /// change in the future to an explicit "peer has shut down" error.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &mut [u8],
    ) -> Result<usize, errors::ReadError> {
        self.read_inner(cx, fd, buf, false)
    }

    /// Like [`read`](Self::read), but with vfork awareness.
    ///
    /// When `is_vfork_child` is true and a blocking read would deadlock
    /// (the only remaining write-end FD belongs to the blocked parent),
    /// returns `Ok(0)` (EOF) instead of blocking forever.
    pub fn read_vfork_aware(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &mut [u8],
        is_vfork_child: bool,
    ) -> Result<usize, errors::ReadError> {
        self.read_inner(cx, fd, buf, is_vfork_child)
    }

    fn read_inner(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &mut [u8],
        is_vfork_child: bool,
    ) -> Result<usize, errors::ReadError> {
        let dt = self.litebox.descriptor_table();
        let p = match &dt.get_entry(fd).ok_or(errors::ReadError::ClosedFd)?.entry {
            PipeEnd::Receiver(p) => Arc::clone(p),
            PipeEnd::Sender(_) => return Err(errors::ReadError::NotForReading),
        };
        drop(dt);
        if is_vfork_child {
            p.read_vfork_aware(cx, buf).map_err(From::from)
        } else {
            p.read(cx, buf).map_err(From::from)
        }
    }

    /// Write the values in `buf` into the pipe, returning the number of elements written.
    ///
    /// See [`Self::create_pipe`] for details on blocking and atomicity of writes.
    pub fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &[u8],
    ) -> Result<usize, errors::WriteError> {
        let dt = self.litebox.descriptor_table();
        let p = match &dt.get_entry(fd).ok_or(errors::WriteError::ClosedFd)?.entry {
            PipeEnd::Sender(p) => Arc::clone(p),
            PipeEnd::Receiver(_) => return Err(errors::WriteError::NotForWriting),
        };
        drop(dt);
        p.write(cx, buf).map_err(From::from)
    }

    /// Whether the provided FD points to a reader or a writer end.
    pub fn half_pipe_type(
        &self,
        fd: &PipeFd<Platform>,
    ) -> Result<HalfPipeType, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        match dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Sender(_) => Ok(HalfPipeType::SenderHalf),
            PipeEnd::Receiver(_) => Ok(HalfPipeType::ReceiverHalf),
        }
    }

    /// Get the flags set on the pipe at `fd`.
    pub fn get_flags(&self, fd: &PipeFd<Platform>) -> Result<Flags, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        let oflags = match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Receiver(p) => p.get_status(),
            PipeEnd::Sender(p) => p.get_status(),
        };
        Ok(Flags::from_oflags_truncate(oflags))
    }

    /// Update the flags set on the pipe at `fd`.
    ///
    /// Specifically, sets the bits in the `mask` to `on`, leaving the others unchanged.
    pub fn update_flags(
        &self,
        fd: &PipeFd<Platform>,
        mask: Flags,
        on: bool,
    ) -> Result<(), errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Receiver(p) => p.set_status(OFlags::from(mask), on),
            PipeEnd::Sender(p) => p.set_status(OFlags::from(mask), on),
        }
        Ok(())
    }

    /// Perform `f` with the [`IOPollable`] associated with the pipe at `fd`.
    pub fn with_iopollable<R>(
        &self,
        fd: &PipeFd<Platform>,
        f: impl FnOnce(&dyn IOPollable) -> R,
    ) -> Result<R, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Receiver(p) => Ok(f(p)),
            PipeEnd::Sender(p) => Ok(f(p)),
        }
    }

    /// Return the number of bytes available for reading on a pipe receiver.
    /// Returns 0 for sender ends.
    pub fn readable_bytes(&self, fd: &PipeFd<Platform>) -> Result<usize, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Receiver(p) => Ok(p.endpoint.rb.lock().occupied_len()),
            PipeEnd::Sender(_) => Ok(0),
        }
    }

    /// Return the number of bytes that can still be written without blocking.
    pub fn writable_bytes(&self, fd: &PipeFd<Platform>) -> Result<usize, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Receiver(_) => Ok(0),
            PipeEnd::Sender(p) => {
                let rb = p.endpoint.rb.lock();
                Ok(rb.vacant_len())
            }
        }
    }

    /// Return an opaque identifier for the pipe pair that this FD belongs to.
    ///
    /// Both the read and write endpoints of the same pipe return the same ID.
    /// This can be used to match counterpart endpoints across cloned FD tables
    /// (e.g. after fork).
    pub fn pipe_pair_id(&self, fd: &PipeFd<Platform>) -> Result<usize, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Sender(w) => Ok(Arc::as_ptr(w) as usize),
            PipeEnd::Receiver(r) => {
                // Use the write end pointer as the canonical identity.
                // If the write end has been dropped, fall back to the read
                // end pointer (the pipe is broken anyway).
                match r.peer.upgrade() {
                    Some(w) => Ok(Arc::as_ptr(&w) as usize),
                    None => Ok(Arc::as_ptr(r) as usize),
                }
            }
        }
    }
}

/// Whether a particular pipe end is the sender half or the receiver half
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalfPipeType {
    SenderHalf,
    ReceiverHalf,
}

enum PipeEnd<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Receiver(Arc<ReadEnd<Platform, u8>>),
    Sender(Arc<WriteEnd<Platform, u8>>),
}

bitflags::bitflags! {
    /// Flags for controlling the pipe behaviors.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct Flags: u32 {
        /// `NON_BLOCKING` impacts what happens when a full channel is written, or an empty channel
        /// is read from. If set, the operations returns immediately with a `WouldBlock` error.
        const NON_BLOCKING = 0x1;
    }
}

impl Flags {
    fn from_oflags_truncate(oflags: OFlags) -> Self {
        let mut flags = Flags::empty();
        flags.set(Flags::NON_BLOCKING, oflags.contains(OFlags::NONBLOCK));
        flags
    }
}
impl From<Flags> for OFlags {
    fn from(flags: Flags) -> Self {
        let mut oflags = OFlags::empty();
        oflags.set(OFlags::NONBLOCK, flags.contains(Flags::NON_BLOCKING));
        oflags
    }
}

pub mod errors {
    use crate::event::wait::WaitError;

    #[expect(
        unused_imports,
        reason = "used for doc string links to work out, but not for code"
    )]
    use super::Pipes;

    use thiserror::Error;

    /// Possible errors from [`Pipes::close`]
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum CloseError {}

    /// Possible errors from [`Pipes::read`]
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum ReadError {
        #[error("not an open file descriptor")]
        ClosedFd,
        #[error("not open for reading")]
        NotForReading,
        #[error("read would block")]
        WouldBlock,
        #[error("wait error")]
        WaitError(WaitError),
        #[error("would deadlock: the only writer is the suspended vfork parent")]
        Deadlock,
    }

    /// Possible errors from [`Pipes::write`]
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum WriteError {
        #[error("not an open file descriptor")]
        ClosedFd,
        #[error("the reading end of this pipe is closed")]
        ReadEndClosed,
        #[error("not open for writing")]
        NotForWriting,
        #[error("write would block")]
        WouldBlock,
        #[error("wait error")]
        WaitError(WaitError),
    }

    /// Possible errors from functions that always succeed unless the descriptor is closed.
    #[derive(Error, Debug)]
    pub enum ClosedError {
        #[error("not an open file descriptor")]
        ClosedFd,
    }
}

struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    rb: Mutex<Platform, T>,
    pollee: Pollee<Platform>,
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> EndPointer<Platform, T> {
    fn new(rb: T) -> Self {
        Self {
            rb: Mutex::new(rb),
            pollee: Pollee::new(),
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
        /// Get the status flags for this channel
        fn get_status(&self) -> OFlags {
            OFlags::from_bits(self.status.load(Relaxed)).unwrap() & OFlags::STATUS_FLAGS_MASK
        }

        /// Update the status flags for `mask` to `on`.
        fn set_status(&self, mask: OFlags, on: bool) {
            if on {
                self.status.fetch_or(mask.bits(), Relaxed);
            } else {
                self.status.fetch_and(mask.complement().bits(), Relaxed);
            }
        }

        /// Has this been shut down?
        fn is_shutdown(&self) -> bool {
            self.endpoint.is_shutdown()
        }

        /// Shut this channel down.
        fn shutdown(&self) {
            self.endpoint.shutdown();
        }

        /// Has the peer (i.e., other end) been shut down?
        fn is_peer_shutdown(&self) -> bool {
            if let Some(peer) = self.peer.upgrade() {
                peer.endpoint.is_shutdown()
            } else {
                true
            }
        }
    };
}

/// The "writer" (aka producer or transmit) side of a pipe
struct WriteEnd<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    endpoint: EndPointer<Platform, HeapProd<T>>,
    peer: Weak<ReadEnd<Platform, T>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    /// Slice length that is guaranteed to be an atomic write (i.e., non-interleaved).
    atomic_slice_guarantee_size: usize,
    /// Number of open file descriptors referencing this write end.
    /// Starts at 1 when created, incremented by fork, decremented by close.
    /// When this reaches 0, the write end is shut down and the read peer
    /// receives HUP — even if the Arc<WriteEnd> itself hasn't been dropped yet.
    fd_ref_count: AtomicUsize,
}

/// Potential errors when writing or reading from a pipe
#[derive(Error, Debug)]
#[non_exhaustive]
enum PipeError {
    #[error("this end has been shut down")]
    ThisEndShutdown,
    #[error("peer has been shut down")]
    PeerShutdown,
    #[error("this operation would block")]
    WouldBlock,
    #[error("wait error")]
    WaitError(WaitError),
    #[error("would deadlock: the only writer is the suspended vfork parent")]
    Deadlock,
}

impl From<PipeError> for errors::ReadError {
    fn from(err: PipeError) -> Self {
        match err {
            PipeError::ThisEndShutdown => errors::ReadError::ClosedFd,
            PipeError::PeerShutdown => {
                unreachable!("unreachable for now; see documentation of `read`")
            }
            PipeError::WouldBlock => errors::ReadError::WouldBlock,
            PipeError::WaitError(e) => errors::ReadError::WaitError(e),
            PipeError::Deadlock => errors::ReadError::Deadlock,
        }
    }
}
impl From<PipeError> for errors::WriteError {
    fn from(err: PipeError) -> Self {
        match err {
            PipeError::ThisEndShutdown => errors::WriteError::ClosedFd,
            PipeError::PeerShutdown => errors::WriteError::ReadEndClosed,
            PipeError::WouldBlock => errors::WriteError::WouldBlock,
            PipeError::WaitError(e) => errors::WriteError::WaitError(e),
            PipeError::Deadlock => unreachable!("deadlock detection is read-side only"),
        }
    }
}

impl From<TryOpError<PipeError>> for PipeError {
    fn from(err: TryOpError<PipeError>) -> Self {
        match err {
            TryOpError::TryAgain => PipeError::WouldBlock,
            TryOpError::WaitError(e) => PipeError::WaitError(e),
            TryOpError::Other(e) => e,
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> WriteEnd<Platform, T> {
    fn new(rb: HeapProd<T>, flags: OFlags, atomic_slice_guarantee_size: usize) -> Self {
        Self {
            endpoint: EndPointer::new(rb),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::WRONLY).bits()),
            atomic_slice_guarantee_size,
            fd_ref_count: AtomicUsize::new(1),
        }
    }

    fn try_write(&self, buf: &[T]) -> Result<usize, TryOpError<PipeError>>
    where
        T: Copy,
    {
        if self.is_shutdown() {
            return Err(TryOpError::Other(PipeError::ThisEndShutdown));
        }
        if self.is_peer_shutdown() {
            return Err(TryOpError::Other(PipeError::PeerShutdown));
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let write_len = {
            let mut rb = self.endpoint.rb.lock();
            let total_size = buf.len();
            if rb.vacant_len() < total_size && total_size <= self.atomic_slice_guarantee_size {
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
    fn write(&self, cx: &WaitContext<'_, Platform>, buf: &[T]) -> Result<usize, PipeError>
    where
        T: Copy,
    {
        self.endpoint
            .pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::OUT,
                || self.try_write(buf),
            )
            .map_err(PipeError::from)
    }

    common_functions_for_channel!();
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> IOPollable for WriteEnd<Platform, T> {
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> Drop for WriteEnd<Platform, T> {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(peer) = self.peer.upgrade() {
            // when reading from a channel such as a pipe or a stream socket, this event
            // merely indicates that the peer closed its end of the channel.
            peer.endpoint.pollee.notify_observers(Events::HUP);
        }
    }
}

/// The "reader" (aka consumer or receive) side of a pipe
struct ReadEnd<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    endpoint: EndPointer<Platform, HeapCons<T>>,
    peer: Weak<WriteEnd<Platform, T>>,
    status: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> IOPollable for ReadEnd<Platform, T> {
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> ReadEnd<Platform, T> {
    fn new(rb: HeapCons<T>, flags: OFlags) -> Self {
        Self {
            endpoint: EndPointer::new(rb),
            peer: Weak::new(),
            status: AtomicU32::new((flags | OFlags::RDONLY).bits()),
        }
    }

    fn try_read(&self, buf: &mut [T]) -> Result<usize, TryOpError<PipeError>>
    where
        T: Copy,
    {
        if self.is_shutdown() {
            return Err(TryOpError::Other(PipeError::ThisEndShutdown));
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
    fn read(&self, cx: &WaitContext<'_, Platform>, buf: &mut [T]) -> Result<usize, PipeError>
    where
        T: Copy,
    {
        self.endpoint
            .pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::IN,
                || self.try_read(buf),
            )
            .map_err(PipeError::from)
    }

    /// Read with vfork deadlock avoidance.
    ///
    /// When the pipe buffer is empty and the only remaining write-end FD
    /// belongs to a vfork-blocked parent, a normal blocking read would
    /// deadlock (parent waits for child, child waits for pipe data that
    /// only the parent could produce by closing its end). In this case,
    /// return `Ok(0)` (EOF) instead of blocking.
    fn read_vfork_aware(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [T],
    ) -> Result<usize, PipeError>
    where
        T: Copy,
    {
        match self.try_read(buf) {
            Ok(n) => return Ok(n),
            Err(TryOpError::TryAgain) => {}
            Err(e) => return Err(PipeError::from(e)),
        }

        // The pipe buffer is empty and the write-end is not shut down.
        // fd_ref_count tracks the number of open FDs for the write-end
        // (incremented on dup/fork, decremented on close). After the vfork
        // child closes its write-end copy, if fd_ref_count == 1, the sole
        // remaining writer is the blocked parent — a blocking read would
        // deadlock. Return EDEADLK so the caller fails loudly instead of
        // silently receiving a fake EOF.
        if self
            .peer
            .upgrade()
            .is_some_and(|p| p.fd_ref_count.load(Ordering::Acquire) <= 1)
        {
            return Err(PipeError::Deadlock);
        }

        // Standard blocking path.
        self.endpoint
            .pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::IN,
                || self.try_read(buf),
            )
            .map_err(PipeError::from)
    }

    common_functions_for_channel!();
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> Drop for ReadEnd<Platform, T> {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(peer) = self.peer.upgrade() {
            // This bit is also set for a file descriptor referring to the write end
            // of a pipe when the read end has been closed.
            peer.endpoint.pollee.notify_observers(Events::ERR);
        }
    }
}

/// Create a unidirectional communication channel for sending messages of (slices of) type `T`.
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
#[expect(
    clippy::type_complexity,
    reason = "clippy believes this result type to be complex, but factoring it out into a type def would not help readability in any way"
)]
fn new_pipe<Platform: RawSyncPrimitivesProvider + TimeProvider, T>(
    capacity: usize,
    flags: OFlags,
    atomic_slice_guarantee_size: Option<NonZeroUsize>,
) -> (Arc<WriteEnd<Platform, T>>, Arc<ReadEnd<Platform, T>>) {
    let rb: HeapRb<T> = HeapRb::new(capacity);
    let (rb_prod, rb_cons) = rb.split();

    // Create the producer and consumer, and set up cyclic references.
    let mut producer = Arc::new(WriteEnd::new(
        rb_prod,
        flags,
        atomic_slice_guarantee_size
            .map(NonZeroUsize::get)
            .unwrap_or_default(),
    ));
    let consumer = Arc::new_cyclic(|weak_self| {
        Arc::get_mut(&mut producer).unwrap().peer = weak_self.clone();
        let mut consumer = ReadEnd::new(rb_cons, flags);
        consumer.peer = Arc::downgrade(&producer);
        consumer
    });

    (producer, consumer)
}

// Manual implementation of FD subsystem integration for pipes.
// We can't use the `enable_fds_for_subsystem!` macro here because we need
// to override `on_dup()` and `on_close()` to properly track pipe writer
// file descriptor counts across dup/fork.
#[allow(unused, reason = "NOTE(jayb): remove this lint before merging the PR")]
#[doc(hidden)]
pub struct DescriptorEntry<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    entry: PipeEnd<Platform>,
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> crate::fd::FdEnabledSubsystem
    for Pipes<Platform>
{
    type Entry = DescriptorEntry<Platform>;
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> crate::fd::FdEnabledSubsystemEntry
    for DescriptorEntry<Platform>
{
    fn on_dup(&self) {
        if let PipeEnd::Sender(w) = &self.entry {
            w.fd_ref_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_close(&self) {
        if let PipeEnd::Sender(w) = &self.entry {
            w.fd_ref_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> From<PipeEnd<Platform>>
    for DescriptorEntry<Platform>
{
    fn from(entry: PipeEnd<Platform>) -> Self {
        Self { entry }
    }
}
pub type PipeFd<Platform> = crate::fd::TypedFd<Pipes<Platform>>;

#[cfg(test)]
mod tests {
    use crate::{
        event::wait::WaitState,
        pipes::errors::{ReadError, WriteError},
    };

    extern crate std;

    #[test]
    fn test_blocking_channel() {
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = &crate::LiteBox::new(platform);
        let pipes = &super::Pipes::new(litebox);

        let (prod, cons) = pipes.create_pipe(2, super::Flags::empty(), None);

        std::thread::scope(|scope| {
            scope.spawn(move || {
                let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
                let mut i = 0;
                while i < data.len() {
                    let ret = pipes
                        .write(&WaitState::new(platform).context(), &prod, &data[i..])
                        .unwrap();
                    i += ret;
                }
                pipes.close(&prod).unwrap();
                assert_eq!(i, data.len());
            });

            let mut buf = [0; 10];
            let mut i = 0;
            loop {
                let ret = pipes
                    .read(&WaitState::new(platform).context(), &cons, &mut buf[i..])
                    .unwrap();
                if ret == 0 {
                    pipes.close(&cons).unwrap();
                    break;
                }
                i += ret;
            }
            assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        });
    }

    #[test]
    fn test_nonblocking_channel() {
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = &crate::LiteBox::new(platform);
        let pipes = &super::Pipes::new(litebox);

        let (prod, cons) = pipes.create_pipe(2, super::Flags::NON_BLOCKING, None);

        std::thread::scope(|scope| {
            scope.spawn(move || {
                let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
                let mut i = 0;
                while i < data.len() {
                    match pipes.write(&WaitState::new(platform).context(), &prod, &data[i..]) {
                        Ok(n) => {
                            i += n;
                        }
                        Err(WriteError::WouldBlock) => {
                            // busy wait
                            // TODO: use poll rather than busy wait
                        }
                        Err(e) => {
                            panic!("Error writing to channel: {:?}", e);
                        }
                    }
                }
                pipes.close(&prod).unwrap();
                assert_eq!(i, data.len());
            });

            let mut buf = [0; 10];
            let mut i = 0;
            loop {
                match pipes.read(&WaitState::new(platform).context(), &cons, &mut buf[i..]) {
                    Ok(n) => {
                        if n == 0 {
                            break;
                        }
                        i += n;
                    }
                    Err(ReadError::WouldBlock) => {
                        // busy wait
                        // TODO: use poll rather than busy wait
                    }
                    Err(e) => {
                        panic!("Error reading from channel: {:?}", e);
                    }
                }
            }
            pipes.close(&cons).unwrap();
            assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        });
    }
}
