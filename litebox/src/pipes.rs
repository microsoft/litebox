// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unidirectional communication channels

use core::{
    num::NonZeroUsize,
    sync::atomic::{
        AtomicBool, AtomicU32,
        Ordering::{self, Relaxed},
    },
};

use alloc::sync::{Arc, Weak};
use either::Either;
use litebox_broker_protocol::{
    ObjectHandle, pipe::MAX_PIPE_TRANSFER_SIZE, readiness::ReadinessFlags,
};
use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Observer as _, Producer as _, Split as _},
};
use thiserror::Error;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry,
        error::{BrokerControlError, BrokerObjectError},
        readiness_events,
    },
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
    ) -> Result<(PipeFd<Platform>, PipeFd<Platform>), errors::CreateError> {
        let (sender, receiver) = if let Some(broker) = self.litebox.broker_control() {
            let (sender, receiver) = new_broker_pipe(
                broker,
                self.litebox.broker_pollable_registry(),
                capacity,
                OFlags::from(flags),
                atomic_slice_guarantee_size,
            )?;
            (
                PipeEnd::BrokerSender(sender),
                PipeEnd::BrokerReceiver(receiver),
            )
        } else {
            let (sender, receiver) = new_pipe::<Platform, u8>(
                capacity,
                OFlags::from(flags),
                atomic_slice_guarantee_size,
            );
            (PipeEnd::Sender(sender), PipeEnd::Receiver(receiver))
        };
        let mut dt = self.litebox.descriptor_table_mut();
        let sender = dt.insert(sender);
        let receiver = dt.insert(receiver);
        Ok((sender, receiver))
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
        let dt = self.litebox.descriptor_table();
        let p = match &dt.get_entry(fd).ok_or(errors::ReadError::ClosedFd)?.entry {
            PipeEnd::Receiver(p) => Either::Left(Arc::clone(p)),
            PipeEnd::BrokerReceiver(p) => Either::Right(Arc::clone(p)),
            PipeEnd::Sender(_) | PipeEnd::BrokerSender(_) => {
                return Err(errors::ReadError::NotForReading);
            }
        };
        drop(dt);
        match p {
            Either::Left(p) => p.read(cx, buf).map_err(From::from),
            Either::Right(p) => p.read(cx, buf).map_err(From::from),
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
            PipeEnd::Sender(p) => Either::Left(Arc::clone(p)),
            PipeEnd::BrokerSender(p) => Either::Right(Arc::clone(p)),
            PipeEnd::Receiver(_) | PipeEnd::BrokerReceiver(_) => {
                return Err(errors::WriteError::NotForWriting);
            }
        };
        drop(dt);
        match p {
            Either::Left(p) => p.write(cx, buf).map_err(From::from),
            Either::Right(p) => p.write(cx, buf).map_err(From::from),
        }
    }

    /// Whether the provided FD points to a reader or a writer end.
    pub fn half_pipe_type(
        &self,
        fd: &PipeFd<Platform>,
    ) -> Result<HalfPipeType, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        match dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Sender(_) | PipeEnd::BrokerSender(_) => Ok(HalfPipeType::SenderHalf),
            PipeEnd::Receiver(_) | PipeEnd::BrokerReceiver(_) => Ok(HalfPipeType::ReceiverHalf),
        }
    }

    /// Get the flags set on the pipe at `fd`.
    pub fn get_flags(&self, fd: &PipeFd<Platform>) -> Result<Flags, errors::ClosedError> {
        let dt = self.litebox.descriptor_table();
        let oflags = match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
            PipeEnd::Receiver(p) => p.get_status(),
            PipeEnd::Sender(p) => p.get_status(),
            PipeEnd::BrokerReceiver(p) | PipeEnd::BrokerSender(p) => p.get_status(),
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
            PipeEnd::BrokerReceiver(p) | PipeEnd::BrokerSender(p) => {
                p.set_status(OFlags::from(mask), on);
            }
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
            PipeEnd::BrokerReceiver(p) | PipeEnd::BrokerSender(p) => Ok(f(p)),
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
    BrokerReceiver(Arc<BrokerPipeEnd<Platform>>),
    BrokerSender(Arc<BrokerPipeEnd<Platform>>),
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

    /// Possible errors from [`Pipes::create_pipe`].
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum CreateError {
        #[error("pipe resource exhausted")]
        ResourceExhausted,
        #[error("pipe memory allocation failed")]
        OutOfMemory,
        #[error("pipe permission denied")]
        PermissionDenied,
        #[error("pipe broker I/O failed")]
        Io,
    }

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
        #[error("pipe I/O failed")]
        Io,
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
        #[error("pipe I/O failed")]
        Io,
    }

    /// Possible errors from functions that always succeed unless the descriptor is closed.
    #[derive(Error, Debug)]
    pub enum ClosedError {
        #[error("not an open file descriptor")]
        ClosedFd,
    }
}

struct BrokerPipeEnd<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
    peer: Weak<Self>,
    endpoint_type: HalfPipeType,
    status: AtomicU32,
}

#[expect(
    clippy::type_complexity,
    reason = "a type alias would not make the two pipe endpoint result clearer"
)]
fn new_broker_pipe<Platform: RawSyncPrimitivesProvider + TimeProvider>(
    broker: Arc<dyn BrokerControl>,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    capacity: usize,
    flags: OFlags,
    atomic_slice_guarantee_size: Option<NonZeroUsize>,
) -> Result<(Arc<BrokerPipeEnd<Platform>>, Arc<BrokerPipeEnd<Platform>>), errors::CreateError> {
    let atomic_write_size = atomic_slice_guarantee_size
        .map(NonZeroUsize::get)
        .unwrap_or_default();
    if atomic_write_size > MAX_PIPE_TRANSFER_SIZE as usize {
        return Err(errors::CreateError::ResourceExhausted);
    }
    let response = broker
        .create_pipe(
            capacity
                .try_into()
                .map_err(|_| errors::CreateError::ResourceExhausted)?,
            atomic_write_size
                .try_into()
                .map_err(|_| errors::CreateError::ResourceExhausted)?,
        )
        .map_err(BrokerObjectError::from)
        .map_err(errors::CreateError::from)?;

    let mut writer = Arc::new(BrokerPipeEnd {
        broker: Arc::clone(&broker),
        handle: response.write_handle,
        pollable_registry: Arc::clone(&pollable_registry),
        pollee: Arc::new(Pollee::new()),
        peer: Weak::new(),
        endpoint_type: HalfPipeType::SenderHalf,
        status: AtomicU32::new((flags | OFlags::WRONLY).bits()),
    });
    let reader = Arc::new_cyclic(|weak_reader| {
        Arc::get_mut(&mut writer)
            .expect("new pipe writer must be uniquely owned")
            .peer = weak_reader.clone();
        BrokerPipeEnd {
            broker,
            handle: response.read_handle,
            pollable_registry: Arc::clone(&pollable_registry),
            pollee: Arc::new(Pollee::new()),
            peer: Arc::downgrade(&writer),
            endpoint_type: HalfPipeType::ReceiverHalf,
            status: AtomicU32::new((flags | OFlags::RDONLY).bits()),
        }
    });

    pollable_registry.register_pollable(response.write_handle, &writer.pollee);
    pollable_registry.register_pollable(response.read_handle, &reader.pollee);
    Ok((writer, reader))
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> BrokerPipeEnd<Platform> {
    fn get_status(&self) -> OFlags {
        OFlags::from_bits(self.status.load(Relaxed)).unwrap() & OFlags::STATUS_FLAGS_MASK
    }

    fn set_status(&self, mask: OFlags, on: bool) {
        if on {
            self.status.fetch_or(mask.bits(), Relaxed);
        } else {
            self.status.fetch_and(mask.complement().bits(), Relaxed);
        }
    }

    fn read(&self, cx: &WaitContext<'_, Platform>, buf: &mut [u8]) -> Result<usize, PipeError> {
        let length = buf.len().min(MAX_PIPE_TRANSFER_SIZE as usize);
        if length == 0 {
            return Ok(0);
        }
        let request_length = length
            .try_into()
            .expect("pipe transfer limit must fit in u32");

        self.pollee
            .wait(
                cx,
                self.get_status().contains(OFlags::NONBLOCK),
                Events::IN,
                || {
                    let data = self
                        .broker
                        .read_pipe(self.handle, request_length)
                        .map_err(|error| self.broker_request_error(error))?;
                    if data.len() > length {
                        return Err(TryOpError::Other(PipeError::Io));
                    }
                    buf[..data.len()].copy_from_slice(&data);
                    if !data.is_empty()
                        && let Some(peer) = self.peer.upgrade()
                    {
                        peer.pollee.notify_observers(Events::OUT);
                    }
                    Ok(data.len())
                },
            )
            .map_err(PipeError::from)
    }

    fn write(&self, cx: &WaitContext<'_, Platform>, buf: &[u8]) -> Result<usize, PipeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let nonblock = self.get_status().contains(OFlags::NONBLOCK);
        if nonblock {
            let data = &buf[..buf.len().min(MAX_PIPE_TRANSFER_SIZE as usize)];
            return self
                .pollee
                .wait(cx, nonblock, Events::OUT, || self.try_write(data))
                .map_err(PipeError::from);
        }

        let mut total_written = 0;
        while total_written < buf.len() {
            let end = total_written
                .saturating_add(MAX_PIPE_TRANSFER_SIZE as usize)
                .min(buf.len());
            let data = &buf[total_written..end];
            match self
                .pollee
                .wait(cx, false, Events::OUT, || self.try_write(data))
            {
                Ok(written) => total_written += written,
                Err(_) if total_written != 0 => return Ok(total_written),
                Err(error) => return Err(PipeError::from(error)),
            }
        }
        Ok(total_written)
    }

    fn try_write(&self, data: &[u8]) -> Result<usize, TryOpError<PipeError>> {
        let written = self
            .broker
            .write_pipe(self.handle, data)
            .map_err(|error| self.broker_request_error(error))?;
        if written > data.len() || (written == 0 && !data.is_empty()) {
            return Err(TryOpError::Other(PipeError::Io));
        }
        if written != 0
            && let Some(peer) = self.peer.upgrade()
        {
            peer.pollee.notify_observers(Events::IN);
        }
        Ok(written)
    }

    fn broker_request_error(&self, error: BrokerControlError) -> BrokerObjectError {
        let error = error.into();
        if error != BrokerObjectError::WouldBlock {
            self.pollee.notify_observers(Events::ERR);
        }
        error
    }

    fn readiness(&self) -> Result<ReadinessFlags, BrokerControlError> {
        self.broker.check_readiness(self.handle)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for BrokerPipeEnd<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        match self.readiness() {
            Ok(readiness) => readiness_events(readiness),
            Err(_) => Events::ERR,
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for BrokerPipeEnd<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
        if let Some(peer) = self.peer.upgrade() {
            let event = match self.endpoint_type {
                HalfPipeType::SenderHalf => Events::HUP,
                HalfPipeType::ReceiverHalf => Events::ERR,
            };
            peer.pollee.notify_observers(event);
        }
    }
}

impl From<BrokerObjectError> for TryOpError<PipeError> {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => TryOpError::TryAgain,
            BrokerObjectError::PeerClosed => TryOpError::Other(PipeError::PeerShutdown),
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::ResourceExhausted
            | BrokerObjectError::PermissionDenied
            | BrokerObjectError::OutOfMemory => TryOpError::Other(PipeError::Io),
        }
    }
}

impl From<BrokerObjectError> for errors::CreateError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::ResourceExhausted => Self::ResourceExhausted,
            BrokerObjectError::OutOfMemory => Self::OutOfMemory,
            BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::WouldBlock
            | BrokerObjectError::PeerClosed => Self::Io,
        }
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
}

/// Potential errors when writing or reading from a pipe
#[derive(Error, Debug)]
enum PipeError {
    #[error("this end has been shut down")]
    ThisEndShutdown,
    #[error("peer has been shut down")]
    PeerShutdown,
    #[error("this operation would block")]
    WouldBlock,
    #[error("wait error")]
    WaitError(WaitError),
    #[error("pipe I/O failed")]
    Io,
}

impl From<PipeError> for errors::ReadError {
    fn from(err: PipeError) -> Self {
        match err {
            PipeError::ThisEndShutdown => errors::ReadError::ClosedFd,
            PipeError::PeerShutdown | PipeError::Io => errors::ReadError::Io,
            PipeError::WouldBlock => errors::ReadError::WouldBlock,
            PipeError::WaitError(e) => errors::ReadError::WaitError(e),
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
            PipeError::Io => errors::WriteError::Io,
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
        }
    }

    fn try_write(&self, buf: &[T]) -> Result<usize, TryOpError<PipeError>>
    where
        T: Copy,
    {
        if self.is_shutdown() {
            return Err(TryOpError::Other(PipeError::ThisEndShutdown));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.is_peer_shutdown() {
            return Err(TryOpError::Other(PipeError::PeerShutdown));
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
        if self.get_status().contains(OFlags::NONBLOCK) {
            return self
                .endpoint
                .pollee
                .wait(cx, true, Events::OUT, || self.try_write(buf))
                .map_err(PipeError::from);
        }

        let mut total_written = 0;
        while total_written < buf.len() {
            match self.endpoint.pollee.wait(cx, false, Events::OUT, || {
                self.try_write(&buf[total_written..])
            }) {
                Ok(written) => total_written += written,
                Err(_) if total_written != 0 => return Ok(total_written),
                Err(error) => return Err(PipeError::from(error)),
            }
        }
        Ok(total_written)
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

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use alloc::sync::Arc;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::channel::LocalControlChannel;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
        BrokerResponse, PipeRequest, ReadinessNotification,
    };
    use litebox_broker_protocol::pipe::CreatePipeResponse;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle};

    use crate::{
        event::{Events, observer::Observer, wait::WaitState},
        pipes::errors::{ReadError, WriteError},
    };

    extern crate std;

    #[test]
    fn broker_control_failure_notifies_all_pipe_observers() {
        let platform = crate::platform::mock::MockPlatform::new();
        let request_count = Arc::new(AtomicUsize::new(0));
        let force_transport = Arc::new(AtomicBool::new(false));
        let local = BrokerLocal::negotiate(
            FailingPipeChannel {
                last_request: None,
                request_count: Arc::clone(&request_count),
                read_failure: ReadFailure::Transport,
                force_transport,
            },
            |_| Ok(Arc::new(NoopSharedMemory)),
        )
        .unwrap();
        let litebox = crate::LiteBox::new_with_broker_local(platform, local);
        let pipes = super::Pipes::new(&litebox);
        let (writer, reader) = pipes.create_pipe(2, super::Flags::empty(), None).unwrap();
        let writer_observer = Arc::new(ErrorObserver(AtomicBool::new(false)));
        let writer_observer_dyn: Arc<dyn Observer<Events>> = writer_observer.clone();
        pipes
            .with_iopollable(&writer, |pollable| {
                pollable.register_observer(Arc::downgrade(&writer_observer_dyn), Events::ERR);
            })
            .unwrap();
        let reader_observer = Arc::new(ErrorObserver(AtomicBool::new(false)));
        let reader_observer_dyn: Arc<dyn Observer<Events>> = reader_observer.clone();
        pipes
            .with_iopollable(&reader, |pollable| {
                pollable.register_observer(Arc::downgrade(&reader_observer_dyn), Events::ERR);
            })
            .unwrap();

        let mut value = 0;
        assert!(matches!(
            pipes.read(
                &WaitState::new(platform).context(),
                &reader,
                core::slice::from_mut(&mut value),
            ),
            Err(ReadError::Io)
        ));
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        assert!(writer_observer.0.load(Ordering::SeqCst));
        assert!(reader_observer.0.load(Ordering::SeqCst));
    }

    #[test]
    fn broker_failure_wakes_blocked_pipe_read() {
        let platform = crate::platform::mock::MockPlatform::new();
        let request_count = Arc::new(AtomicUsize::new(0));
        let force_transport = Arc::new(AtomicBool::new(false));
        let local = BrokerLocal::negotiate(
            FailingPipeChannel {
                last_request: None,
                request_count: Arc::clone(&request_count),
                read_failure: ReadFailure::WouldBlock,
                force_transport: Arc::clone(&force_transport),
            },
            |_| Ok(Arc::new(NoopSharedMemory)),
        )
        .unwrap();
        let litebox = Arc::new(crate::LiteBox::new_with_broker_local(platform, local));
        let pipes = super::Pipes::new(&litebox);
        let (writer, reader) = pipes.create_pipe(2, super::Flags::empty(), None).unwrap();

        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let read_litebox = Arc::clone(&litebox);
        let read_thread = std::thread::spawn(move || {
            let pipes = super::Pipes::new(&read_litebox);
            let mut value = 0;
            result_sender
                .send(pipes.read(
                    &WaitState::new(platform).context(),
                    &reader,
                    core::slice::from_mut(&mut value),
                ))
                .unwrap();
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut setup_completed = true;
        while request_count.load(Ordering::SeqCst) < 3 {
            if std::time::Instant::now() >= deadline {
                setup_completed = false;
                force_transport.store(true, Ordering::SeqCst);
                let _ = pipes.close(&writer);
                break;
            }
            std::thread::yield_now();
        }

        if setup_completed {
            litebox.dispatch_broker_notification(BrokerNotification::Readiness(
                ReadinessNotification {
                    handle: ObjectHandle(1),
                    readiness: ReadinessFlags::READ,
                },
            ));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while request_count.load(Ordering::SeqCst) < 4 {
                if std::time::Instant::now() >= deadline {
                    setup_completed = false;
                    force_transport.store(true, Ordering::SeqCst);
                    let _ = pipes.close(&writer);
                    break;
                }
                std::thread::yield_now();
            }
        }

        if setup_completed {
            litebox.broker_failure_dispatcher()();
        }

        let initial_read_result = result_receiver.recv_timeout(std::time::Duration::from_secs(1));
        let woke_without_cleanup = initial_read_result.is_ok();
        let mut read_result = initial_read_result.ok();
        if read_result.is_none() {
            force_transport.store(true, Ordering::SeqCst);
            let _ = pipes.close(&writer);
            read_result = result_receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .ok();
        }
        if read_result.is_some() {
            read_thread.join().unwrap();
        } else {
            std::process::abort();
        }

        assert!(setup_completed);
        assert!(woke_without_cleanup);
        assert!(matches!(read_result, Some(Err(ReadError::Io))));
        assert_eq!(request_count.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn local_zero_length_write_succeeds_after_reader_closes() {
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = crate::LiteBox::new(platform);
        let pipes = super::Pipes::new(&litebox);
        let (writer, reader) = pipes.create_pipe(2, super::Flags::empty(), None).unwrap();

        pipes.close(&reader).unwrap();

        assert_eq!(
            pipes
                .write(&WaitState::new(platform).context(), &writer, &[])
                .unwrap(),
            0
        );
        pipes.close(&writer).unwrap();
    }

    struct ErrorObserver(AtomicBool);

    impl Observer<Events> for ErrorObserver {
        fn on_events(&self, events: &Events) {
            if events.contains(Events::ERR) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
    }

    #[derive(Debug)]
    struct FailingPipeChannel {
        last_request: Option<BrokerRequest>,
        request_count: Arc<AtomicUsize>,
        read_failure: ReadFailure,
        force_transport: Arc<AtomicBool>,
    }

    #[derive(Clone, Copy)]
    struct NoopSharedMemory;

    impl litebox_broker_protocol::shared_memory::SharedMemory for NoopSharedMemory {
        fn len(&self) -> usize {
            litebox_broker_protocol::pipe::PIPE_TRANSFER_BUFFER_SIZE
        }

        fn read(
            &self,
            _offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), litebox_broker_protocol::shared_memory::SharedMemoryError>
        {
            destination.fill(0);
            Ok(())
        }

        fn write(
            &self,
            _offset: usize,
            _source: &[u8],
        ) -> core::result::Result<(), litebox_broker_protocol::shared_memory::SharedMemoryError>
        {
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ReadFailure {
        Transport,
        WouldBlock,
    }

    impl LocalControlChannel for FailingPipeChannel {
        type Error = ();

        fn send_handshake_request(
            &mut self,
            _request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
        }

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.last_request = Some(request.clone());
            self.request_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn recv_response(&mut self) -> core::result::Result<Option<BrokerResponse>, Self::Error> {
            match self.last_request.take().unwrap() {
                BrokerRequest::Pipe(PipeRequest::Create(_)) => Ok(Some(BrokerResponse::Pipe(
                    litebox_broker_protocol::message::PipeResponse::Create(CreatePipeResponse {
                        read_handle: ObjectHandle(1),
                        write_handle: ObjectHandle(2),
                    }),
                ))),
                BrokerRequest::Pipe(PipeRequest::Read(_))
                    if self.force_transport.load(Ordering::SeqCst) =>
                {
                    Err(())
                }
                BrokerRequest::Pipe(PipeRequest::Read(_)) => match self.read_failure {
                    ReadFailure::Transport => Err(()),
                    ReadFailure::WouldBlock => {
                        Ok(Some(BrokerResponse::Error(ErrorCode::WouldBlock)))
                    }
                },
                BrokerRequest::CloseObject(_) => Ok(Some(BrokerResponse::ObjectClosed)),
                BrokerRequest::CheckReadiness(_) => {
                    Ok(Some(BrokerResponse::Readiness(ReadinessFlags::default())))
                }
                request @ (BrokerRequest::Pipe(_) | BrokerRequest::Event(_)) => {
                    panic!("unexpected broker request: {request:?}")
                }
            }
        }
    }

    #[test]
    fn test_blocking_channel() {
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = &crate::LiteBox::new(platform);
        let pipes = &super::Pipes::new(litebox);

        let (prod, cons) = pipes.create_pipe(2, super::Flags::empty(), None).unwrap();

        std::thread::scope(|scope| {
            scope.spawn(move || {
                let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
                let written = pipes
                    .write(&WaitState::new(platform).context(), &prod, &data)
                    .unwrap();
                assert_eq!(written, data.len());
                pipes.close(&prod).unwrap();
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

        let (prod, cons) = pipes
            .create_pipe(2, super::Flags::NON_BLOCKING, None)
            .unwrap();

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
                            panic!("Error writing to channel: {e:?}");
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
                        panic!("Error reading from channel: {e:?}");
                    }
                }
            }
            pipes.close(&cons).unwrap();
            assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        });
    }
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    Pipes<Platform>;
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    PipeEnd<Platform>;
    -> PipeFd<Platform>;
}
