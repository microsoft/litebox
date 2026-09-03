// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unidirectional communication channels

use core::{
    num::NonZeroUsize,
    sync::atomic::{AtomicU32, Ordering::Relaxed},
};

use alloc::sync::{Arc, Weak};
use litebox_broker_protocol::{
    ObjectHandle, pipe::MAX_PIPE_TRANSFER_SIZE, readiness::ReadinessFlags,
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
    sync::RawSyncPrimitivesProvider,
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
        let broker = self
            .litebox
            .broker_control()
            .ok_or(errors::CreateError::Io)?;
        let (sender, receiver) = new_broker_pipe(
            broker,
            self.litebox.broker_pollable_registry(),
            capacity,
            OFlags::from(flags),
            atomic_slice_guarantee_size,
        )?;
        let mut dt = self.litebox.descriptor_table_mut();
        let sender = dt.insert(PipeEnd::Sender(sender));
        let receiver = dt.insert(PipeEnd::Receiver(receiver));
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
            PipeEnd::Receiver(p) => Arc::clone(p),
            PipeEnd::Sender(_) => return Err(errors::ReadError::NotForReading),
        };
        drop(dt);
        p.read(cx, buf).map_err(From::from)
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
            PipeEnd::Receiver(p) | PipeEnd::Sender(p) => p.get_status(),
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
            PipeEnd::Receiver(p) | PipeEnd::Sender(p) => {
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
            PipeEnd::Receiver(p) | PipeEnd::Sender(p) => Ok(f(p)),
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
    Receiver(Arc<BrokerPipeEnd<Platform>>),
    Sender(Arc<BrokerPipeEnd<Platform>>),
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

/// Potential errors when writing or reading from a pipe.
#[derive(Error, Debug)]
enum PipeError {
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
    fn from(error: PipeError) -> Self {
        match error {
            PipeError::PeerShutdown | PipeError::Io => Self::Io,
            PipeError::WouldBlock => Self::WouldBlock,
            PipeError::WaitError(error) => Self::WaitError(error),
        }
    }
}

impl From<PipeError> for errors::WriteError {
    fn from(error: PipeError) -> Self {
        match error {
            PipeError::PeerShutdown => Self::ReadEndClosed,
            PipeError::WouldBlock => Self::WouldBlock,
            PipeError::WaitError(error) => Self::WaitError(error),
            PipeError::Io => Self::Io,
        }
    }
}

impl From<TryOpError<PipeError>> for PipeError {
    fn from(error: TryOpError<PipeError>) -> Self {
        match error {
            TryOpError::TryAgain => Self::WouldBlock,
            TryOpError::WaitError(error) => Self::WaitError(error),
            TryOpError::Other(error) => error,
        }
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
            | BrokerObjectError::OutOfMemory
            | BrokerObjectError::UnsupportedOperation => TryOpError::Other(PipeError::Io),
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
            | BrokerObjectError::PeerClosed
            | BrokerObjectError::UnsupportedOperation => Self::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use alloc::sync::Arc;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
        BrokerRequest, BrokerResponse, BrokerResult, PipeRequest, ReadinessNotification,
    };
    use litebox_broker_protocol::pipe::CreatePipeResponse;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle};
    use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};

    use crate::{
        event::{Events, observer::Observer, wait::WaitState},
        pipes::errors::ReadError,
    };

    extern crate std;

    #[test]
    fn broker_control_failure_notifies_all_pipe_observers() {
        let platform = crate::platform::mock::MockPlatform::new();
        let request_count = Arc::new(AtomicUsize::new(0));
        let force_transport = Arc::new(AtomicBool::new(false));
        let (local, ()) = BrokerLocal::negotiate(
            FailingPipeChannel {
                request_count: Arc::clone(&request_count),
                read_failure: ReadFailure::Transport,
                force_transport,
            },
            |channel| Ok((channel, Arc::new(NoopSharedMemory), ())),
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
        let (local, ()) = BrokerLocal::negotiate(
            FailingPipeChannel {
                request_count: Arc::clone(&request_count),
                read_failure: ReadFailure::WouldBlock,
                force_transport: Arc::clone(&force_transport),
            },
            |channel| Ok((channel, Arc::new(NoopSharedMemory), ())),
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
    fn pipe_creation_requires_broker() {
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = crate::LiteBox::new(platform);
        let pipes = super::Pipes::new(&litebox);
        assert!(matches!(
            pipes.create_pipe(2, super::Flags::empty(), None),
            Err(super::errors::CreateError::Io)
        ));
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
        request_count: Arc<AtomicUsize>,
        read_failure: ReadFailure,
        force_transport: Arc<AtomicBool>,
    }

    #[derive(Clone, Copy)]
    struct NoopSharedMemory;

    impl litebox_broker_transport::shared_memory::SharedMemory for NoopSharedMemory {
        fn len(&self) -> usize {
            litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE
        }

        fn read(
            &self,
            _offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), litebox_broker_transport::shared_memory::SharedMemoryError>
        {
            destination.fill(0);
            Ok(())
        }

        fn write(
            &self,
            _offset: usize,
            _source: &[u8],
        ) -> core::result::Result<(), litebox_broker_transport::shared_memory::SharedMemoryError>
        {
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ReadFailure {
        Transport,
        WouldBlock,
    }

    impl LocalSetupChannel for FailingPipeChannel {
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
    }

    impl LocalCallChannel for FailingPipeChannel {
        type Error = ();

        fn call(
            &self,
            request: BrokerRequest,
        ) -> core::result::Result<BrokerResponse, Self::Error> {
            self.request_count.fetch_add(1, Ordering::SeqCst);
            let result = match request.operation {
                BrokerOperation::Pipe(PipeRequest::Create(_)) => BrokerResult::Pipe(
                    litebox_broker_protocol::message::PipeResponse::Create(CreatePipeResponse {
                        read_handle: ObjectHandle(1),
                        write_handle: ObjectHandle(2),
                    }),
                ),
                BrokerOperation::Pipe(PipeRequest::Read(_))
                    if self.force_transport.load(Ordering::SeqCst) =>
                {
                    return Err(());
                }
                BrokerOperation::Pipe(PipeRequest::Read(_)) => match self.read_failure {
                    ReadFailure::Transport => return Err(()),
                    ReadFailure::WouldBlock => BrokerResult::Error(ErrorCode::WouldBlock),
                },
                BrokerOperation::CloseObject(_) => BrokerResult::ObjectClosed,
                BrokerOperation::CheckReadiness(_) => {
                    BrokerResult::Readiness(ReadinessFlags::default())
                }
                request @ (BrokerOperation::Pipe(_)
                | BrokerOperation::Event(_)
                | BrokerOperation::Socket(_)
                | BrokerOperation::FillRandom(_)) => {
                    panic!("unexpected broker request: {request:?}")
                }
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    Pipes<Platform>;
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    PipeEnd<Platform>;
    -> PipeFd<Platform>;
}
