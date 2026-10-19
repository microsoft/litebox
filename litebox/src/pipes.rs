// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unidirectional communication channels

use core::num::NonZeroUsize;

use alloc::sync::{Arc, Weak};
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileOpenFlags, FileStatusFlags},
    pipe::MAX_PIPE_TRANSFER_SIZE,
};
use litebox_platform::time::TimeProvider;
use thiserror::Error;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry,
        error::{BrokerControlError, BrokerObjectError},
        readiness_events,
    },
    buffer::{ReadBuffer, WriteBuffer, copy_from_buffer, copy_to_buffer},
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError},
    },
    fs::errors::StatusFlagsError,
    process::ProcessError,
    sync::RawSyncPrimitivesProvider,
};

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Create a unidirectional communication channel for sending messages of (slices of) bytes.
    ///
    /// This function returns the sender and receiver halves respectively.
    ///
    /// `capacity` defines the maximum capacity of the channel, beyond which writes wait or, if the
    /// writer is non-blocking, fail.
    ///
    /// `flags` are the initial status flags of both halves, within [`FileOpenFlags::STATUS`].
    ///
    /// `atomic_slice_guarantee_size` (if provided) is the number of elements that are guaranteed to be
    /// written atomically (i.e., not interleaved with other writes) if a slice of those many (or fewer)
    /// elements are passed at once. Slices longer than this length have no guarantees on atomicity of
    /// writes and might be interleaved with other writes.
    pub fn create_pipe(
        &self,
        capacity: usize,
        flags: FileOpenFlags,
        atomic_slice_guarantee_size: Option<NonZeroUsize>,
    ) -> Result<(PipeEnd<Platform>, PipeEnd<Platform>), errors::CreateError> {
        let broker = self.broker_control().ok_or(errors::CreateError::Io)?;
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
                flags,
            )
            .map_err(BrokerObjectError::from)
            .map_err(errors::CreateError::from)?;
        let mut writer = PipeEnd::new(
            self,
            Arc::clone(&broker),
            response.write_handle,
            HalfPipeType::SenderHalf,
        );
        let mut reader = PipeEnd::new(
            self,
            broker,
            response.read_handle,
            HalfPipeType::ReceiverHalf,
        );
        writer.peer_pollee = Arc::downgrade(&reader.pollee);
        reader.peer_pollee = Arc::downgrade(&writer.pollee);
        Ok((writer, reader))
    }

    /// Returns the pipe end of type `endpoint_type` this process inherited
    /// from its parent as `handle` through
    /// [`PendingChild::inherit`](crate::process::PendingChild::inherit).
    ///
    /// The end owns `handle`, so callers adopt each handle once and share the
    /// end for every other use. The end has no peer in this process, so broker
    /// readiness notifications alone wake its waiters.
    pub fn adopt_inherited_pipe(
        &self,
        handle: ObjectHandle,
        endpoint_type: HalfPipeType,
    ) -> Result<PipeEnd<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(PipeEnd::new(self, broker, handle, endpoint_type))
    }
}

/// Whether a particular pipe end is the sender half or the receiver half
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalfPipeType {
    SenderHalf,
    ReceiverHalf,
}

pub mod errors {
    use crate::event::wait::WaitError;

    use thiserror::Error;

    /// Possible errors from [`crate::LiteBox::create_pipe`].
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

    /// Possible errors from [`super::PipeEnd::read`]
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum ReadError {
        #[error("not open for reading")]
        NotForReading,
        #[error("read would block")]
        WouldBlock,
        #[error("wait error")]
        WaitError(WaitError),
        #[error("pipe I/O failed")]
        Io,
        /// Copying into the buffer faulted; the bytes read are lost.
        #[error("copying into the buffer faulted")]
        Fault,
    }

    /// Possible errors from [`super::PipeEnd::write`]
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum WriteError {
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
        /// Copying from the buffer faulted before anything was written.
        #[error("copying from the buffer faulted")]
        Fault,
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
    #[error("copying the transferred bytes faulted")]
    Fault,
}

impl From<PipeError> for errors::ReadError {
    fn from(error: PipeError) -> Self {
        match error {
            PipeError::PeerShutdown | PipeError::Io => Self::Io,
            PipeError::WouldBlock => Self::WouldBlock,
            PipeError::WaitError(error) => Self::WaitError(error),
            PipeError::Fault => Self::Fault,
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
            PipeError::Fault => Self::Fault,
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

/// A reference to one end of a broker-owned pipe, which closes its handle
/// when dropped.
pub struct PipeEnd<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
    /// The other end's pollee, if this process created the pipe, which this
    /// end notifies directly when it changes the other end's readiness.
    peer_pollee: Weak<Pollee<Platform>>,
    endpoint_type: HalfPipeType,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> PipeEnd<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
        endpoint_type: HalfPipeType,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            pollable_registry,
            pollee,
            peer_pollee: Weak::new(),
            endpoint_type,
        }
    }

    /// The broker handle this end owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Whether this end is the sender half or the receiver half.
    pub fn endpoint_type(&self) -> HalfPipeType {
        self.endpoint_type
    }

    /// Read values in the pipe into `buf`, returning the number of elements read.
    ///
    /// Fails with [`errors::ReadError::NotForReading`] on the sender half. See
    /// [`LiteBox::create_pipe`] for details on blocking behavior.
    ///
    /// Note: currently, this function returns `Ok(0)` if the peer end has been shut down, this may
    /// change in the future to an explicit "peer has shut down" error.
    pub fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut (impl ReadBuffer + ?Sized),
    ) -> Result<usize, errors::ReadError> {
        if self.endpoint_type != HalfPipeType::ReceiverHalf {
            return Err(errors::ReadError::NotForReading);
        }
        self.read_pipe(cx, buf).map_err(From::from)
    }

    /// Write the values in `buf` into the pipe, returning the number of elements written.
    ///
    /// Fails with [`errors::WriteError::NotForWriting`] on the receiver half. See
    /// [`LiteBox::create_pipe`] for details on blocking and atomicity of writes.
    pub fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &(impl WriteBuffer + ?Sized),
    ) -> Result<usize, errors::WriteError> {
        if self.endpoint_type != HalfPipeType::SenderHalf {
            return Err(errors::WriteError::NotForWriting);
        }
        self.write_pipe(cx, buf).map_err(From::from)
    }

    /// Returns the end's access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`],
    /// to their values in `flags`.
    ///
    /// Every reference to the end, in any process, sees the change.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }

    fn read_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut (impl ReadBuffer + ?Sized),
    ) -> Result<usize, PipeError> {
        let length = buf.len().min(MAX_PIPE_TRANSFER_SIZE as usize);
        if length == 0 {
            return Ok(0);
        }

        // On a non-blocking end, the broker returns `NonBlockingWouldBlock` instead of `WouldBlock`,
        // so the wait returns `PipeError::WouldBlock` instead of blocking.
        self.pollee
            .wait(cx, false, Events::IN, || {
                let read = self
                    .broker
                    .read_pipe(self.handle, length, &mut copy_to_buffer(&mut *buf, 0))
                    .map_err(|error| self.broker_request_error(error))?;
                if read > length {
                    return Err(TryOpError::Other(PipeError::Io));
                }
                if read != 0
                    && let Some(peer_pollee) = self.peer_pollee.upgrade()
                {
                    peer_pollee.notify_observers(Events::OUT);
                }
                Ok(read)
            })
            .map_err(PipeError::from)
    }

    fn write_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &(impl WriteBuffer + ?Sized),
    ) -> Result<usize, PipeError> {
        if buf.is_empty() {
            return Ok(0);
        }

        // On a non-blocking end, the broker returns `NonBlockingWouldBlock` instead of `WouldBlock`,
        // so the wait returns instead of blocking and the loop returns what was written so far, or
        // `PipeError::WouldBlock` if nothing was written.
        let mut total_written = 0;
        while total_written < buf.len() {
            let length = (buf.len() - total_written).min(MAX_PIPE_TRANSFER_SIZE as usize);
            match self.pollee.wait(cx, false, Events::OUT, || {
                self.try_write(buf, total_written, length)
            }) {
                Ok(written) => total_written += written,
                Err(_) if total_written != 0 => return Ok(total_written),
                Err(error) => return Err(PipeError::from(error)),
            }
        }
        Ok(total_written)
    }

    /// Writes the `length` bytes at `offset` in `buf`.
    fn try_write(
        &self,
        buf: &(impl WriteBuffer + ?Sized),
        offset: usize,
        length: usize,
    ) -> Result<usize, TryOpError<PipeError>> {
        let written = self
            .broker
            .write_pipe(self.handle, length, &mut copy_from_buffer(buf, offset))
            .map_err(|error| self.broker_request_error(error))?;
        if written > length || (written == 0 && length != 0) {
            return Err(TryOpError::Other(PipeError::Io));
        }
        if written != 0
            && let Some(peer_pollee) = self.peer_pollee.upgrade()
        {
            peer_pollee.notify_observers(Events::IN);
        }
        Ok(written)
    }

    fn broker_request_error(&self, error: BrokerControlError) -> TryOpError<PipeError> {
        match error {
            BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock) => {
                return TryOpError::Other(PipeError::WouldBlock);
            }
            // The fault is the caller's buffer's, not the pipe's.
            BrokerControlError::Fault => return TryOpError::Other(PipeError::Fault),
            _ => {}
        }
        let error = BrokerObjectError::from(error);
        if error != BrokerObjectError::WouldBlock {
            self.pollee.notify_observers(Events::ERR);
        }
        error.into()
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for PipeEnd<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        match self.broker.check_readiness(self.handle) {
            Ok(readiness) => readiness_events(readiness),
            Err(_) => Events::ERR,
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for PipeEnd<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
        if let Some(peer_pollee) = self.peer_pollee.upgrade() {
            let event = match self.endpoint_type {
                HalfPipeType::SenderHalf => Events::HUP,
                HalfPipeType::ReceiverHalf => Events::ERR,
            };
            peer_pollee.notify_observers(event);
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
            BrokerObjectError::Fault => TryOpError::Other(PipeError::Fault),
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
            | BrokerObjectError::UnsupportedOperation
            | BrokerObjectError::Fault => Self::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use alloc::sync::Arc;
    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::fs::FileOpenFlags;
    use litebox_broker_protocol::message::{
        BrokerNotification, BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult,
        PipeRequest, ReadinessNotification,
    };
    use litebox_broker_protocol::pipe::CreatePipeResponse;
    use litebox_broker_protocol::pipe::ReadPipeResponse;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::HeapSharedMemory;

    use crate::{
        buffer::{RawBytes, ReadBuffer},
        event::{Events, IOPollable, observer::Observer, wait::WaitState},
        mm::exception_table::Fault,
        pipes::errors::ReadError,
    };

    extern crate std;

    #[test]
    fn broker_control_failure_notifies_all_pipe_observers() {
        let platform = crate::platform::mock::MockPlatform::new();
        let request_count = Arc::new(AtomicUsize::new(0));
        let force_transport = Arc::new(AtomicBool::new(false));
        let local = test_broker_local(
            FailingPipeChannel {
                request_count: Arc::clone(&request_count),
                read_failure: ReadFailure::Transport,
                force_transport,
            },
            test_shared_memory(),
        );
        let litebox = crate::LiteBox::new_with_broker_local(platform, local);
        let (writer, reader) = litebox.create_pipe(2, FileOpenFlags::NONE, None).unwrap();
        let writer_observer = Arc::new(ErrorObserver(AtomicBool::new(false)));
        let writer_observer_dyn: Arc<dyn Observer<Events>> = writer_observer.clone();
        writer.register_observer(Arc::downgrade(&writer_observer_dyn), Events::ERR);
        let reader_observer = Arc::new(ErrorObserver(AtomicBool::new(false)));
        let reader_observer_dyn: Arc<dyn Observer<Events>> = reader_observer.clone();
        reader.register_observer(Arc::downgrade(&reader_observer_dyn), Events::ERR);

        let mut value = 0;
        assert!(matches!(
            reader.read(
                &WaitState::new(platform).context(),
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
        let local = test_broker_local(
            FailingPipeChannel {
                request_count: Arc::clone(&request_count),
                read_failure: ReadFailure::WouldBlock,
                force_transport: Arc::clone(&force_transport),
            },
            test_shared_memory(),
        );
        let litebox = crate::LiteBox::new_with_broker_local(platform, local);
        let (writer, reader) = litebox.create_pipe(2, FileOpenFlags::NONE, None).unwrap();
        let mut writer = Some(writer);

        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let read_thread = std::thread::spawn(move || {
            let mut value = 0;
            result_sender
                .send(reader.read(
                    &WaitState::new(platform).context(),
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
                drop(writer.take());
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
                    drop(writer.take());
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
            drop(writer.take());
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
    fn pipe_read_faults_fail_without_notifying_errors() {
        let platform = crate::platform::mock::MockPlatform::new();
        let local = test_broker_local(
            FailingPipeChannel {
                request_count: Arc::new(AtomicUsize::new(0)),
                read_failure: ReadFailure::None,
                force_transport: Arc::new(AtomicBool::new(false)),
            },
            test_shared_memory(),
        );
        let litebox = crate::LiteBox::new_with_broker_local(platform, local);
        let (_writer, reader) = litebox.create_pipe(2, FileOpenFlags::NONE, None).unwrap();
        let observer = Arc::new(ErrorObserver(AtomicBool::new(false)));
        let observer_dyn: Arc<dyn Observer<Events>> = observer.clone();
        reader.register_observer(Arc::downgrade(&observer_dyn), Events::ERR);

        assert!(matches!(
            reader.read(&WaitState::new(platform).context(), &mut FaultingBuffer),
            Err(ReadError::Fault)
        ));
        assert!(!observer.0.load(Ordering::SeqCst));
    }

    #[test]
    fn pipe_creation_requires_broker() {
        let platform = crate::platform::mock::MockPlatform::new();
        let litebox = crate::LiteBox::new(platform);
        assert!(matches!(
            litebox.create_pipe(2, FileOpenFlags::NONE, None),
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

    fn test_shared_memory() -> Arc<HeapSharedMemory> {
        Arc::new(HeapSharedMemory::new(
            litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE,
        ))
    }

    /// A buffer whose copies always fault.
    struct FaultingBuffer;

    impl ReadBuffer for FaultingBuffer {
        fn len(&self) -> usize {
            1
        }

        fn copy_from_slice_at(&mut self, _offset: usize, _source: &[u8]) -> Result<(), Fault> {
            Err(Fault)
        }

        fn copy_from_raw_at(&mut self, _offset: usize, _source: RawBytes<'_>) -> Result<(), Fault> {
            Err(Fault)
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ReadFailure {
        Transport,
        WouldBlock,
        None,
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
                    ReadFailure::None => {
                        BrokerResult::Pipe(litebox_broker_protocol::message::PipeResponse::Read(
                            ReadPipeResponse { read: 1 },
                        ))
                    }
                },
                BrokerOperation::CloseObject(_) => BrokerResult::ObjectClosed,
                BrokerOperation::CheckReadiness(_) => {
                    BrokerResult::Readiness(ReadinessFlags::default())
                }
                request => {
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
