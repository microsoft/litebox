// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Unix sockets, which connect processes through names in the
//! filesystem or in an abstract namespace.
//!
//! The broker owns each socket's state, including its name, connection,
//! queued data, and options, so processes that share a socket through
//! inheritance see one socket.

use alloc::sync::{Arc, Weak};
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileMode, FileOpenFlags, FileStatusFlags, FileUser},
    socket::{
        ShutdownMode, SocketConnectionStatus, SocketOptionName, SocketOptionValue, SocketType,
    },
    unix_socket::{
        UNIX_SOCKET_BUFFER_SIZE, UnixSocketAddress, UnixSocketError as ProtocolError,
        UnixSocketName,
    },
};
use litebox_platform::time::TimeProvider;

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
    fs::errors::StatusFlagsError,
    process::ProcessError,
    sync::RawSyncPrimitivesProvider,
};
use litebox_platform::buffer::{Buffer, ReadBuffer, WriteBuffer};

use errors::UnixSocketError;

/// Data a [`UnixSocket::receive`] copied into its buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// Number of bytes copied into the buffer.
    pub received: usize,
    /// Length of the whole datagram or record, or `received` for a stream
    /// socket.
    pub length: usize,
    /// Name of the sending socket, if requested.
    pub source: Option<UnixSocketName>,
}

/// A reference to a broker-owned Unix socket, which closes its handle when
/// dropped.
pub struct UnixSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    socket_type: SocketType,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Creates an unnamed, unconnected Unix socket.
    ///
    /// `socket_type` must be [`SocketType::Stream`],
    /// [`SocketType::Datagram`], or [`SocketType::SeqPacket`], and `flags`
    /// must be within [`FileOpenFlags::STATUS`].
    pub fn create_unix_socket(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<UnixSocket<Platform>, UnixSocketError> {
        let broker = self.broker_control().ok_or(UnixSocketError::Io)?;
        let handle = broker
            .create_unix_socket(socket_type, flags)
            .map_err(UnixSocketError::from)?;
        Ok(UnixSocket::new(self, broker, handle, socket_type))
    }

    /// Creates an unnamed, unconnected stream socket that the broker treats
    /// as a vsock socket even before it has a name (see
    /// [`CreateVsockSocketRequest`](litebox_broker_protocol::unix_socket::CreateVsockSocketRequest)).
    ///
    /// `flags` must be within [`FileOpenFlags::STATUS`].
    pub fn create_vsock_socket(
        &self,
        flags: FileOpenFlags,
    ) -> Result<UnixSocket<Platform>, UnixSocketError> {
        let broker = self.broker_control().ok_or(UnixSocketError::Io)?;
        let handle = broker
            .create_vsock_socket(flags)
            .map_err(UnixSocketError::from)?;
        Ok(UnixSocket::new(self, broker, handle, SocketType::Stream))
    }

    /// Creates a pair of unnamed Unix sockets connected to each other.
    ///
    /// The arguments are as for [`Self::create_unix_socket`].
    pub fn create_unix_socket_pair(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<(UnixSocket<Platform>, UnixSocket<Platform>), UnixSocketError> {
        let broker = self.broker_control().ok_or(UnixSocketError::Io)?;
        let response = broker
            .create_unix_socket_pair(socket_type, flags)
            .map_err(UnixSocketError::from)?;
        Ok((
            UnixSocket::new(self, Arc::clone(&broker), response.first, socket_type),
            UnixSocket::new(self, broker, response.second, socket_type),
        ))
    }

    /// Returns the Unix socket of type `socket_type` this process inherited
    /// from its parent as `handle`.
    ///
    /// The socket owns `handle`, so callers adopt each handle once and share
    /// the socket for every other use.
    pub fn adopt_inherited_unix_socket(
        &self,
        handle: ObjectHandle,
        socket_type: SocketType,
    ) -> Result<UnixSocket<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(UnixSocket::new(self, broker, handle, socket_type))
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> UnixSocket<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
        socket_type: SocketType,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            socket_type,
            pollable_registry,
            pollee,
        }
    }

    /// The broker handle this socket owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// The socket's type.
    pub fn socket_type(&self) -> SocketType {
        self.socket_type
    }

    /// Binds the socket to `address`.
    ///
    /// A path address creates a filesystem node with `mode` on behalf of
    /// `user`, failing if the path exists.
    pub fn bind(
        &self,
        address: &UnixSocketAddress,
        user: FileUser,
        mode: FileMode,
    ) -> Result<(), UnixSocketError> {
        flatten(
            self.broker
                .bind_unix_socket(self.handle, address, user, mode),
        )
    }

    /// Makes a bound stream or sequenced-packet socket accept connections,
    /// with up to `backlog` connections waiting beyond the first.
    pub fn listen(&self, backlog: u32) -> Result<(), UnixSocketError> {
        flatten(self.broker.listen_unix_socket(self.handle, backlog))
    }

    /// Connects a stream or sequenced-packet socket to the listener at
    /// `address`, or sets the default destination of a datagram socket.
    ///
    /// A connection waits while the listener's backlog is full, unless
    /// `nonblock` is set or the socket is non-blocking, for at most the
    /// socket's send timeout.
    ///
    /// A stream socket's connect to the host's vsock port, or a connect to a
    /// vsock address that finds one in progress, waits for it to complete, as
    /// Linux does, with no timeout but the broker's, which fails the connect
    /// ([`ProtocolError::TimedOut`]); it fails with the connect's error if it
    /// fails, which, as in Linux, stays pending ([`Self::take_error`]) unless
    /// the connect timed out. If it does not wait, it fails with
    /// [`UnixSocketError::InProgress`], or, if it found one in progress, with
    /// [`ProtocolError::AlreadyInProgress`]. As in Linux, an interrupted wait
    /// cancels the connect, leaving the socket unconnected and still bound,
    /// and fails with [`UnixSocketError::Interrupted`], unless the connect
    /// completed meanwhile: then it reports its outcome. A wait that finds the
    /// socket unconnected with no pending error, as when another call took
    /// it, starts another attempt. A connect to any other address that finds
    /// a vsock connect in progress, or the socket connected, fails at once.
    pub fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: &UnixSocketAddress,
        user: FileUser,
        nonblock: bool,
    ) -> Result<(), UnixSocketError> {
        let vsock = matches!(address, UnixSocketAddress::Vsock { .. });
        // The broker reports a vsock connect in progress whether or not the
        // socket is non-blocking.
        let nonblock = nonblock
            || (vsock
                && self
                    .broker
                    .get_status_flags(self.handle)?
                    .flags
                    .contains(FileOpenFlags::NONBLOCKING));
        let mut in_progress = None;
        let timeout = (!vsock).then_some(SocketOptionName::SendTimeout);
        let result = self.wait_for(cx, nonblock, timeout, || {
            // A wait reads a vsock connect's outcome without taking its
            // error, which a connect would.
            let checked = if vsock && in_progress.is_some() {
                self.broker.check_unix_socket_connect(self.handle)
            } else {
                Ok(Ok(SocketConnectionStatus::Unconnected))
            };
            let result = match checked {
                Ok(Ok(SocketConnectionStatus::Unconnected)) => {
                    self.broker.connect_unix_socket(self.handle, address, user)
                }
                result => result,
            };
            match result {
                Ok(Ok(SocketConnectionStatus::Connected)) => Ok(()),
                // Checked again as the socket's readiness changes.
                Ok(Ok(_)) => {
                    in_progress.get_or_insert(InProgress::Started);
                    Err(TryOpError::TryAgain)
                }
                Ok(Err(ProtocolError::AlreadyInProgress)) if vsock => {
                    in_progress.get_or_insert(InProgress::Found);
                    Err(TryOpError::TryAgain)
                }
                // The connect in progress completed.
                Ok(Err(ProtocolError::AlreadyConnected)) if vsock && in_progress.is_some() => {
                    Ok(())
                }
                result => attempt(result).map(drop),
            }
        });
        match (result, in_progress) {
            (Err(UnixSocketError::WouldBlock), Some(InProgress::Started)) => {
                Err(UnixSocketError::InProgress)
            }
            (Err(UnixSocketError::WouldBlock), Some(InProgress::Found)) => {
                Err(UnixSocketError::Socket(ProtocolError::AlreadyInProgress))
            }
            (Err(UnixSocketError::WaitError(WaitError::Interrupted)), Some(_)) if vsock => {
                match self.broker.cancel_unix_socket_connect(self.handle)? {
                    Ok(()) => Err(UnixSocketError::Interrupted),
                    Err(ProtocolError::AlreadyConnected) => Ok(()),
                    Err(error) => Err(UnixSocketError::Socket(error)),
                }
            }
            (result, _) => result,
        }
    }

    /// Takes why the socket's last connect failed, if no call took it.
    pub fn take_error(&self) -> Result<Option<ProtocolError>, UnixSocketError> {
        Ok(self.broker.take_unix_socket_error(self.handle)?)
    }

    /// Accepts a connection from a listening socket as a new socket of the
    /// same type, giving it the status flags `flags`.
    ///
    /// Waits while no connection is pending, unless `nonblock` is set or the
    /// socket is non-blocking, for at most the socket's receive timeout.
    pub fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: FileOpenFlags,
        nonblock: bool,
    ) -> Result<Self, UnixSocketError> {
        let handle = self.wait(cx, nonblock, SocketOptionName::ReceiveTimeout, || {
            self.broker.accept_unix_socket(self.handle, flags)
        })?;
        let pollee = Arc::new(Pollee::new());
        self.pollable_registry.register_pollable(handle, &pollee);
        Ok(Self {
            broker: Arc::clone(&self.broker),
            handle,
            socket_type: self.socket_type,
            pollable_registry: Arc::clone(&self.pollable_registry),
            pollee,
        })
    }

    /// Sends `data` to `address`, or to the connected peer if `address` is
    /// `None`, returning the number of bytes sent.
    ///
    /// A datagram socket sends `data` as one datagram. A sequenced-packet
    /// socket sends it as one record to its connected peer, ignoring
    /// `address`. A stream socket sends all of `data`. Each waits while the
    /// receiver is full, unless `nonblock` is set or the socket is
    /// non-blocking, for at most the socket's send timeout each time. A
    /// stream socket that stops early after sending some bytes returns their
    /// count instead of failing.
    pub fn send(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: Option<&UnixSocketAddress>,
        data: impl WriteBuffer,
        user: FileUser,
        nonblock: bool,
    ) -> Result<usize, UnixSocketError> {
        if self.socket_type != SocketType::Stream {
            return self.wait(cx, nonblock, SocketOptionName::SendTimeout, || {
                self.broker
                    .send_unix_socket(self.handle, address, &data, user)
            });
        }
        let mut sent: usize = 0;
        loop {
            let length = (data.len() - sent).min(UNIX_SOCKET_BUFFER_SIZE as usize);
            let chunk = &(&data).sub_buffer(sent, length);
            let result = self.wait(cx, nonblock, SocketOptionName::SendTimeout, || {
                self.broker
                    .send_unix_socket(self.handle, address, chunk, user)
            });
            match result {
                Ok(written) => sent += written,
                Err(_) if sent != 0 => return Ok(sent),
                Err(error) => return Err(error),
            }
            if sent == data.len() {
                return Ok(sent);
            }
        }
    }

    /// Receives into `buffer`, leaving the data queued if `peek` is set and
    /// returning the sender's name if `source` is set.
    ///
    /// If copying into `buffer` faults, the operation fails with
    /// [`UnixSocketError::Fault`] and, unless peeking, the bytes received are
    /// lost.
    ///
    /// A stream socket receives queued bytes. A datagram or sequenced-packet
    /// socket receives one datagram or record, discarding the bytes that do
    /// not fit unless peeking. Waits while no data is queued, unless
    /// `nonblock` is set or the socket is non-blocking, for at most the
    /// socket's receive timeout. Receiving zero bytes into a nonempty buffer
    /// means an empty datagram or record arrived, or no more data can arrive;
    /// a datagram socket that would not wait fails with
    /// [`UnixSocketError::WouldBlock`] instead of reporting the end of data.
    pub fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        mut buffer: impl ReadBuffer,
        peek: bool,
        source: bool,
        nonblock: bool,
    ) -> Result<Received, UnixSocketError> {
        self.wait(cx, nonblock, SocketOptionName::ReceiveTimeout, || {
            self.broker
                .receive_unix_socket(self.handle, &mut buffer, peek, source, nonblock)
                .map(|result| {
                    result.map(|(received, source)| Received {
                        received: received.received as usize,
                        length: received.length as usize,
                        source,
                    })
                })
        })
    }

    /// Shuts down one or both directions of the socket.
    pub fn shutdown(&self, mode: ShutdownMode) -> Result<(), UnixSocketError> {
        flatten(self.broker.shutdown_unix_socket(self.handle, mode))
    }

    /// Returns the socket's name, or its peer's name if `peer` is set.
    pub fn name(&self, peer: bool) -> Result<UnixSocketName, UnixSocketError> {
        flatten(self.broker.unix_socket_name(self.handle, peer))
    }

    /// Stores one option, which every reference to the socket shares.
    pub fn set_option(&self, value: SocketOptionValue) -> Result<(), UnixSocketError> {
        Ok(self.broker.set_unix_socket_option(self.handle, value)?)
    }

    /// Returns the stored value of the option `name`.
    pub fn get_option(&self, name: SocketOptionName) -> Result<SocketOptionValue, UnixSocketError> {
        Ok(self.broker.get_unix_socket_option(self.handle, name)?)
    }

    /// Returns the socket's access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`],
    /// to their values in `flags`.
    ///
    /// Every reference to the socket sees the change.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }

    /// Runs `op`, waiting while the broker reports it would block, unless
    /// `nonblock` is set, for at most the stored timeout `timeout` names
    /// ([`SocketOptionName::ReceiveTimeout`] or
    /// [`SocketOptionName::SendTimeout`]).
    ///
    /// The broker publishes a blocked socket's readiness when the operation
    /// may succeed, so any readiness notification retries it. The timeout is
    /// read only once `op` would block, so operations that need not wait cost
    /// one request.
    fn wait<R>(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        timeout: SocketOptionName,
        mut op: impl FnMut() -> Result<Result<R, ProtocolError>, BrokerControlError>,
    ) -> Result<R, UnixSocketError> {
        self.wait_for(cx, nonblock, Some(timeout), || attempt(op()))
    }

    /// Runs `attempt` as [`Self::wait`] runs its operation, retrying while it
    /// fails with [`TryOpError::TryAgain`]; with no `timeout`, it waits for as
    /// long as it takes.
    fn wait_for<R>(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        timeout: Option<SocketOptionName>,
        mut attempt: impl FnMut() -> Result<R, TryOpError<UnixSocketError>>,
    ) -> Result<R, UnixSocketError> {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(TryOpError::TryAgain) if !nonblock => {}
            Err(TryOpError::TryAgain) => return Err(UnixSocketError::WouldBlock),
            Err(TryOpError::Other(error)) => return Err(error),
            Err(TryOpError::WaitError(error)) => return Err(UnixSocketError::WaitError(error)),
        }
        let timeout = match timeout
            .map(|timeout| self.get_option(timeout))
            .transpose()?
        {
            Some(
                SocketOptionValue::ReceiveTimeout(timeout)
                | SocketOptionValue::SendTimeout(timeout),
            ) => timeout,
            None => None,
            Some(value) => unreachable!("{value:?} is not a wait timeout"),
        };
        self.pollee
            .wait(
                &cx.with_timeout(timeout),
                false,
                Events::IN | Events::OUT,
                attempt,
            )
            .map_err(|error| match error {
                TryOpError::TryAgain | TryOpError::WaitError(WaitError::TimedOut) => {
                    UnixSocketError::WouldBlock
                }
                TryOpError::WaitError(WaitError::Interrupted) if timeout.is_some() => {
                    UnixSocketError::Interrupted
                }
                TryOpError::WaitError(error) => UnixSocketError::WaitError(error),
                TryOpError::Other(error) => error,
            })
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for UnixSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for UnixSocket<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

/// A vsock connect in progress that [`UnixSocket::connect`] waits for.
enum InProgress {
    /// This call started it.
    Started,
    /// An earlier call started it.
    Found,
}

/// What a wait makes of a broker operation's `result`: it tries again if it
/// would block.
fn attempt<R>(
    result: Result<Result<R, ProtocolError>, BrokerControlError>,
) -> Result<R, TryOpError<UnixSocketError>> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(TryOpError::Other(UnixSocketError::Socket(error))),
        Err(BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock)) => {
            Err(TryOpError::Other(UnixSocketError::WouldBlock))
        }
        Err(error) => match BrokerObjectError::from(error) {
            BrokerObjectError::WouldBlock => Err(TryOpError::TryAgain),
            error => Err(TryOpError::Other(error.into())),
        },
    }
}

fn flatten<R>(
    result: Result<Result<R, ProtocolError>, BrokerControlError>,
) -> Result<R, UnixSocketError> {
    result?.map_err(UnixSocketError::Socket)
}

impl From<BrokerControlError> for UnixSocketError {
    fn from(error: BrokerControlError) -> Self {
        BrokerObjectError::from(error).into()
    }
}

impl From<BrokerObjectError> for UnixSocketError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::ResourceExhausted => Self::ResourceExhausted,
            BrokerObjectError::OutOfMemory => Self::OutOfMemory,
            BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            BrokerObjectError::UnsupportedOperation => Self::Unsupported,
            BrokerObjectError::Fault => Self::Fault,
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::WouldBlock
            | BrokerObjectError::PeerClosed => Self::Io,
        }
    }
}

pub mod errors {
    use thiserror::Error;

    use crate::event::wait::WaitError;

    /// Possible errors from Unix socket operations.
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum UnixSocketError {
        /// The socket operation failed in a way meaningful to the guest.
        #[error(transparent)]
        Socket(litebox_broker_protocol::unix_socket::UnixSocketError),
        /// The operation would block and must not wait, or its socket's
        /// timeout expired.
        #[error("Unix socket operation would block")]
        WouldBlock,
        /// A connect started, and did not wait for it to complete.
        #[error("Unix socket connect is in progress")]
        InProgress,
        #[error("wait error")]
        WaitError(WaitError),
        /// A wait bounded by the socket's timeout was interrupted, so the
        /// operation cannot restart without restarting the timeout.
        #[error("Unix socket wait with a timeout was interrupted")]
        Interrupted,
        #[error("Unix socket resource exhausted")]
        ResourceExhausted,
        #[error("Unix socket memory allocation failed")]
        OutOfMemory,
        #[error("Unix socket permission denied")]
        PermissionDenied,
        #[error("Unix socket type or flags are unsupported")]
        Unsupported,
        #[error("Unix socket broker I/O failed")]
        Io,
        /// Copying to or from the caller's buffer faulted.
        #[error("copying the transferred bytes faulted")]
        Fault,
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags, FileUser};
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, UnixSocketRequest,
        UnixSocketResponse,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
    use litebox_broker_protocol::socket::{SocketConnectionStatus, SocketType};
    use litebox_broker_protocol::unix_socket::{
        CheckUnixSocketConnectResponse, ConnectUnixSocketResponse, CreateUnixSocketResponse,
        UnixSocketAddress, UnixSocketError as ProtocolError, VMADDR_CID_HOST,
    };
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::HeapSharedMemory;

    use super::errors::UnixSocketError;
    use crate::event::wait::{CheckForInterrupt, WaitState};
    use crate::platform::mock::MockPlatform;

    extern crate std;

    const SOCKET: ObjectHandle = ObjectHandle(7);

    /// A broker that answers connects with `connect`, and whose vsock
    /// connects stay in progress until cancelled, when it answers `cancel`;
    /// it records the Unix socket requests it serves.
    struct PendingConnectChannel {
        connect: Result<SocketConnectionStatus, ProtocolError>,
        cancel: Result<(), ProtocolError>,
        requests: Arc<Mutex<Vec<UnixSocketRequest>>>,
    }

    impl LocalCallChannel for PendingConnectChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            let result = match request.operation {
                BrokerOperation::UnixSocket(request) => {
                    self.requests.lock().unwrap().push(request.clone());
                    BrokerResult::UnixSocket(match request {
                        UnixSocketRequest::Create(_) => {
                            UnixSocketResponse::Create(CreateUnixSocketResponse { handle: SOCKET })
                        }
                        UnixSocketRequest::Connect(_) => match self.connect {
                            Ok(status) => {
                                UnixSocketResponse::Connect(ConnectUnixSocketResponse { status })
                            }
                            Err(error) => UnixSocketResponse::Failed(error),
                        },
                        UnixSocketRequest::CheckConnect(_) => {
                            UnixSocketResponse::CheckConnect(CheckUnixSocketConnectResponse {
                                status: SocketConnectionStatus::Connecting,
                            })
                        }
                        UnixSocketRequest::CancelConnect(_) => match self.cancel {
                            Ok(()) => UnixSocketResponse::CancelConnect,
                            Err(error) => UnixSocketResponse::Failed(error),
                        },
                        request => panic!("unexpected Unix socket request {request:?}"),
                    })
                }
                BrokerOperation::GetStatusFlags(SOCKET) => {
                    BrokerResult::StatusFlags(FileStatusFlags {
                        access: FileAccessMode::ReadWrite,
                        flags: FileOpenFlags::NONE,
                    })
                }
                BrokerOperation::CheckReadiness(SOCKET) => {
                    BrokerResult::Readiness(ReadinessFlags::default())
                }
                BrokerOperation::CloseObject(SOCKET) => BrokerResult::ObjectClosed,
                operation => panic!("unexpected broker operation {operation:?}"),
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }

    struct Interrupted;

    impl CheckForInterrupt for Interrupted {
        fn check_for_interrupt(&self) -> bool {
            true
        }
    }

    /// Interrupts a blocking connect to the host's vsock port while the
    /// broker keeps it in progress, cancelling it with the result `cancel`;
    /// returns the connect's result and the Unix socket requests it made.
    fn interrupt_connect(
        cancel: Result<(), ProtocolError>,
    ) -> (Result<(), UnixSocketError>, Vec<UnixSocketRequest>) {
        connect_through(
            Ok(SocketConnectionStatus::Connecting),
            cancel,
            &UnixSocketAddress::Vsock {
                cid: VMADDR_CID_HOST,
                port: 5000,
            },
        )
    }

    /// Interrupts a blocking connect to `address`, which the broker answers
    /// with `connect`, and, for a vsock connect in progress, cancels with
    /// `cancel`; returns the connect's result and the Unix socket requests it
    /// made.
    fn connect_through(
        connect: Result<SocketConnectionStatus, ProtocolError>,
        cancel: Result<(), ProtocolError>,
        address: &UnixSocketAddress,
    ) -> (Result<(), UnixSocketError>, Vec<UnixSocketRequest>) {
        let platform = MockPlatform::new();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let channel = PendingConnectChannel {
            connect,
            cancel,
            requests: Arc::clone(&requests),
        };
        let shared_memory = Arc::new(HeapSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let litebox = crate::LiteBox::new_with_broker_local(
            platform,
            test_broker_local(channel, shared_memory),
        );
        let socket = litebox
            .create_unix_socket(SocketType::Stream, FileOpenFlags::NONE)
            .unwrap();
        let wait = WaitState::new(platform);
        let result = socket.connect(
            &wait.context().with_check_for_interrupt(&Interrupted),
            address,
            FileUser::ROOT,
            false,
        );
        drop(socket);
        let requests = requests.lock().unwrap().clone();
        (result, requests)
    }

    #[test]
    fn interrupted_vsock_connects_are_cancelled() {
        let (result, requests) = interrupt_connect(Ok(()));
        assert!(matches!(result, Err(UnixSocketError::Interrupted)));
        // The wait checks the attempt rather than connecting again, has no
        // timeout, so reads none, and cancels the attempt once.
        assert!(matches!(
            requests.as_slice(),
            [
                UnixSocketRequest::Create(_),
                UnixSocketRequest::Connect(_),
                checks @ ..,
                UnixSocketRequest::CancelConnect(_),
            ] if !checks.is_empty()
                && checks
                    .iter()
                    .all(|request| matches!(request, UnixSocketRequest::CheckConnect(_)))
        ));

        // A connect that completed meanwhile succeeds, and one that failed
        // reports its error.
        let (result, _) = interrupt_connect(Err(ProtocolError::AlreadyConnected));
        assert!(matches!(result, Ok(())));
        let (result, _) = interrupt_connect(Err(ProtocolError::ConnectionReset));
        assert!(matches!(
            result,
            Err(UnixSocketError::Socket(ProtocolError::ConnectionReset))
        ));
    }

    #[test]
    fn path_connects_fail_at_once_with_another_connects_progress() {
        for error in [
            ProtocolError::AlreadyInProgress,
            ProtocolError::AlreadyConnected,
        ] {
            let (result, requests) = connect_through(
                Err(error),
                Ok(()),
                &UnixSocketAddress::Abstract(b"unix".into()),
            );
            assert!(matches!(
                result,
                Err(UnixSocketError::Socket(found)) if found == error
            ));
            assert!(matches!(
                requests.as_slice(),
                [UnixSocketRequest::Create(_), UnixSocketRequest::Connect(_)]
            ));
        }
    }
}
