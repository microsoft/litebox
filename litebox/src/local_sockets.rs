// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned local sockets, which connect processes through names in the
//! filesystem or in an abstract namespace.
//!
//! The broker owns each socket's state, including its name, connection,
//! queued data, and options, so processes that share a socket through
//! inheritance see one socket.

use alloc::sync::{Arc, Weak};
use core::time::Duration;
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileMode, FileOpenFlags, FileStatusFlags, FileUser},
    local_socket::{
        LOCAL_SOCKET_BUFFER_SIZE, LocalSocketAddress, LocalSocketError as ProtocolError,
        LocalSocketName, LocalSocketOption, LocalSocketOptions,
    },
    readiness::ReadinessFlags,
    socket::{ShutdownMode, SocketType},
};
use litebox_platform::time::TimeProvider;

use crate::{
    LiteBox,
    broker::{
        BrokerControl, BrokerPollableRegistry,
        error::{BrokerControlError, BrokerObjectError},
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

use errors::LocalSocketError;

/// Data a [`LocalSocket::receive`] copied into its buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// Number of bytes copied into the buffer.
    pub received: usize,
    /// Length of the whole datagram, or `received` for a stream socket.
    pub length: usize,
    /// Name of the sending socket.
    pub source: LocalSocketName,
}

/// A reference to a broker-owned local socket, which closes its handle when
/// dropped.
pub struct LocalSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    socket_type: SocketType,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Creates an unnamed, unconnected local socket.
    ///
    /// `socket_type` must be [`SocketType::Stream`] or
    /// [`SocketType::Datagram`], and `flags` must be within
    /// [`FileOpenFlags::STATUS`].
    pub fn create_local_socket(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<LocalSocket<Platform>, LocalSocketError> {
        let broker = self.broker_control().ok_or(LocalSocketError::Io)?;
        let handle = broker
            .create_local_socket(socket_type, flags)
            .map_err(LocalSocketError::from)?;
        Ok(LocalSocket::new(self, broker, handle, socket_type))
    }

    /// Creates a pair of unnamed local sockets connected to each other.
    ///
    /// The arguments are as for [`Self::create_local_socket`].
    pub fn create_local_socket_pair(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<(LocalSocket<Platform>, LocalSocket<Platform>), LocalSocketError> {
        let broker = self.broker_control().ok_or(LocalSocketError::Io)?;
        let response = broker
            .create_local_socket_pair(socket_type, flags)
            .map_err(LocalSocketError::from)?;
        Ok((
            LocalSocket::new(self, Arc::clone(&broker), response.first, socket_type),
            LocalSocket::new(self, broker, response.second, socket_type),
        ))
    }

    /// Returns the local socket this process inherited from its parent as
    /// `handle`.
    ///
    /// The socket owns `handle`, so callers adopt each handle once and share
    /// the socket for every other use.
    pub fn adopt_inherited_local_socket(
        &self,
        handle: ObjectHandle,
    ) -> Result<LocalSocket<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let socket_type = match broker.local_socket_options(handle) {
            Ok(response) => response.socket_type,
            Err(error) => {
                let _ = broker.close_object(handle);
                return Err(error.into());
            }
        };
        Ok(LocalSocket::new(self, broker, handle, socket_type))
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LocalSocket<Platform> {
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
        address: &LocalSocketAddress,
        user: FileUser,
        mode: FileMode,
    ) -> Result<(), LocalSocketError> {
        flatten(
            self.broker
                .bind_local_socket(self.handle, address, user, mode),
        )
    }

    /// Makes a bound stream socket accept connections, with up to `backlog`
    /// connections waiting beyond the first.
    pub fn listen(&self, backlog: u32) -> Result<(), LocalSocketError> {
        flatten(self.broker.listen_local_socket(self.handle, backlog))
    }

    /// Connects a stream socket to the listener at `address`, or sets the
    /// default destination of a datagram socket.
    ///
    /// A stream connection waits while the listener's backlog is full, unless
    /// `nonblock` is set or the socket is non-blocking, for at most the
    /// socket's send timeout.
    pub fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: &LocalSocketAddress,
        user: FileUser,
        nonblock: bool,
    ) -> Result<(), LocalSocketError> {
        self.wait(cx, nonblock, send_timeout, || {
            self.broker.connect_local_socket(self.handle, address, user)
        })
    }

    /// Accepts a connection from a listening stream socket, giving the new
    /// socket the status flags `flags`.
    ///
    /// Waits while no connection is pending, unless `nonblock` is set or the
    /// socket is non-blocking, for at most the socket's receive timeout.
    pub fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: FileOpenFlags,
        nonblock: bool,
    ) -> Result<Self, LocalSocketError> {
        let handle = self.wait(cx, nonblock, receive_timeout, || {
            self.broker.accept_local_socket(self.handle, flags)
        })?;
        let pollee = Arc::new(Pollee::new());
        self.pollable_registry.register_pollable(handle, &pollee);
        Ok(Self {
            broker: Arc::clone(&self.broker),
            handle,
            socket_type: SocketType::Stream,
            pollable_registry: Arc::clone(&self.pollable_registry),
            pollee,
        })
    }

    /// Sends `data` to `address`, or to the connected peer if `address` is
    /// `None`, returning the number of bytes sent.
    ///
    /// A datagram socket sends `data` as one datagram. A stream socket sends
    /// all of `data`. Either waits while the receiver is full, unless
    /// `nonblock` is set or the socket is non-blocking, for at most the
    /// socket's send timeout each time. A stream socket that stops early
    /// after sending some bytes returns their count instead of failing.
    pub fn send(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: Option<&LocalSocketAddress>,
        data: &[u8],
        user: FileUser,
        nonblock: bool,
    ) -> Result<usize, LocalSocketError> {
        if self.socket_type != SocketType::Stream {
            return self.wait(cx, nonblock, send_timeout, || {
                self.broker
                    .send_local_socket(self.handle, address, data, user)
            });
        }
        let mut sent: usize = 0;
        loop {
            let end = sent
                .saturating_add(LOCAL_SOCKET_BUFFER_SIZE as usize)
                .min(data.len());
            let chunk = &data[sent..end];
            let result = self.wait(cx, nonblock, send_timeout, || {
                self.broker
                    .send_local_socket(self.handle, address, chunk, user)
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

    /// Receives into `buffer`, leaving the data queued if `peek` is set.
    ///
    /// A stream socket receives queued bytes. A datagram socket receives one
    /// datagram, discarding the bytes that do not fit unless peeking. Waits
    /// while no data is queued, unless `nonblock` is set or the socket is
    /// non-blocking, for at most the socket's receive timeout. Receiving zero
    /// bytes into a nonempty buffer means no more data can arrive, except that
    /// a datagram socket that would not wait fails with
    /// [`LocalSocketError::WouldBlock`] instead.
    pub fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        buffer: &mut [u8],
        peek: bool,
        nonblock: bool,
    ) -> Result<Received, LocalSocketError> {
        self.wait(cx, nonblock, receive_timeout, || {
            self.broker
                .receive_local_socket(self.handle, buffer, peek, nonblock)
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
    pub fn shutdown(&self, mode: ShutdownMode) -> Result<(), LocalSocketError> {
        flatten(self.broker.shutdown_local_socket(self.handle, mode))
    }

    /// Returns the socket's name, or its peer's name if `peer` is set.
    pub fn name(&self, peer: bool) -> Result<LocalSocketName, LocalSocketError> {
        flatten(self.broker.local_socket_name(self.handle, peer))
    }

    /// Stores one option, which every reference to the socket shares.
    pub fn set_option(&self, option: LocalSocketOption) -> Result<(), LocalSocketError> {
        Ok(self.broker.set_local_socket_option(self.handle, option)?)
    }

    /// Returns the socket's stored options.
    pub fn options(&self) -> Result<LocalSocketOptions, LocalSocketError> {
        Ok(self.broker.local_socket_options(self.handle)?.options)
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
    /// `nonblock` is set, for at most the stored timeout `timeout` selects.
    ///
    /// The broker publishes a blocked socket's readiness when the operation
    /// may succeed, so any readiness notification retries it. The timeout is
    /// read only once `op` would block, so operations that need not wait cost
    /// one request.
    fn wait<R>(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        timeout: fn(&LocalSocketOptions) -> Option<Duration>,
        mut op: impl FnMut() -> Result<Result<R, ProtocolError>, BrokerControlError>,
    ) -> Result<R, LocalSocketError> {
        let mut attempt = || match op() {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(TryOpError::Other(LocalSocketError::Socket(error))),
            Err(BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock)) => {
                Err(TryOpError::Other(LocalSocketError::WouldBlock))
            }
            Err(error) => match BrokerObjectError::from(error) {
                BrokerObjectError::WouldBlock => Err(TryOpError::TryAgain),
                error => Err(TryOpError::Other(error.into())),
            },
        };
        match attempt() {
            Ok(value) => return Ok(value),
            Err(TryOpError::TryAgain) if !nonblock => {}
            Err(TryOpError::TryAgain) => return Err(LocalSocketError::WouldBlock),
            Err(TryOpError::Other(error)) => return Err(error),
            Err(TryOpError::WaitError(error)) => return Err(LocalSocketError::WaitError(error)),
        }
        let timeout = timeout(&self.options()?);
        self.pollee
            .wait(
                &cx.with_timeout(timeout),
                false,
                Events::IN | Events::OUT,
                attempt,
            )
            .map_err(|error| match error {
                TryOpError::TryAgain | TryOpError::WaitError(WaitError::TimedOut) => {
                    LocalSocketError::WouldBlock
                }
                TryOpError::WaitError(WaitError::Interrupted) if timeout.is_some() => {
                    LocalSocketError::Interrupted
                }
                TryOpError::WaitError(error) => LocalSocketError::WaitError(error),
                TryOpError::Other(error) => error,
            })
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for LocalSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, local_socket_events)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for LocalSocket<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

fn receive_timeout(options: &LocalSocketOptions) -> Option<Duration> {
    options.receive_timeout
}

fn send_timeout(options: &LocalSocketOptions) -> Option<Duration> {
    options.send_timeout
}

/// Maps local socket readiness to events: a socket that can no longer
/// receive reports [`Events::RDHUP`], and one that can neither send nor
/// receive, or is a stream socket that is not connected, reports
/// [`Events::HUP`].
fn local_socket_events(readiness: ReadinessFlags) -> Events {
    let mut events = Events::empty();
    events.set(Events::IN, readiness.contains(ReadinessFlags::READ));
    events.set(Events::OUT, readiness.contains(ReadinessFlags::WRITE));
    events.set(Events::RDHUP, readiness.contains(ReadinessFlags::HANGUP));
    events.set(Events::HUP, readiness.contains(ReadinessFlags::CLOSED));
    events.set(Events::ERR, readiness.contains(ReadinessFlags::ERROR));
    events
}

fn flatten<R>(
    result: Result<Result<R, ProtocolError>, BrokerControlError>,
) -> Result<R, LocalSocketError> {
    result?.map_err(LocalSocketError::Socket)
}

impl From<BrokerControlError> for LocalSocketError {
    fn from(error: BrokerControlError) -> Self {
        BrokerObjectError::from(error).into()
    }
}

impl From<BrokerObjectError> for LocalSocketError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::ResourceExhausted => Self::ResourceExhausted,
            BrokerObjectError::OutOfMemory => Self::OutOfMemory,
            BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            BrokerObjectError::UnsupportedOperation => Self::Unsupported,
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

    /// Possible errors from local socket operations.
    #[non_exhaustive]
    #[derive(Error, Debug)]
    pub enum LocalSocketError {
        /// The socket operation failed in a way meaningful to the guest.
        #[error(transparent)]
        Socket(litebox_broker_protocol::local_socket::LocalSocketError),
        /// The operation would block and must not wait, or its socket's
        /// timeout expired.
        #[error("local socket operation would block")]
        WouldBlock,
        #[error("wait error")]
        WaitError(WaitError),
        /// A wait bounded by the socket's timeout was interrupted, so the
        /// operation cannot restart without restarting the timeout.
        #[error("local socket wait with a timeout was interrupted")]
        Interrupted,
        #[error("local socket resource exhausted")]
        ResourceExhausted,
        #[error("local socket memory allocation failed")]
        OutOfMemory,
        #[error("local socket permission denied")]
        PermissionDenied,
        #[error("local socket type or flags are unsupported")]
        Unsupported,
        #[error("local socket broker I/O failed")]
        Io,
    }
}
