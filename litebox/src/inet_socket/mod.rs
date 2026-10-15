// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned IPv4 TCP and UDP sockets.
//!
//! The broker owns each socket's host socket, options, status flags,
//! connection state, and pending errors, and publishes its readiness, so
//! every reference to a socket shares them.

use alloc::sync::{Arc, Weak};
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bitflags::bitflags;
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileOpenFlags, FileStatusFlags},
    socket::{
        MAX_TCP_LISTEN_BACKLOG, ShutdownMode, SocketConnectionStatus,
        SocketError as BrokerSocketError, SocketOptionName, SocketOptionValue, SocketOutcome,
        SocketType,
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
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    fs::errors::StatusFlagsError,
    process::ProcessError,
    sync::{Mutex, RawSyncPrimitivesProvider},
};

pub mod errors;
mod tcp;
mod udp;

use errors::{
    AcceptError, BindError, ConnectError, ListenError, RemoteAddrError, ShutdownError,
    SocketAsyncError, SocketError, SocketReadError, SocketWriteError,
};

/// Socket buffer size reported through socket option interfaces.
pub const SOCKET_BUFFER_SIZE: usize = 65536 * 4;
/// Maximum bytes one socket receive syscall stages before returning.
pub const SOCKET_RECEIVE_OPERATION_SIZE: usize = 0x80_000;
/// Maximum payload size of one IPv4 UDP datagram.
pub const MAX_UDP_DATAGRAM_SIZE: usize =
    litebox_broker_protocol::socket::MAX_UDP_DATAGRAM_SIZE as usize;

/// A reference to a broker-owned IPv4 socket, which closes its handle when
/// dropped.
///
/// A [`SocketType::Stream`] socket is a TCP socket, and a
/// [`SocketType::Datagram`] socket is a UDP socket.
pub struct InetSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    socket_type: SocketType,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
    /// Serializes a TCP socket's receives, since a large peek takes several
    /// requests. The broker cuts a peek short if a receive through another
    /// reference to the socket, such as in another process, comes between
    /// them.
    receive_lock: Mutex<Platform, ()>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Creates an unbound, unconnected IPv4 socket.
    ///
    /// `flags` must be within [`FileOpenFlags::STATUS`].
    pub fn create_inet_socket(
        &self,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Result<InetSocket<Platform>, SocketError> {
        let broker = self
            .broker_control()
            .ok_or(SocketError::BrokerUnavailable)?;
        let handle = match socket_type {
            SocketType::Stream => broker.create_tcp_socket(flags),
            SocketType::Datagram => broker.create_udp_socket(flags),
            _ => return Err(SocketError::UnsupportedType),
        }
        .map_err(BrokerObjectError::from)?;
        Ok(InetSocket::new(
            broker,
            self.broker_pollable_registry(),
            handle,
            socket_type,
        ))
    }

    /// Returns the IPv4 socket of type `socket_type` this process inherited
    /// from its parent as `handle`.
    ///
    /// The socket owns `handle`, so callers adopt each handle once and share
    /// the socket for every other use.
    pub fn adopt_inherited_inet_socket(
        &self,
        handle: ObjectHandle,
        socket_type: SocketType,
    ) -> Result<InetSocket<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(InetSocket::new(
            broker,
            self.broker_pollable_registry(),
            handle,
            socket_type,
        ))
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> InetSocket<Platform> {
    fn new(
        broker: Arc<dyn BrokerControl>,
        pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
        handle: ObjectHandle,
        socket_type: SocketType,
    ) -> Self {
        let socket = Self {
            broker,
            handle,
            socket_type,
            pollable_registry,
            pollee: Arc::new(Pollee::new()),
            receive_lock: Mutex::new(()),
        };
        socket
            .pollable_registry
            .register_pollable(handle, &socket.pollee);
        socket
    }

    /// The broker handle this socket owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// The socket's type.
    pub fn socket_type(&self) -> SocketType {
        self.socket_type
    }

    fn is_stream(&self) -> bool {
        self.socket_type == SocketType::Stream
    }

    /// Binds the socket to `address`.
    pub fn bind(&self, address: &SocketAddr) -> Result<(), BindError> {
        let SocketAddr::V4(address) = address else {
            return Err(BindError::UnsupportedAddress(*address));
        };
        match self
            .broker
            .bind_socket(self.handle, *address)
            .map_err(|error| BindError::OperationFailed(control_error(error)))?
        {
            SocketOutcome::Completed(_) => Ok(()),
            SocketOutcome::Failed(error) => Err(BindError::OperationFailed(error.into())),
        }
    }

    /// Prepares a TCP socket to accept incoming connections.
    pub fn listen(&self, backlog: u16) -> Result<(), ListenError> {
        if !self.is_stream() {
            return Err(ListenError::UnsupportedOperation);
        }
        match self
            .broker
            .listen_socket(self.handle, u32::from(backlog).min(MAX_TCP_LISTEN_BACKLOG))
            .map_err(|error| ListenError::OperationFailed(control_error(error)))?
        {
            SocketOutcome::Completed(_) => Ok(()),
            SocketOutcome::Failed(error) => Err(ListenError::OperationFailed(error.into())),
        }
    }

    /// Accepts a connection on a listening TCP socket, giving the new socket
    /// the status `flags`, within [`FileOpenFlags::STATUS`].
    ///
    /// If `peer` is provided, it is filled with the remote address of the
    /// accepted connection.
    pub fn accept(
        &self,
        flags: FileOpenFlags,
        peer: Option<&mut SocketAddr>,
    ) -> Result<Self, AcceptError> {
        if !self.is_stream() {
            return Err(AcceptError::UnsupportedOperation);
        }
        let outcome = self
            .broker
            .accept_socket(self.handle, flags)
            .map_err(|error| {
                if is_nonblocking_would_block(error) {
                    return AcceptError::NonBlocking;
                }
                match BrokerObjectError::from(error) {
                    BrokerObjectError::WouldBlock => AcceptError::NoConnectionsReady,
                    error => AcceptError::OperationFailed(error.into()),
                }
            })?;
        let accepted = match outcome {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(BrokerSocketError::NotConnected) => {
                return Err(AcceptError::NotListening);
            }
            SocketOutcome::Failed(error) => return Err(AcceptError::OperationFailed(error.into())),
        };
        if let Some(peer) = peer {
            *peer = SocketAddr::V4(accepted.remote_address);
        }
        Ok(Self::new(
            Arc::clone(&self.broker),
            Arc::clone(&self.pollable_registry),
            accepted.handle,
            SocketType::Stream,
        ))
    }

    /// Initiates a connection to `address`, or, if `check_progress` is set,
    /// checks the progress of an ongoing connection attempt.
    pub fn connect(&self, address: &SocketAddr, check_progress: bool) -> Result<(), ConnectError> {
        let SocketAddr::V4(address) = address else {
            return Err(ConnectError::UnsupportedAddress(*address));
        };
        let outcome = if check_progress {
            self.broker.check_connect_socket(self.handle)
        } else {
            self.broker.connect_socket(self.handle, *address)
        }
        .map_err(|error| ConnectError::OperationFailed(control_error(error)))?;
        match outcome {
            SocketOutcome::Completed(SocketConnectionStatus::Connected) => Ok(()),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting) => {
                Err(ConnectError::InProgress)
            }
            SocketOutcome::Completed(SocketConnectionStatus::Unconnected) => {
                Err(ConnectError::InvalidState)
            }
            SocketOutcome::Completed(SocketConnectionStatus::Failed(error))
            | SocketOutcome::Failed(error) => Err(match error {
                BrokerSocketError::AlreadyConnected => ConnectError::AlreadyConnected,
                BrokerSocketError::AlreadyInProgress => ConnectError::AlreadyInProgress,
                error => ConnectError::OperationFailed(error.into()),
            }),
            SocketOutcome::Completed(_) => Err(ConnectError::OperationFailed(
                SocketAsyncError::BackendFailure,
            )),
        }
    }

    /// The local address and port the socket is bound to, which is
    /// unspecified for an unbound socket.
    pub fn local_addr(&self) -> SocketAddr {
        let address = self
            .broker
            .get_socket_name(self.handle, false)
            .ok()
            .flatten();
        SocketAddr::V4(address.unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    }

    /// The remote address and port the socket is connected to.
    pub fn remote_addr(&self) -> Result<SocketAddr, RemoteAddrError> {
        match self.broker.get_socket_name(self.handle, true) {
            Ok(Some(address)) => Ok(SocketAddr::V4(address)),
            _ => Err(RemoteAddrError::NotConnected),
        }
    }

    /// Shuts down one or both directions of the socket.
    ///
    /// `mode` must be [`ShutdownMode::Read`], [`ShutdownMode::Write`], or
    /// [`ShutdownMode::Both`]; [`Self::stop_listening`] stops a listener.
    pub fn shutdown(&self, mode: ShutdownMode) -> Result<(), ShutdownError> {
        if !matches!(
            mode,
            ShutdownMode::Read | ShutdownMode::Write | ShutdownMode::Both
        ) {
            return Err(ShutdownError::UnsupportedOperation);
        }
        self.shutdown_socket(mode)
    }

    /// Stops a listening TCP socket without closing it.
    pub fn stop_listening(&self) -> Result<(), ShutdownError> {
        if !self.is_stream() {
            return Err(ShutdownError::UnsupportedOperation);
        }
        self.shutdown_socket(ShutdownMode::StopListening)
    }

    fn shutdown_socket(&self, mode: ShutdownMode) -> Result<(), ShutdownError> {
        match self
            .broker
            .shutdown_socket(self.handle, mode)
            .map_err(|error| ShutdownError::OperationFailed(control_error(error)))?
        {
            SocketOutcome::Completed(()) => Ok(()),
            SocketOutcome::Failed(BrokerSocketError::Listening) => Err(ShutdownError::Listening),
            SocketOutcome::Failed(error) => Err(ShutdownError::OperationFailed(error.into())),
        }
    }

    /// Makes `error` the oldest pending socket error.
    ///
    /// A socket keeps at most two pending errors, so this may discard the
    /// newest one.
    pub fn set_async_error(&self, error: SocketAsyncError) {
        // A broker that cannot record the error fails the socket's later
        // operations instead.
        let _ = self.broker.set_socket_error(self.handle, error.into());
    }

    /// Takes the oldest pending socket error.
    pub fn take_async_error(&self) -> Option<SocketAsyncError> {
        match self.broker.take_socket_error(self.handle) {
            Ok(error) => error.map(SocketAsyncError::from),
            Err(error) => Some(control_error(error)),
        }
    }

    /// Attempts to read from the socket without waiting.
    ///
    /// Returns the number of bytes read, or for a UDP socket, the length of
    /// the whole datagram, which may exceed `buf`. A UDP socket stores the
    /// sender's address in `source_addr` if requested.
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: ReceiveFlags,
        mut source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketReadError> {
        if let Some(source_addr) = source_addr.as_deref_mut() {
            *source_addr = None;
        }
        if self.is_stream() {
            self.read_stream(buf, flags)
        } else {
            self.read_datagram(buf, flags, source_addr)
        }
    }

    /// Attempts to write to the socket without waiting, sending a UDP
    /// datagram to `destination` if provided.
    ///
    /// A TCP socket ignores `destination`.
    pub fn try_write(
        &self,
        buf: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddr>,
    ) -> Result<usize, SocketWriteError> {
        if !flags.is_empty() {
            unimplemented!()
        }
        if let Some(addr) = destination
            && (addr.port() == 0 || addr.ip().is_unspecified())
        {
            return Err(SocketWriteError::Unaddressable);
        }
        if self.is_stream() {
            self.write_stream(buf)
        } else {
            self.write_datagram(buf, destination)
        }
    }

    /// Stores one option, which every reference to the socket shares.
    pub fn set_option(&self, value: SocketOptionValue) -> Result<(), SocketAsyncError> {
        self.broker
            .set_socket_option(self.handle, value)
            .map_err(control_error)
    }

    /// Returns the stored value of the option `name`.
    pub fn get_option(
        &self,
        name: SocketOptionName,
    ) -> Result<SocketOptionValue, SocketAsyncError> {
        self.broker
            .get_socket_option(self.handle, name)
            .map_err(control_error)
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
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for InetSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mut filter: Events) {
        // A hangup also closes the read side.
        if filter.contains(Events::RDHUP) {
            filter.insert(Events::HUP);
        }
        self.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for InetSocket<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

/// Converts a failed broker request into a socket error.
fn control_error(error: BrokerControlError) -> SocketAsyncError {
    BrokerObjectError::from(error).into()
}

/// Whether the broker reported that an operation on a nonblocking socket
/// would block.
fn is_nonblocking_would_block(error: BrokerControlError) -> bool {
    error == BrokerControlError::Broker(ErrorCode::NonBlockingWouldBlock)
}

bitflags! {
    /// Flags for the `receive` function.
    #[derive(Clone, Copy, Debug)]
    pub struct ReceiveFlags: u32 {
        /// `MSG_CMSG_CLOEXEC`: close-on-exec for the associated file descriptor
        const CMSG_CLOEXEC = 0x40000000;
        /// `MSG_DONTWAIT`: non-blocking operation
        const DONTWAIT = 0x40;
        /// `MSG_ERRQUEUE`: destination for error messages
        const ERRQUEUE = 0x2000;
        /// `MSG_OOB`: requests receipt of out-of-band data
        const OOB = 0x1;
        /// `MSG_PEEK`: requests to peek at incoming messages
        const PEEK = 0x2;
        /// `MSG_TRUNC`: truncate the message
        const TRUNC = 0x20;
        /// `MSG_WAITALL`: wait for the full amount of data
        const WAITALL = 0x100;
        /// Discard the received data
        const DISCARD = 0x8000;
    }
}

bitflags! {
    /// Flags for the `send` function.
    #[derive(Clone, Copy, Debug)]
    pub struct SendFlags: u32 {
        /// `MSG_CONFIRM`: requests confirmation of the message delivery.
        const CONFIRM = 0x800;
        /// `MSG_DONTROUTE`: send the message directly to the interface, bypassing routing.
        const DONTROUTE = 0x4;
        /// `MSG_DONTWAIT`: non-blocking operation, do not wait for buffer space to become available.
        const DONTWAIT = 0x40;
        /// `MSG_EOR`: indicates the end of a record for message-oriented sockets.
        const EOR = 0x80;
        /// `MSG_MORE`: indicates that more data will follow.
        const MORE = 0x8000;
        /// `MSG_NOSIGNAL`: prevents the sending of SIGPIPE signals when writing to a socket that is closed.
        const NOSIGNAL = 0x4000;
        /// `MSG_OOB`: sends out-of-band data.
        const OOB = 0x1;
    }
}

impl From<BrokerObjectError> for SocketError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::ResourceExhausted | BrokerObjectError::OutOfMemory => {
                Self::ResourceExhausted
            }
            BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::WouldBlock
            | BrokerObjectError::PeerClosed
            | BrokerObjectError::UnsupportedOperation => Self::BackendFailure,
        }
    }
}

impl From<BrokerObjectError> for SocketReadError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::WouldBlock,
            BrokerObjectError::PeerClosed => Self::ConnectionClosed,
            error => Self::Socket(error.into()),
        }
    }
}

impl From<BrokerObjectError> for SocketWriteError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::WouldBlock => Self::BufferFull,
            BrokerObjectError::PeerClosed => Self::ConnectionClosed,
            error => Self::Socket(error.into()),
        }
    }
}

impl From<BrokerObjectError> for SocketAsyncError {
    fn from(error: BrokerObjectError) -> Self {
        match error {
            BrokerObjectError::Control
            | BrokerObjectError::InvalidObject
            | BrokerObjectError::PeerClosed
            | BrokerObjectError::WouldBlock => Self::BackendFailure,
            BrokerObjectError::ResourceExhausted | BrokerObjectError::OutOfMemory => {
                Self::ResourceExhausted
            }
            BrokerObjectError::PermissionDenied => Self::PolicyDenied,
            BrokerObjectError::UnsupportedOperation => Self::UnsupportedOperation,
        }
    }
}

impl From<BrokerSocketError> for SocketAsyncError {
    fn from(error: BrokerSocketError) -> Self {
        match error {
            BrokerSocketError::ConnectionRefused => Self::ConnectionRefused,
            BrokerSocketError::ConnectionReset => Self::ConnectionReset,
            BrokerSocketError::ConnectionAborted => Self::ConnectionAborted,
            BrokerSocketError::NetworkUnreachable => Self::NetworkUnreachable,
            BrokerSocketError::HostUnreachable => Self::HostUnreachable,
            BrokerSocketError::TimedOut => Self::TimedOut,
            BrokerSocketError::AddressInUse => Self::AddressInUse,
            BrokerSocketError::AddressNotAvailable => Self::AddressNotAvailable,
            BrokerSocketError::NotConnected => Self::NotConnected,
            BrokerSocketError::InvalidArgument => Self::InvalidArgument,
            BrokerSocketError::PolicyDenied => Self::PolicyDenied,
            BrokerSocketError::ResourceExhausted => Self::ResourceExhausted,
            BrokerSocketError::UnsupportedOperation => Self::UnsupportedOperation,
            // The remaining errors are transport failures without a more
            // specific error, or report a failed precondition of the
            // operations that map them.
            _ => Self::BackendFailure,
        }
    }
}

impl From<SocketAsyncError> for BrokerSocketError {
    fn from(error: SocketAsyncError) -> Self {
        match error {
            SocketAsyncError::ConnectionRefused => Self::ConnectionRefused,
            SocketAsyncError::ConnectionReset => Self::ConnectionReset,
            SocketAsyncError::TimedOut => Self::TimedOut,
            SocketAsyncError::ConnectionAborted => Self::ConnectionAborted,
            SocketAsyncError::NetworkUnreachable => Self::NetworkUnreachable,
            SocketAsyncError::HostUnreachable => Self::HostUnreachable,
            SocketAsyncError::AddressInUse => Self::AddressInUse,
            SocketAsyncError::AddressNotAvailable => Self::AddressNotAvailable,
            SocketAsyncError::NotConnected => Self::NotConnected,
            SocketAsyncError::PolicyDenied => Self::PolicyDenied,
            SocketAsyncError::ResourceExhausted => Self::ResourceExhausted,
            SocketAsyncError::UnsupportedOperation => Self::UnsupportedOperation,
            SocketAsyncError::BackendFailure => Self::Other,
            SocketAsyncError::InvalidArgument => Self::InvalidArgument,
        }
    }
}
