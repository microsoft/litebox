// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned IPv4 TCP and UDP sockets.
//!
//! The broker owns each socket's host socket, options, and status flags, while
//! LiteBox caches its connection state and pending errors.

use alloc::sync::Weak;
use core::net::SocketAddr;

use bitflags::bitflags;
use litebox_broker_protocol::{
    ObjectHandle,
    error::ErrorCode,
    fs::{FileOpenFlags, FileStatusFlags},
    socket::{
        MAX_TCP_LISTEN_BACKLOG, ShutdownMode, SocketError as BrokerSocketError, SocketOptionName,
        SocketOptionValue, SocketType,
    },
};
use litebox_platform::time::TimeProvider;

use crate::{
    LiteBox,
    broker::error::{BrokerControlError, BrokerObjectError},
    event::{Events, IOPollable, observer::Observer},
    fs::errors::StatusFlagsError,
    sync::RawSyncPrimitivesProvider,
};

pub mod errors;
mod tcp;
mod udp;

use errors::{
    AcceptError, BindError, ConnectError, ListenError, RemoteAddrError, ShutdownError,
    SocketAsyncError, SocketError, SocketReadError, SocketWriteError,
};
use tcp::TcpSocket;
use udp::UdpSocket;

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
    socket: Socket<Platform>,
}

enum Socket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Tcp(TcpSocket<Platform>),
    Udp(UdpSocket<Platform>),
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
        let registry = self.broker_pollable_registry();
        let socket = match socket_type {
            SocketType::Stream => Socket::Tcp(TcpSocket::new(broker, registry, flags)?),
            SocketType::Datagram => Socket::Udp(UdpSocket::new(broker, registry, flags)?),
            _ => return Err(SocketError::UnsupportedType),
        };
        Ok(InetSocket { socket })
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> InetSocket<Platform> {
    /// The broker handle this socket owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        match &self.socket {
            Socket::Tcp(socket) => socket.handle(),
            Socket::Udp(socket) => socket.handle(),
        }
    }

    /// The socket's type.
    pub fn socket_type(&self) -> SocketType {
        match &self.socket {
            Socket::Tcp(_) => SocketType::Stream,
            Socket::Udp(_) => SocketType::Datagram,
        }
    }

    /// Binds the socket to `address`.
    pub fn bind(&self, address: &SocketAddr) -> Result<(), BindError> {
        let SocketAddr::V4(address) = address else {
            return Err(BindError::UnsupportedAddress(*address));
        };
        match &self.socket {
            Socket::Tcp(socket) => socket.bind(*address),
            Socket::Udp(socket) => socket.bind(*address),
        }
    }

    /// Prepares a TCP socket to accept incoming connections.
    pub fn listen(&self, backlog: u16) -> Result<(), ListenError> {
        let Socket::Tcp(socket) = &self.socket else {
            return Err(ListenError::UnsupportedOperation);
        };
        socket.listen(u32::from(backlog).min(MAX_TCP_LISTEN_BACKLOG))
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
        let Socket::Tcp(listener) = &self.socket else {
            return Err(AcceptError::UnsupportedOperation);
        };
        let accepted = listener.accept(flags)?;
        if let Some(peer) = peer {
            *peer = accepted
                .remote_addr()
                .map_err(|_| AcceptError::OperationFailed(SocketAsyncError::BackendFailure))?;
        }
        Ok(Self {
            socket: Socket::Tcp(accepted),
        })
    }

    /// Initiates a connection to `address`, or, if `check_progress` is set,
    /// checks the progress of an ongoing connection attempt.
    pub fn connect(&self, address: &SocketAddr, check_progress: bool) -> Result<(), ConnectError> {
        let SocketAddr::V4(address) = address else {
            return Err(ConnectError::UnsupportedAddress(*address));
        };
        match (&self.socket, check_progress) {
            (Socket::Tcp(socket), false) => socket.start_connect(*address),
            (Socket::Tcp(socket), true) => socket.check_connect_progress(),
            (Socket::Udp(socket), false) => socket.start_connect(*address),
            (Socket::Udp(socket), true) => socket.check_connect_progress(),
        }
    }

    /// The local address and port the socket is bound to, which is
    /// unspecified for an unbound socket.
    pub fn local_addr(&self) -> SocketAddr {
        match &self.socket {
            Socket::Tcp(socket) => socket.local_addr(),
            Socket::Udp(socket) => socket.local_addr(),
        }
    }

    /// The remote address and port the socket is connected to.
    pub fn remote_addr(&self) -> Result<SocketAddr, RemoteAddrError> {
        match &self.socket {
            Socket::Tcp(socket) => socket.remote_addr(),
            Socket::Udp(socket) => socket.remote_addr(),
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
        match &self.socket {
            Socket::Tcp(socket) => {
                if socket.is_listening() {
                    return Err(ShutdownError::Listening);
                }
                socket.shutdown(mode)
            }
            Socket::Udp(socket) => socket.shutdown(mode),
        }
        .map_err(ShutdownError::OperationFailed)
    }

    /// Stops a listening TCP socket without closing it.
    pub fn stop_listening(&self) -> Result<(), ShutdownError> {
        let Socket::Tcp(socket) = &self.socket else {
            return Err(ShutdownError::UnsupportedOperation);
        };
        if !socket.is_listening() {
            return Err(ShutdownError::OperationFailed(
                SocketAsyncError::NotConnected,
            ));
        }
        socket
            .stop_listening()
            .map_err(ShutdownError::OperationFailed)
    }

    /// Sets the pending socket error, ahead of any other pending error.
    pub fn set_async_error(&self, error: SocketAsyncError) {
        match &self.socket {
            Socket::Tcp(socket) => socket.set_async_error(error),
            Socket::Udp(socket) => socket.set_async_error(error),
        }
    }

    /// Returns the pending socket error, clearing it if `clear` is set.
    pub fn get_async_error(&self, clear: bool) -> Option<SocketAsyncError> {
        match &self.socket {
            Socket::Tcp(socket) => socket.get_async_error(clear),
            Socket::Udp(socket) => socket.get_async_error(clear),
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
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketReadError> {
        match &self.socket {
            Socket::Tcp(socket) => socket.try_read(buf, flags, source_addr),
            Socket::Udp(socket) => socket.try_read(buf, flags, source_addr),
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
        match &self.socket {
            Socket::Tcp(socket) => socket.try_write(buf),
            Socket::Udp(socket) => socket.try_write(buf, destination),
        }
    }

    /// Stores one option, which every reference to the socket shares.
    pub fn set_option(&self, value: SocketOptionValue) -> Result<(), SocketAsyncError> {
        self.broker()
            .set_socket_option(self.handle(), value)
            .map_err(|error| BrokerObjectError::from(error).into())
    }

    /// Returns the stored value of the option `name`.
    pub fn get_option(
        &self,
        name: SocketOptionName,
    ) -> Result<SocketOptionValue, SocketAsyncError> {
        self.broker()
            .get_socket_option(self.handle(), name)
            .map_err(|error| BrokerObjectError::from(error).into())
    }

    /// Returns the socket's access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker().get_status_flags(self.handle())?)
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
        Ok(self.broker().set_status_flags(self.handle(), mask, flags)?)
    }

    fn broker(&self) -> &dyn crate::broker::BrokerControl {
        match &self.socket {
            Socket::Tcp(socket) => socket.broker(),
            Socket::Udp(socket) => socket.broker(),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for InetSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        match &self.socket {
            Socket::Tcp(socket) => socket.register_observer(observer, mask),
            Socket::Udp(socket) => socket.register_observer(observer, mask),
        }
    }

    fn check_io_events(&self) -> Events {
        match &self.socket {
            Socket::Tcp(socket) => socket.check_io_events(),
            Socket::Udp(socket) => socket.check_io_events(),
        }
    }
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
            _ => Self::BackendFailure,
        }
    }
}
