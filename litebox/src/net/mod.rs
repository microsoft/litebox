// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network-related functionality

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};

use bitflags::bitflags;
use litebox_platform::time::TimeProvider;

use crate::{
    LiteBox,
    net::socket_channel::NetworkProxy,
    sync::{self, RawSyncPrimitivesProvider},
};

mod broker_socket;
pub mod errors;
pub mod socket_channel;

pub use broker_socket::{BrokerTcpSocket, BrokerUdpSocket};

use errors::{
    AcceptError, BindError, CloseError, ConnectError, ListenError, LocalAddrError, ReceiveError,
    RemoteAddrError, SendError, SocketError,
};

impl From<crate::broker::error::BrokerObjectError> for SocketError {
    fn from(error: crate::broker::error::BrokerObjectError) -> Self {
        match error {
            crate::broker::error::BrokerObjectError::ResourceExhausted
            | crate::broker::error::BrokerObjectError::OutOfMemory => Self::ResourceExhausted,
            crate::broker::error::BrokerObjectError::PermissionDenied => Self::PermissionDenied,
            crate::broker::error::BrokerObjectError::Control
            | crate::broker::error::BrokerObjectError::InvalidObject
            | crate::broker::error::BrokerObjectError::WouldBlock
            | crate::broker::error::BrokerObjectError::PeerClosed
            | crate::broker::error::BrokerObjectError::UnsupportedOperation => Self::BackendFailure,
        }
    }
}

const ICMP_PROTOCOL_NUMBER: u8 = 1;

/// Socket buffer size reported through socket option interfaces.
pub const SOCKET_BUFFER_SIZE: usize = 65536 * 4;
/// Maximum bytes one socket receive syscall stages before returning.
pub const SOCKET_RECEIVE_OPERATION_SIZE: usize = 0x80_000;
/// Maximum payload size of one IPv4 UDP datagram.
pub const MAX_UDP_DATAGRAM_SIZE: usize =
    litebox_broker_protocol::socket::MAX_UDP_DATAGRAM_SIZE as usize;

/// Directions of a socket to shut down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownDirection {
    /// Stop receiving.
    Read,
    /// Stop sending.
    Write,
    /// Stop receiving and sending.
    Both,
}

/// The `Network` provides access to broker-owned networking functionality.
///
/// [`attach_socket_proxy`](Self::attach_socket_proxy) provides a per-socket interface for
/// nonblocking I/O and readiness notification.
pub struct Network<Platform>
where
    Platform: TimeProvider + sync::RawSyncPrimitivesProvider,
{
    litebox: LiteBox<Platform>,
    /// FDs that are queued for eventual closure while another operation pins their entry.
    queued_for_closure: Vec<SocketFd<Platform>>,
}

impl<Platform> Network<Platform>
where
    Platform: TimeProvider + sync::RawSyncPrimitivesProvider,
{
    /// Construct a new `Network` instance.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            litebox: litebox.clone(),
            queued_for_closure: vec![],
        }
    }
}

/// Per-open-file-description state for a broker-owned socket.
pub(crate) struct SocketHandle<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker_socket: BrokerSocket<Platform>,
    /// Whether the final TCP close should be abortive.
    immediate_close: AtomicBool,
    /// The proxy associated with this socket for I/O and event notification.
    proxy: Option<Arc<NetworkProxy<Platform>>>,
}

enum BrokerSocket<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Tcp(Arc<BrokerTcpSocket<Platform>>),
    Udp(Arc<BrokerUdpSocket<Platform>>),
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Clone for BrokerSocket<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::Tcp(socket) => Self::Tcp(Arc::clone(socket)),
            Self::Udp(socket) => Self::Udp(Arc::clone(socket)),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> SocketHandle<Platform> {
    fn protocol(&self) -> Protocol {
        match self.broker_socket {
            BrokerSocket::Tcp(_) => Protocol::Tcp,
            BrokerSocket::Udp(_) => Protocol::Udp,
        }
    }
}

impl<Platform> Network<Platform>
where
    Platform: TimeProvider + sync::RawSyncPrimitivesProvider,
{
    /// Creates a broker-owned TCP or UDP socket.
    ///
    /// By default, the created socket has no associated proxy; to set a proxy, use
    /// [`attach_socket_proxy`](Self::attach_socket_proxy).
    pub fn socket(&mut self, protocol: Protocol) -> Result<SocketFd<Platform>, SocketError> {
        let broker_socket = match (&protocol, self.litebox.broker_control()) {
            (Protocol::Tcp, Some(broker)) => BrokerSocket::Tcp(
                BrokerTcpSocket::new(broker, self.litebox.broker_pollable_registry())
                    .map_err(SocketError::from)?,
            ),
            (Protocol::Udp, Some(broker)) => BrokerSocket::Udp(
                BrokerUdpSocket::new(broker, self.litebox.broker_pollable_registry())
                    .map_err(SocketError::from)?,
            ),
            (Protocol::Tcp | Protocol::Udp, None) => {
                return Err(SocketError::BrokerUnavailable);
            }
            (Protocol::Icmp, _) => {
                return Err(SocketError::UnsupportedProtocol(ICMP_PROTOCOL_NUMBER));
            }
            (Protocol::Raw { protocol }, _) => {
                return Err(SocketError::UnsupportedProtocol(*protocol));
            }
        };

        Ok(self.litebox.descriptor_table_mut().insert(SocketHandle {
            broker_socket,
            immediate_close: AtomicBool::new(false),
            proxy: None,
        }))
    }

    /// Creates and attaches the userspace I/O proxy matching `fd`.
    ///
    /// If a proxy is already attached, this returns another reference to that proxy.
    ///
    /// Returns `None` if `fd` is invalid.
    #[must_use]
    pub fn attach_socket_proxy(
        &self,
        fd: &SocketFd<Platform>,
    ) -> Option<Arc<NetworkProxy<Platform>>> {
        let descriptor_table = self.litebox.descriptor_table();
        let mut entry = descriptor_table.get_entry_mut(fd)?;
        let socket_handle = &mut entry.entry;
        if let Some(proxy) = &socket_handle.proxy {
            return Some(Arc::clone(proxy));
        }
        let proxy = match &socket_handle.broker_socket {
            BrokerSocket::Tcp(socket) => NetworkProxy::BrokerStream(Arc::clone(socket)),
            BrokerSocket::Udp(socket) => NetworkProxy::BrokerDatagram(Arc::clone(socket)),
        };
        let proxy = Arc::new(proxy);
        socket_handle.proxy = Some(Arc::clone(&proxy));
        Some(proxy)
    }

    /// Close the socket at `fd`.
    pub fn close(
        &mut self,
        fd: &SocketFd<Platform>,
        behavior: CloseBehavior,
    ) -> Result<(), CloseError> {
        let mut descriptor_table = self.litebox.descriptor_table_mut();
        descriptor_table
            .with_entry_mut(fd, |entry| {
                if matches!(entry.entry.protocol(), Protocol::Tcp) {
                    entry.entry.immediate_close.store(
                        matches!(behavior, CloseBehavior::Immediate),
                        Ordering::SeqCst,
                    );
                }
            })
            .ok_or(CloseError::InvalidFd)?;

        match descriptor_table
            .close_and_duplicate_if_shared(fd, |_| true)
            .ok_or(CloseError::InvalidFd)?
        {
            super::fd::CloseResult::Closed(socket_handle) => {
                drop(descriptor_table);
                Self::close_handle(socket_handle.entry);
            }
            super::fd::CloseResult::Duplicated(duplicate) => {
                self.queued_for_closure.push(duplicate);
                drop(descriptor_table);
                self.attempt_to_close_queued();
            }
            super::fd::CloseResult::Deferred => unreachable!(),
        }
        Ok(())
    }

    /// Attempt to close as many queued FDs as possible.
    fn attempt_to_close_queued(&mut self) -> bool {
        if self.queued_for_closure.is_empty() {
            return false;
        }
        let mut descriptor_table = self.litebox.descriptor_table_mut();
        let entries = descriptor_table.drain_entries_full_covered_by(&mut self.queued_for_closure);
        drop(descriptor_table);
        if entries.is_empty() {
            return false;
        }
        for entry in entries {
            Self::close_handle(entry.entry);
        }
        true
    }

    /// Completes socket closures that were deferred while descriptor entries were in use.
    pub fn finish_deferred_closes(&mut self) -> bool {
        self.attempt_to_close_queued();
        !self.queued_for_closure.is_empty()
    }

    fn close_handle(socket_handle: SocketHandle<Platform>) {
        let SocketHandle {
            broker_socket,
            immediate_close,
            proxy: _,
        } = socket_handle;
        match broker_socket {
            BrokerSocket::Tcp(socket) => socket.close(immediate_close.load(Ordering::SeqCst)),
            BrokerSocket::Udp(socket) => socket.close(),
        }
    }

    /// Initiate a connection to an IP address.
    ///
    /// When `check_progress` is false, this function attempts to initiate a connection.
    /// Otherwise, this function checks the progress of an ongoing connection.
    pub fn connect(
        &mut self,
        fd: &SocketFd<Platform>,
        addr: &SocketAddr,
        check_progress: bool,
    ) -> Result<(), ConnectError> {
        let SocketAddr::V4(addr) = addr else {
            return Err(ConnectError::UnsupportedAddress(*addr));
        };

        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(ConnectError::InvalidFd)?;
        match &entry.entry.broker_socket {
            BrokerSocket::Tcp(socket) => {
                if check_progress {
                    socket.check_connect_progress()
                } else {
                    socket.start_connect(*addr)
                }
            }
            BrokerSocket::Udp(socket) => {
                if check_progress {
                    socket.check_connect_progress()
                } else {
                    socket.start_connect(*addr)
                }
            }
        }
    }

    /// Get the local address and port a socket is bound to.
    pub fn get_local_addr(&self, fd: &SocketFd<Platform>) -> Result<SocketAddr, LocalAddrError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(LocalAddrError::InvalidFd)?;
        Ok(match &entry.entry.broker_socket {
            BrokerSocket::Tcp(socket) => socket.local_addr(),
            BrokerSocket::Udp(socket) => socket.local_addr(),
        })
    }

    /// Get the remote address and port a socket is connected to, if any.
    pub fn get_remote_addr(&self, fd: &SocketFd<Platform>) -> Result<SocketAddr, RemoteAddrError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(RemoteAddrError::InvalidFd)?;
        Self::get_remote_addr_for_handle(&entry.entry)
    }

    /// Shuts down one or both directions of a socket.
    pub fn shutdown(
        &self,
        fd: &SocketFd<Platform>,
        direction: ShutdownDirection,
    ) -> Result<(), errors::ShutdownError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(errors::ShutdownError::InvalidFd)?;
        let mode = match direction {
            ShutdownDirection::Read => litebox_broker_protocol::socket::ShutdownMode::Read,
            ShutdownDirection::Write => litebox_broker_protocol::socket::ShutdownMode::Write,
            ShutdownDirection::Both => litebox_broker_protocol::socket::ShutdownMode::Both,
        };
        match &entry.entry.broker_socket {
            BrokerSocket::Tcp(socket) => {
                if socket.is_listening() {
                    return Err(errors::ShutdownError::Listening);
                }
                socket.shutdown(mode)
            }
            BrokerSocket::Udp(socket) => socket.shutdown(mode),
        }
        .map_err(errors::ShutdownError::OperationFailed)
    }

    /// Stops a listener without closing its socket object.
    pub fn stop_listening(&self, fd: &SocketFd<Platform>) -> Result<(), errors::ShutdownError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(errors::ShutdownError::InvalidFd)?;
        let BrokerSocket::Tcp(socket) = &entry.entry.broker_socket else {
            return Err(errors::ShutdownError::UnsupportedOperation);
        };
        if !socket.is_listening() {
            return Err(errors::ShutdownError::OperationFailed(
                errors::SocketAsyncError::NotConnected,
            ));
        }
        socket
            .stop_listening()
            .map_err(errors::ShutdownError::OperationFailed)
    }

    fn get_remote_addr_for_handle(
        socket_handle: &SocketHandle<Platform>,
    ) -> Result<SocketAddr, RemoteAddrError> {
        match &socket_handle.broker_socket {
            BrokerSocket::Tcp(socket) => socket.remote_addr(),
            BrokerSocket::Udp(socket) => socket.remote_addr(),
        }
    }

    /// Bind a socket to a specific address and port.
    pub fn bind(
        &mut self,
        fd: &SocketFd<Platform>,
        socket_addr: &SocketAddr,
    ) -> Result<(), BindError> {
        let SocketAddr::V4(addr) = socket_addr else {
            return Err(BindError::UnsupportedAddress(*socket_addr));
        };

        let descriptor_table = self.litebox.descriptor_table();
        let entry_handle = descriptor_table
            .entry_handle(fd)
            .ok_or(BindError::InvalidFd)?;
        let entry = descriptor_table.get_entry(fd).ok_or(BindError::InvalidFd)?;
        let socket = entry.entry.broker_socket.clone();
        drop(entry);
        drop(descriptor_table);
        let result = match socket {
            BrokerSocket::Tcp(socket) => socket.bind(*addr),
            BrokerSocket::Udp(socket) => socket.bind(*addr),
        };
        drop(entry_handle);
        result
    }

    /// Prepare a socket to accept incoming connections.
    pub fn listen(&mut self, fd: &SocketFd<Platform>, backlog: u16) -> Result<(), ListenError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry_handle = descriptor_table
            .entry_handle(fd)
            .ok_or(ListenError::InvalidFd)?;
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(ListenError::InvalidFd)?;
        let BrokerSocket::Tcp(socket) = &entry.entry.broker_socket else {
            return Err(ListenError::UnsupportedOperation);
        };
        let socket = Arc::clone(socket);
        drop(entry);
        drop(descriptor_table);
        let result = socket.listen(
            u32::from(backlog).min(litebox_broker_protocol::socket::MAX_TCP_LISTEN_BACKLOG),
        );
        drop(entry_handle);
        result
    }

    /// Accept a new incoming connection on a listening socket.
    ///
    /// If `peer` is provided, it is filled with the remote address of the accepted connection.
    ///
    /// The returned socket has no associated proxy; use
    /// [`attach_socket_proxy`](Self::attach_socket_proxy) to attach one.
    pub fn accept(
        &mut self,
        fd: &SocketFd<Platform>,
        peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd<Platform>, AcceptError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry_handle = descriptor_table
            .entry_handle(fd)
            .ok_or(AcceptError::InvalidFd)?;
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(AcceptError::InvalidFd)?;
        let BrokerSocket::Tcp(listener) = &entry.entry.broker_socket else {
            return Err(AcceptError::UnsupportedOperation);
        };
        let listener = Arc::clone(listener);
        drop(entry);
        drop(descriptor_table);
        let accepted = listener.accept()?;
        drop(entry_handle);
        if let Some(peer) = peer {
            *peer = accepted.remote_addr().map_err(|_| {
                AcceptError::OperationFailed(errors::SocketAsyncError::BackendFailure)
            })?;
        }
        Ok(self.litebox.descriptor_table_mut().insert(SocketHandle {
            broker_socket: BrokerSocket::Tcp(accepted),
            immediate_close: AtomicBool::new(false),
            proxy: None,
        }))
    }

    /// Send data over a socket, optionally specifying the destination address.
    pub fn send(
        &mut self,
        fd: &SocketFd<Platform>,
        buf: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddr>,
    ) -> Result<usize, SendError> {
        if !flags.is_empty() {
            unimplemented!()
        }
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd).ok_or(SendError::InvalidFd)?;
        let outcome = match &entry.entry.broker_socket {
            BrokerSocket::Tcp(socket) => {
                if destination.is_some() {
                    return Err(SendError::UnnecessaryDestinationAddress);
                }
                socket.try_write(buf)
            }
            BrokerSocket::Udp(socket) => socket.try_write(buf, destination),
        };
        outcome.map_err(|error| match error {
            socket_channel::ChannelWriteError::BufferFull => SendError::BufferFull,
            socket_channel::ChannelWriteError::MessageTooLong => SendError::MessageTooLong,
            socket_channel::ChannelWriteError::Unaddressable => SendError::Unaddressable,
            socket_channel::ChannelWriteError::DestinationAddressRequired => {
                SendError::DestinationAddressRequired
            }
            socket_channel::ChannelWriteError::WriteShutdown
            | socket_channel::ChannelWriteError::NotConnected
            | socket_channel::ChannelWriteError::ConnectionClosed
            | socket_channel::ChannelWriteError::Socket(_) => SendError::SocketInInvalidState,
        })
    }

    /// Receive data from a socket.
    pub fn receive(
        &mut self,
        fd: &SocketFd<Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, ReceiveError> {
        if flags.intersects(
            (ReceiveFlags::DONTWAIT | ReceiveFlags::TRUNC | ReceiveFlags::DISCARD).complement(),
        ) {
            unimplemented!("flags: {:?}", flags);
        }
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(ReceiveError::InvalidFd)?;
        let outcome = match &entry.entry.broker_socket {
            BrokerSocket::Tcp(socket) => socket.try_read(buf, flags, source_addr),
            BrokerSocket::Udp(socket) => socket.try_read(buf, flags, source_addr).map(|received| {
                if flags.intersects(ReceiveFlags::TRUNC | ReceiveFlags::DISCARD) {
                    received
                } else {
                    received.min(buf.len())
                }
            }),
        };
        outcome.or_else(|error| match error {
            socket_channel::ChannelReadError::WouldBlock => Ok(0),
            socket_channel::ChannelReadError::ReadShutdown
            | socket_channel::ChannelReadError::ConnectionClosed => {
                Err(ReceiveError::OperationFinished)
            }
            socket_channel::ChannelReadError::NotConnected
            | socket_channel::ChannelReadError::Socket(_) => {
                Err(ReceiveError::SocketInInvalidState)
            }
        })
    }

    /// Set TCP options.
    pub fn set_tcp_option(
        &mut self,
        fd: &SocketFd<Platform>,
        data: TcpOptionData,
    ) -> Result<(), errors::SetTcpOptionError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry_handle = descriptor_table
            .entry_handle(fd)
            .ok_or(errors::SetTcpOptionError::InvalidFd)?;
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(errors::SetTcpOptionError::InvalidFd)?;
        let BrokerSocket::Tcp(socket) = &entry.entry.broker_socket else {
            return Err(errors::SetTcpOptionError::NotTcpSocket);
        };
        let socket = Arc::clone(socket);
        drop(entry);
        drop(descriptor_table);
        let result = socket.set_tcp_option(data);
        drop(entry_handle);
        result
    }

    /// Get TCP options.
    pub fn get_tcp_option(
        &self,
        fd: &SocketFd<Platform>,
        name: TcpOptionName,
    ) -> Result<TcpOptionData, errors::GetTcpOptionError> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry_handle = descriptor_table
            .entry_handle(fd)
            .ok_or(errors::GetTcpOptionError::InvalidFd)?;
        let entry = descriptor_table
            .get_entry(fd)
            .ok_or(errors::GetTcpOptionError::InvalidFd)?;
        let BrokerSocket::Tcp(socket) = &entry.entry.broker_socket else {
            return Err(errors::GetTcpOptionError::NotTcpSocket);
        };
        let socket = Arc::clone(socket);
        drop(entry);
        drop(descriptor_table);
        let result = socket.get_tcp_option(name);
        drop(entry_handle);
        result
    }
}

/// Protocols for sockets supported by LiteBox.
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw { protocol: u8 },
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

/// Socket options for TCP.
#[non_exhaustive]
pub enum TcpOptionName {
    /// If set, disable the Nagle algorithm.
    NODELAY,
    /// Enable sending of keep-alive messages.
    KEEPALIVE,
    /// Interval between keep-alive probes.
    KEEPINTVL,
    /// TCP congestion control algorithm.
    CONGESTION,
}

/// Data for TCP options.
#[non_exhaustive]
pub enum TcpOptionData {
    NODELAY(bool),
    KEEPALIVE(bool),
    KEEPINTVL(Option<core::time::Duration>),
    CONGESTION(CongestionControl),
}

/// TCP congestion control algorithms.
#[non_exhaustive]
pub enum CongestionControl {
    None,
    Reno,
    Cubic,
}

#[derive(Debug, Clone, Copy)]
pub enum CloseBehavior {
    /// Close the socket immediately (i.e., abortive close).
    Immediate,
    /// Close the socket gracefully.
    Graceful,
    /// Close gracefully only if no data is pending transmission.
    ///
    /// Broker socket operations are synchronous, so this is equivalent to [`Self::Graceful`].
    GracefulIfNoPendingData,
}

crate::fd::enable_fds_for_subsystem! {
    @Platform: { TimeProvider + sync::RawSyncPrimitivesProvider };
    Network<Platform>;
    @Platform: { TimeProvider + sync::RawSyncPrimitivesProvider };
    SocketHandle<Platform>;
    -> SocketFd<Platform>;
}
