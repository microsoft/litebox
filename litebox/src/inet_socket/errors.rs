// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Possible errors from [`InetSocket`] operations

use core::net::SocketAddr;

#[expect(
    unused_imports,
    reason = "used for doc string links to work out, but not for code"
)]
use super::InetSocket;

use thiserror::Error;

/// Possible errors from [`LiteBox::create_inet_socket`](crate::LiteBox::create_inet_socket)
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SocketError {
    #[error("Unsupported socket type")]
    UnsupportedType,
    #[error("Brokered networking is unavailable")]
    BrokerUnavailable,
    #[error("Socket resources are exhausted")]
    ResourceExhausted,
    #[error("Socket creation was denied")]
    PermissionDenied,
    #[error("Socket backend failed to create the socket")]
    BackendFailure,
}

/// Possible errors from [`InetSocket::shutdown`] and [`InetSocket::stop_listening`]
#[non_exhaustive]
#[derive(Error, Clone, Copy, Debug)]
pub enum ShutdownError {
    #[error("Socket is listening for connections")]
    Listening,
    #[error("Shutdown is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`InetSocket::connect`]
#[non_exhaustive]
#[derive(Error, Clone, Copy, Debug)]
pub enum ConnectError {
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Connection is still in progress")]
    InProgress,
    #[error("An earlier connection attempt is still in progress")]
    AlreadyInProgress,
    #[error("Socket is already connected")]
    AlreadyConnected,
    #[error("Socket is in an invalid state")]
    InvalidState,
    #[error("Connection timed out")]
    TimedOut,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`InetSocket::remote_addr`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RemoteAddrError {
    #[error("Socket is not connected")]
    NotConnected,
}

/// Possible errors from [`InetSocket::bind`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum BindError {
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Port {0} already in use")]
    PortAlreadyInUse(u16),
    #[error("Binding is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`InetSocket::listen`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ListenError {
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Socket is in invalid state")]
    InvalidState,
    #[error("Listening is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`InetSocket::accept`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum AcceptError {
    #[error("🙉 Socket is not listening for connections")]
    NotListening,
    #[error("No connections ready to be accepted")]
    NoConnectionsReady,
    #[error("No connections ready to be accepted on a nonblocking socket")]
    NonBlocking,
    #[error("Accepting connections is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`InetSocket::try_read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketReadError {
    /// The local read side has been shut down.
    ReadShutdown,
    /// No data is currently available.
    WouldBlock,
    /// No data is currently available, and the socket is nonblocking.
    NonBlocking,
    /// The stream has not reached a connected state.
    NotConnected,
    /// The stream is closed.
    ConnectionClosed,
    /// The host network operation failed.
    Socket(SocketAsyncError),
}

/// Possible errors from [`InetSocket::try_write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketWriteError {
    /// The local write side has been shut down.
    WriteShutdown,
    /// The stream has not reached a connected state.
    NotConnected,
    /// The stream is closed.
    ConnectionClosed,
    /// The destination address cannot be used.
    Unaddressable,
    /// The transmit buffer is full.
    BufferFull,
    /// The transmit buffer is full, and the socket is nonblocking.
    NonBlocking,
    /// The datagram exceeds the protocol maximum.
    MessageTooLong,
    /// A destination address is required but was not provided.
    DestinationAddressRequired,
    /// The host network operation failed.
    Socket(SocketAsyncError),
}

crate::utilities::macros::repr_enum! {
    /// Asynchronous socket errors
    #[non_exhaustive]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SocketAsyncError: u32, from_u32 {
        /// Connection was refused by the remote host (e.g., RST received during SYN).
        ConnectionRefused = 1,
        /// An established connection was reset by the remote host.
        ConnectionReset = 2,
        /// Connection timed out (e.g., SYN retransmission timeout expired without response).
        TimedOut = 3,
        /// The connection was aborted before it completed.
        ConnectionAborted = 4,
        /// No route to the network exists.
        NetworkUnreachable = 5,
        /// No route to the host exists.
        HostUnreachable = 6,
        /// The requested address is already in use.
        AddressInUse = 7,
        /// The requested address is unavailable.
        AddressNotAvailable = 8,
        /// The socket is not connected.
        NotConnected = 9,
        /// Policy denied the socket operation.
        PolicyDenied = 10,
        /// Socket resources are exhausted.
        ResourceExhausted = 11,
        /// The socket operation is unsupported.
        UnsupportedOperation = 12,
        /// The broker association or host socket failed.
        BackendFailure = 13,
        /// An argument or socket state is invalid for the operation.
        InvalidArgument = 14,
    }
}
