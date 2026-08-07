// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Possible errors from [`Network`]

use core::net::SocketAddr;

#[expect(
    unused_imports,
    reason = "used for doc string links to work out, but not for code"
)]
use super::Network;

use thiserror::Error;

/// Possible errors from [`Network::socket`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SocketError {
    #[error("Unsupported protocol {0}")]
    UnsupportedProtocol(u8),
    #[error("Brokered networking is unavailable")]
    BrokerUnavailable,
    #[error("Socket resources are exhausted")]
    ResourceExhausted,
    #[error("Socket creation was denied")]
    PermissionDenied,
    #[error("Socket backend failed to create the socket")]
    BackendFailure,
}

/// Possible errors from [`Network::close`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum CloseError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket closed with data still pending transmission")]
    DataPending,
}

/// Possible errors from [`Network::shutdown`]
#[non_exhaustive]
#[derive(Error, Clone, Copy, Debug)]
pub enum ShutdownError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket is listening for connections")]
    Listening,
    #[error("Shutdown is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`Network::connect`]
#[non_exhaustive]
#[derive(Error, Clone, Copy, Debug)]
pub enum ConnectError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Invalid address")]
    Unaddressable,
    #[error("Connection is still in progress")]
    InProgress,
    #[error("Socket is in an invalid state")]
    InvalidState,
    #[error("Connection timed out")]
    TimedOut,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`Network::get_local_addr`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum LocalAddrError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
}

/// Possible errors from [`Network::get_remote_addr`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum RemoteAddrError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket is not connected")]
    NotConnected,
}

/// Possible errors from [`Network::bind`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum BindError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Port {0} already in use")]
    PortAlreadyInUse(u16),
    #[error("Already bound to an address")]
    AlreadyBound,
    #[error("Binding is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`Network::listen`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ListenError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Socket is in invalid state")]
    InvalidState,
    #[error("Listening is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`Network::accept`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum AcceptError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("🙉 Socket is not listening for connections")]
    NotListening,
    #[error("No connections ready to be accepted")]
    NoConnectionsReady,
    #[error("Accepting connections is unsupported for this socket")]
    UnsupportedOperation,
    #[error("Socket operation failed: {0:?}")]
    OperationFailed(SocketAsyncError),
}

/// Possible errors from [`Network::send`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SendError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket is in an invalid state")]
    SocketInInvalidState,
    #[error("Destination address is unaddressable")]
    Unaddressable,
    #[error("Buffer is full")]
    BufferFull,
    #[error("Datagram is too large")]
    MessageTooLong,
    #[error("unnecessary destination address provided")]
    UnnecessaryDestinationAddress,
    #[error("destination address required but not provided")]
    DestinationAddressRequired,
}

/// Possible errors from [`Network::receive`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReceiveError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket is in an invalid state")]
    SocketInInvalidState,
    #[error("Operation finished")]
    OperationFinished,
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

/// Possible errors from [`Network::set_tcp_option`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SetTcpOptionError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Not a TCP socket")]
    NotTcpSocket,
    #[error("TCP option is unsupported by this socket backend")]
    Unsupported,
    #[error("TCP socket backend failed")]
    BackendFailure,
}
/// Possible errors from [`Network::get_tcp_option`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum GetTcpOptionError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Not a TCP socket")]
    NotTcpSocket,
    #[error("TCP option is unsupported by this socket backend")]
    Unsupported,
    #[error("TCP socket backend failed")]
    BackendFailure,
}
