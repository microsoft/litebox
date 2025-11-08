//! Possible errors from [`Network`]

use core::net::SocketAddr;

use super::local_ports::LocalPortAllocationError;

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
}

/// Possible errors from [`Network::close`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum CloseError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
}

/// Possible errors from [`Network::connect`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Port allocation failed: {0}")]
    PortAllocationFailure(#[from] LocalPortAllocationError),
    #[error("Invalid address")]
    Unaddressable,
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
    #[error("No available free ephemeral ports")]
    NoAvailableFreeEphemeralPorts,
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
    #[error("port allocation failed: {0}")]
    PortAllocationFailure(#[from] LocalPortAllocationError),
    #[error("unnecessary destination address provided")]
    UnnecessaryDestinationAddress,
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

/// Possible errors from [`Network::set_tcp_option`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SetTcpOptionError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Not a TCP socket")]
    NotTcpSocket,
}
/// Possible errors from [`Network::get_tcp_option`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum GetTcpOptionError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Not a TCP socket")]
    NotTcpSocket,
}
