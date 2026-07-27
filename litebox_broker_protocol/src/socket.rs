// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed values for broker-mediated network sockets.
//!
//! These describe what a local endpoint may ask the broker to do with a socket,
//! never how the broker does it: no descriptor, poll registration, or platform
//! error appears here. Every value is a closed set rather than a passthrough
//! integer, so a local endpoint cannot name an address family, type, protocol,
//! or flag the broker has not agreed to support.

use crate::ObjectHandle;
use crate::shared_buffer::SharedBufferDescriptor;
use thiserror::Error;

/// Address family of a broker socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
}

/// Communication semantics of a broker socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketType {
    /// Reliable ordered byte stream.
    Stream,
}

/// IP protocol carried by a broker socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpProtocol {
    /// TCP.
    Tcp,
}

/// Which directions of a socket to shut down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShutdownMode {
    /// Further receives return end of stream.
    Read,
    /// The peer sees end of stream.
    Write,
    /// Both directions.
    Both,
}

/// IPv4 address in network byte order.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Address(pub [u8; 4]);

/// Transport port in host byte order.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(pub u16);

/// IPv4 socket address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketAddressV4 {
    /// IPv4 address.
    pub address: Ipv4Address,
    /// Transport port.
    pub port: Port,
}

/// Flags for a send operation.
///
/// Send and receive flags are separate types because their underlying flag sets
/// are disjoint: a receive-only flag such as [`ReceiveFlags::PEEK`] is
/// meaningless on a send, and one shared type would let a local endpoint name it
/// there.
///
/// Like [`ReceiveFlags`] and unlike [`ReadinessFlags`], which preserves bits a
/// peer may not understand, this is bounded: flags are forwarded to a host
/// socket operation, so a bit the broker does not recognize must never reach
/// one. [`Self::SUPPORTED`] defines the bound as part of the ABI, and the broker
/// rejects anything outside it rather than masking it away, which would silently
/// perform an operation the caller did not ask for.
///
/// No send flag is supported yet, so any nonzero value is rejected.
///
/// [`ReadinessFlags`]: crate::readiness::ReadinessFlags
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendFlags(pub u32);

impl SendFlags {
    /// No flags.
    pub const NONE: Self = Self(0);

    /// Every send flag this protocol version defines.
    pub const SUPPORTED: Self = Self(0);

    /// Returns whether any bit outside [`Self::SUPPORTED`] is set.
    #[must_use]
    pub const fn has_unsupported_bits(self) -> bool {
        self.0 & !Self::SUPPORTED.0 != 0
    }
}

/// Flags for a receive operation.
///
/// See [`SendFlags`] for why the two directions are separate types and why both
/// are bounded rather than passthrough.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiveFlags(pub u32);

impl ReceiveFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Return data without consuming it.
    pub const PEEK: Self = Self(1 << 0);

    /// Every receive flag this protocol version defines.
    pub const SUPPORTED: Self = Self(Self::PEEK.0);

    /// Returns whether any bit outside [`Self::SUPPORTED`] is set.
    #[must_use]
    pub const fn has_unsupported_bits(self) -> bool {
        self.0 & !Self::SUPPORTED.0 != 0
    }

    /// Returns whether every flag in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Reason a socket operation failed.
///
/// This is a bounded restatement of the network failures a host stack reports,
/// kept separate from [`ErrorCode`] because those describe how the broker
/// handled a request, not what a remote peer or network did. Keeping them apart
/// also means adding a network failure never widens the error type every broker
/// operation can return.
///
/// [`ErrorCode`]: crate::error::ErrorCode
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketError {
    /// The peer refused the connection.
    #[error("connection refused")]
    ConnectionRefused,
    /// The connection was reset by the peer.
    #[error("connection reset")]
    ConnectionReset,
    /// The connection was aborted before it completed.
    #[error("connection aborted")]
    ConnectionAborted,
    /// No route to the network.
    #[error("network unreachable")]
    NetworkUnreachable,
    /// No route to the host.
    #[error("host unreachable")]
    HostUnreachable,
    /// The connection attempt timed out.
    #[error("connection timed out")]
    TimedOut,
    /// The address is already in use.
    #[error("address already in use")]
    AddressInUse,
    /// The address is not available on this host.
    #[error("address not available")]
    AddressNotAvailable,
    /// The policy engine refused the destination.
    #[error("socket policy denied the operation")]
    PolicyDenied,
    /// The host stack failed in a way this protocol does not distinguish.
    #[error("other socket error")]
    Other,
}

impl SocketError {
    /// Raw socket error values are part of the broker wire ABI.
    ///
    /// Value `0` is unassigned so a zero-filled value never represents a
    /// concrete network failure.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::ConnectionRefused),
            2 => Some(Self::ConnectionReset),
            3 => Some(Self::ConnectionAborted),
            4 => Some(Self::NetworkUnreachable),
            5 => Some(Self::HostUnreachable),
            6 => Some(Self::TimedOut),
            7 => Some(Self::AddressInUse),
            8 => Some(Self::AddressNotAvailable),
            9 => Some(Self::PolicyDenied),
            10 => Some(Self::Other),
            _ => None,
        }
    }

    /// Returns the raw broker wire ABI value.
    pub const fn as_raw(self) -> u8 {
        match self {
            Self::ConnectionRefused => 1,
            Self::ConnectionReset => 2,
            Self::ConnectionAborted => 3,
            Self::NetworkUnreachable => 4,
            Self::HostUnreachable => 5,
            Self::TimedOut => 6,
            Self::AddressInUse => 7,
            Self::AddressNotAvailable => 8,
            Self::PolicyDenied => 9,
            Self::Other => 10,
        }
    }
}

/// Request to create a broker-owned socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateSocketRequest {
    /// Address family.
    pub address_family: AddressFamily,
    /// Communication semantics.
    pub socket_type: SocketType,
    /// Transport protocol.
    pub protocol: IpProtocol,
}

/// Response to a socket create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateSocketResponse {
    /// Handle naming the new socket.
    pub handle: ObjectHandle,
}

/// Request to connect a socket to a remote address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Remote address to connect to.
    pub address: SocketAddressV4,
}

/// Response to a socket connect request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectSocketResponse {
    /// Connection state after the nonblocking attempt.
    pub status: SocketConnectionStatus,
}

/// Broker-authoritative socket connection state.
///
/// The broker only performs non-blocking operations, so a connect that cannot
/// complete immediately reports [`Self::Connecting`] rather than waiting. The
/// caller waits for write readiness and then reads the authoritative state with
/// a status request.
///
/// Connected and failed states are terminal and idempotent: repeated status
/// requests return the same state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketConnectionStatus {
    /// No connection attempt has started.
    Unconnected,
    /// The connection is still being established.
    Connecting,
    /// The connection is established.
    Connected,
    /// The connection attempt failed.
    Failed(SocketError),
}

/// Request to send bytes staged in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer region containing the staged bytes.
    pub buffer: SharedBufferDescriptor,
    /// Send flags.
    pub flags: SendFlags,
}

/// Response describing a completed send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendSocketResponse {
    /// Number of bytes accepted by the socket.
    pub sent: u32,
}

/// Request to receive bytes into shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer region to receive the bytes.
    pub buffer: SharedBufferDescriptor,
    /// Receive flags.
    pub flags: ReceiveFlags,
}

/// Response to a socket receive request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiveSocketResponse {
    /// Number of bytes placed in the receive region.
    ///
    /// Zero is the successful result of a zero-length request. A socket with
    /// nothing to read yet reports [`ErrorCode::WouldBlock`] instead.
    ///
    /// [`ErrorCode::WouldBlock`]: crate::error::ErrorCode::WouldBlock
    Received(u32),
    /// The socket's receive direction reached end of stream.
    EndOfStream,
}

/// Request to shut down one or both directions of a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Directions to shut down.
    pub mode: ShutdownMode,
}

/// Request for a socket's connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketStatusRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
}

/// Response describing a socket's broker-authoritative connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketStatusResponse {
    /// Current connection state.
    pub status: SocketConnectionStatus,
}
