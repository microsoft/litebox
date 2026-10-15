// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Typed values for broker-mediated network sockets.
//!
//! These describe what a local endpoint may ask the broker to do with a socket,
//! never how the broker does it: no descriptor, poll registration, or platform
//! error appears here. Every value is a closed set rather than a passthrough
//! integer, so a local endpoint cannot name an address family, type, protocol,
//! or flag the broker has not agreed to support.

use core::net::SocketAddrV4;
use core::time::Duration;

use crate::ObjectHandle;
use crate::fs::FileOpenFlags;
use crate::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence};
use thiserror::Error;

/// Maximum socket bytes transferred by one broker request.
///
/// This remains independent of slot capacity so increasing the shared-buffer
/// layout does not change existing TCP behavior.
pub const MAX_SOCKET_TRANSFER_SIZE: u32 = 32 * 1024;

const _: () = assert!(MAX_SOCKET_TRANSFER_SIZE <= SHARED_BUFFER_SLOT_SIZE);

/// Maximum bytes carried by one IPv4 UDP datagram.
///
/// A complete datagram fits in one association shared-buffer slot, preserving
/// datagram atomicity across the broker boundary.
pub const MAX_UDP_DATAGRAM_SIZE: u32 = 65_507;

const _: () = assert!(MAX_UDP_DATAGRAM_SIZE <= SHARED_BUFFER_SLOT_SIZE);

/// Maximum stream prefix addressable by offset-based peek requests.
pub const MAX_SOCKET_PEEK_SIZE: u32 = 0x80_000;
/// Maximum TCP listen backlog accepted by the broker protocol.
pub const MAX_TCP_LISTEN_BACKLOG: u32 = 4096;

/// Address family of a broker socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
}

/// Communication semantics of a broker socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SocketType {
    /// Reliable ordered byte stream.
    Stream,
    /// Message-oriented datagrams.
    Datagram,
}

/// IP protocol carried by a broker socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// How to stop I/O on a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShutdownMode {
    /// Disables further receives.
    Read,
    /// Disables further sends.
    Write,
    /// Both directions.
    Both,
    /// The final TCP close discards queued data and resets the connection.
    Abort,
    /// Stops accepting new TCP connections while retaining the socket object.
    StopListening,
}

/// Socket option name, shared by internet and Unix sockets.
///
/// Every reference to a socket shares its options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOptionName {
    /// Longest time a blocking receive or accept waits.
    ReceiveTimeout,
    /// Longest time a blocking send or connect waits.
    SendTimeout,
    /// Linger time on close.
    Linger,
    /// Whether address reuse was requested.
    ReuseAddress,
    /// Whether keepalive was requested, which enables keepalive probes on a
    /// TCP socket.
    KeepAlive,
    /// Whether broadcast was requested.
    Broadcast,
    /// Whether Nagle's algorithm is disabled, which only TCP sockets support.
    NoDelay,
}

/// Socket option value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOptionValue {
    /// [`SocketOptionName::ReceiveTimeout`], or `None` to wait indefinitely.
    ReceiveTimeout(Option<Duration>),
    /// [`SocketOptionName::SendTimeout`], or `None` to wait indefinitely.
    SendTimeout(Option<Duration>),
    /// [`SocketOptionName::Linger`], or `None` to close in the background.
    Linger(Option<Duration>),
    /// [`SocketOptionName::ReuseAddress`].
    ReuseAddress(bool),
    /// [`SocketOptionName::KeepAlive`].
    KeepAlive(bool),
    /// [`SocketOptionName::Broadcast`].
    Broadcast(bool),
    /// [`SocketOptionName::NoDelay`].
    NoDelay(bool),
}

impl SocketOptionValue {
    /// Returns the name of the option this value sets.
    pub fn name(self) -> SocketOptionName {
        match self {
            Self::ReceiveTimeout(_) => SocketOptionName::ReceiveTimeout,
            Self::SendTimeout(_) => SocketOptionName::SendTimeout,
            Self::Linger(_) => SocketOptionName::Linger,
            Self::ReuseAddress(_) => SocketOptionName::ReuseAddress,
            Self::KeepAlive(_) => SocketOptionName::KeepAlive,
            Self::Broadcast(_) => SocketOptionName::Broadcast,
            Self::NoDelay(_) => SocketOptionName::NoDelay,
        }
    }
}

/// IPv4 address in network byte order.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Address(pub [u8; 4]);

/// Transport port in host byte order.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(pub u16);

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
    /// Wait for the requested amount of peeked data when the operation may block.
    pub const WAITALL: Self = Self(1 << 1);

    /// Every receive flag this protocol version defines.
    pub const SUPPORTED: Self = Self(Self::PEEK.0 | Self::WAITALL.0);

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

/// Flags for receiving one datagram.
///
/// Stream-only flags such as [`ReceiveFlags::WAITALL`] are intentionally not
/// representable on this operation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiveFromFlags(pub u32);

impl ReceiveFromFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Return the next datagram without consuming it.
    pub const PEEK: Self = Self(1 << 0);

    /// Every datagram receive flag this protocol version defines.
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
    /// The operation requires a connected socket.
    #[error("socket is not connected")]
    NotConnected,
    /// An argument or socket state is invalid for the operation.
    #[error("invalid socket operation argument")]
    InvalidArgument,
    /// The policy engine refused the destination.
    #[error("socket policy denied the operation")]
    PolicyDenied,
    /// The host stack failed in a way this protocol does not distinguish.
    #[error("other socket error")]
    Other,
    /// The socket is already connected.
    #[error("socket is already connected")]
    AlreadyConnected,
    /// A connection attempt is already in progress.
    #[error("connection already in progress")]
    AlreadyInProgress,
    /// The direction the operation needs has been shut down.
    #[error("socket direction is shut down")]
    Shutdown,
    /// A datagram send on an unconnected socket named no destination.
    #[error("destination address required")]
    DestinationAddressRequired,
    /// The operation is not valid on a listening socket.
    #[error("socket is listening")]
    Listening,
    /// Socket resources are exhausted.
    #[error("socket resources exhausted")]
    ResourceExhausted,
    /// The socket does not support the operation.
    #[error("socket operation unsupported")]
    UnsupportedOperation,
}

/// Result of a socket operation that can fail with an ordinary network outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum SocketOutcome<T> {
    /// The operation completed successfully.
    Completed(T),
    /// The host network stack reported an ordinary socket failure.
    Failed(SocketError),
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
    /// Initial status flags, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
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
    pub address: SocketAddrV4,
}

/// Response to a socket connect request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectSocketResponse {
    /// Connection state after the nonblocking attempt.
    pub status: SocketConnectionStatus,
}

/// Request to bind a socket to a local IPv4 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Requested local address. Port zero requests an ephemeral port.
    pub address: SocketAddrV4,
}

/// Response to a socket bind request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindSocketResponse {
    /// Local address assigned by the host network stack.
    pub local_address: SocketAddrV4,
}

/// Request to make a bound socket listen for connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Maximum pending connection backlog.
    pub backlog: u32,
}

/// Response to a socket listen request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenSocketResponse {
    /// Local address assigned by the host network stack.
    pub local_address: SocketAddrV4,
}

/// Request to accept one pending connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptSocketRequest {
    /// Listening socket handle.
    pub handle: ObjectHandle,
    /// Status flags of the accepted socket, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
}

/// Response containing one accepted broker socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptSocketResponse {
    /// Handle naming the accepted socket.
    pub handle: ObjectHandle,
    /// Local endpoint of the accepted connection.
    pub local_address: SocketAddrV4,
    /// Remote endpoint of the accepted connection.
    pub remote_address: SocketAddrV4,
}

/// Broker-authoritative socket connection state.
///
/// The broker only performs non-blocking operations, so a connect that cannot
/// complete immediately reports [`Self::Connecting`] rather than waiting. The
/// caller waits for write readiness and then finishes the attempt with a
/// check-connect request.
///
/// Connect and check-connect responses report a failed attempt as an
/// operation failure, so they never carry [`Self::Failed`]. Datagram connects
/// complete immediately and may replace an existing peer.
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
    pub buffer: SharedBufferSequence,
    /// Send flags.
    pub flags: SendFlags,
}

/// Response describing a completed send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendSocketResponse {
    /// Number of bytes accepted by the socket.
    pub sent: u32,
}

/// Request to send one datagram staged in shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendToSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer region containing the complete datagram.
    pub buffer: SharedBufferSequence,
    /// Send flags.
    pub flags: SendFlags,
    /// Explicit destination, or `None` to use the connected peer.
    pub destination: Option<SocketAddrV4>,
}

/// Response describing a completed atomic datagram send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendToSocketResponse {
    /// Number of bytes accepted by the socket.
    pub sent: u32,
}

/// Request to receive bytes into shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer region to receive the bytes.
    pub buffer: SharedBufferSequence,
    /// Receive flags.
    pub flags: ReceiveFlags,
    /// Byte offset from the start of the stream for a peek request.
    pub peek_offset: u32,
    /// Total stream prefix covered by this logical peek.
    pub peek_length: u32,
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

/// Request to receive one datagram into shared memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveFromSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Leased shared-buffer receive region.
    pub buffer: SharedBufferSequence,
    /// Datagram receive flags.
    pub flags: ReceiveFromFlags,
}

/// Response describing one received datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveFromSocketResponse {
    /// Number of bytes copied into the shared-buffer region.
    pub received: u32,
    /// Original datagram length before any truncation.
    pub datagram_length: u32,
    /// Source address of the datagram.
    pub source_address: SocketAddrV4,
}

/// Request to shut down one or both directions of a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Directions to shut down.
    pub mode: ShutdownMode,
}

/// Request to set a socket option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetSocketOptionRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Option value to apply.
    pub value: SocketOptionValue,
}

/// Request to read a socket option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetSocketOptionRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Option name to read.
    pub name: SocketOptionName,
}

/// Response containing a socket option value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetSocketOptionResponse {
    /// Stored option value.
    pub value: SocketOptionValue,
}

/// Request to check the progress of a socket's connection attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckConnectSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
}

/// Request for the local or peer address of a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetSocketNameRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Whether to read the peer's address instead of the socket's own.
    pub peer: bool,
}

/// Response containing a socket address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetSocketNameResponse {
    /// Requested address, or `None` if the socket has none.
    pub address: Option<SocketAddrV4>,
}

/// Request to take a socket's oldest pending error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeSocketErrorRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
}

/// Response containing a socket's oldest pending error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeSocketErrorResponse {
    /// Taken error, or `None` if no error was pending.
    pub error: Option<SocketError>,
}

/// Request to report an error before any already pending one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetSocketErrorRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Error to report.
    pub error: SocketError,
}
