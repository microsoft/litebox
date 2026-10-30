// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Unix sockets.
//!
//! A Unix socket connects processes on the same broker without host
//! networking. It is named by either a filesystem path, identified by the node
//! the path resolves to, or a byte string in an abstract namespace. Data moves
//! through broker-owned queues, so every reference to a socket, including
//! references in other processes, shares its state.
//!
//! A stream socket may instead be named by a vsock address, in a namespace of
//! its own that no path or abstract name reaches. Connections to a vsock
//! listener come from the broker on behalf of the VM's host, and a guest's
//! connect to a vsock address reaches only the host, through the broker, if
//! it has a vsock device. Such a connect completes later: its socket reports
//! [`SocketConnectionStatus::Connecting`] until then, and a failure is the
//! socket's pending error ([`TakeUnixSocketErrorRequest`]), which a blocking
//! connect's wait reads ([`CheckUnixSocketConnectRequest`]); it may be
//! cancelled meanwhile ([`CancelUnixSocketConnectRequest`]). A socket
//! created as a vsock socket ([`CreateVsockSocketRequest`]) is one even
//! before it has a name.

use alloc::string::String;
use alloc::vec::Vec;

use thiserror::Error;

use crate::ObjectHandle;
use crate::fs::{FileError, FileMode, FileOpenFlags, FileUser};
use crate::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence};
use crate::socket::{
    ShutdownMode, SocketConnectionStatus, SocketOptionName, SocketOptionValue, SocketType,
};

/// Maximum length in bytes of the guest-visible part of a Unix socket name.
pub const MAX_UNIX_SOCKET_NAME_SIZE: u32 = 108;

/// Length in bytes of the encoded payload of a vsock name or address: its
/// CID and port.
const VSOCK_NAME_SIZE: u32 = 8;

/// Maximum length in bytes of an encoded [`UnixSocketName`].
pub const MAX_ENCODED_UNIX_SOCKET_NAME_SIZE: u32 = 1 + MAX_UNIX_SOCKET_NAME_SIZE;

/// Maximum length in bytes of the absolute lookup path of a path name.
pub const MAX_UNIX_SOCKET_PATH_SIZE: u32 = 4096;

/// Maximum length in bytes of an encoded [`UnixSocketAddress`].
pub const MAX_ENCODED_UNIX_SOCKET_ADDRESS_SIZE: u32 =
    3 + MAX_UNIX_SOCKET_PATH_SIZE + MAX_UNIX_SOCKET_NAME_SIZE;

/// Bytes each direction of a connection may queue, which also bounds one
/// datagram.
pub const UNIX_SOCKET_BUFFER_SIZE: u32 = 212_992;

/// Maximum bytes one send or receive request transfers, including an encoded
/// address or name staged with the data.
pub const MAX_UNIX_SOCKET_TRANSFER_SIZE: u32 = 4 * SHARED_BUFFER_SLOT_SIZE;

/// Largest accepted listen backlog; larger requests are clamped.
pub const MAX_UNIX_SOCKET_BACKLOG: u32 = 4096;

const _: () = assert!(
    UNIX_SOCKET_BUFFER_SIZE + MAX_ENCODED_UNIX_SOCKET_ADDRESS_SIZE <= MAX_UNIX_SOCKET_TRANSFER_SIZE
);
const _: () = assert!(
    MAX_UNIX_SOCKET_TRANSFER_SIZE.div_ceil(SHARED_BUFFER_SLOT_SIZE) as usize
        <= crate::shared_buffer::MAX_SHARED_BUFFER_SEQUENCE_SLOTS
);
const _: () = assert!(MAX_UNIX_SOCKET_PATH_SIZE <= u16::MAX as u32);
const _: () = assert!(VSOCK_NAME_SIZE <= MAX_UNIX_SOCKET_NAME_SIZE);

const NAME_TAG_UNNAMED: u8 = 0;
const NAME_TAG_PATH: u8 = 1;
const NAME_TAG_ABSTRACT: u8 = 2;
const NAME_TAG_VSOCK: u8 = 3;

/// `VMADDR_CID_ANY`: the CID of a vsock name a guest binds, which accepts
/// connections to any of the VM's CIDs.
pub const VMADDR_CID_ANY: u32 = u32::MAX;

/// `VMADDR_CID_HOST`: the CID of the VM's host.
pub const VMADDR_CID_HOST: u32 = 2;

/// `VMADDR_PORT_ANY`: binding to it binds an unused ephemeral port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

/// The name a Unix socket reports for itself or its peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum UnixSocketName {
    /// The socket has no name.
    #[default]
    Unnamed,
    /// A filesystem name, holding the path bytes the socket was bound with.
    Path(Vec<u8>),
    /// A name in the abstract namespace.
    Abstract(Vec<u8>),
    /// A vsock address.
    Vsock {
        /// Context ID: [`VMADDR_CID_ANY`] for a guest's socket,
        /// [`VMADDR_CID_HOST`] for the host's.
        cid: u32,
        /// Port.
        port: u32,
    },
}

impl UnixSocketName {
    /// Encodes this name for a shared buffer.
    ///
    /// Returns `None` if the name is longer than [`MAX_UNIX_SOCKET_NAME_SIZE`].
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let (tag, bytes): (u8, &[u8]) = match self {
            Self::Unnamed => (NAME_TAG_UNNAMED, &[]),
            Self::Path(bytes) => (NAME_TAG_PATH, bytes),
            Self::Abstract(bytes) => (NAME_TAG_ABSTRACT, bytes),
            &Self::Vsock { cid, port } => return Some(encode_vsock(cid, port)),
        };
        if bytes.len() > MAX_UNIX_SOCKET_NAME_SIZE as usize {
            return None;
        }
        let mut encoded = Vec::with_capacity(1 + bytes.len());
        encoded.push(tag);
        encoded.extend_from_slice(bytes);
        Some(encoded)
    }

    /// Decodes a name produced by [`Self::encode`].
    pub fn decode(encoded: &[u8]) -> Result<Self, UnixSocketCodecError> {
        let (&tag, bytes) = encoded
            .split_first()
            .ok_or(UnixSocketCodecError::Truncated)?;
        if bytes.len() > MAX_UNIX_SOCKET_NAME_SIZE as usize {
            return Err(UnixSocketCodecError::TooLong);
        }
        match tag {
            NAME_TAG_UNNAMED if bytes.is_empty() => Ok(Self::Unnamed),
            NAME_TAG_PATH => Ok(Self::Path(bytes.into())),
            NAME_TAG_ABSTRACT => Ok(Self::Abstract(bytes.into())),
            NAME_TAG_VSOCK => {
                let (cid, port) = decode_vsock(bytes)?;
                Ok(Self::Vsock { cid, port })
            }
            _ => Err(UnixSocketCodecError::Invalid),
        }
    }
}

fn encode_vsock(cid: u32, port: u32) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + VSOCK_NAME_SIZE as usize);
    encoded.push(NAME_TAG_VSOCK);
    encoded.extend_from_slice(&cid.to_le_bytes());
    encoded.extend_from_slice(&port.to_le_bytes());
    encoded
}

/// Decodes the payload of a vsock name or address, which is exactly its CID
/// and port.
fn decode_vsock(bytes: &[u8]) -> Result<(u32, u32), UnixSocketCodecError> {
    let bytes: &[u8; VSOCK_NAME_SIZE as usize] = bytes.try_into().map_err(|_| {
        if bytes.len() < VSOCK_NAME_SIZE as usize {
            UnixSocketCodecError::Truncated
        } else {
            UnixSocketCodecError::TooLong
        }
    })?;
    let [c0, c1, c2, c3, p0, p1, p2, p3] = *bytes;
    Ok((
        u32::from_le_bytes([c0, c1, c2, c3]),
        u32::from_le_bytes([p0, p1, p2, p3]),
    ))
}

/// An address that binds, connects, or sends to a Unix socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnixSocketAddress {
    /// A filesystem name.
    Path {
        /// Absolute UTF-8 path the broker resolves.
        path: String,
        /// Guest-visible name that binding records.
        name: Vec<u8>,
    },
    /// A name in the abstract namespace.
    Abstract(Vec<u8>),
    /// A vsock address, which only a stream socket binds.
    Vsock {
        /// Context ID, which a guest binds only as [`VMADDR_CID_ANY`].
        cid: u32,
        /// Port, or [`VMADDR_PORT_ANY`] to bind an unused ephemeral one.
        port: u32,
    },
}

impl UnixSocketAddress {
    /// Returns the name a socket bound to this address reports, but for
    /// [`VMADDR_PORT_ANY`], which binds another port.
    #[must_use]
    pub fn name(&self) -> UnixSocketName {
        match self {
            Self::Path { name, .. } => UnixSocketName::Path(name.clone()),
            Self::Abstract(bytes) => UnixSocketName::Abstract(bytes.clone()),
            &Self::Vsock { cid, port } => UnixSocketName::Vsock { cid, port },
        }
    }

    /// Encodes this address for a shared buffer.
    ///
    /// Returns `None` if the path or name is too long.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        match self {
            Self::Path { path, name } => {
                if path.len() > MAX_UNIX_SOCKET_PATH_SIZE as usize
                    || name.len() > MAX_UNIX_SOCKET_NAME_SIZE as usize
                {
                    return None;
                }
                let path_length = u16::try_from(path.len()).ok()?;
                let mut encoded = Vec::with_capacity(3 + path.len() + name.len());
                encoded.push(NAME_TAG_PATH);
                encoded.extend_from_slice(&path_length.to_le_bytes());
                encoded.extend_from_slice(path.as_bytes());
                encoded.extend_from_slice(name);
                Some(encoded)
            }
            Self::Abstract(bytes) => UnixSocketName::Abstract(bytes.clone()).encode(),
            &Self::Vsock { cid, port } => Some(encode_vsock(cid, port)),
        }
    }

    /// Decodes an address produced by [`Self::encode`].
    pub fn decode(encoded: &[u8]) -> Result<Self, UnixSocketCodecError> {
        match encoded.split_first() {
            Some((&NAME_TAG_PATH, rest)) => {
                let (length, rest) = rest
                    .split_first_chunk::<2>()
                    .ok_or(UnixSocketCodecError::Truncated)?;
                let length = usize::from(u16::from_le_bytes(*length));
                if length > MAX_UNIX_SOCKET_PATH_SIZE as usize {
                    return Err(UnixSocketCodecError::TooLong);
                }
                let (path, name) = rest
                    .split_at_checked(length)
                    .ok_or(UnixSocketCodecError::Truncated)?;
                if name.len() > MAX_UNIX_SOCKET_NAME_SIZE as usize {
                    return Err(UnixSocketCodecError::TooLong);
                }
                let path = core::str::from_utf8(path).map_err(|_| UnixSocketCodecError::Invalid)?;
                if !path.starts_with('/') {
                    return Err(UnixSocketCodecError::Invalid);
                }
                Ok(Self::Path {
                    path: path.into(),
                    name: name.into(),
                })
            }
            Some((&NAME_TAG_ABSTRACT, _)) => match UnixSocketName::decode(encoded)? {
                UnixSocketName::Abstract(bytes) => Ok(Self::Abstract(bytes)),
                _ => Err(UnixSocketCodecError::Invalid),
            },
            Some((&NAME_TAG_VSOCK, bytes)) => {
                let (cid, port) = decode_vsock(bytes)?;
                Ok(Self::Vsock { cid, port })
            }
            Some(_) => Err(UnixSocketCodecError::Invalid),
            None => Err(UnixSocketCodecError::Truncated),
        }
    }
}

/// Failure to decode a Unix socket name or address from a shared buffer.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum UnixSocketCodecError {
    #[error("truncated Unix socket name")]
    Truncated,
    #[error("Unix socket name is too long")]
    TooLong,
    #[error("invalid Unix socket name")]
    Invalid,
}

/// Unix socket operation failure that is meaningful to the guest ABI.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnixSocketError {
    #[error("address is already in use")]
    AddressInUse,
    #[error("no socket accepts connections at the address")]
    ConnectionRefused,
    #[error("socket at the address has a different type")]
    WrongType,
    #[error("invalid argument for the socket's state")]
    InvalidArgument,
    #[error("socket is already connected")]
    AlreadyConnected,
    #[error("socket is not connected")]
    NotConnected,
    #[error("operation is not supported by the socket type")]
    Unsupported,
    #[error("message is too large")]
    MessageTooLarge,
    #[error("sending side is shut down")]
    BrokenPipe,
    #[error("receiving socket is connected to another socket")]
    NotPermitted,
    #[error("connection was reset")]
    ConnectionReset,
    #[error("address is not available to bind")]
    AddressNotAvailable,
    #[error("address is unreachable")]
    Unreachable,
    #[error("a connection attempt is already in progress")]
    AlreadyInProgress,
    #[error("connection attempt timed out")]
    TimedOut,
    #[error("address lookup failed: {0}")]
    File(FileError),
}

/// Request to create one Unix socket or a connected pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateUnixSocketRequest {
    /// Socket type.
    pub socket_type: SocketType,
    /// Initial status flags, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
}

/// Request to create an unbound, unconnected vsock stream socket, which, as
/// in Linux, is not hung up while unconnected, even before it has a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateVsockSocketRequest {
    /// Initial status flags, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
}

/// Response to a Unix socket or vsock socket create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateUnixSocketResponse {
    /// Handle for the new socket.
    pub handle: ObjectHandle,
}

/// Response to a Unix socket pair create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateUnixSocketPairResponse {
    /// Handle for the first socket.
    pub first: ObjectHandle,
    /// Handle for the second socket, connected to the first.
    pub second: ObjectHandle,
}

/// Request to bind a Unix socket to a name.
///
/// A path name creates a filesystem node at the path, which fails if one
/// exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindUnixSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region holding one encoded [`UnixSocketAddress`].
    pub address: SharedBufferSequence,
    /// Caller identity for filesystem permission checks.
    pub user: FileUser,
    /// Mode of the filesystem node a path name creates.
    pub mode: FileMode,
}

/// Request to make a bound stream or sequenced-packet socket accept
/// connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenUnixSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Connections that may wait to be accepted beyond the first.
    pub backlog: u32,
}

/// Request to connect a stream or sequenced-packet socket, or to set a
/// datagram socket's default destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectUnixSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region holding one encoded [`UnixSocketAddress`].
    pub address: SharedBufferSequence,
    /// Caller identity for filesystem permission checks.
    pub user: FileUser,
}

/// Response to a connect request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectUnixSocketResponse {
    /// [`SocketConnectionStatus::Connected`], or
    /// [`SocketConnectionStatus::Connecting`] for a vsock connect that
    /// completes later.
    pub status: SocketConnectionStatus,
}

/// Request to accept one pending connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptUnixSocketRequest {
    /// Listening socket handle.
    pub handle: ObjectHandle,
    /// Status flags of the accepted socket, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
}

/// Response to an accept request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptUnixSocketResponse {
    /// Handle for the accepted connection.
    pub handle: ObjectHandle,
}

/// Request to send bytes staged in shared memory.
///
/// A stream socket may send only part of the bytes. A datagram socket sends
/// them as one datagram. A sequenced-packet socket sends them as one record
/// to its connected peer, ignoring any destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendUnixSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region holding an encoded destination
    /// [`UnixSocketAddress`] of `address_length` bytes followed by the data.
    pub buffer: SharedBufferSequence,
    /// Length of the destination address, or zero to send to the connected
    /// peer.
    pub address_length: u32,
    /// Caller identity for filesystem permission checks.
    pub user: FileUser,
}

/// Response to a send request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendUnixSocketResponse {
    /// Number of data bytes sent.
    pub sent: u32,
}

/// Request to receive bytes into shared memory.
///
/// A stream socket receives queued bytes. A datagram or sequenced-packet
/// socket receives one datagram or record, discarding the bytes beyond
/// `capacity` unless peeking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveUnixSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region that receives the data, followed by the sender's
    /// encoded [`UnixSocketName`] if `source` is set.
    ///
    /// It must hold `capacity` bytes, plus
    /// [`MAX_ENCODED_UNIX_SOCKET_NAME_SIZE`] if `source` is set.
    pub buffer: SharedBufferSequence,
    /// Maximum data bytes to receive.
    pub capacity: u32,
    /// Whether to leave the data queued.
    pub peek: bool,
    /// Whether to return the sender's name.
    pub source: bool,
    /// Whether the caller will not wait for data, as if the socket were
    /// non-blocking.
    ///
    /// A datagram socket whose receive direction is shut down then reports
    /// that the receive would block instead of the end of data.
    pub nonblocking: bool,
}

/// Response to a receive request.
///
/// A response with zero `received` and `length` for a nonzero `capacity`
/// means an empty datagram or record arrived, or no more data can arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveUnixSocketResponse {
    /// Number of data bytes placed in the buffer.
    pub received: u32,
    /// Length of the whole datagram or record, or `received` for a stream
    /// socket.
    pub length: u32,
    /// Length of the sender's encoded name, which follows the data, or zero
    /// if the request did not ask for it.
    pub source_length: u32,
}

/// Request to shut down one or both directions of a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownUnixSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// [`ShutdownMode::Read`], [`ShutdownMode::Write`], or [`ShutdownMode::Both`].
    pub mode: ShutdownMode,
}

/// Request to read the name of a socket or its peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetUnixSocketNameRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Whether to read the peer's name instead of the socket's own.
    pub peer: bool,
    /// Shared-buffer region of [`MAX_ENCODED_UNIX_SOCKET_NAME_SIZE`] bytes
    /// that receives the encoded [`UnixSocketName`].
    pub buffer: SharedBufferSequence,
}

/// Response to a name request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetUnixSocketNameResponse {
    /// Length of the encoded name.
    pub length: u32,
}

/// Request to store one socket option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetUnixSocketOptionRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Option value to store.
    pub value: SocketOptionValue,
}

/// Request to read one socket option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetUnixSocketOptionRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Option name to read.
    pub name: SocketOptionName,
}

/// Response containing one socket option value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetUnixSocketOptionResponse {
    /// Stored option value.
    pub value: SocketOptionValue,
}

/// Request to take a socket's pending error: why its last connect failed,
/// which is reported once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeUnixSocketErrorRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
}

/// Request for the outcome of a socket's vsock connect, as a blocking
/// connect waiting for it sees it: whether it is still in progress, or
/// connected, or the error it failed with, which stays pending unless the
/// connect timed out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckUnixSocketConnectRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
}

/// Response to a check-connect request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckUnixSocketConnectResponse {
    /// [`SocketConnectionStatus::Connecting`],
    /// [`SocketConnectionStatus::Connected`], or
    /// [`SocketConnectionStatus::Unconnected`] for a socket with no connect
    /// in progress and no pending error.
    pub status: SocketConnectionStatus,
}

/// Request to cancel a socket's vsock connect in progress, as an interrupted
/// blocking connect does: the socket is unconnected again, and still bound.
/// With none in progress, it reports the outcome as
/// [`CheckUnixSocketConnectRequest`] does, failing with
/// [`UnixSocketError::AlreadyConnected`] if the connect completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelUnixSocketConnectRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
}

/// Response containing a socket's pending error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeUnixSocketErrorResponse {
    /// Taken error, or `None` if no error was pending.
    pub error: Option<UnixSocketError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for name in [
            UnixSocketName::Unnamed,
            UnixSocketName::Path(b"./sock".into()),
            UnixSocketName::Abstract(b"\0x".into()),
            UnixSocketName::Abstract(Vec::new()),
            UnixSocketName::Vsock {
                cid: VMADDR_CID_HOST,
                port: 0x1234_5678,
            },
            UnixSocketName::Vsock {
                cid: VMADDR_CID_ANY,
                port: VMADDR_PORT_ANY,
            },
        ] {
            let encoded = name.encode().unwrap();
            assert!(encoded.len() <= MAX_ENCODED_UNIX_SOCKET_NAME_SIZE as usize);
            assert_eq!(UnixSocketName::decode(&encoded), Ok(name));
        }
        assert_eq!(
            UnixSocketName::Path(alloc::vec![1; MAX_UNIX_SOCKET_NAME_SIZE as usize + 1]).encode(),
            None
        );
        assert_eq!(
            UnixSocketName::decode(&[NAME_TAG_UNNAMED, 1]),
            Err(UnixSocketCodecError::Invalid)
        );
        assert_eq!(
            UnixSocketName::decode(&[]),
            Err(UnixSocketCodecError::Truncated)
        );
    }

    #[test]
    fn addresses_round_trip() {
        for address in [
            UnixSocketAddress::Path {
                path: "/tmp/sock".into(),
                name: b"sock".into(),
            },
            UnixSocketAddress::Abstract(b"name".into()),
            UnixSocketAddress::Vsock {
                cid: VMADDR_CID_ANY,
                port: 1024,
            },
        ] {
            let encoded = address.encode().unwrap();
            assert!(encoded.len() <= MAX_ENCODED_UNIX_SOCKET_ADDRESS_SIZE as usize);
            assert_eq!(UnixSocketAddress::decode(&encoded), Ok(address));
        }
        let relative = UnixSocketAddress::Path {
            path: "tmp/sock".into(),
            name: Vec::new(),
        };
        assert_eq!(
            UnixSocketAddress::decode(&relative.encode().unwrap()),
            Err(UnixSocketCodecError::Invalid)
        );
        assert_eq!(
            UnixSocketAddress::decode(&[NAME_TAG_UNNAMED]),
            Err(UnixSocketCodecError::Invalid)
        );
        assert_eq!(
            UnixSocketAddress::decode(&[NAME_TAG_PATH, 5, 0, b'/']),
            Err(UnixSocketCodecError::Truncated)
        );
    }

    #[test]
    fn vsock_names_are_little_endian_and_exactly_sized() {
        let name = UnixSocketName::Vsock {
            cid: 2,
            port: 0x0102_0304,
        };
        let encoded = name.encode().unwrap();
        assert_eq!(encoded, [NAME_TAG_VSOCK, 2, 0, 0, 0, 4, 3, 2, 1]);
        assert_eq!(
            UnixSocketAddress::decode(&encoded),
            Ok(UnixSocketAddress::Vsock {
                cid: 2,
                port: 0x0102_0304
            })
        );
        for length in 0..encoded.len() - 1 {
            let truncated = &encoded[..=length];
            assert_eq!(
                UnixSocketName::decode(truncated),
                Err(UnixSocketCodecError::Truncated)
            );
            assert_eq!(
                UnixSocketAddress::decode(truncated),
                Err(UnixSocketCodecError::Truncated)
            );
        }
        let mut long = encoded;
        long.push(0);
        assert_eq!(
            UnixSocketName::decode(&long),
            Err(UnixSocketCodecError::TooLong)
        );
        assert_eq!(
            UnixSocketAddress::decode(&long),
            Err(UnixSocketCodecError::TooLong)
        );
    }
}
