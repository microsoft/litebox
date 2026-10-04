// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned local sockets.
//!
//! A local socket connects processes on the same broker without host
//! networking. Its names live in either a filesystem path, identified by the
//! node the path resolves to, or an abstract namespace of byte strings, as
//! Unix domain sockets name them on POSIX systems and Windows. Data moves
//! through broker-owned queues, so every reference to a socket, including
//! references in other processes, shares its state.

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use thiserror::Error;

use crate::ObjectHandle;
use crate::fs::{FileError, FileMode, FileOpenFlags, FileUser};
use crate::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence};
use crate::socket::{ShutdownMode, SocketType};

/// Maximum length in bytes of the guest-visible part of a local socket name.
pub const MAX_LOCAL_SOCKET_NAME_SIZE: u32 = 108;

/// Maximum length in bytes of an encoded [`LocalSocketName`].
pub const MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE: u32 = 1 + MAX_LOCAL_SOCKET_NAME_SIZE;

/// Maximum length in bytes of the absolute lookup path of a path name.
pub const MAX_LOCAL_SOCKET_PATH_SIZE: u32 = 4096;

/// Maximum length in bytes of an encoded [`LocalSocketAddress`].
pub const MAX_ENCODED_LOCAL_SOCKET_ADDRESS_SIZE: u32 =
    3 + MAX_LOCAL_SOCKET_PATH_SIZE + MAX_LOCAL_SOCKET_NAME_SIZE;

/// Bytes each direction of a connection may queue, which also bounds one
/// datagram.
pub const LOCAL_SOCKET_BUFFER_SIZE: u32 = 212_992;

/// Maximum bytes one send or receive request transfers, including an encoded
/// address or name staged with the data.
pub const MAX_LOCAL_SOCKET_TRANSFER_SIZE: u32 = 4 * SHARED_BUFFER_SLOT_SIZE;

/// Largest accepted listen backlog; larger requests are clamped.
pub const MAX_LOCAL_SOCKET_BACKLOG: u32 = 4096;

const _: () = assert!(
    LOCAL_SOCKET_BUFFER_SIZE + MAX_ENCODED_LOCAL_SOCKET_ADDRESS_SIZE
        <= MAX_LOCAL_SOCKET_TRANSFER_SIZE
);
const _: () = assert!(
    MAX_LOCAL_SOCKET_TRANSFER_SIZE.div_ceil(SHARED_BUFFER_SLOT_SIZE) as usize
        <= crate::shared_buffer::MAX_SHARED_BUFFER_SEQUENCE_SLOTS
);
const _: () = assert!(MAX_LOCAL_SOCKET_PATH_SIZE <= u16::MAX as u32);

const NAME_TAG_UNNAMED: u8 = 0;
const NAME_TAG_PATH: u8 = 1;
const NAME_TAG_ABSTRACT: u8 = 2;

/// The name a local socket reports for itself or its peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LocalSocketName {
    /// The socket has no name.
    #[default]
    Unnamed,
    /// A filesystem name, holding the path bytes the socket was bound with.
    Path(Vec<u8>),
    /// A name in the abstract namespace.
    Abstract(Vec<u8>),
}

impl LocalSocketName {
    /// Encodes this name for a shared buffer.
    ///
    /// Returns `None` if the name is longer than [`MAX_LOCAL_SOCKET_NAME_SIZE`].
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let (tag, bytes): (u8, &[u8]) = match self {
            Self::Unnamed => (NAME_TAG_UNNAMED, &[]),
            Self::Path(bytes) => (NAME_TAG_PATH, bytes),
            Self::Abstract(bytes) => (NAME_TAG_ABSTRACT, bytes),
        };
        if bytes.len() > MAX_LOCAL_SOCKET_NAME_SIZE as usize {
            return None;
        }
        let mut encoded = Vec::with_capacity(1 + bytes.len());
        encoded.push(tag);
        encoded.extend_from_slice(bytes);
        Some(encoded)
    }

    /// Decodes a name produced by [`Self::encode`].
    pub fn decode(encoded: &[u8]) -> Result<Self, LocalSocketCodecError> {
        let (&tag, bytes) = encoded
            .split_first()
            .ok_or(LocalSocketCodecError::Truncated)?;
        if bytes.len() > MAX_LOCAL_SOCKET_NAME_SIZE as usize {
            return Err(LocalSocketCodecError::TooLong);
        }
        match tag {
            NAME_TAG_UNNAMED if bytes.is_empty() => Ok(Self::Unnamed),
            NAME_TAG_PATH => Ok(Self::Path(bytes.into())),
            NAME_TAG_ABSTRACT => Ok(Self::Abstract(bytes.into())),
            _ => Err(LocalSocketCodecError::Invalid),
        }
    }
}

/// An address that binds, connects, or sends to a local socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSocketAddress {
    /// A filesystem name.
    Path {
        /// Absolute UTF-8 path the broker resolves.
        path: String,
        /// Guest-visible name that binding records.
        name: Vec<u8>,
    },
    /// A name in the abstract namespace.
    Abstract(Vec<u8>),
}

impl LocalSocketAddress {
    /// Returns the name a socket bound to this address reports.
    #[must_use]
    pub fn name(&self) -> LocalSocketName {
        match self {
            Self::Path { name, .. } => LocalSocketName::Path(name.clone()),
            Self::Abstract(bytes) => LocalSocketName::Abstract(bytes.clone()),
        }
    }

    /// Encodes this address for a shared buffer.
    ///
    /// Returns `None` if the path or name is too long.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        match self {
            Self::Path { path, name } => {
                if path.len() > MAX_LOCAL_SOCKET_PATH_SIZE as usize
                    || name.len() > MAX_LOCAL_SOCKET_NAME_SIZE as usize
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
            Self::Abstract(bytes) => LocalSocketName::Abstract(bytes.clone()).encode(),
        }
    }

    /// Decodes an address produced by [`Self::encode`].
    pub fn decode(encoded: &[u8]) -> Result<Self, LocalSocketCodecError> {
        match encoded.split_first() {
            Some((&NAME_TAG_PATH, rest)) => {
                let (length, rest) = rest
                    .split_first_chunk::<2>()
                    .ok_or(LocalSocketCodecError::Truncated)?;
                let length = usize::from(u16::from_le_bytes(*length));
                if length > MAX_LOCAL_SOCKET_PATH_SIZE as usize {
                    return Err(LocalSocketCodecError::TooLong);
                }
                let (path, name) = rest
                    .split_at_checked(length)
                    .ok_or(LocalSocketCodecError::Truncated)?;
                if name.len() > MAX_LOCAL_SOCKET_NAME_SIZE as usize {
                    return Err(LocalSocketCodecError::TooLong);
                }
                let path =
                    core::str::from_utf8(path).map_err(|_| LocalSocketCodecError::Invalid)?;
                if !path.starts_with('/') {
                    return Err(LocalSocketCodecError::Invalid);
                }
                Ok(Self::Path {
                    path: path.into(),
                    name: name.into(),
                })
            }
            Some((&NAME_TAG_ABSTRACT, _)) => match LocalSocketName::decode(encoded)? {
                LocalSocketName::Abstract(bytes) => Ok(Self::Abstract(bytes)),
                _ => Err(LocalSocketCodecError::Invalid),
            },
            Some(_) => Err(LocalSocketCodecError::Invalid),
            None => Err(LocalSocketCodecError::Truncated),
        }
    }
}

/// Failure to decode a local socket name or address from a shared buffer.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LocalSocketCodecError {
    #[error("truncated local socket name")]
    Truncated,
    #[error("local socket name is too long")]
    TooLong,
    #[error("invalid local socket name")]
    Invalid,
}

/// Local socket operation failure that is meaningful to the guest ABI.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalSocketError {
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
    #[error("address lookup failed: {0}")]
    File(FileError),
}

/// Options stored with a local socket and shared by its references.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalSocketOptions {
    /// Longest time a blocking receive or accept waits, or `None` to wait
    /// indefinitely.
    pub receive_timeout: Option<Duration>,
    /// Longest time a blocking send or connect waits, or `None` to wait
    /// indefinitely.
    pub send_timeout: Option<Duration>,
    /// Linger time on close, or `None` to close in the background.
    pub linger: Option<Duration>,
    /// Whether address reuse was requested.
    pub reuse_address: bool,
    /// Whether keepalive was requested.
    pub keep_alive: bool,
    /// Whether broadcast was requested.
    pub broadcast: bool,
}

/// One local socket option value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalSocketOption {
    /// [`LocalSocketOptions::receive_timeout`].
    ReceiveTimeout(Option<Duration>),
    /// [`LocalSocketOptions::send_timeout`].
    SendTimeout(Option<Duration>),
    /// [`LocalSocketOptions::linger`].
    Linger(Option<Duration>),
    /// [`LocalSocketOptions::reuse_address`].
    ReuseAddress(bool),
    /// [`LocalSocketOptions::keep_alive`].
    KeepAlive(bool),
    /// [`LocalSocketOptions::broadcast`].
    Broadcast(bool),
}

impl LocalSocketOptions {
    /// Stores `option`.
    pub fn set(&mut self, option: LocalSocketOption) {
        match option {
            LocalSocketOption::ReceiveTimeout(timeout) => self.receive_timeout = timeout,
            LocalSocketOption::SendTimeout(timeout) => self.send_timeout = timeout,
            LocalSocketOption::Linger(timeout) => self.linger = timeout,
            LocalSocketOption::ReuseAddress(value) => self.reuse_address = value,
            LocalSocketOption::KeepAlive(value) => self.keep_alive = value,
            LocalSocketOption::Broadcast(value) => self.broadcast = value,
        }
    }
}

/// Request to create one local socket or a connected pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateLocalSocketRequest {
    /// Socket type.
    pub socket_type: SocketType,
    /// Initial status flags, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
}

/// Response to a local socket create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateLocalSocketResponse {
    /// Handle for the new socket.
    pub handle: ObjectHandle,
}

/// Response to a local socket pair create request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateLocalSocketPairResponse {
    /// Handle for the first socket.
    pub first: ObjectHandle,
    /// Handle for the second socket, connected to the first.
    pub second: ObjectHandle,
}

/// Request to bind a local socket to a name.
///
/// A path name creates a filesystem node at the path, which fails if one
/// exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindLocalSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region holding one encoded [`LocalSocketAddress`].
    pub address: SharedBufferSequence,
    /// Caller identity for filesystem permission checks.
    pub user: FileUser,
    /// Mode of the filesystem node a path name creates.
    pub mode: FileMode,
}

/// Request to make a bound stream socket accept connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenLocalSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Connections that may wait to be accepted beyond the first.
    pub backlog: u32,
}

/// Request to connect a stream socket, or to set a datagram socket's default
/// destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectLocalSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region holding one encoded [`LocalSocketAddress`].
    pub address: SharedBufferSequence,
    /// Caller identity for filesystem permission checks.
    pub user: FileUser,
}

/// Request to accept one pending connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptLocalSocketRequest {
    /// Listening socket handle.
    pub handle: ObjectHandle,
    /// Status flags of the accepted socket, within [`FileOpenFlags::STATUS`].
    pub flags: FileOpenFlags,
}

/// Response to an accept request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptLocalSocketResponse {
    /// Handle for the accepted connection.
    pub handle: ObjectHandle,
}

/// Request to send bytes staged in shared memory.
///
/// A stream socket may send only part of the bytes. A datagram socket sends
/// them as one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendLocalSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region holding an encoded destination
    /// [`LocalSocketAddress`] of `address_length` bytes followed by the data.
    pub buffer: SharedBufferSequence,
    /// Length of the destination address, or zero to send to the connected
    /// peer.
    pub address_length: u32,
    /// Caller identity for filesystem permission checks.
    pub user: FileUser,
}

/// Response to a send request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendLocalSocketResponse {
    /// Number of data bytes sent.
    pub sent: u32,
}

/// Request to receive bytes into shared memory.
///
/// A stream socket receives queued bytes. A datagram socket receives one
/// datagram, discarding the bytes beyond `capacity` unless peeking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveLocalSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Shared-buffer region that receives the data followed by the sender's
    /// encoded [`LocalSocketName`].
    ///
    /// It must hold `capacity` bytes plus
    /// [`MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE`].
    pub buffer: SharedBufferSequence,
    /// Maximum data bytes to receive.
    pub capacity: u32,
    /// Whether to leave the data queued.
    pub peek: bool,
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
/// means no more data can arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveLocalSocketResponse {
    /// Number of data bytes placed in the buffer.
    pub received: u32,
    /// Length of the whole datagram, or `received` for a stream socket.
    pub length: u32,
    /// Length of the sender's encoded name, which follows the data.
    pub source_length: u32,
}

/// Request to shut down one or both directions of a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownLocalSocketRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// [`ShutdownMode::Read`], [`ShutdownMode::Write`], or [`ShutdownMode::Both`].
    pub mode: ShutdownMode,
}

/// Request to read the name of a socket or its peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetLocalSocketNameRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Whether to read the peer's name instead of the socket's own.
    pub peer: bool,
    /// Shared-buffer region of [`MAX_ENCODED_LOCAL_SOCKET_NAME_SIZE`] bytes
    /// that receives the encoded [`LocalSocketName`].
    pub buffer: SharedBufferSequence,
}

/// Response to a name request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetLocalSocketNameResponse {
    /// Length of the encoded name.
    pub length: u32,
}

/// Request to store one socket option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetLocalSocketOptionRequest {
    /// Socket handle.
    pub handle: ObjectHandle,
    /// Option value.
    pub option: LocalSocketOption,
}

/// Response describing a socket's type and options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetLocalSocketOptionsResponse {
    /// Socket type.
    pub socket_type: SocketType,
    /// Stored options.
    pub options: LocalSocketOptions,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for name in [
            LocalSocketName::Unnamed,
            LocalSocketName::Path(b"./sock".into()),
            LocalSocketName::Abstract(b"\0x".into()),
            LocalSocketName::Abstract(Vec::new()),
        ] {
            assert_eq!(LocalSocketName::decode(&name.encode().unwrap()), Ok(name));
        }
        assert_eq!(
            LocalSocketName::Path(alloc::vec![1; MAX_LOCAL_SOCKET_NAME_SIZE as usize + 1]).encode(),
            None
        );
        assert_eq!(
            LocalSocketName::decode(&[NAME_TAG_UNNAMED, 1]),
            Err(LocalSocketCodecError::Invalid)
        );
        assert_eq!(
            LocalSocketName::decode(&[]),
            Err(LocalSocketCodecError::Truncated)
        );
    }

    #[test]
    fn addresses_round_trip() {
        for address in [
            LocalSocketAddress::Path {
                path: "/tmp/sock".into(),
                name: b"sock".into(),
            },
            LocalSocketAddress::Abstract(b"name".into()),
        ] {
            let encoded = address.encode().unwrap();
            assert!(encoded.len() <= MAX_ENCODED_LOCAL_SOCKET_ADDRESS_SIZE as usize);
            assert_eq!(LocalSocketAddress::decode(&encoded), Ok(address));
        }
        let relative = LocalSocketAddress::Path {
            path: "tmp/sock".into(),
            name: Vec::new(),
        };
        assert_eq!(
            LocalSocketAddress::decode(&relative.encode().unwrap()),
            Err(LocalSocketCodecError::Invalid)
        );
        assert_eq!(
            LocalSocketAddress::decode(&[NAME_TAG_UNNAMED]),
            Err(LocalSocketCodecError::Invalid)
        );
        assert_eq!(
            LocalSocketAddress::decode(&[NAME_TAG_PATH, 5, 0, b'/']),
            Err(LocalSocketCodecError::Truncated)
        );
    }
}
