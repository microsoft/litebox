// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Unix sockets.
//!
//! A Unix socket connects processes on the same broker without host
//! networking. It is named by either a filesystem path, identified by the node
//! the path resolves to, or a byte string in an abstract namespace. Data moves
//! through broker-owned queues, so every reference to a socket, including
//! references in other processes, shares its state.

use alloc::string::String;
use alloc::vec::Vec;

use thiserror::Error;

use crate::ObjectHandle;
use crate::fs::{FileError, FileMode, FileOpenFlags, FileUser};
use crate::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence};
use crate::socket::{ShutdownMode, SocketOptionName, SocketOptionValue, SocketType};

/// Maximum length in bytes of the guest-visible part of a Unix socket name.
pub const MAX_UNIX_SOCKET_NAME_SIZE: u32 = 108;

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
/// address or name and the carried objects staged with the data.
pub const MAX_UNIX_SOCKET_TRANSFER_SIZE: u32 = 4 * SHARED_BUFFER_SLOT_SIZE;

/// Largest accepted listen backlog; larger requests are clamped.
pub const MAX_UNIX_SOCKET_BACKLOG: u32 = 4096;

/// Most object references one send carries, as Linux's `SCM_MAX_FD`.
pub const MAX_UNIX_SOCKET_OBJECTS: u32 = 253;

/// Length in bytes of one encoded [`TransferredObject`]: its handle, then its
/// kind's tag and detail.
pub const ENCODED_TRANSFERRED_OBJECT_SIZE: u32 = 10;

const _: () = assert!(ENCODED_TRANSFERRED_OBJECT_SIZE as usize == ObjectHandle::ENCODED_SIZE + 2);

const _: () = assert!(
    UNIX_SOCKET_BUFFER_SIZE as usize
        + MAX_ENCODED_UNIX_SOCKET_ADDRESS_SIZE as usize
        + MAX_UNIX_SOCKET_OBJECTS as usize * ObjectHandle::ENCODED_SIZE
        <= MAX_UNIX_SOCKET_TRANSFER_SIZE as usize
);
const _: () = assert!(
    UNIX_SOCKET_BUFFER_SIZE
        + MAX_ENCODED_UNIX_SOCKET_NAME_SIZE
        + MAX_UNIX_SOCKET_OBJECTS * ENCODED_TRANSFERRED_OBJECT_SIZE
        <= MAX_UNIX_SOCKET_TRANSFER_SIZE
);
const _: () = assert!(
    MAX_UNIX_SOCKET_TRANSFER_SIZE.div_ceil(SHARED_BUFFER_SLOT_SIZE) as usize
        <= crate::shared_buffer::MAX_SHARED_BUFFER_SEQUENCE_SLOTS
);
const _: () = assert!(MAX_UNIX_SOCKET_PATH_SIZE <= u16::MAX as u32);

const NAME_TAG_UNNAMED: u8 = 0;
const NAME_TAG_PATH: u8 = 1;
const NAME_TAG_ABSTRACT: u8 = 2;

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
            _ => Err(UnixSocketCodecError::Invalid),
        }
    }
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
}

impl UnixSocketAddress {
    /// Returns the name a socket bound to this address reports.
    #[must_use]
    pub fn name(&self) -> UnixSocketName {
        match self {
            Self::Path { name, .. } => UnixSocketName::Path(name.clone()),
            Self::Abstract(bytes) => UnixSocketName::Abstract(bytes.clone()),
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
            Some(_) => Err(UnixSocketCodecError::Invalid),
            None => Err(UnixSocketCodecError::Truncated),
        }
    }
}

/// The kind of an object whose reference another process passed on, by a
/// Unix socket message or by inheritance, which tells the receiver how to use
/// its new handle.
///
/// For a Unix socket message the broker reports the kind, so receivers need
/// not trust senders for it.
///
/// Receivers match every kind to adopt its handle, so a new kind is
/// deliberately a breaking change rather than `#[non_exhaustive]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferredObjectKind {
    /// A file, including a terminal or standard stream.
    File,
    /// The read end of a pipe.
    PipeReadEnd,
    /// The write end of a pipe.
    PipeWriteEnd,
    /// A Unix socket of the given type.
    UnixSocket(SocketType),
    /// An internet socket of the given type.
    InetSocket(SocketType),
    /// A vsock stream socket.
    VsockSocket,
    /// An event counter.
    EventCounter,
    /// A timer.
    Timer,
    /// A readiness queue.
    ReadinessQueue,
    /// A process.
    Process,
}

/// Options of a receive from a Unix socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReceiveOptions {
    /// Whether to leave the data queued.
    pub peek: bool,
    /// Whether to return the sender's name.
    pub source: bool,
    /// Whether the caller will not wait for data, as if the socket were
    /// non-blocking.
    pub nonblocking: bool,
    /// Maximum carried objects to receive handles for.
    pub max_objects: usize,
}

/// A handle the receiver of a Unix socket message got for an object the
/// message carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferredObject {
    /// The receiver's new handle.
    pub handle: ObjectHandle,
    /// What the handle refers to.
    pub kind: TransferredObjectKind,
}

impl TransferredObject {
    /// Encodes this object for a shared buffer.
    #[must_use]
    pub fn encode(self) -> [u8; ENCODED_TRANSFERRED_OBJECT_SIZE as usize] {
        let socket_type = |socket_type| match socket_type {
            SocketType::Stream => 0,
            SocketType::Datagram => 1,
            SocketType::SeqPacket => 2,
        };
        let (tag, detail) = match self.kind {
            TransferredObjectKind::File => (0, 0),
            TransferredObjectKind::PipeReadEnd => (1, 0),
            TransferredObjectKind::PipeWriteEnd => (2, 0),
            TransferredObjectKind::UnixSocket(kind) => (3, socket_type(kind)),
            TransferredObjectKind::InetSocket(kind) => (4, socket_type(kind)),
            TransferredObjectKind::VsockSocket => (5, 0),
            TransferredObjectKind::EventCounter => (6, 0),
            TransferredObjectKind::Timer => (7, 0),
            TransferredObjectKind::ReadinessQueue => (8, 0),
            TransferredObjectKind::Process => (9, 0),
        };
        let mut encoded = [0; ENCODED_TRANSFERRED_OBJECT_SIZE as usize];
        let (handle, kind) = encoded.split_at_mut(ObjectHandle::ENCODED_SIZE);
        handle.copy_from_slice(&self.handle.encode());
        kind.copy_from_slice(&[tag, detail]);
        encoded
    }

    /// Decodes an object produced by [`Self::encode`].
    pub fn decode(
        encoded: &[u8; ENCODED_TRANSFERRED_OBJECT_SIZE as usize],
    ) -> Result<Self, UnixSocketCodecError> {
        let [handle @ .., tag, detail] = encoded;
        let handle = ObjectHandle::decode(handle);
        let (tag, detail) = (*tag, *detail);
        let socket_type = || match detail {
            0 => Ok(SocketType::Stream),
            1 => Ok(SocketType::Datagram),
            2 => Ok(SocketType::SeqPacket),
            _ => Err(UnixSocketCodecError::Invalid),
        };
        let plain = |kind: TransferredObjectKind, detail: u8| {
            if detail == 0 {
                Ok(kind)
            } else {
                Err(UnixSocketCodecError::Invalid)
            }
        };
        let kind = match tag {
            0 => plain(TransferredObjectKind::File, detail)?,
            1 => plain(TransferredObjectKind::PipeReadEnd, detail)?,
            2 => plain(TransferredObjectKind::PipeWriteEnd, detail)?,
            3 => TransferredObjectKind::UnixSocket(socket_type()?),
            4 => TransferredObjectKind::InetSocket(socket_type()?),
            5 => plain(TransferredObjectKind::VsockSocket, detail)?,
            6 => plain(TransferredObjectKind::EventCounter, detail)?,
            7 => plain(TransferredObjectKind::Timer, detail)?,
            8 => plain(TransferredObjectKind::ReadinessQueue, detail)?,
            9 => plain(TransferredObjectKind::Process, detail)?,
            _ => return Err(UnixSocketCodecError::Invalid),
        };
        Ok(Self { handle, kind })
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

wire_enum! {
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
        #[error("address lookup failed: {0}")]
        File(FileError),
        /// The sender has as many references in flight in queued messages as
        /// it may.
        #[error("too many references are in flight")]
        TooManyReferences,
    }
}

wire_struct! {
    /// Request to create one Unix socket or a connected pair.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CreateUnixSocketRequest {
        /// Socket type.
        pub socket_type: SocketType,
        /// Initial status flags, within [`FileOpenFlags::STATUS`].
        pub flags: FileOpenFlags,
    }
}

wire_struct! {
    /// Response to a Unix socket create request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CreateUnixSocketResponse {
        /// Handle for the new socket.
        pub handle: ObjectHandle,
    }
}

wire_struct! {
    /// Response to a Unix socket pair create request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CreateUnixSocketPairResponse {
        /// Handle for the first socket.
        pub first: ObjectHandle,
        /// Handle for the second socket, connected to the first.
        pub second: ObjectHandle,
    }
}

wire_struct! {
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
}

wire_struct! {
    /// Request to make a bound stream or sequenced-packet socket accept
    /// connections.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ListenUnixSocketRequest {
        /// Socket handle.
        pub handle: ObjectHandle,
        /// Connections that may wait to be accepted beyond the first.
        pub backlog: u32,
    }
}

wire_struct! {
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
}

wire_struct! {
    /// Request to accept one pending connection.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AcceptUnixSocketRequest {
        /// Listening socket handle.
        pub handle: ObjectHandle,
        /// Status flags of the accepted socket, within [`FileOpenFlags::STATUS`].
        pub flags: FileOpenFlags,
    }
}

wire_struct! {
    /// Response to an accept request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AcceptUnixSocketResponse {
        /// Handle for the accepted connection.
        pub handle: ObjectHandle,
    }
}

wire_struct! {
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
        /// [`UnixSocketAddress`] of `address_length` bytes, then `object_count`
        /// handles encoded by [`ObjectHandle::encode`], then the data.
        pub buffer: SharedBufferSequence,
        /// Length of the destination address, or zero to send to the connected
        /// peer.
        pub address_length: u32,
        /// Number of the caller's object handles whose objects the data
        /// carries, at most [`MAX_UNIX_SOCKET_OBJECTS`].
        ///
        /// The receiver gets its own references to the objects with the first
        /// byte of the data. A stream socket that sends no data carries none.
        pub object_count: u32,
        /// Caller identity for filesystem permission checks.
        pub user: FileUser,
    }
}

wire_struct! {
    /// Response to a send request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SendUnixSocketResponse {
        /// Number of data bytes sent.
        pub sent: u32,
    }
}

wire_struct! {
    /// Request to receive bytes into shared memory.
    ///
    /// A stream socket receives queued bytes. A datagram or sequenced-packet
    /// socket receives one datagram or record, discarding the bytes beyond
    /// `capacity` unless peeking.
    ///
    /// Objects carried with the received data are received too. A stream
    /// socket stops receiving at the end of the data sent with the objects,
    /// so one receive gets the objects of at most one send.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ReceiveUnixSocketRequest {
        /// Socket handle.
        pub handle: ObjectHandle,
        /// Shared-buffer region that receives the data, followed by the sender's
        /// encoded [`UnixSocketName`] if `source` is set.
        ///
        /// It must hold `capacity` bytes, plus
        /// [`MAX_ENCODED_UNIX_SOCKET_NAME_SIZE`] if `source` is set, plus
        /// `max_objects` [`TransferredObject`]s of
        /// [`ENCODED_TRANSFERRED_OBJECT_SIZE`] bytes, which start after the
        /// name's room.
        pub buffer: SharedBufferSequence,
        /// Maximum data bytes to receive.
        pub capacity: u32,
        /// Maximum carried objects to receive handles for, at most
        /// [`MAX_UNIX_SOCKET_OBJECTS`].
        ///
        /// Unless peeking, the receive discards the carried objects beyond
        /// this.
        pub max_objects: u32,
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
}

wire_struct! {
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
        /// Number of encoded [`TransferredObject`]s in the buffer.
        pub object_count: u32,
        /// Whether the received data carried objects the caller got no handle
        /// for.
        pub objects_truncated: bool,
    }
}

wire_struct! {
    /// Request to shut down one or both directions of a socket.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ShutdownUnixSocketRequest {
        /// Socket handle.
        pub handle: ObjectHandle,
        /// [`ShutdownMode::Read`], [`ShutdownMode::Write`], or [`ShutdownMode::Both`].
        pub mode: ShutdownMode,
    }
}

wire_struct! {
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
}

wire_struct! {
    /// Response to a name request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GetUnixSocketNameResponse {
        /// Length of the encoded name.
        pub length: u32,
    }
}

wire_struct! {
    /// Request to store one socket option.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SetUnixSocketOptionRequest {
        /// Socket handle.
        pub handle: ObjectHandle,
        /// Option value to store.
        pub value: SocketOptionValue,
    }
}

wire_struct! {
    /// Request to read one socket option.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GetUnixSocketOptionRequest {
        /// Socket handle.
        pub handle: ObjectHandle,
        /// Option name to read.
        pub name: SocketOptionName,
    }
}

wire_struct! {
    /// Response containing one socket option value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GetUnixSocketOptionResponse {
        /// Stored option value.
        pub value: SocketOptionValue,
    }
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
        ] {
            assert_eq!(UnixSocketName::decode(&name.encode().unwrap()), Ok(name));
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
    fn transferred_objects_round_trip() {
        for kind in [
            TransferredObjectKind::File,
            TransferredObjectKind::PipeReadEnd,
            TransferredObjectKind::PipeWriteEnd,
            TransferredObjectKind::UnixSocket(SocketType::SeqPacket),
            TransferredObjectKind::InetSocket(SocketType::Datagram),
            TransferredObjectKind::VsockSocket,
            TransferredObjectKind::EventCounter,
            TransferredObjectKind::Timer,
            TransferredObjectKind::ReadinessQueue,
            TransferredObjectKind::Process,
        ] {
            let object = TransferredObject {
                handle: ObjectHandle(0x0102_0304_0506_0708),
                kind,
            };
            assert_eq!(TransferredObject::decode(&object.encode()), Ok(object));
        }
        let valid = TransferredObject {
            handle: ObjectHandle(1),
            kind: TransferredObjectKind::File,
        }
        .encode();
        // A plain kind with a detail, an unknown tag, and a socket kind with
        // an unknown socket type.
        for (tag, detail) in [(0, 1), (10, 0), (3, 3)] {
            let mut invalid = valid;
            invalid[ObjectHandle::ENCODED_SIZE] = tag;
            invalid[ObjectHandle::ENCODED_SIZE + 1] = detail;
            assert_eq!(
                TransferredObject::decode(&invalid),
                Err(UnixSocketCodecError::Invalid),
                "tag {tag}, detail {detail}"
            );
        }
    }

    #[test]
    fn addresses_round_trip() {
        for address in [
            UnixSocketAddress::Path {
                path: "/tmp/sock".into(),
                name: b"sock".into(),
            },
            UnixSocketAddress::Abstract(b"name".into()),
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
}
