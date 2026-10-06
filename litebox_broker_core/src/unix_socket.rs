// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Unix sockets.
//!
//! Every Unix socket lives in one broker-wide table behind a single lock,
//! since connecting, sending, and closing change the sockets at both ends of
//! a connection. A socket stays in the table while any reference to it
//! exists, or while it waits in a listener's backlog. Operations call the
//! file service and drop files only after releasing the table lock.
//!
//! Readiness reaches every reference's registration from the moment the
//! reference exists, since another process can change a socket through a
//! connection without sharing a reference to it.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileError, FileMode, FileOpenFlags, FileStatusFlags, FileUser,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{ShutdownMode, SocketType};
use litebox_broker_protocol::unix_socket::{
    MAX_UNIX_SOCKET_BACKLOG, MAX_UNIX_SOCKET_TRANSFER_SIZE, UNIX_SOCKET_BUFFER_SIZE,
    UnixSocketAddress, UnixSocketError, UnixSocketName, UnixSocketOption, UnixSocketOptions,
};
use spin::{Mutex, MutexGuard, rwlock::RwLock};

use crate::fs::File;
use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink, ReadinessWatchers};
use crate::{BrokerCoreLimits, BrokerError, BrokerProcess, Result};

/// Guest-visible result of a Unix socket operation.
pub type UnixSocketResult<T> = core::result::Result<T, UnixSocketError>;

/// Bytes a socket queues before senders to it wait.
const CAPACITY: usize = UNIX_SOCKET_BUFFER_SIZE as usize;

/// Bytes charged for each queued datagram beyond its data, so empty
/// datagrams still consume queue space and quota.
const DATAGRAM_OVERHEAD: usize = 256;

/// Bytes charged to a listener for each connection waiting in its backlog,
/// which holds no reference until accepted.
const CONNECTION_OVERHEAD: usize = 256;

/// Data received from a Unix socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// Received bytes.
    pub data: Vec<u8>,
    /// Length of the whole datagram, or of `data` for a stream socket.
    pub length: usize,
    /// Name of the sending socket.
    pub source: UnixSocketName,
}

/// Creates an unconnected Unix socket.
///
/// The socket starts with the status flags `flags`, which must be within
/// [`FileOpenFlags::STATUS`]. Its reference publishes readiness through
/// `readiness_sink`.
pub fn create(
    process: &BrokerProcess,
    socket_type: SocketType,
    flags: FileOpenFlags,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = creation_rights(process, flags)?;
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    let object = new_object(process, socket_type, flags)?;
    object.watch(&registration)?;
    reference.commit_with_readiness(ObjectEntry::UnixSocket(object), Some(registration))
}

/// Creates a pair of Unix sockets connected to each other.
///
/// Both sockets start with the status flags `flags`, which must be within
/// [`FileOpenFlags::STATUS`]. Their references publish readiness through
/// `readiness_sink`.
pub fn create_pair(
    process: &BrokerProcess,
    socket_type: SocketType,
    flags: FileOpenFlags,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<(ObjectHandle, ObjectHandle)> {
    let rights = creation_rights(process, flags)?;
    let first_reference = process.reserve_object_reference(rights)?;
    let second_reference = process.reserve_object_reference(rights)?;
    let first_registration =
        ReadinessRegistration::new(first_reference.handle(), Arc::clone(readiness_sink));
    let second_registration =
        ReadinessRegistration::new(second_reference.handle(), Arc::clone(readiness_sink));
    let first = new_object(process, socket_type, flags)?;
    let second = new_object(process, socket_type, flags)?;
    {
        let mut table = process.core.unix_sockets.lock();
        for (id, peer) in [(first.id, second.id), (second.id, first.id)] {
            table.socket_mut(id)?.connection = Connection::Connected {
                peer: Some(peer),
                peer_name: UnixSocketName::Unnamed,
            };
        }
    }
    first.watch(&first_registration)?;
    second.watch(&second_registration)?;
    let first = first_reference
        .commit_with_readiness(ObjectEntry::UnixSocket(first), Some(first_registration))?;
    match second_reference
        .commit_with_readiness(ObjectEntry::UnixSocket(second), Some(second_registration))
    {
        Ok(second) => Ok((first, second)),
        Err(error) => {
            process.close_object_reference(first)?;
            Err(error)
        }
    }
}

/// Binds a Unix socket to `address`.
///
/// Binding to a path creates a file there with `mode` as `user`, which fails
/// with [`UnixSocketError::AddressInUse`] if the path already exists.
pub fn bind(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: &UnixSocketAddress,
    user: FileUser,
    mode: FileMode,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let path = {
        let mut table = lease.lock();
        let socket = table.socket_mut(lease.id)?;
        if socket.binding || socket.name != UnixSocketName::Unnamed {
            return Ok(Err(UnixSocketError::InvalidArgument));
        }
        match address {
            UnixSocketAddress::Abstract(_) => {
                return table.register_name(
                    lease.id,
                    NameKey::of(address, lease.socket_type),
                    address.name(),
                    &mut None,
                );
            }
            UnixSocketAddress::Path { path, .. } => {
                socket.binding = true;
                path
            }
        }
    };

    let created = crate::fs::open_node(
        process,
        path,
        user,
        FileAccessMode::WriteOnly,
        FileOpenFlags::CREATE | FileOpenFlags::EXCLUSIVE,
        mode,
    );
    // Declared before the table guard, so a marker the socket does not keep
    // drops after the lock.
    let mut marker;
    let mut table = lease.lock();
    table.socket_mut(lease.id)?.binding = false;
    let key = match created? {
        Ok((file, status)) => {
            marker = Some(file);
            NameKey::Node {
                dev: status.node_info.dev,
                ino: status.node_info.ino,
            }
        }
        Err(FileError::AlreadyExists) => return Ok(Err(UnixSocketError::AddressInUse)),
        Err(error) => return Ok(Err(UnixSocketError::File(error))),
    };
    table.register_name(lease.id, key, address.name(), &mut marker)
}

/// Starts accepting connections on a bound stream socket, or changes the
/// backlog limit of a listening one.
pub fn listen(
    process: &BrokerProcess,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    if lease.socket_type != SocketType::Stream {
        return Ok(Err(UnixSocketError::Unsupported));
    }
    let limit = backlog.min(MAX_UNIX_SOCKET_BACKLOG) as usize;
    let mut table = lease.lock();
    let socket = table.socket_mut(lease.id)?;
    if socket.name == UnixSocketName::Unnamed {
        return Ok(Err(UnixSocketError::InvalidArgument));
    }
    match &mut socket.connection {
        Connection::None => {
            socket.connection = Connection::Listening {
                backlog: VecDeque::new(),
                limit,
            };
        }
        Connection::Listening { limit: current, .. } => *current = limit,
        Connection::Connected { .. } => return Ok(Err(UnixSocketError::InvalidArgument)),
    }
    table.wake_waiters(lease.id);
    table.publish(lease.id);
    Ok(Ok(()))
}

/// Connects a Unix socket to the socket bound to `address`.
///
/// A stream socket queues a new connection on the listening socket there,
/// failing with [`BrokerError::WouldBlock`] while its backlog is full. A
/// datagram socket sets its default destination.
pub fn connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: &UnixSocketAddress,
    user: FileUser,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    // The node stays open until after the table guard drops, so its identity
    // cannot be reused while the operation runs.
    let (key, _node) = match lookup(process, address, user, lease.socket_type)? {
        Ok(found) => found,
        Err(error) => return Ok(Err(error)),
    };
    let mut table = lease.lock();
    let target = match table.target(&key, lease.socket_type)? {
        Ok(target) => target,
        Err(error) => return Ok(Err(error)),
    };
    match lease.socket_type {
        SocketType::Stream => table.connect_stream(lease.id, target, lease.nonblocking),
        SocketType::Datagram => {
            if !table.accepts_datagrams_from(target, lease.id)? {
                return Ok(Err(UnixSocketError::NotPermitted));
            }
            let peer_name = table.socket(target)?.name.clone();
            let socket = table.socket_mut(lease.id)?;
            let previous = core::mem::replace(
                &mut socket.connection,
                Connection::Connected {
                    peer: Some(target),
                    peer_name,
                },
            );
            // Like Linux, connecting to another peer discards the queued
            // datagrams.
            if matches!(previous, Connection::Connected { peer: Some(old), .. } if old != target) {
                table.purge_datagrams(lease.id)?;
            }
            // Senders blocked on this socket recheck whether it still
            // accepts their datagrams.
            table.wake_waiters(lease.id);
            table.publish(lease.id);
            Ok(Ok(()))
        }
        _ => Err(BrokerError::Internal),
    }
}

/// Accepts the oldest queued connection of a listening stream socket.
///
/// The accepted socket starts with the status flags `flags`, which must be
/// within [`FileOpenFlags::STATUS`], and its reference publishes readiness
/// through `readiness_sink`. Fails with [`BrokerError::WouldBlock`] while no
/// connection is queued.
pub fn accept(
    process: &BrokerProcess,
    handle: ObjectHandle,
    flags: FileOpenFlags,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<UnixSocketResult<ObjectHandle>> {
    let rights = creation_rights(process, flags)?;
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WAIT)?)?;
    if lease.socket_type != SocketType::Stream {
        return Ok(Err(UnixSocketError::Unsupported));
    }
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    let accepted = {
        let mut table = lease.lock();
        let listener = table.socket_mut(lease.id)?;
        let Connection::Listening { backlog, .. } = &mut listener.connection else {
            return Ok(Err(UnixSocketError::InvalidArgument));
        };
        let Some(accepted) = backlog.pop_front() else {
            // Linux reports a shut-down listener as invalid only to callers
            // that would otherwise wait.
            return if listener.read_shut && !lease.nonblocking {
                Ok(Err(UnixSocketError::InvalidArgument))
            } else {
                Err(BrokerError::would_block(lease.nonblocking))
            };
        };
        table.refund(lease.id, CONNECTION_OVERHEAD)?;
        table.wake_waiters(lease.id);
        accepted
    };
    let object = UnixSocketObject::new(
        Arc::clone(&lease.sockets),
        accepted,
        SocketType::Stream,
        flags,
    );
    object.watch(&registration)?;
    reference
        .commit_with_readiness(ObjectEntry::UnixSocket(object), Some(registration))
        .map(Ok)
}

/// Sends bytes from a Unix socket, to `address` if given or otherwise to
/// its connected peer, and returns how many were sent.
///
/// A stream socket sends as many bytes as its peer has room for. A datagram
/// socket sends `data` as one datagram. Fails with [`BrokerError::WouldBlock`]
/// while the receiving socket is full.
pub fn send(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: Option<&UnixSocketAddress>,
    data: &[u8],
    user: FileUser,
) -> Result<UnixSocketResult<usize>> {
    if data.len() > MAX_UNIX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    match lease.socket_type {
        SocketType::Stream => {
            lease
                .lock()
                .send_stream(lease.id, address.is_some(), data, lease.nonblocking)
        }
        SocketType::Datagram => {
            // The node stays open until after the table guard drops, as for
            // `connect`.
            let (key, _node) =
                match address.map(|address| lookup(process, address, user, SocketType::Datagram)) {
                    Some(found) => match found? {
                        Ok((key, node)) => (Some(key), node),
                        Err(error) => return Ok(Err(error)),
                    },
                    None => (None, None),
                };
            let mut table = lease.lock();
            table.send_datagram(lease.id, key.as_ref(), data, lease.nonblocking)
        }
        _ => Err(BrokerError::Internal),
    }
}

/// Receives up to `capacity` bytes from a Unix socket, leaving them queued
/// if `peek` is set.
///
/// A stream socket receives queued bytes. A datagram socket receives one
/// datagram, discarding the bytes beyond `capacity` unless peeking. Empty
/// data with zero length for a nonzero `capacity` means no more data can
/// arrive. Fails with [`BrokerError::WouldBlock`] while nothing is queued.
///
/// If `nonblocking` is set, the receive acts as for a non-blocking socket:
/// it fails with [`BrokerError::NonBlockingWouldBlock`], and a datagram
/// socket whose receive direction is shut down fails instead of reporting the
/// end of data, as Linux does.
pub fn receive(
    process: &BrokerProcess,
    handle: ObjectHandle,
    capacity: u32,
    peek: bool,
    nonblocking: bool,
) -> Result<UnixSocketResult<Received>> {
    if capacity > MAX_UNIX_SOCKET_TRANSFER_SIZE {
        return Err(BrokerError::ResourceExhausted);
    }
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WAIT)?)?;
    let nonblocking = nonblocking || lease.nonblocking;
    let mut table = lease.lock();
    match lease.socket_type {
        SocketType::Stream => table.receive_stream(lease.id, capacity as usize, peek, nonblocking),
        SocketType::Datagram => {
            table.receive_datagram(lease.id, capacity as usize, peek, nonblocking)
        }
        _ => Err(BrokerError::Internal),
    }
}

/// Shuts down one or both directions of a Unix socket.
///
/// Shutting down a direction of a connected stream socket also shuts down
/// the opposite direction of its peer.
pub fn shutdown(
    process: &BrokerProcess,
    handle: ObjectHandle,
    mode: ShutdownMode,
) -> Result<UnixSocketResult<()>> {
    let (read, write) = match mode {
        ShutdownMode::Read => (true, false),
        ShutdownMode::Write => (false, true),
        ShutdownMode::Both => (true, true),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let mut table = lease.lock();
    let socket = table.socket_mut(lease.id)?;
    socket.read_shut |= read;
    socket.write_shut |= write;
    let peer = match (&socket.connection, socket.kind) {
        (
            Connection::Connected {
                peer: Some(peer), ..
            },
            SocketType::Stream,
        ) => Some(*peer),
        _ => None,
    };
    if let Some(peer) = peer.and_then(|peer| table.sockets.get_mut(&peer)) {
        peer.read_shut |= write;
        peer.write_shut |= read;
    }
    table.publish(lease.id);
    if let Some(peer) = peer {
        table.publish(peer);
    }
    // Senders waiting for room now fail.
    table.wake_waiters(lease.id);
    Ok(Ok(()))
}

/// Returns the name of a Unix socket, or of its connected peer if `peer`
/// is set.
pub fn name(
    process: &BrokerProcess,
    handle: ObjectHandle,
    peer: bool,
) -> Result<UnixSocketResult<UnixSocketName>> {
    let lease = Lease::new(
        process
            .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?,
    )?;
    let table = lease.lock();
    let socket = table.socket(lease.id)?;
    if !peer {
        return Ok(Ok(socket.name.clone()));
    }
    match &socket.connection {
        Connection::Connected { peer_name, .. } => Ok(Ok(peer_name.clone())),
        Connection::None | Connection::Listening { .. } => Ok(Err(UnixSocketError::NotConnected)),
    }
}

/// Stores one option of a Unix socket.
pub fn set_option(
    process: &BrokerProcess,
    handle: ObjectHandle,
    option: UnixSocketOption,
) -> Result<()> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    lease.lock().socket_mut(lease.id)?.options.set(option);
    Ok(())
}

/// Returns the type and stored options of a Unix socket.
pub fn options(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<(SocketType, UnixSocketOptions)> {
    let lease = Lease::new(
        process
            .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?,
    )?;
    let options = lease.lock().socket(lease.id)?.options;
    Ok((lease.socket_type, options))
}

fn creation_rights(process: &BrokerProcess, flags: FileOpenFlags) -> Result<ObjectRights> {
    if !FileOpenFlags::STATUS.contains(flags) {
        return Err(BrokerError::UnsupportedOperation);
    }
    process
        .core
        .policy
        .principal_object_rights(process.caller_credential)
}

fn new_object(
    process: &BrokerProcess,
    socket_type: SocketType,
    flags: FileOpenFlags,
) -> Result<UnixSocketObject> {
    if !matches!(socket_type, SocketType::Stream | SocketType::Datagram) {
        return Err(BrokerError::UnsupportedOperation);
    }
    let sockets = &process.core.unix_sockets;
    let id = sockets.lock().insert(Socket::new(
        socket_type,
        UnixSocketName::Unnamed,
        Arc::clone(&process.unix_socket_bytes),
    ))?;
    Ok(UnixSocketObject::new(
        Arc::clone(sockets),
        id,
        socket_type,
        flags,
    ))
}

/// Resolves `address` to the key of the name a `socket_type` socket bound to
/// it holds.
///
/// A path resolves to its node, which requires write permission like Linux.
/// The node is returned open, so callers keep its key from naming another
/// node while they use it.
fn lookup(
    process: &BrokerProcess,
    address: &UnixSocketAddress,
    user: FileUser,
    socket_type: SocketType,
) -> Result<UnixSocketResult<(NameKey, Option<File>)>> {
    let UnixSocketAddress::Path { path, .. } = address else {
        return Ok(Ok((NameKey::of(address, socket_type), None)));
    };
    // A path-only open does not copy the node up an overlay, so write
    // permission is checked against its status instead.
    let (file, status) = match crate::fs::open_node(
        process,
        path,
        user,
        FileAccessMode::ReadOnly,
        FileOpenFlags::PATH,
        FileMode::empty(),
    )? {
        Ok(opened) => opened,
        Err(error) => return Ok(Err(UnixSocketError::File(error))),
    };
    let write = if user.user == status.owner.user {
        FileMode::WUSR
    } else if user.group == status.owner.group {
        FileMode::WGRP
    } else {
        FileMode::WOTH
    };
    if !status.mode.contains(write) {
        return Ok(Err(UnixSocketError::File(FileError::AccessNotAllowed)));
    }
    let key = NameKey::Node {
        dev: status.node_info.dev,
        ino: status.node_info.ino,
    };
    Ok(Ok((key, Some(file))))
}

impl ObjectEntry {
    fn as_unix_socket(&self) -> Result<&UnixSocketObject> {
        match self {
            Self::UnixSocket(socket) => Ok(socket),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

/// One Unix socket's open state, which its references share.
pub(crate) struct UnixSocketObject {
    sockets: Arc<UnixSockets>,
    id: SocketId,
    socket_type: SocketType,
    /// Whether operations that would block fail instead of waiting.
    nonblocking: bool,
    /// Whether `O_APPEND` is set, which Linux reports but which has no effect on a socket.
    append: bool,
}

impl UnixSocketObject {
    fn new(
        sockets: Arc<UnixSockets>,
        id: SocketId,
        socket_type: SocketType,
        flags: FileOpenFlags,
    ) -> Self {
        Self {
            sockets,
            id,
            socket_type,
            nonblocking: flags.contains(FileOpenFlags::NONBLOCKING),
            append: flags.contains(FileOpenFlags::APPEND),
        }
    }

    /// Publishes this socket's readiness changes through `registration`
    /// until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.sockets
            .lock()
            .socket_mut(self.id)?
            .watchers
            .watch(registration)
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.sockets.lock().readiness(self.id)
    }

    /// Returns the socket's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        let mut flags = FileOpenFlags::NONE;
        for (set, flag) in [
            (self.nonblocking, FileOpenFlags::NONBLOCKING),
            (self.append, FileOpenFlags::APPEND),
        ] {
            if set {
                flags = flags | flag;
            }
        }
        FileStatusFlags {
            access: FileAccessMode::ReadWrite,
            flags,
        }
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        if mask.contains(FileOpenFlags::NONBLOCKING) {
            self.nonblocking = flags.contains(FileOpenFlags::NONBLOCKING);
        }
        if mask.contains(FileOpenFlags::APPEND) {
            self.append = flags.contains(FileOpenFlags::APPEND);
        }
    }
}

impl Drop for UnixSocketObject {
    fn drop(&mut self) {
        let marker = self.sockets.lock().remove(self.id);
        drop(marker);
    }
}

/// An authorized socket whose object stays alive until the lease drops.
///
/// Callers drop table guards before the lease, since dropping the last
/// reference to the object removes the socket from the table.
struct Lease {
    _object: Arc<RwLock<ObjectEntry>>,
    sockets: Arc<UnixSockets>,
    id: SocketId,
    socket_type: SocketType,
    nonblocking: bool,
}

impl Lease {
    fn new(object: Arc<RwLock<ObjectEntry>>) -> Result<Self> {
        let (sockets, id, socket_type, nonblocking) = {
            let entry = object.read();
            let socket = entry.as_unix_socket()?;
            (
                Arc::clone(&socket.sockets),
                socket.id,
                socket.socket_type,
                socket.nonblocking,
            )
        };
        Ok(Self {
            _object: object,
            sockets,
            id,
            socket_type,
            nonblocking,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.sockets.lock()
    }
}

/// Every Unix socket of a broker.
pub(crate) struct UnixSockets(Mutex<Table>);

impl UnixSockets {
    pub(crate) fn new(limits: &BrokerCoreLimits) -> Self {
        Self(Mutex::new(Table {
            sockets: HashMap::new(),
            names: HashMap::new(),
            next_id: 0,
            queued: 0,
            max_queued: limits.max_total_unix_socket_bytes,
            max_queued_per_process: limits.max_unix_socket_bytes_per_process,
        }))
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.0.lock()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SocketId(u64);

/// Identity of a bound name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum NameKey {
    /// The filesystem node a path name created.
    Node { dev: u64, ino: u64 },
    /// An abstract name, which sockets of each type hold separately like
    /// Linux.
    Abstract(SocketType, Vec<u8>),
}

impl NameKey {
    /// Returns the key of an abstract address held by a `socket_type` socket.
    fn of(address: &UnixSocketAddress, socket_type: SocketType) -> Self {
        match address {
            UnixSocketAddress::Abstract(bytes) => Self::Abstract(socket_type, bytes.clone()),
            UnixSocketAddress::Path { .. } => unreachable!("path names are keyed by their node"),
        }
    }
}

struct Socket {
    kind: SocketType,
    name: UnixSocketName,
    /// Whether a bind is creating the socket's path outside the table lock.
    binding: bool,
    name_key: Option<NameKey>,
    /// File created by binding to a path, held open so the node that
    /// identifies the name stays allocated.
    marker: Option<File>,
    options: UnixSocketOptions,
    read_shut: bool,
    write_shut: bool,
    connection: Connection,
    /// Bytes queued for a stream socket.
    stream: VecDeque<u8>,
    /// Datagrams queued for a datagram socket.
    datagrams: VecDeque<Datagram>,
    /// Bytes charged for queued data, or for a listener's backlog.
    queued: usize,
    /// Quota of the process that created the socket, charged for its queued
    /// data.
    quota: Arc<AtomicUsize>,
    /// Sockets to wake once this socket's queue drains or it closes.
    waiters: Vec<SocketId>,
    watchers: ReadinessWatchers,
}

impl Socket {
    fn new(kind: SocketType, name: UnixSocketName, quota: Arc<AtomicUsize>) -> Self {
        Self {
            kind,
            name,
            binding: false,
            name_key: None,
            marker: None,
            options: UnixSocketOptions::default(),
            read_shut: false,
            write_shut: false,
            connection: Connection::None,
            stream: VecDeque::new(),
            datagrams: VecDeque::new(),
            queued: 0,
            quota,
            waiters: Vec::new(),
            watchers: ReadinessWatchers::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.stream.is_empty() && self.datagrams.is_empty()
    }
}

enum Connection {
    None,
    Listening {
        /// Connected sockets not yet accepted.
        backlog: VecDeque<SocketId>,
        /// Backlog length beyond which connecting waits.
        limit: usize,
    },
    Connected {
        /// The peer, or `None` once a stream peer closes.
        peer: Option<SocketId>,
        /// Name the peer had when the connection formed.
        peer_name: UnixSocketName,
    },
}

struct Datagram {
    data: Vec<u8>,
    source: UnixSocketName,
}

impl Datagram {
    fn charge(&self) -> usize {
        self.data.len() + DATAGRAM_OVERHEAD
    }
}

struct Table {
    sockets: HashMap<SocketId, Socket>,
    names: HashMap<NameKey, SocketId>,
    next_id: u64,
    /// Bytes charged for data queued in every socket.
    queued: usize,
    max_queued: usize,
    max_queued_per_process: usize,
}

impl Table {
    fn socket(&self, id: SocketId) -> Result<&Socket> {
        self.sockets.get(&id).ok_or(BrokerError::Internal)
    }

    fn socket_mut(&mut self, id: SocketId) -> Result<&mut Socket> {
        self.sockets.get_mut(&id).ok_or(BrokerError::Internal)
    }

    fn insert(&mut self, socket: Socket) -> Result<SocketId> {
        let id = SocketId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        self.sockets
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.sockets.insert(id, socket);
        Ok(id)
    }

    /// Records that socket `id` holds the name `name` identified by `key`,
    /// taking `marker` if it succeeds.
    fn register_name(
        &mut self,
        id: SocketId,
        key: NameKey,
        name: UnixSocketName,
        marker: &mut Option<File>,
    ) -> Result<UnixSocketResult<()>> {
        if self.names.contains_key(&key) {
            return Ok(Err(UnixSocketError::AddressInUse));
        }
        self.names
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        socket.name = name;
        socket.name_key = Some(key.clone());
        socket.marker = marker.take();
        self.names.insert(key, id);
        Ok(Ok(()))
    }

    /// Returns the socket holding the name `key`, which must have type
    /// `socket_type`.
    fn target(&self, key: &NameKey, socket_type: SocketType) -> Result<UnixSocketResult<SocketId>> {
        let Some(&target) = self.names.get(key) else {
            return Ok(Err(UnixSocketError::ConnectionRefused));
        };
        if self.socket(target)?.kind != socket_type {
            return Ok(Err(UnixSocketError::WrongType));
        }
        Ok(Ok(target))
    }

    /// Returns whether datagram socket `receiver` accepts datagrams from
    /// `sender`, which it does unless connected to another socket.
    fn accepts_datagrams_from(&self, receiver: SocketId, sender: SocketId) -> Result<bool> {
        Ok(match self.socket(receiver)?.connection {
            Connection::Connected {
                peer: Some(peer), ..
            } => peer == sender,
            _ => true,
        })
    }

    fn connect_stream(
        &mut self,
        id: SocketId,
        target: SocketId,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<()>> {
        let client = self.socket(id)?;
        match client.connection {
            Connection::None => {}
            Connection::Connected { .. } => return Ok(Err(UnixSocketError::AlreadyConnected)),
            Connection::Listening { .. } => return Ok(Err(UnixSocketError::InvalidArgument)),
        }
        let client_name = client.name.clone();
        let listener = self.socket(target)?;
        let Connection::Listening { backlog, limit } = &listener.connection else {
            return Ok(Err(UnixSocketError::ConnectionRefused));
        };
        if listener.read_shut {
            return Ok(Err(UnixSocketError::ConnectionRefused));
        }
        if backlog.len() > *limit {
            self.add_waiter(target, id)?;
            return Err(BrokerError::would_block(nonblocking));
        }
        let listener_name = listener.name.clone();
        let mut server = Socket::new(
            SocketType::Stream,
            listener_name.clone(),
            Arc::clone(&listener.quota),
        );
        server.connection = Connection::Connected {
            peer: Some(id),
            peer_name: client_name,
        };
        let Connection::Listening { backlog, .. } = &mut self.socket_mut(target)?.connection else {
            return Err(BrokerError::Internal);
        };
        backlog
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.charge(target, CONNECTION_OVERHEAD)?;
        let server = match self.insert(server) {
            Ok(server) => server,
            Err(error) => {
                self.refund(target, CONNECTION_OVERHEAD)?;
                return Err(error);
            }
        };
        let Connection::Listening { backlog, .. } = &mut self.socket_mut(target)?.connection else {
            return Err(BrokerError::Internal);
        };
        backlog.push_back(server);
        self.socket_mut(id)?.connection = Connection::Connected {
            peer: Some(server),
            peer_name: listener_name,
        };
        self.publish(target);
        self.publish(id);
        Ok(Ok(()))
    }

    fn send_stream(
        &mut self,
        id: SocketId,
        addressed: bool,
        data: &[u8],
        nonblocking: bool,
    ) -> Result<UnixSocketResult<usize>> {
        let socket = self.socket(id)?;
        let Connection::Connected { peer, .. } = socket.connection else {
            return Ok(Err(if addressed {
                UnixSocketError::Unsupported
            } else {
                UnixSocketError::NotConnected
            }));
        };
        if addressed {
            return Ok(Err(UnixSocketError::AlreadyConnected));
        }
        if socket.write_shut {
            return Ok(Err(UnixSocketError::BrokenPipe));
        }
        if data.is_empty() {
            return Ok(Ok(0));
        }
        let Some(peer) = peer.filter(|peer| self.sockets.get(peer).is_some_and(|p| !p.read_shut))
        else {
            return Ok(Err(UnixSocketError::BrokenPipe));
        };
        let available = CAPACITY.saturating_sub(self.socket(peer)?.queued);
        if available == 0 {
            return Err(BrokerError::would_block(nonblocking));
        }
        let length = available.min(data.len());
        // Charging first keeps a rejected send from growing the queue.
        self.charge(peer, length)?;
        let receiver = self.socket_mut(peer)?;
        if receiver.stream.try_reserve(length).is_err() {
            self.refund(peer, length)?;
            return Err(BrokerError::OutOfMemory);
        }
        receiver.stream.extend(&data[..length]);
        self.publish(peer);
        Ok(Ok(length))
    }

    fn send_datagram(
        &mut self,
        id: SocketId,
        key: Option<&NameKey>,
        data: &[u8],
        nonblocking: bool,
    ) -> Result<UnixSocketResult<usize>> {
        let target = match key {
            Some(key) => match self.target(key, SocketType::Datagram)? {
                Ok(target) => target,
                Err(error) => return Ok(Err(error)),
            },
            None => match self.socket(id)?.connection {
                Connection::Connected {
                    peer: Some(peer), ..
                } => {
                    if !self.sockets.contains_key(&peer) {
                        self.socket_mut(id)?.connection = Connection::None;
                        // Like Linux, disconnecting from the closed peer
                        // discards the queued datagrams.
                        self.purge_datagrams(id)?;
                        self.wake_waiters(id);
                        self.publish(id);
                        return Ok(Err(UnixSocketError::ConnectionRefused));
                    }
                    peer
                }
                _ => return Ok(Err(UnixSocketError::NotConnected)),
            },
        };
        if data.len() > CAPACITY {
            return Ok(Err(UnixSocketError::MessageTooLarge));
        }
        let socket = self.socket(id)?;
        if socket.write_shut {
            return Ok(Err(UnixSocketError::BrokenPipe));
        }
        let source = socket.name.clone();
        if !self.accepts_datagrams_from(target, id)? {
            return Ok(Err(UnixSocketError::NotPermitted));
        }
        let receiver = self.socket(target)?;
        if receiver.read_shut {
            return Ok(Err(UnixSocketError::BrokenPipe));
        }
        // A datagram may overrun the capacity, so a socket that is not full
        // accepts any datagram, as its readiness reports.
        if receiver.queued >= CAPACITY {
            self.add_waiter(target, id)?;
            return Err(BrokerError::would_block(nonblocking));
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(data.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        copy.extend_from_slice(data);
        let datagram = Datagram { data: copy, source };
        self.charge(target, datagram.charge())?;
        let receiver = self.socket_mut(target)?;
        if receiver.datagrams.try_reserve(1).is_err() {
            self.refund(target, datagram.charge())?;
            return Err(BrokerError::OutOfMemory);
        }
        receiver.datagrams.push_back(datagram);
        self.publish(target);
        Ok(Ok(data.len()))
    }

    fn receive_stream(
        &mut self,
        id: SocketId,
        capacity: usize,
        peek: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<Received>> {
        let socket = self.socket_mut(id)?;
        let Connection::Connected { peer_name, .. } = &socket.connection else {
            return Ok(Err(UnixSocketError::InvalidArgument));
        };
        let source = peer_name.clone();
        if capacity == 0 {
            return Ok(Ok(Received {
                source,
                ..Received::default()
            }));
        }
        if socket.stream.is_empty() {
            return if socket.read_shut {
                Ok(Ok(Received {
                    source,
                    ..Received::default()
                }))
            } else {
                Err(BrokerError::would_block(nonblocking))
            };
        }
        let length = capacity.min(socket.stream.len());
        let mut data = Vec::new();
        data.try_reserve_exact(length)
            .map_err(|_| BrokerError::OutOfMemory)?;
        if peek {
            data.extend(socket.stream.iter().take(length));
        } else {
            data.extend(socket.stream.drain(..length));
            if socket.stream.is_empty() {
                socket.stream = VecDeque::new();
            }
            self.refund(id, length)?;
            self.drained(id);
        }
        Ok(Ok(Received {
            data,
            length,
            source,
        }))
    }

    fn receive_datagram(
        &mut self,
        id: SocketId,
        capacity: usize,
        peek: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<Received>> {
        let socket = self.socket_mut(id)?;
        let Some(datagram) = socket.datagrams.front() else {
            return if socket.read_shut && !nonblocking {
                Ok(Ok(Received::default()))
            } else {
                Err(BrokerError::would_block(nonblocking))
            };
        };
        let length = datagram.data.len();
        let mut data = Vec::new();
        data.try_reserve_exact(capacity.min(length))
            .map_err(|_| BrokerError::OutOfMemory)?;
        data.extend_from_slice(&datagram.data[..capacity.min(length)]);
        let source = datagram.source.clone();
        if !peek {
            let datagram = socket.datagrams.pop_front().ok_or(BrokerError::Internal)?;
            self.refund(id, datagram.charge())?;
            self.drained(id);
        }
        Ok(Ok(Received {
            data,
            length,
            source,
        }))
    }

    /// Charges `bytes` of newly queued data to socket `id`.
    fn charge(&mut self, id: SocketId, bytes: usize) -> Result<()> {
        let queued = self
            .queued
            .checked_add(bytes)
            .filter(|queued| *queued <= self.max_queued)
            .ok_or(BrokerError::ResourceExhausted)?;
        let max_queued_per_process = self.max_queued_per_process;
        let socket = self.socket_mut(id)?;
        socket
            .quota
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |charged| {
                charged
                    .checked_add(bytes)
                    .filter(|charged| *charged <= max_queued_per_process)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        socket.queued += bytes;
        self.queued = queued;
        Ok(())
    }

    /// Releases the charge for `bytes` of data dequeued from socket `id`.
    fn refund(&mut self, id: SocketId, bytes: usize) -> Result<()> {
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        Self::release(&mut self.queued, socket, bytes);
        Ok(())
    }

    /// Discards the datagrams queued on socket `id`, which is disconnecting
    /// from its peer.
    fn purge_datagrams(&mut self, id: SocketId) -> Result<()> {
        let socket = self.socket_mut(id)?;
        socket.datagrams.clear();
        let queued = socket.queued;
        self.refund(id, queued)
    }

    fn release(total: &mut usize, socket: &mut Socket, bytes: usize) {
        socket.queued = socket
            .queued
            .checked_sub(bytes)
            .expect("a socket's charge must cover its queued data");
        *total = total
            .checked_sub(bytes)
            .expect("the broker's Unix socket charge must cover every socket's");
        socket
            .quota
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |charged| {
                charged.checked_sub(bytes)
            })
            .expect("a process's Unix socket charge must cover its sockets'");
    }

    /// Wakes the sockets that may send to socket `id` after its queue shrank.
    fn drained(&mut self, id: SocketId) {
        if let Some(Socket {
            connection: Connection::Connected {
                peer: Some(peer), ..
            },
            ..
        }) = self.sockets.get(&id)
        {
            let peer = *peer;
            self.publish(peer);
        }
        self.wake_waiters(id);
    }

    /// Records that socket `waiter` waits for socket `target` to drain or
    /// accept a connection.
    fn add_waiter(&mut self, target: SocketId, waiter: SocketId) -> Result<()> {
        let Self { sockets, .. } = self;
        let Some(mut waiters) = sockets
            .get_mut(&target)
            .map(|target| core::mem::take(&mut target.waiters))
        else {
            return Ok(());
        };
        // Pruning closed waiters bounds the list by the live sockets.
        waiters.retain(|waiter| sockets.contains_key(waiter));
        let reserved = if waiters.contains(&waiter) {
            Ok(())
        } else {
            waiters
                .try_reserve(1)
                .map(|()| waiters.push(waiter))
                .map_err(|_| BrokerError::OutOfMemory)
        };
        if let Some(target) = sockets.get_mut(&target) {
            target.waiters = waiters;
        }
        reserved
    }

    fn wake_waiters(&mut self, id: SocketId) {
        let Some(waiters) = self
            .sockets
            .get_mut(&id)
            .map(|socket| core::mem::take(&mut socket.waiters))
        else {
            return;
        };
        for waiter in waiters {
            self.publish(waiter);
        }
    }

    /// Wakes the watchers of socket `id` after a change that may make it ready.
    ///
    /// Callers hold the table lock, so publications follow the changes in
    /// order.
    fn publish(&mut self, id: SocketId) {
        let readiness = self.readiness(id);
        if let Some(socket) = self.sockets.get(&id) {
            socket.watchers.publish(readiness);
        }
    }

    /// Returns the readiness of socket `id`.
    ///
    /// A datagram socket that cannot send because its peer is full starts
    /// waiting for the peer to drain, as Linux does when polled.
    fn readiness(&mut self, id: SocketId) -> ReadinessFlags {
        let Some(socket) = self.sockets.get(&id) else {
            return ReadinessFlags::default();
        };
        let socket_type = socket.kind;
        let mut readiness = ReadinessFlags::default();
        if socket.read_shut {
            readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
            if socket.write_shut {
                readiness = readiness | ReadinessFlags::CLOSED;
            }
        }
        if !socket.is_empty() {
            readiness = readiness | ReadinessFlags::READ;
        }
        let peer = match &socket.connection {
            Connection::Listening { backlog, .. } => {
                if !backlog.is_empty() {
                    readiness = readiness | ReadinessFlags::READ;
                }
                return readiness;
            }
            Connection::None => {
                if socket_type == SocketType::Stream {
                    readiness = readiness | ReadinessFlags::CLOSED;
                }
                None
            }
            Connection::Connected { peer, .. } => *peer,
        };
        let full_peer = peer.filter(|peer| {
            self.sockets
                .get(peer)
                .is_some_and(|peer| !peer.read_shut && peer.queued >= CAPACITY)
        });
        match full_peer {
            Some(peer) => {
                if socket_type == SocketType::Datagram {
                    // Failing to record the waiter only loses a wakeup the
                    // waiter's next send would record.
                    let _ = self.add_waiter(peer, id);
                }
                readiness
            }
            None => readiness | ReadinessFlags::WRITE,
        }
    }

    /// Removes socket `id` once nothing references it, returning the file
    /// that held its path name for the caller to drop after the table lock.
    fn remove(&mut self, id: SocketId) -> Option<File> {
        let mut socket = self.sockets.remove(&id)?;
        let queued = socket.queued;
        Self::release(&mut self.queued, &mut socket, queued);
        if let Some(key) = socket.name_key.take()
            && self.names.get(&key) == Some(&id)
        {
            self.names.remove(&key);
        }
        match core::mem::replace(&mut socket.connection, Connection::None) {
            Connection::Listening { backlog, .. } => {
                // Unaccepted sockets have no references, so no names.
                for accepted in backlog {
                    let marker = self.remove(accepted);
                    debug_assert!(marker.is_none());
                }
            }
            Connection::Connected {
                peer: Some(peer), ..
            } if socket.kind == SocketType::Stream => {
                if let Some(peer_socket) = self.sockets.get_mut(&peer) {
                    peer_socket.read_shut = true;
                    peer_socket.write_shut = true;
                    if let Connection::Connected { peer, .. } = &mut peer_socket.connection {
                        *peer = None;
                    }
                }
                self.publish(peer);
            }
            Connection::None | Connection::Connected { .. } => {}
        }
        for waiter in core::mem::take(&mut socket.waiters) {
            self.publish(waiter);
        }
        socket.marker.take()
    }
}

#[cfg(test)]
mod tests;
