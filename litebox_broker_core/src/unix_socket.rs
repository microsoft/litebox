// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned Unix sockets.
//!
//! Every socket has its own locks, so operations on different sockets, and on
//! the two directions of one connection, proceed in parallel. A socket's
//! state lock guards its name and connection, and its incoming channel holds
//! the data queued for it to receive. Connected sockets refer to each other
//! weakly. A socket is torn down explicitly once its last reference closes,
//! or once its listener closes without accepting it.
//!
//! Locks are taken only in this order:
//!
//! 1. one socket's readiness watchers, which serialize its publications;
//! 2. one socket's state, or two in address order while one connects to the
//!    other;
//! 3. the broker's registry of names;
//! 4. one socket's incoming channel;
//! 5. the broker's charge for queued data.
//!
//! Sockets are published, and waiting senders woken, only once every other
//! lock is released. Operations call the file service and drop files without
//! holding any lock.
//!
//! Readiness reaches every reference's registration from the moment the
//! reference exists, since another process can change a socket through a
//! connection without sharing a reference to it.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileError, FileMode, FileOpenFlags, FileStatusFlags, FileUser,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    ShutdownMode, SocketOptionName, SocketOptionValue, SocketType,
};
use litebox_broker_protocol::unix_socket::{
    MAX_UNIX_SOCKET_BACKLOG, MAX_UNIX_SOCKET_TRANSFER_SIZE, UNIX_SOCKET_BUFFER_SIZE,
    UnixSocketAddress, UnixSocketError, UnixSocketName,
};
use spin::{Mutex, MutexGuard, rwlock::RwLock};

use crate::channel::{Channel, ChannelState, Waiter, Wakeups};
use crate::fs::File;
use crate::object::{ObjectEntry, ObjectRights, StatusFlags};
use crate::readiness::{ReadinessRegistration, ReadinessSink, ReadinessWatchers};
use crate::socket::SocketOptions;
use crate::transfer::copy_from_queue;
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
    /// Name of the sending socket, if requested.
    pub source: Option<UnixSocketName>,
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
    let (rights, status) = creation_rights(process, flags)?;
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    let object = UnixSocketObject::new(process, socket_type, status)?;
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
    let (rights, status) = creation_rights(process, flags)?;
    let first_reference = process.reserve_object_reference(rights)?;
    let second_reference = process.reserve_object_reference(rights)?;
    let first_registration =
        ReadinessRegistration::new(first_reference.handle(), Arc::clone(readiness_sink));
    let second_registration =
        ReadinessRegistration::new(second_reference.handle(), Arc::clone(readiness_sink));
    let first = UnixSocketObject::new(process, socket_type, status)?;
    let second = UnixSocketObject::new(process, socket_type, status)?;
    for (socket, peer) in [
        (&first.socket, &second.socket),
        (&second.socket, &first.socket),
    ] {
        socket.state.lock().connection = Connection::Connected {
            peer: Arc::downgrade(peer),
            peer_name: UnixSocketName::Unnamed,
        };
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
    let socket = &lease.socket;
    let path = {
        let mut state = socket.state.lock();
        if state.binding || state.name != UnixSocketName::Unnamed {
            return Ok(Err(UnixSocketError::InvalidArgument));
        }
        match address {
            UnixSocketAddress::Abstract(_) => {
                return socket.register_name(
                    &mut state,
                    NameKey::of(address, socket.kind),
                    address.name(),
                );
            }
            UnixSocketAddress::Path { path, .. } => {
                state.binding = true;
                path
            }
        }
    };

    let created = crate::fs::open_without_reference(
        process,
        path,
        user,
        FileAccessMode::WriteOnly,
        FileOpenFlags::CREATE | FileOpenFlags::EXCLUSIVE,
        mode,
    );
    // Declared before the state guard, so a marker the socket does not keep
    // drops after the lock.
    let mut marker;
    let mut state = socket.state.lock();
    state.binding = false;
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
    let registered = socket.register_name(&mut state, key, address.name())?;
    if registered.is_ok() {
        state.marker = marker.take();
    }
    Ok(registered)
}

/// Starts accepting connections on a bound stream socket, or changes the
/// backlog limit of a listening one.
pub fn listen(
    process: &BrokerProcess,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    if socket.kind != SocketType::Stream {
        return Ok(Err(UnixSocketError::Unsupported));
    }
    let limit = backlog.min(MAX_UNIX_SOCKET_BACKLOG) as usize;
    let wakeups = {
        let mut state = socket.state.lock();
        if state.name == UnixSocketName::Unnamed {
            return Ok(Err(UnixSocketError::InvalidArgument));
        }
        match &mut state.connection {
            Connection::None => {
                state.connection = Connection::Listening {
                    backlog: VecDeque::new(),
                    limit,
                };
            }
            Connection::Listening { limit: current, .. } => *current = limit,
            Connection::Connected { .. } => return Ok(Err(UnixSocketError::InvalidArgument)),
        }
        // Sockets waiting for room in the backlog retry.
        socket.incoming.lock().wake()
    };
    wakeups.wake();
    socket.publish();
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
    let socket = &lease.socket;
    // The node stays open until the connect finishes, so its identity cannot
    // be reused meanwhile.
    let (key, _node) = match lookup(process, address, user, socket.kind)? {
        Ok(found) => found,
        Err(error) => return Ok(Err(error)),
    };
    let target = match socket.sockets.find(&key, socket.kind) {
        Ok(target) => target,
        Err(error) => return Ok(Err(error)),
    };
    match socket.kind {
        SocketType::Stream => socket.connect_stream(&target, lease.nonblocking),
        SocketType::Datagram => Ok(socket.connect_datagram(&target)),
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
    let (rights, status) = creation_rights(process, flags)?;
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WAIT)?)?;
    let listener = &lease.socket;
    if listener.kind != SocketType::Stream {
        return Ok(Err(UnixSocketError::Unsupported));
    }
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    let (accepted, wakeups) = {
        let mut state = listener.state.lock();
        let Connection::Listening { backlog, .. } = &mut state.connection else {
            return Ok(Err(UnixSocketError::InvalidArgument));
        };
        let mut channel = listener.incoming.lock();
        let Some(accepted) = backlog.pop_front() else {
            // Linux reports a shut-down listener as invalid only to callers
            // that would otherwise wait.
            return if channel.is_shut() && !lease.nonblocking {
                Ok(Err(UnixSocketError::InvalidArgument))
            } else {
                Err(BrokerError::would_block(lease.nonblocking))
            };
        };
        listener
            .sockets
            .refund(&listener.quota, CONNECTION_OVERHEAD);
        // Sockets waiting for room in the backlog retry.
        (accepted, channel.wake())
    };
    wakeups.wake();
    let object = UnixSocketObject::from_socket(accepted, status);
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
    let socket = &lease.socket;
    match socket.kind {
        SocketType::Stream => socket.send_stream(address.is_some(), data, lease.nonblocking),
        SocketType::Datagram => {
            // The node stays open until the send finishes, as for `connect`.
            let (target, _node) = match address {
                Some(address) => {
                    let (key, node) = match lookup(process, address, user, SocketType::Datagram)? {
                        Ok(found) => found,
                        Err(error) => return Ok(Err(error)),
                    };
                    match socket.sockets.find(&key, SocketType::Datagram) {
                        Ok(target) => (Some(target), node),
                        Err(error) => return Ok(Err(error)),
                    }
                }
                None => (None, None),
            };
            socket.send_datagram(target, data, lease.nonblocking)
        }
        _ => Err(BrokerError::Internal),
    }
}

/// Receives up to `capacity` bytes from a Unix socket, leaving them queued
/// if `peek` is set and returning the sender's name if `source` is set.
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
    source: bool,
    nonblocking: bool,
) -> Result<UnixSocketResult<Received>> {
    if capacity > MAX_UNIX_SOCKET_TRANSFER_SIZE {
        return Err(BrokerError::ResourceExhausted);
    }
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WAIT)?)?;
    let socket = &lease.socket;
    let nonblocking = nonblocking || lease.nonblocking;
    match socket.kind {
        SocketType::Stream => socket.receive_stream(capacity as usize, peek, source, nonblocking),
        SocketType::Datagram => {
            socket.receive_datagram(capacity as usize, peek, source, nonblocking)
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
    let socket = &lease.socket;
    let (peer, wakeups) = socket.shut_down(read, write);
    wakeups.wake();
    socket.publish();
    if let Some(peer) = peer {
        let (_, wakeups) = peer.shut_down(write, read);
        wakeups.wake();
        peer.publish();
    }
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
    let state = lease.socket.state.lock();
    if !peer {
        return Ok(Ok(state.name.clone()));
    }
    match &state.connection {
        Connection::Connected { peer_name, .. } => Ok(Ok(peer_name.clone())),
        Connection::None | Connection::Listening { .. } => Ok(Err(UnixSocketError::NotConnected)),
    }
}

/// Stores one option of a Unix socket.
///
/// Fails with `UnsupportedOperation` for [`SocketOptionValue::NoDelay`].
pub fn set_option(
    process: &BrokerProcess,
    handle: ObjectHandle,
    value: SocketOptionValue,
) -> Result<()> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    lease.socket.state.lock().options.set(value)
}

/// Returns one stored option of a Unix socket.
pub fn get_option(
    process: &BrokerProcess,
    handle: ObjectHandle,
    name: SocketOptionName,
) -> Result<SocketOptionValue> {
    let lease = Lease::new(
        process
            .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?,
    )?;
    lease.socket.state.lock().options.get(name)
}

/// Returns the rights and status flags of a new socket with the status flags
/// `flags`.
fn creation_rights(
    process: &BrokerProcess,
    flags: FileOpenFlags,
) -> Result<(ObjectRights, StatusFlags)> {
    let status = StatusFlags::new(flags)?;
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    Ok((rights, status))
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
    let (file, status) = match crate::fs::open_without_reference(
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
    socket: Arc<Socket>,
    status: StatusFlags,
}

impl UnixSocketObject {
    /// Creates a new unnamed, unconnected `socket_type` socket.
    fn new(process: &BrokerProcess, socket_type: SocketType, status: StatusFlags) -> Result<Self> {
        if !matches!(socket_type, SocketType::Stream | SocketType::Datagram) {
            return Err(BrokerError::UnsupportedOperation);
        }
        let socket = Socket::new(
            socket_type,
            Arc::clone(&process.core.unix_sockets),
            Arc::clone(&process.unix_socket_bytes),
            UnixSocketName::Unnamed,
            Connection::None,
        );
        Ok(Self::from_socket(Arc::new(socket), status))
    }

    /// Takes ownership of `socket`, which closes once the object drops.
    fn from_socket(socket: Arc<Socket>, status: StatusFlags) -> Self {
        Self { socket, status }
    }

    /// Publishes this socket's readiness changes through `registration`
    /// until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.socket.watchers.lock().watch(registration)
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.socket.readiness()
    }

    /// Returns the socket's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(FileAccessMode::ReadWrite)
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }
}

impl Drop for UnixSocketObject {
    fn drop(&mut self) {
        self.socket.close();
    }
}

/// An authorized socket whose object stays alive until the lease drops.
///
/// Dropping the last reference to the object closes the socket, which takes
/// the locks of the socket and its peer, so callers release every lock
/// before the lease drops.
struct Lease {
    _object: Arc<RwLock<ObjectEntry>>,
    socket: Arc<Socket>,
    nonblocking: bool,
}

impl Lease {
    fn new(object: Arc<RwLock<ObjectEntry>>) -> Result<Self> {
        let (socket, nonblocking) = {
            let entry = object.read();
            let socket = entry.as_unix_socket()?;
            (Arc::clone(&socket.socket), socket.status.nonblocking())
        };
        Ok(Self {
            _object: object,
            socket,
            nonblocking,
        })
    }
}

/// The Unix sockets of a broker: the names they hold, and the charge for the
/// data queued in them.
pub(crate) struct UnixSockets {
    /// Socket holding each bound name.
    names: RwLock<HashMap<NameKey, Weak<Socket>>>,
    /// Bytes charged for data queued in every socket. Processes' charges
    /// change only under this lock too, so a charge commits both or neither.
    queued: Mutex<usize>,
    max_queued: usize,
    max_queued_per_process: usize,
}

impl UnixSockets {
    pub(crate) fn new(limits: &BrokerCoreLimits) -> Self {
        Self {
            names: RwLock::new(HashMap::new()),
            queued: Mutex::new(0),
            max_queued: limits.max_total_unix_socket_bytes,
            max_queued_per_process: limits.max_unix_socket_bytes_per_process,
        }
    }

    /// Returns the socket holding the name `key`, which must have type
    /// `socket_type`.
    fn find(&self, key: &NameKey, socket_type: SocketType) -> UnixSocketResult<Arc<Socket>> {
        let socket = self
            .names
            .read()
            .get(key)
            .and_then(Weak::upgrade)
            .ok_or(UnixSocketError::ConnectionRefused)?;
        if socket.kind != socket_type {
            return Err(UnixSocketError::WrongType);
        }
        Ok(socket)
    }

    /// Releases the name `key` if `socket` still holds it.
    fn unregister(&self, key: &NameKey, socket: &Socket) {
        let mut names = self.names.write();
        if names
            .get(key)
            .is_some_and(|holder| core::ptr::eq(holder.as_ptr(), socket))
        {
            names.remove(key);
        }
    }

    /// Charges `bytes` of newly queued data, to the process quota `quota`
    /// among others.
    fn charge(&self, quota: &AtomicUsize, bytes: usize) -> Result<()> {
        let mut queued = self.queued.lock();
        let total = queued
            .checked_add(bytes)
            .filter(|total| *total <= self.max_queued)
            .ok_or(BrokerError::ResourceExhausted)?;
        let charged = quota
            .load(Ordering::Relaxed)
            .checked_add(bytes)
            .filter(|charged| *charged <= self.max_queued_per_process)
            .ok_or(BrokerError::ResourceExhausted)?;
        quota.store(charged, Ordering::Relaxed);
        *queued = total;
        Ok(())
    }

    /// Releases the charge for `bytes` of dequeued data.
    fn refund(&self, quota: &AtomicUsize, bytes: usize) {
        let mut queued = self.queued.lock();
        let charged = quota
            .load(Ordering::Relaxed)
            .checked_sub(bytes)
            .expect("a process's Unix socket charge must cover its sockets'");
        quota.store(charged, Ordering::Relaxed);
        *queued = queued
            .checked_sub(bytes)
            .expect("the broker's Unix socket charge must cover every socket's");
    }
}

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

/// One Unix socket.
///
/// Dropping a socket tears nothing down: [`Socket::close`] does once nothing
/// reaches the socket through a reference or a backlog, so temporary handles
/// to it may drop anywhere.
struct Socket {
    kind: SocketType,
    sockets: Arc<UnixSockets>,
    /// Quota of the process that created the socket, charged for the data
    /// queued for it and for its backlog.
    quota: Arc<AtomicUsize>,
    state: Mutex<State>,
    /// Data queued for the socket to receive. Its waiters are the sockets
    /// waiting for room in it, or in the socket's backlog.
    incoming: Channel<Queue, Socket>,
    /// Registrations that receive the socket's readiness. Their lock
    /// serializes publications, so the last one reflects the latest state.
    watchers: Mutex<ReadinessWatchers>,
}

struct State {
    name: UnixSocketName,
    /// Whether a bind is creating the socket's path without holding the lock.
    binding: bool,
    name_key: Option<NameKey>,
    /// File created by binding to a path, held open so the node that
    /// identifies the name stays allocated.
    marker: Option<File>,
    options: SocketOptions,
    /// Whether the socket stopped sending. Its incoming channel is shut once
    /// it stops receiving.
    write_shut: bool,
    /// Whether the socket was torn down.
    closed: bool,
    connection: Connection,
}

enum Connection {
    None,
    Listening {
        /// Connected sockets not yet accepted.
        backlog: VecDeque<Arc<Socket>>,
        /// Backlog length beyond which connecting waits.
        limit: usize,
    },
    Connected {
        /// The peer, which a stream socket forgets once the peer closes.
        peer: Weak<Socket>,
        /// Name the peer had when the connection formed.
        peer_name: UnixSocketName,
    },
}

/// Data queued for a socket to receive.
#[derive(Default)]
struct Queue {
    /// Bytes queued for a stream socket.
    bytes: VecDeque<u8>,
    /// Datagrams queued for a datagram socket.
    datagrams: VecDeque<Datagram>,
}

impl Queue {
    fn is_empty(&self) -> bool {
        self.bytes.is_empty() && self.datagrams.is_empty()
    }
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

/// Returns whether `weak` refers to `socket`.
///
/// A weak reference keeps its allocation, so no other socket can take its
/// address while it exists.
fn refers_to(weak: &Weak<Socket>, socket: &Arc<Socket>) -> bool {
    core::ptr::eq(weak.as_ptr(), Arc::as_ptr(socket))
}

/// Locks the states of two different sockets in address order, so connects
/// in opposite directions cannot deadlock.
fn lock_both<'a>(
    first: &'a Socket,
    second: &'a Socket,
) -> (MutexGuard<'a, State>, MutexGuard<'a, State>) {
    if core::ptr::from_ref(first) < core::ptr::from_ref(second) {
        let first = first.state.lock();
        (first, second.state.lock())
    } else {
        let second = second.state.lock();
        (first.state.lock(), second)
    }
}

impl Waiter for Socket {
    fn wake(self: Arc<Self>) {
        self.publish();
    }
}

impl Socket {
    fn new(
        kind: SocketType,
        sockets: Arc<UnixSockets>,
        quota: Arc<AtomicUsize>,
        name: UnixSocketName,
        connection: Connection,
    ) -> Self {
        Self {
            kind,
            sockets,
            quota,
            state: Mutex::new(State {
                name,
                binding: false,
                name_key: None,
                marker: None,
                options: SocketOptions::default(),
                write_shut: false,
                closed: false,
                connection,
            }),
            incoming: Channel::new(Queue::default(), CAPACITY),
            watchers: Mutex::new(ReadinessWatchers::default()),
        }
    }

    /// Publishes the socket's readiness after a change that may affect it.
    fn publish(self: &Arc<Self>) {
        let watchers = self.watchers.lock();
        watchers.publish(self.readiness());
    }

    /// Returns the readiness of the socket.
    ///
    /// A socket that cannot send because its peer is full starts waiting for
    /// the peer to drain, as Linux does when polled. If it cannot wait, it
    /// reports itself writable, so a send retries and reports the failure
    /// rather than waiting for a wakeup that never comes.
    fn readiness(self: &Arc<Self>) -> ReadinessFlags {
        let (write_shut, connection) = {
            let state = self.state.lock();
            let connection = match &state.connection {
                Connection::None => None,
                Connection::Listening { backlog, .. } => Some(Err(!backlog.is_empty())),
                Connection::Connected { peer, .. } => Some(Ok(peer.clone())),
            };
            (state.write_shut, connection)
        };
        let mut readiness = ReadinessFlags::default();
        {
            let channel = self.incoming.lock();
            if channel.is_shut() {
                readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
                if write_shut {
                    readiness = readiness | ReadinessFlags::CLOSED;
                }
            }
            if !channel.queue.is_empty() {
                readiness = readiness | ReadinessFlags::READ;
            }
        }
        let peer = match connection {
            None => {
                if self.kind == SocketType::Stream {
                    readiness = readiness | ReadinessFlags::CLOSED;
                }
                None
            }
            Some(Err(pending)) => {
                if pending {
                    readiness = readiness | ReadinessFlags::READ;
                }
                return readiness;
            }
            Some(Ok(peer)) => peer.upgrade(),
        };
        if let Some(peer) = peer {
            let mut channel = peer.incoming.lock();
            if !channel.is_shut() && channel.room() == 0 && channel.wait(self).is_ok() {
                return readiness;
            }
        }
        readiness | ReadinessFlags::WRITE
    }

    /// Records that the socket holds the name `name` identified by `key`.
    fn register_name(
        self: &Arc<Self>,
        state: &mut State,
        key: NameKey,
        name: UnixSocketName,
    ) -> Result<UnixSocketResult<()>> {
        let mut names = self.sockets.names.write();
        if names.contains_key(&key) {
            return Ok(Err(UnixSocketError::AddressInUse));
        }
        names.try_reserve(1).map_err(|_| BrokerError::OutOfMemory)?;
        names.insert(key.clone(), Arc::downgrade(self));
        state.name = name;
        state.name_key = Some(key);
        Ok(Ok(()))
    }

    fn connect_stream(
        self: &Arc<Self>,
        listener: &Arc<Socket>,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<()>> {
        if Arc::ptr_eq(self, listener) {
            // A socket never listens while connecting.
            return Ok(Err(match self.state.lock().connection {
                Connection::None => UnixSocketError::ConnectionRefused,
                Connection::Connected { .. } => UnixSocketError::AlreadyConnected,
                Connection::Listening { .. } => UnixSocketError::InvalidArgument,
            }));
        }
        {
            let (mut state, mut listening) = lock_both(self, listener);
            // A closed listener is gone, as if its name were never found.
            if listening.closed {
                return Ok(Err(UnixSocketError::ConnectionRefused));
            }
            match state.connection {
                Connection::None => {}
                Connection::Connected { .. } => return Ok(Err(UnixSocketError::AlreadyConnected)),
                Connection::Listening { .. } => return Ok(Err(UnixSocketError::InvalidArgument)),
            }
            let listener_name = listening.name.clone();
            let Connection::Listening { backlog, limit } = &mut listening.connection else {
                return Ok(Err(UnixSocketError::ConnectionRefused));
            };
            {
                let mut channel = listener.incoming.lock();
                if channel.is_shut() {
                    return Ok(Err(UnixSocketError::ConnectionRefused));
                }
                if backlog.len() > *limit {
                    channel.wait(self)?;
                    return Err(BrokerError::would_block(nonblocking));
                }
            }
            backlog
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.sockets.charge(&listener.quota, CONNECTION_OVERHEAD)?;
            let server = Arc::new(Socket::new(
                SocketType::Stream,
                Arc::clone(&listener.sockets),
                Arc::clone(&listener.quota),
                listener_name.clone(),
                Connection::Connected {
                    peer: Arc::downgrade(self),
                    peer_name: state.name.clone(),
                },
            ));
            state.connection = Connection::Connected {
                peer: Arc::downgrade(&server),
                peer_name: listener_name,
            };
            backlog.push_back(server);
        }
        listener.publish();
        self.publish();
        Ok(Ok(()))
    }

    fn connect_datagram(self: &Arc<Self>, target: &Arc<Socket>) -> UnixSocketResult<()> {
        // Both states stay locked from the check to the connection, like
        // Linux, so neither socket connects elsewhere meanwhile.
        let wakeups = if Arc::ptr_eq(self, target) {
            let mut state = self.state.lock();
            let peer_name = self.accept_peer(&state)?;
            self.set_datagram_peer(&mut state, target, peer_name)
        } else {
            let (mut state, target_state) = lock_both(self, target);
            let peer_name = self.accept_peer(&target_state)?;
            self.set_datagram_peer(&mut state, target, peer_name)
        };
        wakeups.wake();
        self.publish();
        Ok(())
    }

    /// Returns the name of the datagram socket whose state is `target` if it
    /// lets this socket connect to it.
    fn accept_peer(self: &Arc<Self>, target: &State) -> UnixSocketResult<UnixSocketName> {
        if target.closed {
            return Err(UnixSocketError::ConnectionRefused);
        }
        if let Connection::Connected { peer, .. } = &target.connection
            && !refers_to(peer, self)
        {
            return Err(UnixSocketError::NotPermitted);
        }
        Ok(target.name.clone())
    }

    /// Connects this datagram socket, whose state is `state`, to `target`
    /// named `peer_name`.
    fn set_datagram_peer(
        &self,
        state: &mut State,
        target: &Arc<Socket>,
        peer_name: UnixSocketName,
    ) -> Wakeups<Socket> {
        let previous = core::mem::replace(
            &mut state.connection,
            Connection::Connected {
                peer: Arc::downgrade(target),
                peer_name,
            },
        );
        let mut channel = self.incoming.lock();
        // Like Linux, connecting to another peer discards the queued
        // datagrams.
        if matches!(&previous, Connection::Connected { peer, .. } if !refers_to(peer, target)) {
            self.purge(&mut channel);
        }
        // Senders waiting on this socket recheck whether it still accepts
        // their datagrams.
        channel.wake()
    }

    fn send_stream(
        self: &Arc<Self>,
        addressed: bool,
        data: &[u8],
        nonblocking: bool,
    ) -> Result<UnixSocketResult<usize>> {
        let peer = {
            let state = self.state.lock();
            let Connection::Connected { peer, .. } = &state.connection else {
                return Ok(Err(if addressed {
                    UnixSocketError::Unsupported
                } else {
                    UnixSocketError::NotConnected
                }));
            };
            if addressed {
                return Ok(Err(UnixSocketError::AlreadyConnected));
            }
            if state.write_shut {
                return Ok(Err(UnixSocketError::BrokenPipe));
            }
            peer.clone()
        };
        if data.is_empty() {
            return Ok(Ok(0));
        }
        let Some(peer) = peer.upgrade() else {
            return Ok(Err(UnixSocketError::BrokenPipe));
        };
        let length = {
            let mut channel = peer.incoming.lock();
            if channel.is_shut() {
                return Ok(Err(UnixSocketError::BrokenPipe));
            }
            let room = channel.room();
            if room == 0 {
                channel.wait(self)?;
                return Err(BrokerError::would_block(nonblocking));
            }
            let length = room.min(data.len());
            // Charging first keeps a rejected send from growing the queue.
            self.sockets.charge(&peer.quota, length)?;
            if channel.queue.bytes.try_reserve(length).is_err() {
                self.sockets.refund(&peer.quota, length);
                return Err(BrokerError::OutOfMemory);
            }
            channel.queue.bytes.extend(&data[..length]);
            channel.add(length);
            length
        };
        peer.publish();
        Ok(Ok(length))
    }

    /// Sends `data` as one datagram to `target`, or to the connected peer if
    /// `target` is `None`.
    fn send_datagram(
        self: &Arc<Self>,
        target: Option<Arc<Socket>>,
        data: &[u8],
        nonblocking: bool,
    ) -> Result<UnixSocketResult<usize>> {
        let (peer, write_shut, source) = {
            let state = self.state.lock();
            let peer = match &state.connection {
                Connection::Connected { peer, .. } => Some(peer.clone()),
                Connection::None | Connection::Listening { .. } => None,
            };
            (peer, state.write_shut, state.name.clone())
        };
        let (target, connected) = if let Some(target) = target {
            (target, false)
        } else {
            let Some(peer) = peer else {
                return Ok(Err(UnixSocketError::NotConnected));
            };
            // A closed peer may outlive its close while an operation holds
            // it.
            match peer.upgrade() {
                Some(peer) if !peer.state.lock().closed => (peer, true),
                _ => return Ok(self.disconnect_from(peer.as_ptr())),
            }
        };
        if data.len() > CAPACITY {
            return Ok(Err(UnixSocketError::MessageTooLarge));
        }
        if write_shut {
            return Ok(Err(UnixSocketError::BrokenPipe));
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(data.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        copy.extend_from_slice(data);
        let datagram = Datagram { data: copy, source };
        let charge = datagram.charge();
        // The receiver's state stays locked while the datagram is queued, so
        // connecting it rejects other senders from then on, as in Linux.
        let closed = {
            let state = target.state.lock();
            if let Connection::Connected { peer, .. } = &state.connection
                && !refers_to(peer, self)
            {
                return Ok(Err(UnixSocketError::NotPermitted));
            }
            if state.closed {
                true
            } else {
                let mut channel = target.incoming.lock();
                if channel.is_shut() {
                    return Ok(Err(UnixSocketError::BrokenPipe));
                }
                // A datagram may overrun the capacity, so a socket that is
                // not full accepts any datagram, as its readiness reports.
                if channel.room() == 0 {
                    channel.wait(self)?;
                    return Err(BrokerError::would_block(nonblocking));
                }
                self.sockets.charge(&target.quota, charge)?;
                if channel.queue.datagrams.try_reserve(1).is_err() {
                    self.sockets.refund(&target.quota, charge);
                    return Err(BrokerError::OutOfMemory);
                }
                channel.queue.datagrams.push_back(datagram);
                channel.add(charge);
                false
            }
        };
        if closed {
            return Ok(if connected {
                self.disconnect_from(Arc::as_ptr(&target))
            } else {
                Err(UnixSocketError::ConnectionRefused)
            });
        }
        target.publish();
        Ok(Ok(data.len()))
    }

    /// Disconnects this datagram socket from `peer`, which closed, and
    /// refuses the send that found it closed. Like Linux, a send that raced
    /// a change of connection fails with a reset instead.
    fn disconnect_from(self: &Arc<Self>, peer: *const Socket) -> UnixSocketResult<usize> {
        let wakeups = {
            let mut state = self.state.lock();
            match &state.connection {
                Connection::Connected { peer: current, .. }
                    if core::ptr::eq(current.as_ptr(), peer) => {}
                _ => return Err(UnixSocketError::ConnectionReset),
            }
            state.connection = Connection::None;
            let mut channel = self.incoming.lock();
            // Like Linux, disconnecting from the closed peer discards the
            // queued datagrams.
            self.purge(&mut channel);
            // Senders it rejected while connected retry.
            channel.wake()
        };
        wakeups.wake();
        self.publish();
        Err(UnixSocketError::ConnectionRefused)
    }

    fn receive_stream(
        &self,
        capacity: usize,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<Received>> {
        let source = match &self.state.lock().connection {
            Connection::Connected { peer_name, .. } => source.then(|| peer_name.clone()),
            Connection::None | Connection::Listening { .. } => {
                return Ok(Err(UnixSocketError::InvalidArgument));
            }
        };
        if capacity == 0 {
            return Ok(Ok(Received {
                source,
                ..Received::default()
            }));
        }
        let (data, wakeups) = {
            let mut channel = self.incoming.lock();
            if channel.queue.bytes.is_empty() {
                return if channel.is_shut() {
                    Ok(Ok(Received {
                        source,
                        ..Received::default()
                    }))
                } else {
                    Err(BrokerError::would_block(nonblocking))
                };
            }
            let length = capacity.min(channel.queue.bytes.len());
            let data = copy_from_queue(&channel.queue.bytes, 0..length)?;
            if peek {
                (data, Wakeups::default())
            } else {
                channel.queue.bytes.drain(..length);
                if channel.queue.bytes.is_empty() {
                    channel.queue.bytes = VecDeque::new();
                }
                channel.remove(length);
                self.sockets.refund(&self.quota, length);
                // Senders waiting for room retry.
                (data, channel.wake())
            }
        };
        wakeups.wake();
        Ok(Ok(Received {
            length: data.len(),
            data,
            source,
        }))
    }

    fn receive_datagram(
        &self,
        capacity: usize,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<Received>> {
        let (received, wakeups) = {
            let mut channel = self.incoming.lock();
            let Some(datagram) = channel.queue.datagrams.front() else {
                return if channel.is_shut() && !nonblocking {
                    Ok(Ok(Received {
                        source: source.then_some(UnixSocketName::Unnamed),
                        ..Received::default()
                    }))
                } else {
                    Err(BrokerError::would_block(nonblocking))
                };
            };
            let length = datagram.data.len();
            if peek {
                let mut data = Vec::new();
                data.try_reserve_exact(capacity.min(length))
                    .map_err(|_| BrokerError::OutOfMemory)?;
                data.extend_from_slice(&datagram.data[..capacity.min(length)]);
                let received = Received {
                    data,
                    length,
                    source: source.then(|| datagram.source.clone()),
                };
                (received, Wakeups::default())
            } else {
                let datagram = channel
                    .queue
                    .datagrams
                    .pop_front()
                    .ok_or(BrokerError::Internal)?;
                channel.remove(datagram.charge());
                self.sockets.refund(&self.quota, datagram.charge());
                let Datagram {
                    mut data,
                    source: name,
                } = datagram;
                data.truncate(capacity);
                let received = Received {
                    data,
                    length,
                    source: source.then_some(name),
                };
                // Senders waiting for room retry.
                (received, channel.wake())
            }
        };
        wakeups.wake();
        Ok(Ok(received))
    }

    /// Stops the socket from receiving if `read` is set, and from sending if
    /// `write` is set, returning its connected stream peer.
    fn shut_down(&self, read: bool, write: bool) -> (Option<Arc<Socket>>, Wakeups<Socket>) {
        let mut state = self.state.lock();
        state.write_shut |= write;
        let peer = match &state.connection {
            Connection::Connected { peer, .. } if self.kind == SocketType::Stream => peer.upgrade(),
            _ => None,
        };
        if !read {
            return (peer, Wakeups::default());
        }
        let mut channel = self.incoming.lock();
        channel.shut();
        // Senders waiting for room now fail.
        (peer, channel.wake())
    }

    /// Ends this stream socket's connection after its peer closed.
    fn hang_up(self: &Arc<Self>) {
        let wakeups = {
            let mut state = self.state.lock();
            state.write_shut = true;
            if let Connection::Connected { peer, .. } = &mut state.connection {
                *peer = Weak::new();
            }
            let mut channel = self.incoming.lock();
            channel.shut();
            channel.wake()
        };
        wakeups.wake();
        self.publish();
    }

    /// Discards the data queued for the socket.
    fn purge(&self, channel: &mut ChannelState<Queue, Socket>) {
        channel.queue = Queue::default();
        let queued = channel.queued();
        channel.remove(queued);
        self.sockets.refund(&self.quota, queued);
    }

    /// Tears the socket down once nothing reaches it through a reference or a
    /// backlog.
    fn close(&self) {
        let (connection, marker, wakeups) = {
            let mut state = self.state.lock();
            if core::mem::replace(&mut state.closed, true) {
                return;
            }
            // The name is released along with the close, so a socket that
            // finds it closed can bind the name, as in Linux.
            if let Some(key) = state.name_key.take() {
                self.sockets.unregister(&key, self);
            }
            let mut channel = self.incoming.lock();
            channel.shut();
            self.purge(&mut channel);
            (
                core::mem::replace(&mut state.connection, Connection::None),
                state.marker.take(),
                channel.wake(),
            )
        };
        drop(marker);
        match connection {
            Connection::Listening { backlog, .. } => {
                self.sockets
                    .refund(&self.quota, backlog.len() * CONNECTION_OVERHEAD);
                // Unaccepted sockets have no references, so they close with
                // their listener.
                for socket in backlog {
                    socket.close();
                }
            }
            Connection::Connected { peer, .. } if self.kind == SocketType::Stream => {
                if let Some(peer) = peer.upgrade() {
                    peer.hang_up();
                }
            }
            Connection::None | Connection::Connected { .. } => {}
        }
        wakeups.wake();
    }
}

#[cfg(test)]
mod tests;
