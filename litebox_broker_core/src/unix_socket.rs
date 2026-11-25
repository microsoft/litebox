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
//! 0. the broker's registry of carried sockets, which also serializes the
//!    collector;
//! 1. one socket's readiness watchers, which serialize its publications;
//! 2. one socket's state, or two in address order while one connects to the
//!    other;
//! 3. the broker's registry of names;
//! 4. one socket's incoming channel;
//! 5. the broker's charge for queued data.
//!
//! Sockets are published, and waiting senders woken, only once every other
//! lock is released. Operations call the file service, and drop files and
//! carried objects, without holding any lock.
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
    MAX_UNIX_SOCKET_BACKLOG, MAX_UNIX_SOCKET_OBJECTS, MAX_UNIX_SOCKET_TRANSFER_SIZE,
    ReceiveOptions, TransferredObject, UNIX_SOCKET_BUFFER_SIZE, UnixSocketAddress, UnixSocketError,
    UnixSocketName,
};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::{Mutex, MutexGuard, rwlock::RwLock};

use crate::channel::{Channel, ChannelState, Waiter, Wakeups};
use crate::fs::File;
use crate::object::{ObjectEntry, ObjectRights, StatusFlags};
use crate::readiness::{ReadinessRegistration, ReadinessSink, ReadinessWatchers};
use crate::socket::SocketOptions;
use crate::transfer::{append_to_queue, copy_from_queue, take_from_queue};
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

/// Bytes charged for each object reference a queued message carries.
const OBJECT_OVERHEAD: usize = 256;

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
        litebox_broker_protocol::fs::PathAnchor::None,
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
        Err(FileError::AlreadyExists | FileError::IsDirectory) => {
            return Ok(Err(UnixSocketError::AddressInUse));
        }
        Err(error) => return Ok(Err(UnixSocketError::File(error))),
    };
    let registered = socket.register_name(&mut state, key, address.name())?;
    if registered.is_ok() {
        state.marker = marker.take();
    }
    Ok(registered)
}

/// Starts accepting connections on a bound stream or sequenced-packet socket,
/// or changes the backlog limit of a listening one.
pub fn listen(
    process: &BrokerProcess,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    if !socket.is_connection_oriented() {
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
/// A stream or sequenced-packet socket queues a new connection on the
/// listening socket there, failing with [`BrokerError::WouldBlock`] while its
/// backlog is full. A datagram socket sets its default destination.
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
        SocketType::Stream | SocketType::SeqPacket => {
            socket.connect_to_listener(&target, lease.nonblocking)
        }
        SocketType::Datagram => Ok(socket.connect_datagram(&target)),
        _ => Err(BrokerError::Internal),
    }
}

/// Accepts the oldest queued connection of a listening stream or
/// sequenced-packet socket.
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
    if !listener.is_connection_oriented() {
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

/// Sends bytes from the start of `data` from a Unix socket, to `address` if
/// given or otherwise to its connected peer, and returns how many were sent.
///
/// A stream socket sends as many bytes as its peer has room for. A datagram
/// socket sends `data` as one datagram. A sequenced-packet socket sends
/// `data` as one record to its peer, ignoring `address` like Linux. Fails
/// with [`BrokerError::WouldBlock`] while the receiving socket is full.
///
/// The sent data carries the objects `objects` refer to, at most
/// [`MAX_UNIX_SOCKET_OBJECTS`], so its receiver gets its own references to
/// them with their rights, as [`receive`] describes. A stream socket that
/// sends no data carries none, like Linux. Like Linux, the send fails with
/// [`UnixSocketError::TooManyReferences`] if the references this process
/// sent that queued messages carry would exceed its reference quota. Since
/// the receiver can then change the objects, this process's references first
/// start publishing readiness through `readiness_sink`, as
/// [`BrokerProcess::register_readiness`] describes.
pub fn send(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: Option<&UnixSocketAddress>,
    objects: &[ObjectHandle],
    data: &dyn WriteBuffer,
    user: FileUser,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<UnixSocketResult<usize>> {
    if data.len() > MAX_UNIX_SOCKET_TRANSFER_SIZE as usize
        || objects.len() > MAX_UNIX_SOCKET_OBJECTS as usize
    {
        return Err(BrokerError::ResourceExhausted);
    }
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    let result = (|| {
        // Declared before the operations take any lock, so the objects a
        // failed send leaves drop after every lock is released.
        let mut carrying = match Carrying::new(process, objects, readiness_sink)? {
            Ok(carrying) => carrying,
            Err(error) => return Ok(Err(error)),
        };
        match socket.kind {
            SocketType::Stream => {
                socket.send_stream(address.is_some(), data, &mut carrying, lease.nonblocking)
            }
            SocketType::Datagram => {
                // The node stays open until the send finishes, as for `connect`.
                let (target, _node) = match address {
                    Some(address) => {
                        let (key, node) =
                            match lookup(process, address, user, SocketType::Datagram)? {
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
                socket.send_datagram(target, data, &mut carrying, lease.nonblocking)
            }
            SocketType::SeqPacket => socket.send_record(data, &mut carrying, lease.nonblocking),
            _ => Err(BrokerError::Internal),
        }
    })();
    if !objects.is_empty() {
        // A failed send released the sockets it carried, which may have been
        // all that reached them.
        socket.sockets.collect_garbage();
    }
    result
}

/// What a receive from a Unix socket got.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnixSocketReceive {
    /// Number of bytes received into the start of the caller's buffer.
    pub received: usize,
    /// Length of the whole datagram or record, or `received` for a stream
    /// socket.
    pub length: usize,
    /// Name of the sending socket, if requested.
    pub source: Option<UnixSocketName>,
    /// The caller's new handles to the objects the received data carried.
    pub objects: Vec<TransferredObject>,
    /// Whether the received data carried objects the caller got no handle
    /// for.
    pub objects_truncated: bool,
}

/// Receives bytes from a Unix socket into the start of `output`, leaving them
/// queued if `options.peek` is set and returning the sender's name if
/// `options.source` is set.
///
/// A stream socket receives queued bytes. A datagram or sequenced-packet
/// socket receives one datagram or record, discarding the bytes beyond
/// `output`'s length unless peeking. Receiving no bytes with zero length into
/// a nonempty `output` means an empty datagram or record arrived, or no more
/// data can arrive. Fails with [`BrokerError::WouldBlock`] while nothing is
/// queued.
///
/// If `options.nonblocking` is set, the receive acts as for a non-blocking
/// socket: it fails with [`BrokerError::NonBlockingWouldBlock`], and, as in
/// Linux, a datagram socket whose receive direction is shut down fails
/// instead of reporting the end of data, while a sequenced-packet socket
/// still reports it.
///
/// The caller gets references to the objects the received data carried, up
/// to `options.max_objects`, as [`UnixSocketReceive::objects`] lists. Each has the
/// rights the sender's reference had, within the caller's policy, and
/// publishes readiness through `readiness_sink`. Unless peeking, the objects
/// it gets no reference to are discarded, as [`UnixSocketReceive::objects_truncated`]
/// reports; like Linux, a receive that has taken data never fails to give
/// it, so once one object cannot be given, neither are the rest. A stream
/// socket receives the objects with the first byte sent with them, and stops
/// receiving after the last, so one receive gets the objects of at most one
/// send, as in Linux.
pub fn receive(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut dyn ReadBuffer,
    options: ReceiveOptions,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<UnixSocketResult<UnixSocketReceive>> {
    let ReceiveOptions {
        peek,
        source,
        nonblocking,
        max_objects,
    } = options;
    if output.len() > MAX_UNIX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WAIT)?)?;
    let socket = &lease.socket;
    // Looked up before taking any data, which a failure must not lose.
    let allowed = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    let nonblocking = nonblocking || lease.nonblocking;
    let received = match socket.kind {
        SocketType::Stream => socket.receive_stream(output, peek, source, nonblocking),
        SocketType::Datagram => socket.receive_datagram(output, peek, source, nonblocking),
        SocketType::SeqPacket => socket.receive_record(output, peek, source, nonblocking),
        _ => Err(BrokerError::Internal),
    }?;
    let (mut received, delivery) = match received {
        Ok(received) => received,
        Err(error) => return Ok(Err(error)),
    };
    (received.objects, received.objects_truncated) = delivery.install(
        process,
        &socket.sockets,
        max_objects,
        allowed,
        readiness_sink,
    );
    Ok(Ok(received))
}

/// Shuts down one or both directions of a Unix socket.
///
/// Shutting down a direction of a connected stream or sequenced-packet
/// socket also shuts down the opposite direction of its peer.
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
        litebox_broker_protocol::fs::PathAnchor::None,
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
        if !matches!(
            socket_type,
            SocketType::Stream | SocketType::Datagram | SocketType::SeqPacket
        ) {
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

    /// Returns the socket's type.
    pub(crate) fn socket_type(&self) -> SocketType {
        self.socket.kind
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
    object: Option<Arc<RwLock<ObjectEntry>>>,
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
            object: Some(object),
            socket,
            nonblocking,
        })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let Some(object) = self.object.take() else {
            return;
        };
        // A close that raced the operation leaves carried references the only
        // ones once the lease drops.
        let carried = self.socket.carried.load(Ordering::Relaxed);
        let maybe_garbage = carried != 0 && Arc::strong_count(&object) <= carried + 1;
        drop(object);
        if maybe_garbage {
            self.socket.sockets.collect_all_garbage();
        }
    }
}

/// The Unix sockets of a broker: the names they hold, the charge for the
/// data queued in them, and the sockets messages carry.
pub(crate) struct UnixSockets {
    /// Socket holding each bound name.
    names: RwLock<HashMap<NameKey, Weak<Socket>>>,
    /// Sockets that queued messages carry. Every carried socket joins and
    /// leaves flight under this lock, which the collector holds throughout.
    in_flight: Mutex<InFlight>,
    /// Bytes charged for data queued in every socket. Processes' charges
    /// change only under this lock too, so a charge commits both or neither.
    queued: Mutex<usize>,
    max_queued: usize,
    max_queued_per_process: usize,
    /// Number of references that queued messages carry.
    references: AtomicUsize,
    max_references: usize,
    max_references_per_process: usize,
}

impl UnixSockets {
    pub(crate) fn new(limits: &BrokerCoreLimits) -> Self {
        Self {
            names: RwLock::new(HashMap::new()),
            in_flight: Mutex::new(InFlight::default()),
            queued: Mutex::new(0),
            max_queued: limits.max_total_unix_socket_bytes,
            max_queued_per_process: limits.max_unix_socket_bytes_per_process,
            references: AtomicUsize::new(0),
            max_references: limits.max_references,
            max_references_per_process: limits.max_references_per_process,
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

    /// Waits for a running collection to finish.
    fn synchronize_with_collector(&self) {
        drop(self.in_flight.lock());
    }

    /// Drops `object`, a reference to a Unix socket that its process closed,
    /// then reclaims any garbage that leaves.
    pub(crate) fn release_reference(&self, object: Arc<RwLock<ObjectEntry>>) {
        // Only a socket in flight can become garbage through a closed
        // reference; closing one that carries sockets releases them as it
        // tears down, which marks garbage possible itself.
        let carried = match &*object.read() {
            ObjectEntry::UnixSocket(socket) => socket.socket.carried.load(Ordering::Relaxed) != 0,
            _ => false,
        };
        drop(object);
        if carried {
            self.collect_all_garbage();
        } else {
            self.collect_garbage();
        }
    }

    /// Reclaims garbage even if nothing marked it possible since the last
    /// collection.
    pub(crate) fn collect_all_garbage(&self) {
        self.in_flight.lock().maybe_garbage = true;
        self.collect_garbage();
    }

    /// Reclaims the carried sockets that only messages queued in such sockets
    /// reach, discarding the messages queued for them, if a carried socket
    /// lost a reference since the last collection.
    ///
    /// Like Linux's collector, this finds the carried sockets every
    /// reference to which is a carried one, and keeps those that messages
    /// queued in other sockets reach, directly or through such sockets. The
    /// rest are garbage: no process can receive from them, since receiving
    /// needs a reference that only a receive from one of them could give.
    /// Discarding their messages drops the carried references that keep them
    /// alive.
    ///
    /// Carried sockets join and leave flight only under the registry lock,
    /// held throughout, and a receive that gives a process a reference to a
    /// carried socket first waits for the lock, so the sockets this finds
    /// stay unreachable while it runs.
    fn collect_garbage(&self) {
        // Declared before the lock, so they drop after it is released, since
        // dropping them may close sockets.
        let mut candidates = HashMap::new();
        let mut discarded = Vec::new();
        let mut held_objects = Vec::new();
        let mut held_sockets = Vec::new();
        let mut wakeups = Vec::new();
        {
            let mut in_flight = self.in_flight.lock();
            if !core::mem::take(&mut in_flight.maybe_garbage) || in_flight.sockets.is_empty() {
                return;
            }
            let collected = (|| -> Result<()> {
                let sockets = in_flight.sockets.len();
                candidates
                    .try_reserve(sockets)
                    .map_err(|_| BrokerError::OutOfMemory)?;
                held_objects
                    .try_reserve_exact(sockets)
                    .map_err(|_| BrokerError::OutOfMemory)?;
                for (&key, carried) in &in_flight.sockets {
                    // Each carried reference is one strong reference, so this
                    // finds the sockets that nothing else reaches.
                    if carried.object.strong_count() != carried.count {
                        continue;
                    }
                    let Some(object) = carried.object.upgrade() else {
                        continue;
                    };
                    let socket = match &*object.read() {
                        ObjectEntry::UnixSocket(socket) => Arc::clone(&socket.socket),
                        _ => continue,
                    };
                    candidates.insert(
                        key,
                        Candidate {
                            socket,
                            carried: carried.count,
                            internal: 0,
                            children: Vec::new(),
                            live: false,
                        },
                    );
                    held_objects.push(object);
                }
                let mut keys = Vec::new();
                keys.try_reserve_exact(candidates.len())
                    .map_err(|_| BrokerError::OutOfMemory)?;
                keys.extend(candidates.keys().copied());
                for key in &keys {
                    let mut children = Vec::new();
                    if let Some(candidate) = candidates.get(key) {
                        candidate
                            .socket
                            .carried_socket_keys(&mut children, &mut held_sockets)?;
                    }
                    for child in &children {
                        if let Some(child) = candidates.get_mut(child) {
                            child.internal += 1;
                        }
                    }
                    if let Some(candidate) = candidates.get_mut(key) {
                        candidate.children = children;
                    }
                }
                // Sockets that a message queued elsewhere carries are live, and
                // so is every socket a live socket's messages carry. Each
                // socket joins `live` at most once, so it never grows.
                let mut live = keys;
                live.clear();
                for (key, candidate) in &mut candidates {
                    if candidate.internal < candidate.carried {
                        candidate.live = true;
                        live.push(*key);
                    }
                }
                while let Some(key) = live.pop() {
                    let Some(candidate) = candidates.get_mut(&key) else {
                        continue;
                    };
                    let children = core::mem::take(&mut candidate.children);
                    for child in children {
                        if let Some(child_candidate) = candidates.get_mut(&child)
                            && !child_candidate.live
                        {
                            child_candidate.live = true;
                            live.push(child);
                        }
                    }
                }
                for candidate in candidates.values().filter(|candidate| !candidate.live) {
                    candidate
                        .socket
                        .purge_all(&mut discarded, &mut wakeups, &mut held_sockets)?;
                }
                Ok(())
            })();
            if collected.is_err() {
                // A later collection retries what this one could not finish.
                in_flight.maybe_garbage = true;
            }
        }
        for wakeups in wakeups {
            wakeups.wake();
        }
        let mut teardown = Teardown::default();
        for queue in discarded {
            teardown.discard(queue);
        }
        teardown.objects.extend(held_objects);
        teardown.run();
        drop(held_sockets);
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

/// The sockets that queued messages carry, keyed by their objects'
/// addresses.
#[derive(Default)]
struct InFlight {
    sockets: HashMap<usize, CarriedSocket>,
    /// Whether a carried socket lost a reference since the last collection,
    /// which only then may have left garbage.
    maybe_garbage: bool,
}

/// A socket that queued messages carry.
struct CarriedSocket {
    /// The socket's object, kept allocated so its key stays unique.
    object: Weak<RwLock<ObjectEntry>>,
    /// Number of carried references to it.
    count: usize,
}

/// A carried socket the collector examines.
struct Candidate {
    socket: Arc<Socket>,
    /// Number of carried references to it.
    carried: usize,
    /// Number of those that candidates' messages, including its own, hold.
    internal: usize,
    /// Keys of the carried sockets this socket's messages carry.
    children: Vec<usize>,
    live: bool,
}

/// A reference to an object that a queued message carries, which its
/// receiver takes as its own.
///
/// Dropping it releases the reference. It must not drop while any socket
/// lock is held, since it may close a socket and takes the registry lock.
struct InFlightObject {
    object: Arc<RwLock<ObjectEntry>>,
    rights: ObjectRights,
    /// The socket the object is, counted in flight, if it is a Unix socket.
    socket: Option<Arc<Socket>>,
    _charge: InFlightCharge,
}

impl InFlightObject {
    /// Puts a reference with `rights` to `object` in flight under `charge`,
    /// counting it as carrying `socket` if it is that Unix socket.
    fn new(
        object: Arc<RwLock<ObjectEntry>>,
        rights: ObjectRights,
        socket: Option<Arc<Socket>>,
        charge: InFlightCharge,
    ) -> Result<Self> {
        if let Some(socket) = &socket {
            let mut in_flight = socket.sockets.in_flight.lock();
            in_flight
                .sockets
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            in_flight
                .sockets
                .entry(key_of(&object))
                .or_insert_with(|| CarriedSocket {
                    object: Arc::downgrade(&object),
                    count: 0,
                })
                .count += 1;
            socket.carried.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Self {
            object,
            rights,
            socket,
            _charge: charge,
        })
    }

    /// Returns the key of the carried socket this refers to, if it is one.
    fn socket_key(&self) -> Option<usize> {
        self.socket.is_some().then(|| key_of(&self.object))
    }

    /// Returns another reference to the object, which stays in flight.
    fn duplicate(&self) -> (Arc<RwLock<ObjectEntry>>, ObjectRights) {
        (Arc::clone(&self.object), self.rights)
    }

    /// Takes the reference out of flight once its receiver holds its own.
    fn land(mut self) {
        self.stop_counting(false);
    }

    /// Takes the reference out of flight to discard it.
    fn discard(mut self) -> Arc<RwLock<ObjectEntry>> {
        self.stop_counting(true);
        Arc::clone(&self.object)
    }

    /// Stops counting the reference in flight, noting that the carried socket
    /// may have become garbage if `discarded`.
    fn stop_counting(&mut self, discarded: bool) {
        if let Some(socket) = self.socket.take() {
            let mut in_flight = socket.sockets.in_flight.lock();
            let key = key_of(&self.object);
            let carried = in_flight
                .sockets
                .get_mut(&key)
                .expect("a carried socket stays registered while in flight");
            carried.count -= 1;
            if carried.count == 0 {
                in_flight.sockets.remove(&key);
            }
            socket.carried.fetch_sub(1, Ordering::Relaxed);
            in_flight.maybe_garbage |= discarded;
        }
    }
}

impl Drop for InFlightObject {
    fn drop(&mut self) {
        self.stop_counting(true);
    }
}

/// Returns the key of the carried socket whose object is `object`.
fn key_of(object: &Arc<RwLock<ObjectEntry>>) -> usize {
    Arc::as_ptr(object).addr()
}

/// One reference in flight, counted against the broker's and its sender's
/// limits until this drops.
struct InFlightCharge {
    registry: Arc<UnixSockets>,
    sender: Arc<AtomicUsize>,
}

impl InFlightCharge {
    /// Counts one more reference in flight from the process whose count is
    /// `sender`, or returns `None` if that exceeds either limit.
    fn new(registry: &Arc<UnixSockets>, sender: &Arc<AtomicUsize>) -> Option<Self> {
        let count = |counter: &AtomicUsize, limit: usize| {
            counter
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    count.checked_add(1).filter(|count| *count <= limit)
                })
                .is_ok()
        };
        if !count(&registry.references, registry.max_references) {
            return None;
        }
        if !count(sender, registry.max_references_per_process) {
            registry.references.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Self {
            registry: Arc::clone(registry),
            sender: Arc::clone(sender),
        })
    }
}

impl Drop for InFlightCharge {
    fn drop(&mut self) {
        self.registry.references.fetch_sub(1, Ordering::Relaxed);
        self.sender.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The objects a send carries.
#[derive(Default)]
struct Carrying {
    objects: Vec<InFlightObject>,
}

impl Carrying {
    /// Puts the objects `handles` refer to in flight, or fails with
    /// [`UnixSocketError::TooManyReferences`] if that exceeds the references
    /// in flight `process` may send.
    fn new(
        process: &BrokerProcess,
        handles: &[ObjectHandle],
        readiness_sink: &Arc<dyn ReadinessSink>,
    ) -> Result<UnixSocketResult<Self>> {
        let mut carrying = Self::default();
        if handles.is_empty() {
            return Ok(Ok(carrying));
        }
        // A registration left behind by a later failure only publishes
        // readiness the process does not need.
        process.register_readiness(readiness_sink)?;
        carrying
            .objects
            .try_reserve_exact(handles.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        for &handle in handles {
            let (object, rights) = process.object_reference(handle)?;
            let socket = {
                let entry = object.read();
                if !entry.is_duplicable() {
                    return Err(BrokerError::UnsupportedOperation);
                }
                match &*entry {
                    ObjectEntry::UnixSocket(socket) => Some(Arc::clone(&socket.socket)),
                    _ => None,
                }
            };
            let Some(charge) =
                InFlightCharge::new(&process.core.unix_sockets, &process.unix_socket_references)
            else {
                return Ok(Err(UnixSocketError::TooManyReferences));
            };
            carrying
                .objects
                .push(InFlightObject::new(object, rights, socket, charge)?);
        }
        Ok(Ok(carrying))
    }

    fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Returns the bytes charged for queuing the objects.
    fn charge(&self) -> usize {
        self.objects.len() * OBJECT_OVERHEAD
    }

    fn take(&mut self) -> Vec<InFlightObject> {
        core::mem::take(&mut self.objects)
    }
}

/// Sockets to tear down and carried objects to release, which closing a
/// socket works through in a loop: releasing a carried socket's last
/// reference closes it here rather than in a nested drop, so closing sockets
/// that carry sockets takes bounded stack however deeply they nest.
#[derive(Default)]
struct Teardown {
    sockets: Vec<Arc<Socket>>,
    objects: Vec<Arc<RwLock<ObjectEntry>>>,
}

impl Teardown {
    /// Releases the objects the messages of `queue`, which no socket holds
    /// any more, carry.
    fn discard(&mut self, queue: Queue) {
        self.objects
            .extend(queue.into_objects().map(InFlightObject::discard));
    }

    fn run(mut self) {
        loop {
            if let Some(socket) = self.sockets.pop() {
                socket.close_into(&mut self);
            } else if let Some(object) = self.objects.pop() {
                if let Ok(object) = Arc::try_unwrap(object)
                    && let ObjectEntry::UnixSocket(socket) = object.into_inner()
                {
                    // Its drop then finds it closed.
                    socket.socket.close_into(&mut self);
                }
            } else {
                return;
            }
        }
    }
}

/// The carried objects a receive got, which it gives the caller references to
/// once every socket lock is released.
#[derive(Default)]
enum Delivery {
    #[default]
    None,
    /// Objects taken from the queue.
    Taken(Vec<InFlightObject>),
    /// Objects left in the queue by a peek.
    Peeked(Vec<(Arc<RwLock<ObjectEntry>>, ObjectRights)>),
}

impl Delivery {
    /// Delivers references to `objects`, which a peek leaves queued.
    fn peek(objects: &[InFlightObject]) -> Self {
        if objects.is_empty() {
            Self::None
        } else {
            Self::Peeked(objects.iter().map(InFlightObject::duplicate).collect())
        }
    }

    /// Delivers `objects`, taken from the queue.
    fn take(objects: Vec<InFlightObject>) -> Self {
        if objects.is_empty() {
            Self::None
        } else {
            Self::Taken(objects)
        }
    }

    /// Gives `process` references to at most `max_objects` of the objects,
    /// with the rights the sender's references had within `allowed`,
    /// publishing readiness through `readiness_sink`, and returns them and
    /// whether any were not given.
    ///
    /// The receive already took the data, so this never fails: like Linux,
    /// once one object cannot be given, neither are the rest.
    fn install(
        self,
        process: &BrokerProcess,
        registry: &UnixSockets,
        max_objects: usize,
        allowed: ObjectRights,
        readiness_sink: &Arc<dyn ReadinessSink>,
    ) -> (Vec<TransferredObject>, bool) {
        let give = |object: Arc<RwLock<ObjectEntry>>, rights: ObjectRights| {
            let rights = rights & allowed;
            let kind = object.read().transferred_kind()?;
            if rights.is_empty() {
                return None;
            }
            let handle = process
                .create_object_reference_with_rights(object, rights)
                .ok()?;
            Some(TransferredObject { handle, kind })
        };
        let mut installed = Vec::new();
        let count = match self {
            Self::None => return (Vec::new(), false),
            Self::Taken(objects) => {
                let count = objects.len();
                let max_objects = if installed.try_reserve_exact(count.min(max_objects)).is_ok() {
                    max_objects
                } else {
                    0
                };
                for object in objects.into_iter().take(max_objects) {
                    let (shared, rights) = object.duplicate();
                    let Some(given) = give(shared, rights) else {
                        break;
                    };
                    installed.push(given);
                    object.land();
                }
                // The references discarded on the way may have been all that
                // reached a carried socket, as their release noted.
                registry.collect_garbage();
                count
            }
            Self::Peeked(objects) => {
                registry.synchronize_with_collector();
                let count = objects.len();
                if installed.try_reserve_exact(count.min(max_objects)).is_ok() {
                    installed.extend(
                        objects
                            .into_iter()
                            .take(max_objects)
                            .map_while(|(object, rights)| give(object, rights)),
                    );
                }
                count
            }
        };
        if !installed.is_empty() && process.register_readiness(readiness_sink).is_err() {
            // The caller never learns of the handles. A failed close leaves
            // one to the process's teardown.
            for object in core::mem::take(&mut installed) {
                let _ = process.close_object_reference(object.handle);
            }
        }
        let truncated = installed.len() < count;
        (installed, truncated)
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
    /// Number of references to the socket that queued messages carry, which
    /// changes only under the registry lock.
    carried: AtomicUsize,
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
        /// The peer, which a connection-oriented socket forgets once the peer
        /// closes.
        peer: Weak<Socket>,
        /// Name the peer had when the connection formed.
        peer_name: UnixSocketName,
    },
}

/// Data queued for a socket to receive.
///
/// Dropping it drops the objects its messages carry, so it must not drop
/// while any socket lock is held.
#[derive(Default)]
struct Queue {
    /// Bytes queued for a stream socket.
    bytes: VecDeque<u8>,
    /// Stream position of the first byte of `bytes`.
    head: u64,
    /// Objects carried by the sends whose bytes `bytes` holds, in order, none
    /// of which has started being received.
    carried: VecDeque<StreamObjects>,
    /// Datagrams queued for a datagram socket, or records for a
    /// sequenced-packet socket.
    datagrams: VecDeque<Datagram>,
}

impl Queue {
    fn is_empty(&self) -> bool {
        self.bytes.is_empty() && self.datagrams.is_empty()
    }

    /// Returns the objects the queued messages carry.
    fn into_objects(self) -> impl Iterator<Item = InFlightObject> {
        let carried = self.carried.into_iter().flat_map(|carried| carried.objects);
        let datagrams = self
            .datagrams
            .into_iter()
            .flat_map(|datagram| datagram.objects);
        carried.chain(datagrams)
    }

    /// Calls `f` with every object the queued messages carry.
    fn for_each_object(&self, mut f: impl FnMut(&InFlightObject)) {
        let carried = self.carried.iter().flat_map(|carried| &carried.objects);
        let datagrams = self.datagrams.iter().flat_map(|datagram| &datagram.objects);
        carried.chain(datagrams).for_each(&mut f);
    }
}

/// The objects one stream send carried, with the stream positions of the
/// bytes it sent.
struct StreamObjects {
    start: u64,
    end: u64,
    objects: Vec<InFlightObject>,
}

struct Datagram {
    data: Vec<u8>,
    source: UnixSocketName,
    objects: Vec<InFlightObject>,
}

impl Datagram {
    /// Copies `data` into a datagram sent by the socket named `source`, which
    /// carries the objects of `carrying`.
    fn new(
        data: &dyn WriteBuffer,
        source: UnixSocketName,
        carrying: &mut Carrying,
    ) -> Result<Self> {
        let mut copy = Vec::new();
        copy.try_reserve_exact(data.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        copy.resize(data.len(), 0);
        data.copy_to_slice_at(0, &mut copy)?;
        Ok(Self {
            data: copy,
            source,
            objects: carrying.take(),
        })
    }

    fn charge(&self) -> usize {
        self.data.len() + DATAGRAM_OVERHEAD + self.objects.len() * OBJECT_OVERHEAD
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
            carried: AtomicUsize::new(0),
        }
    }

    /// Publishes the socket's readiness after a change that may affect it.
    fn publish(self: &Arc<Self>) {
        let watchers = self.watchers.lock();
        watchers.publish(self.readiness());
    }

    /// Returns whether the socket must be connected to exchange data, as
    /// stream and sequenced-packet sockets must.
    fn is_connection_oriented(&self) -> bool {
        matches!(self.kind, SocketType::Stream | SocketType::SeqPacket)
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
                if self.is_connection_oriented() {
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

    /// Queues a connection to `listener`, which accepts it as a new socket of
    /// this socket's type.
    fn connect_to_listener(
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
                self.kind,
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
        let (wakeups, discarded) = if Arc::ptr_eq(self, target) {
            let mut state = self.state.lock();
            let peer_name = self.accept_peer(&state)?;
            self.set_datagram_peer(&mut state, target, peer_name)
        } else {
            let (mut state, target_state) = lock_both(self, target);
            let peer_name = self.accept_peer(&target_state)?;
            self.set_datagram_peer(&mut state, target, peer_name)
        };
        drop(discarded);
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
    /// named `peer_name`, returning the datagrams it discarded.
    fn set_datagram_peer(
        &self,
        state: &mut State,
        target: &Arc<Socket>,
        peer_name: UnixSocketName,
    ) -> (Wakeups<Socket>, Queue) {
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
        let discarded = if matches!(
            &previous,
            Connection::Connected { peer, .. } if !refers_to(peer, target)
        ) {
            self.purge(&mut channel)
        } else {
            Queue::default()
        };
        // Senders waiting on this socket recheck whether it still accepts
        // their datagrams.
        (channel.wake(), discarded)
    }

    fn send_stream(
        self: &Arc<Self>,
        addressed: bool,
        data: &dyn WriteBuffer,
        carrying: &mut Carrying,
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
            let charge = length + carrying.charge();
            // Charging first keeps a rejected send from growing the queue.
            self.sockets.charge(&peer.quota, charge)?;
            if !carrying.is_empty() && channel.queue.carried.try_reserve(1).is_err() {
                self.sockets.refund(&peer.quota, charge);
                return Err(BrokerError::OutOfMemory);
            }
            if let Err(error) = append_to_queue(&mut channel.queue.bytes, length, data) {
                self.sockets.refund(&peer.quota, charge);
                return Err(error);
            }
            if !carrying.is_empty() {
                let end = channel.queue.head + channel.queue.bytes.len() as u64;
                channel.queue.carried.push_back(StreamObjects {
                    start: end - length as u64,
                    end,
                    objects: carrying.take(),
                });
            }
            channel.add(charge);
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
        data: &dyn WriteBuffer,
        carrying: &mut Carrying,
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
        // Declared before the locks, so a datagram left unqueued drops after
        // them.
        let mut datagram = Some(Datagram::new(data, source, carrying)?);
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
                if let Err(error) =
                    self.queue_datagram(&target, &mut channel, &mut datagram, nonblocking)?
                {
                    return Ok(Err(error));
                }
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

    /// Sends `data` as one record to the connected peer.
    fn send_record(
        self: &Arc<Self>,
        data: &dyn WriteBuffer,
        carrying: &mut Carrying,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<usize>> {
        let (peer, write_shut, source) = {
            let state = self.state.lock();
            let Connection::Connected { peer, .. } = &state.connection else {
                return Ok(Err(UnixSocketError::NotConnected));
            };
            (peer.clone(), state.write_shut, state.name.clone())
        };
        if data.len() > CAPACITY {
            return Ok(Err(UnixSocketError::MessageTooLarge));
        }
        let Some(peer) = peer.upgrade().filter(|_| !write_shut) else {
            return Ok(Err(UnixSocketError::BrokenPipe));
        };
        // Declared before the lock, so a record left unqueued drops after it.
        let mut record = Some(Datagram::new(data, source, carrying)?);
        {
            let mut channel = peer.incoming.lock();
            if let Err(error) =
                self.queue_datagram(&peer, &mut channel, &mut record, nonblocking)?
            {
                return Ok(Err(error));
            }
        }
        peer.publish();
        Ok(Ok(data.len()))
    }

    /// Queues `datagram` in `channel`, the incoming channel of `receiver`,
    /// taking it only if queued, so callers drop it after their locks.
    ///
    /// A datagram may overrun the capacity, so a receiver that is not full
    /// accepts any datagram, as its readiness reports.
    fn queue_datagram(
        self: &Arc<Self>,
        receiver: &Socket,
        channel: &mut ChannelState<Queue, Socket>,
        datagram: &mut Option<Datagram>,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<()>> {
        if channel.is_shut() {
            return Ok(Err(UnixSocketError::BrokenPipe));
        }
        if channel.room() == 0 {
            channel.wait(self)?;
            return Err(BrokerError::would_block(nonblocking));
        }
        let charge = datagram.as_ref().ok_or(BrokerError::Internal)?.charge();
        self.sockets.charge(&receiver.quota, charge)?;
        if channel.queue.datagrams.try_reserve(1).is_err() {
            self.sockets.refund(&receiver.quota, charge);
            return Err(BrokerError::OutOfMemory);
        }
        channel
            .queue
            .datagrams
            .push_back(datagram.take().ok_or(BrokerError::Internal)?);
        channel.add(charge);
        Ok(Ok(()))
    }

    /// Disconnects this datagram socket from `peer`, which closed, and
    /// refuses the send that found it closed. Like Linux, a send that raced
    /// a change of connection fails with a reset instead.
    fn disconnect_from(self: &Arc<Self>, peer: *const Socket) -> UnixSocketResult<usize> {
        let (wakeups, discarded) = {
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
            let discarded = self.purge(&mut channel);
            // Senders it rejected while connected retry.
            (channel.wake(), discarded)
        };
        drop(discarded);
        wakeups.wake();
        self.publish();
        Err(UnixSocketError::ConnectionRefused)
    }

    fn receive_stream(
        &self,
        output: &mut dyn ReadBuffer,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<(UnixSocketReceive, Delivery)>> {
        let source = match &self.state.lock().connection {
            Connection::Connected { peer_name, .. } => source.then(|| peer_name.clone()),
            Connection::None | Connection::Listening { .. } => {
                return Ok(Err(UnixSocketError::InvalidArgument));
            }
        };
        let nothing = |source| {
            Ok(Ok((
                UnixSocketReceive {
                    source,
                    ..UnixSocketReceive::default()
                },
                Delivery::None,
            )))
        };
        if output.is_empty() {
            return nothing(source);
        }
        let (length, wakeups, delivery) = {
            let mut channel = self.incoming.lock();
            let queue = &mut channel.queue;
            if queue.bytes.is_empty() {
                return if channel.is_shut() {
                    nothing(source)
                } else {
                    Err(BrokerError::would_block(nonblocking))
                };
            }
            let mut length = output.len().min(queue.bytes.len());
            // Like Linux, a receive that reaches bytes sent with objects gets
            // the objects and stops after those bytes.
            let carried = queue
                .carried
                .front()
                .filter(|carried| carried.start < queue.head + length as u64);
            if let Some(carried) = carried {
                length =
                    length.min(usize::try_from(carried.end - queue.head).unwrap_or(usize::MAX));
            }
            let reaches_objects = carried.is_some();
            if peek {
                copy_from_queue(&queue.bytes, 0..length, output)?;
                let delivery = match queue.carried.front().filter(|_| reaches_objects) {
                    Some(carried) => Delivery::peek(&carried.objects),
                    None => Delivery::None,
                };
                (length, Wakeups::default(), delivery)
            } else {
                take_from_queue(&mut queue.bytes, length, output)?;
                queue.head += length as u64;
                let mut removed = length;
                let delivery = match queue.carried.pop_front_if(|_| reaches_objects) {
                    Some(carried) => {
                        removed += carried.objects.len() * OBJECT_OVERHEAD;
                        Delivery::take(carried.objects)
                    }
                    None => Delivery::None,
                };
                if queue.bytes.is_empty() {
                    queue.bytes = VecDeque::new();
                }
                channel.remove(removed);
                self.sockets.refund(&self.quota, removed);
                // Senders waiting for room retry.
                (length, channel.wake(), delivery)
            }
        };
        wakeups.wake();
        Ok(Ok((
            UnixSocketReceive {
                received: length,
                length,
                source,
                ..UnixSocketReceive::default()
            },
            delivery,
        )))
    }

    fn receive_datagram(
        &self,
        output: &mut dyn ReadBuffer,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<(UnixSocketReceive, Delivery)>> {
        let (received, wakeups, delivery) = {
            let mut channel = self.incoming.lock();
            let Some(datagram) = channel.queue.datagrams.front() else {
                // Like Linux, a sequenced-packet socket reports the end of
                // data even to a receive that would not wait; a datagram
                // socket does not.
                return if channel.is_shut() && (!nonblocking || self.kind == SocketType::SeqPacket)
                {
                    Ok(Ok((
                        UnixSocketReceive {
                            source: source.then_some(UnixSocketName::Unnamed),
                            ..UnixSocketReceive::default()
                        },
                        Delivery::None,
                    )))
                } else {
                    Err(BrokerError::would_block(nonblocking))
                };
            };
            let length = datagram.data.len();
            let received = output.len().min(length);
            output.copy_from_slice_at(0, &datagram.data[..received])?;
            if peek {
                let received = UnixSocketReceive {
                    received,
                    length,
                    source: source.then(|| datagram.source.clone()),
                    ..UnixSocketReceive::default()
                };
                (
                    received,
                    Wakeups::default(),
                    Delivery::peek(&datagram.objects),
                )
            } else {
                let datagram = channel
                    .queue
                    .datagrams
                    .pop_front()
                    .ok_or(BrokerError::Internal)?;
                channel.remove(datagram.charge());
                self.sockets.refund(&self.quota, datagram.charge());
                let received = UnixSocketReceive {
                    received,
                    length,
                    source: source.then_some(datagram.source),
                    ..UnixSocketReceive::default()
                };
                // Senders waiting for room retry.
                (received, channel.wake(), Delivery::take(datagram.objects))
            }
        };
        wakeups.wake();
        Ok(Ok((received, delivery)))
    }

    /// Receives one record from the connected peer.
    fn receive_record(
        &self,
        output: &mut dyn ReadBuffer,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<(UnixSocketReceive, Delivery)>> {
        if !matches!(self.state.lock().connection, Connection::Connected { .. }) {
            return Ok(Err(UnixSocketError::NotConnected));
        }
        self.receive_datagram(output, peek, source, nonblocking)
    }

    /// Stops the socket from receiving if `read` is set, and from sending if
    /// `write` is set, returning its connected peer if the peer shares the
    /// shutdown.
    fn shut_down(&self, read: bool, write: bool) -> (Option<Arc<Socket>>, Wakeups<Socket>) {
        let mut state = self.state.lock();
        state.write_shut |= write;
        let peer = match &state.connection {
            Connection::Connected { peer, .. } if self.is_connection_oriented() => peer.upgrade(),
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

    /// Ends this connection-oriented socket's connection after its peer
    /// closed.
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

    /// Discards the data queued for the socket, returning it for the caller
    /// to drop once it releases every lock.
    fn purge(&self, channel: &mut ChannelState<Queue, Socket>) -> Queue {
        let discarded = core::mem::take(&mut channel.queue);
        let queued = channel.queued();
        channel.remove(queued);
        self.sockets.refund(&self.quota, queued);
        discarded
    }

    /// Adds the keys of the carried sockets that the messages queued for
    /// this socket, or for the connections in its backlog, carry to `keys`,
    /// and the backlog to `held` for the caller to drop once it releases
    /// every lock.
    fn carried_socket_keys(
        &self,
        keys: &mut Vec<usize>,
        held: &mut Vec<Arc<Socket>>,
    ) -> Result<()> {
        self.for_each_with_backlog(held, |socket| {
            let mut result = Ok(());
            socket.incoming.lock().queue.for_each_object(|object| {
                if let Some(key) = object.socket_key()
                    && result.is_ok()
                {
                    result = keys
                        .try_reserve(1)
                        .map(|()| keys.push(key))
                        .map_err(|_| BrokerError::OutOfMemory);
                }
            });
            result
        })
    }

    /// Discards the data queued for this garbage socket and the connections
    /// in its backlog, adding it to `discarded`, the senders to wake to
    /// `wakeups`, and the backlog to `held` for the caller to handle once it
    /// releases every lock.
    fn purge_all(
        &self,
        discarded: &mut Vec<Queue>,
        wakeups: &mut Vec<Wakeups<Socket>>,
        held: &mut Vec<Arc<Socket>>,
    ) -> Result<()> {
        self.for_each_with_backlog(held, |socket| {
            // Reserved first, so no discarded data drops under the lock.
            discarded
                .try_reserve(1)
                .and_then(|()| wakeups.try_reserve(1))
                .map_err(|_| BrokerError::OutOfMemory)?;
            let mut channel = socket.incoming.lock();
            discarded.push(socket.purge(&mut channel));
            wakeups.push(channel.wake());
            Ok(())
        })
    }

    /// Calls `f` with this socket, then with each connection waiting in its
    /// backlog, adding those to `held` for the caller to drop once it
    /// releases every lock.
    fn for_each_with_backlog(
        &self,
        held: &mut Vec<Arc<Socket>>,
        mut f: impl FnMut(&Socket) -> Result<()>,
    ) -> Result<()> {
        let mut backlog = Vec::new();
        if let Connection::Listening {
            backlog: waiting, ..
        } = &self.state.lock().connection
        {
            backlog
                .try_reserve_exact(waiting.len())
                .map_err(|_| BrokerError::OutOfMemory)?;
            backlog.extend(waiting.iter().cloned());
        }
        held.try_reserve(backlog.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        let result = core::iter::once(self)
            .chain(backlog.iter().map(|socket| &**socket))
            .try_for_each(&mut f);
        held.extend(backlog);
        result
    }

    /// Tears the socket down once nothing reaches it through a reference or a
    /// backlog.
    fn close(&self) {
        let mut teardown = Teardown::default();
        self.close_into(&mut teardown);
        teardown.run();
    }

    /// Tears the socket down, leaving the sockets and objects that releases to
    /// `teardown`.
    fn close_into(&self, teardown: &mut Teardown) {
        let (connection, marker, wakeups, discarded) = {
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
            let discarded = self.purge(&mut channel);
            (
                core::mem::replace(&mut state.connection, Connection::None),
                state.marker.take(),
                channel.wake(),
                discarded,
            )
        };
        drop(marker);
        teardown.discard(discarded);
        match connection {
            Connection::Listening { backlog, .. } => {
                self.sockets
                    .refund(&self.quota, backlog.len() * CONNECTION_OVERHEAD);
                // Unaccepted sockets have no references, so they close with
                // their listener.
                teardown.sockets.extend(backlog);
            }
            Connection::Connected { peer, .. } if self.is_connection_oriented() => {
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
