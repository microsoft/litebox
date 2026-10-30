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
//!
//! Stream sockets may also hold vsock names, keyed apart from every path and
//! abstract name. A socket binds only a port at [`VMADDR_CID_ANY`], and no
//! socket sends to a vsock address. Only [`connect_from_vsock_host`] and
//! [`listen_for_vsock_host`], which the broker protocol does not reach, name
//! sockets at [`VMADDR_CID_HOST`], so a peer named at that CID is the host.
//! The cursor of ephemeral vsock ports lives in the registry of names. Its
//! seed is drawn without locks, since the random provider may block, and
//! installed under the registry's write lock unless another bind installed
//! one first; ports are taken only under that lock.
//!
//! The broker does not tie a socket to a family: any stream socket may bind
//! or connect either kind of address, and is a vsock socket if created as one
//! ([`create_vsock`]) or named by a vsock address. The shim keeps the
//! families apart: all of a broker's sockets belong to one guest, and only
//! the broker names a peer at [`VMADDR_CID_HOST`].
//!
//! A stream socket connects to a vsock address only at the host's CID, and
//! only through the broker's host connector: the one socket
//! [`listen_for_vsock_host`] made listen, under a key no address names, for
//! the broker's own use. Without it, or at another CID, the address
//! is unreachable. The connect binds an unnamed socket to an ephemeral port,
//! queues on the connector a socket named as the host's port and connected to
//! it, and leaves it connecting: it has no peer name, neither sends nor
//! receives, and is neither readable nor writable. The connector's owner then
//! completes it ([`complete_vsock_host_connect`]): connected, or unconnected
//! again with a pending error, which [`take_error`] or the next connect
//! reports once, while the connector's socket's connection ends as if its
//! peer had closed. [`check_connect`] reports the outcome as a blocking
//! connect's wait does, leaving the error pending unless the connect timed
//! out. Data the connector's socket sends meanwhile is queued for the
//! connecting socket, which receives it, and reports it readable, only once
//! connected: every way a connect ends unconnected discards it. A connecting
//! socket that closes hangs up its peer as a connected one does, and one
//! whose peer closes first fails with
//! [`UnixSocketError::ConnectionReset`]. A connect cancelled
//! ([`cancel_vsock_connect`]) leaves the socket unconnected, still bound, and
//! hangs up its peer as a close does. A connecting socket and its peer hold
//! each other as a connected pair does, and the connect locks the socket's
//! and the connector's states as a connect locks a listener's.
//!
//! The host sees a guest socket's port as the connection's source port.
//! Guests bind any port, those below 1024 included, with no privilege check,
//! so the host must not trust a guest's source port.
//!
//! A vsock socket's own shutdown differs from a Unix socket's, as in Linux:
//! once it shuts down receiving, receives report the end of data at once,
//! even with data queued, and once it shuts down either direction, it has no
//! peer name. Its peer's shutdown does not affect it so. A vsock socket that
//! is not connected does not shut down, and, unlike an unconnected Unix
//! stream socket, is not hung up: it is writable, as in Linux. A socket
//! created as a vsock socket is one even before it has a name.

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
    ShutdownMode, SocketConnectionStatus, SocketOptionName, SocketOptionValue, SocketType,
};
use litebox_broker_protocol::unix_socket::{
    MAX_UNIX_SOCKET_BACKLOG, MAX_UNIX_SOCKET_TRANSFER_SIZE, UNIX_SOCKET_BUFFER_SIZE,
    UnixSocketAddress, UnixSocketError, UnixSocketName, VMADDR_CID_ANY, VMADDR_CID_HOST,
    VMADDR_PORT_ANY,
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

/// The lowest ephemeral vsock port, above the ports Linux reserves.
const FIRST_EPHEMERAL_VSOCK_PORT: u32 = 1024;

/// Number of ephemeral vsock ports: every port from
/// [`FIRST_EPHEMERAL_VSOCK_PORT`] but [`VMADDR_PORT_ANY`].
const EPHEMERAL_VSOCK_PORTS: u32 = VMADDR_PORT_ANY - FIRST_EPHEMERAL_VSOCK_PORT;

/// Ephemeral vsock ports one bind tries before it fails.
const MAX_EPHEMERAL_VSOCK_PORT_ATTEMPTS: u32 = 64;

/// Result of receiving from a Unix socket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// Number of bytes received into the start of the caller's buffer.
    pub received: usize,
    /// Length of the whole datagram or record, or `received` for a stream
    /// socket.
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
    create_socket(process, socket_type, flags, false, readiness_sink)
}

/// Creates an unconnected vsock stream socket: as [`create`] does, but, like
/// a socket named by a vsock address, it is not hung up while unconnected,
/// even before it has a name (see the module docs).
pub fn create_vsock(
    process: &BrokerProcess,
    flags: FileOpenFlags,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    create_socket(process, SocketType::Stream, flags, true, readiness_sink)
}

fn create_socket(
    process: &BrokerProcess,
    socket_type: SocketType,
    flags: FileOpenFlags,
    vsock: bool,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let (rights, status) = creation_rights(process, flags)?;
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    let object = UnixSocketObject::new(process, socket_type, status, vsock)?;
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
    let first = UnixSocketObject::new(process, socket_type, status, false)?;
    let second = UnixSocketObject::new(process, socket_type, status, false)?;
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
///
/// Only a stream socket binds a vsock address, whose CID must be
/// [`VMADDR_CID_ANY`]. Binding [`VMADDR_PORT_ANY`] binds an unused port above
/// 1023, or fails with [`UnixSocketError::AddressNotAvailable`] if the ports
/// it tries are in use.
pub fn bind(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: &UnixSocketAddress,
    user: FileUser,
    mode: FileMode,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    // A socket never loses its name, so one unnamed at the bind below was
    // unnamed here, and the cursor is seeded before it is taken.
    if matches!(
        address,
        UnixSocketAddress::Vsock {
            cid: VMADDR_CID_ANY,
            port: VMADDR_PORT_ANY,
        }
    ) && socket.kind == SocketType::Stream
        && socket.state.lock().name == UnixSocketName::Unnamed
    {
        socket.sockets.seed_ephemeral_vsock_ports(process);
    }
    let path = {
        let mut state = socket.state.lock();
        if state.binding || state.name != UnixSocketName::Unnamed {
            return Ok(Err(UnixSocketError::InvalidArgument));
        }
        match address {
            UnixSocketAddress::Abstract(bytes) => {
                return socket.register_name(
                    &mut state,
                    NameKey::Abstract(socket.kind, bytes.clone()),
                    address.name(),
                );
            }
            &UnixSocketAddress::Vsock { cid, port } => {
                if socket.kind != SocketType::Stream {
                    return Ok(Err(UnixSocketError::InvalidArgument));
                }
                if cid != VMADDR_CID_ANY {
                    return Ok(Err(UnixSocketError::AddressNotAvailable));
                }
                return if port == VMADDR_PORT_ANY {
                    socket.register_ephemeral_vsock_port(&mut state)
                } else {
                    socket.register_name(&mut state, NameKey::Vsock(port), address.name())
                };
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
            Connection::Connecting { .. } | Connection::Connected { .. } => {
                return Ok(Err(UnixSocketError::InvalidArgument));
            }
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
/// backlog is full. A datagram socket sets its default destination. Either is
/// then [`SocketConnectionStatus::Connected`].
///
/// A stream socket's connect to the host's vsock port is
/// [`SocketConnectionStatus::Connecting`] until it completes (see the module
/// docs); it fails with [`BrokerError::ResourceExhausted`] while the host
/// connector's backlog is full. Any other vsock address is
/// [`UnixSocketError::Unreachable`]. As in Linux, a stream or
/// sequenced-packet socket's connect to a vsock address fails first by its
/// state: with [`UnixSocketError::InvalidArgument`] if it listens or is
/// connected and shut down, with [`UnixSocketError::AlreadyConnected`] if it
/// is otherwise connected, with [`UnixSocketError::AlreadyInProgress`] if it
/// is connecting, and with its pending error, which it takes, if it has one.
pub fn connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: &UnixSocketAddress,
    user: FileUser,
) -> Result<UnixSocketResult<SocketConnectionStatus>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    if let &UnixSocketAddress::Vsock { cid, port } = address
        && socket.is_connection_oriented()
    {
        return socket.connect_to_vsock_host(process, cid, port);
    }
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
    let connected = match socket.kind {
        SocketType::Stream | SocketType::SeqPacket => {
            socket.connect_to_listener(&target, lease.nonblocking)?
        }
        SocketType::Datagram => socket.connect_datagram(&target),
        _ => return Err(BrokerError::Internal),
    };
    Ok(connected.map(|()| SocketConnectionStatus::Connected))
}

/// Names the unnamed, unconnected stream socket `handle` as the VM host's
/// vsock port `host_port`, and connects it, without waiting, to the socket
/// listening on vsock port `guest_port`.
///
/// This is the broker's own entry point for the host's connections, which no
/// broker request reaches, so only the host's sockets bear its CID. Fails with
/// [`UnixSocketError::ConnectionRefused`] if no socket listens on the port,
/// and with [`BrokerError::NonBlockingWouldBlock`] while its backlog is full.
/// The socket keeps its name if the connect fails.
pub fn connect_from_vsock_host(
    process: &BrokerProcess,
    handle: ObjectHandle,
    guest_port: u32,
    host_port: u32,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    if socket.kind != SocketType::Stream {
        return Ok(Err(UnixSocketError::WrongType));
    }
    {
        let mut state = socket.state.lock();
        if state.binding
            || state.name != UnixSocketName::Unnamed
            || !matches!(state.connection, Connection::None)
        {
            return Ok(Err(UnixSocketError::InvalidArgument));
        }
        // Host ports name no key, so no guest can bind or connect to them.
        state.name = UnixSocketName::Vsock {
            cid: VMADDR_CID_HOST,
            port: host_port,
        };
    }
    let target = match socket
        .sockets
        .find(&NameKey::Vsock(guest_port), SocketType::Stream)
    {
        Ok(target) => target,
        Err(error) => return Ok(Err(error)),
    };
    socket.connect_to_listener(&target, true)
}

/// Makes the unnamed, unconnected stream socket `handle` the broker's host
/// connector (see the module docs), with up to `backlog` connects waiting
/// beyond the first.
///
/// This is the broker's own entry point, which no broker request reaches.
/// Each socket the connector accepts is named as the host's vsock port its
/// peer connects to, and the peer is named as the guest's port it connects
/// from; its owner completes the connect with
/// [`complete_vsock_host_connect`]. Fails with
/// [`UnixSocketError::AddressInUse`] if the broker has a connector.
pub fn listen_for_vsock_host(
    process: &BrokerProcess,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    if socket.kind != SocketType::Stream {
        return Ok(Err(UnixSocketError::WrongType));
    }
    let mut state = socket.state.lock();
    if state.binding
        || state.name != UnixSocketName::Unnamed
        || !matches!(state.connection, Connection::None)
    {
        return Ok(Err(UnixSocketError::InvalidArgument));
    }
    // Its name, which no key the guests' addresses name holds, keeps it from
    // binding.
    let name = UnixSocketName::Vsock {
        cid: VMADDR_CID_HOST,
        port: VMADDR_PORT_ANY,
    };
    if let Err(error) = socket.register_name(&mut state, NameKey::VsockHost, name)? {
        return Ok(Err(error));
    }
    state.connection = Connection::Listening {
        backlog: VecDeque::new(),
        limit: backlog.min(MAX_UNIX_SOCKET_BACKLOG) as usize,
    };
    Ok(Ok(()))
}

/// Completes the connect of the socket that `handle`, which the host
/// connector accepted, is connected to: it is connected if `result` is `Ok`,
/// receiving the data `handle` sent meanwhile. Else it is unconnected with
/// the pending error `result`, that data is discarded, and `handle`'s
/// connection ends as if its peer had closed: it no longer reaches that
/// socket or sends, and receives the end of data.
///
/// This is the broker's own entry point, which no broker request reaches.
/// Fails with [`UnixSocketError::NotConnected`], changing nothing, if that
/// socket closed, or `handle` is not connecting it.
pub fn complete_vsock_host_connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
    result: UnixSocketResult<()>,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let host = &lease.socket;
    let guest = match &host.state.lock().connection {
        Connection::Connected { peer, .. } => peer.upgrade(),
        _ => None,
    };
    let Some(guest) = guest else {
        return Ok(Err(UnixSocketError::NotConnected));
    };
    let (guest_wakeups, host_wakeups) = {
        let (mut host_state, mut guest_state) = lock_both(host, &guest);
        let peer_name = match &guest_state.connection {
            Connection::Connecting { peer, peer_name } if refers_to(peer, host) => {
                peer_name.clone()
            }
            _ => return Ok(Err(UnixSocketError::NotConnected)),
        };
        match result {
            Ok(()) => {
                guest_state.connection = Connection::Connected {
                    peer: Arc::downgrade(host),
                    peer_name,
                };
                (Wakeups::default(), Wakeups::default())
            }
            Err(error) => (
                guest.end_connect(&mut guest_state, Some(error)),
                host.end_connection(&mut host_state),
            ),
        }
    };
    guest_wakeups.wake();
    host_wakeups.wake();
    guest.publish();
    host.publish();
    Ok(Ok(()))
}

/// Reports the outcome of the socket `handle`'s vsock connect as a blocking
/// connect waiting for it sees it, as in Linux:
/// [`SocketConnectionStatus::Connecting`] while it is in progress, then
/// [`SocketConnectionStatus::Connected`], or its error, which stays pending
/// unless the connect timed out (Linux's waiter times out itself, and leaves
/// no error). An unconnected socket with no pending error is
/// [`SocketConnectionStatus::Unconnected`], and a listening one fails with
/// [`UnixSocketError::InvalidArgument`].
pub fn check_connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<UnixSocketResult<SocketConnectionStatus>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    let (result, taken) = socket.state.lock().connect_outcome();
    if taken {
        socket.publish();
    }
    Ok(result)
}

/// Cancels the vsock connect in progress on the socket `handle`, as Linux
/// does when a blocking connect is interrupted: the socket is unconnected
/// again, still bound, with no pending error, and the connector's socket for
/// it hangs up, as if it had closed.
///
/// With no connect in progress, it reports the outcome as [`check_connect`]
/// does: it fails with [`UnixSocketError::AlreadyConnected`] if the connect
/// completed, or with its error if it failed, and succeeds if the socket is
/// unconnected with no pending error.
pub fn cancel_vsock_connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<UnixSocketResult<()>> {
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WRITE)?)?;
    let socket = &lease.socket;
    let (hung_up, wakeups) = loop {
        let peer = {
            let mut state = socket.state.lock();
            let Connection::Connecting { peer, .. } = &state.connection else {
                let (result, taken) = state.connect_outcome();
                drop(state);
                if taken {
                    socket.publish();
                }
                return Ok(match result {
                    Ok(SocketConnectionStatus::Connected) => Err(UnixSocketError::AlreadyConnected),
                    result => result.map(drop),
                });
            };
            let Some(peer) = peer.upgrade() else {
                break (None, socket.end_connect(&mut state, None));
            };
            peer
        };
        let (mut state, mut peer_state) = lock_both(socket, &peer);
        // Both ends are detached under both locks: a hang-up the connector's
        // socket sends later finds no peer, and one it already sent finds no
        // connect from it.
        if matches!(&state.connection, Connection::Connecting { peer: current, .. }
            if refers_to(current, &peer))
        {
            let wakeups = socket.end_connect(&mut state, None);
            let peer_wakeups = match &peer_state.connection {
                Connection::Connected { peer: back, .. } if refers_to(back, socket) => {
                    peer.end_connection(&mut peer_state)
                }
                _ => Wakeups::default(),
            };
            drop((state, peer_state));
            break (Some((peer, peer_wakeups)), wakeups);
        }
    };
    wakeups.wake();
    if let Some((peer, wakeups)) = hung_up {
        wakeups.wake();
        peer.publish();
    }
    socket.publish();
    Ok(Ok(()))
}

/// Takes the pending error of a Unix socket: why its last connect failed.
pub fn take_error(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<Option<UnixSocketError>> {
    let lease = Lease::new(
        process
            .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?,
    )?;
    let error = lease.socket.state.lock().error.take();
    if error.is_some() {
        lease.socket.publish();
    }
    Ok(error)
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
/// with [`BrokerError::WouldBlock`] while the receiving socket is full. A
/// datagram to a vsock address is [`UnixSocketError::Unreachable`].
pub fn send(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: Option<&UnixSocketAddress>,
    data: &dyn WriteBuffer,
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
        SocketType::SeqPacket => socket.send_record(data, lease.nonblocking),
        _ => Err(BrokerError::Internal),
    }
}

/// Receives bytes from a Unix socket into the start of `output`, leaving them
/// queued if `peek` is set and returning the sender's name if `source` is set.
///
/// A stream socket receives queued bytes. A datagram or sequenced-packet
/// socket receives one datagram or record, discarding the bytes beyond
/// `output`'s length unless peeking. Receiving no bytes with zero length into
/// a nonempty `output` means an empty datagram or record arrived, or no more
/// data can arrive. Fails with [`BrokerError::WouldBlock`] while nothing is
/// queued.
///
/// If `nonblocking` is set, the receive acts as for a non-blocking socket:
/// it fails with [`BrokerError::NonBlockingWouldBlock`], and, as in Linux, a
/// datagram socket whose receive direction is shut down fails instead of
/// reporting the end of data, while a sequenced-packet socket still reports
/// it.
pub fn receive(
    process: &BrokerProcess,
    handle: ObjectHandle,
    output: &mut dyn ReadBuffer,
    peek: bool,
    source: bool,
    nonblocking: bool,
) -> Result<UnixSocketResult<Received>> {
    if output.len() > MAX_UNIX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::ResourceExhausted);
    }
    let lease = Lease::new(process.authorized_object(handle, ObjectRights::WAIT)?)?;
    let socket = &lease.socket;
    let nonblocking = nonblocking || lease.nonblocking;
    match socket.kind {
        SocketType::Stream => socket.receive_stream(output, peek, source, nonblocking),
        SocketType::Datagram => socket.receive_datagram(output, peek, source, nonblocking),
        SocketType::SeqPacket => socket.receive_record(output, peek, source, nonblocking),
        _ => Err(BrokerError::Internal),
    }
}

/// Shuts down one or both directions of a Unix socket.
///
/// Shutting down a direction of a connected stream or sequenced-packet
/// socket also shuts down the opposite direction of its peer. As in Linux, a
/// vsock socket that is not connected fails with
/// [`UnixSocketError::NotConnected`] and is not changed.
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
    if let Err(error) = socket.shut_down_locally(read) {
        return Ok(Err(error));
    }
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
/// is set. A vsock socket that shut down has no peer name.
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
        Connection::Connected { peer_name, .. } if state.local_shutdown.is_none() => {
            Ok(Ok(peer_name.clone()))
        }
        Connection::Connected { .. }
        | Connection::Connecting { .. }
        | Connection::None
        | Connection::Listening { .. } => Ok(Err(UnixSocketError::NotConnected)),
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
/// node while they use it. A vsock address is unreachable: guests do not
/// connect or send to vsock sockets.
fn lookup(
    process: &BrokerProcess,
    address: &UnixSocketAddress,
    user: FileUser,
    socket_type: SocketType,
) -> Result<UnixSocketResult<(NameKey, Option<File>)>> {
    let path = match address {
        UnixSocketAddress::Path { path, .. } => path,
        UnixSocketAddress::Abstract(bytes) => {
            return Ok(Ok((NameKey::Abstract(socket_type, bytes.clone()), None)));
        }
        UnixSocketAddress::Vsock { .. } => return Ok(Err(UnixSocketError::Unreachable)),
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
    /// Creates a new unnamed, unconnected `socket_type` socket, a vsock one
    /// if `vsock` is set.
    fn new(
        process: &BrokerProcess,
        socket_type: SocketType,
        status: StatusFlags,
        vsock: bool,
    ) -> Result<Self> {
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
        )
        .with_vsock(vsock);
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
    registry: RwLock<Registry>,
    /// Bytes charged for data queued in every socket. Processes' charges
    /// change only under this lock too, so a charge commits both or neither.
    queued: Mutex<usize>,
    max_queued: usize,
    max_queued_per_process: usize,
}

impl UnixSockets {
    pub(crate) fn new(limits: &BrokerCoreLimits) -> Self {
        Self {
            registry: RwLock::new(Registry {
                names: HashMap::new(),
                next_ephemeral_vsock_port: None,
            }),
            queued: Mutex::new(0),
            max_queued: limits.max_total_unix_socket_bytes,
            max_queued_per_process: limits.max_unix_socket_bytes_per_process,
        }
    }

    /// Returns the socket holding the name `key`, which must have type
    /// `socket_type`.
    fn find(&self, key: &NameKey, socket_type: SocketType) -> UnixSocketResult<Arc<Socket>> {
        let socket = self
            .registry
            .read()
            .names
            .get(key)
            .and_then(Weak::upgrade)
            .ok_or(UnixSocketError::ConnectionRefused)?;
        if socket.kind != socket_type {
            return Err(UnixSocketError::WrongType);
        }
        Ok(socket)
    }

    /// Starts the ephemeral vsock ports at a random one, like Linux, so they
    /// are unlikely to take the well-known ports a program binds later. The
    /// seed only spreads the ports and is no secret, so without randomness
    /// they start at the first.
    ///
    /// The caller holds no lock: the random provider may block.
    fn seed_ephemeral_vsock_ports(&self, process: &BrokerProcess) {
        if self.registry.read().next_ephemeral_vsock_port.is_some() {
            return;
        }
        let mut seed = [0; 4];
        let offset = match crate::random::fill(process, &mut seed) {
            Ok(()) => u32::from_ne_bytes(seed) % EPHEMERAL_VSOCK_PORTS,
            Err(_) => 0,
        };
        // Another bind may have seeded it, and taken ports, meanwhile.
        self.registry
            .write()
            .next_ephemeral_vsock_port
            .get_or_insert(offset);
    }

    /// Releases the name `key` if `socket` still holds it.
    fn unregister(&self, key: &NameKey, socket: &Socket) {
        let names = &mut self.registry.write().names;
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

/// The names a broker's Unix sockets hold.
struct Registry {
    /// Socket holding each bound name.
    names: HashMap<NameKey, Weak<Socket>>,
    /// Offset from [`FIRST_EPHEMERAL_VSOCK_PORT`] of the next ephemeral vsock
    /// port to try, below [`EPHEMERAL_VSOCK_PORTS`], once seeded.
    next_ephemeral_vsock_port: Option<u32>,
}

impl Registry {
    /// Takes the next ephemeral vsock port to try. The caller seeded the
    /// ports ([`UnixSockets::seed_ephemeral_vsock_ports`]); unseeded, they
    /// start at the first.
    fn take_ephemeral_vsock_port(&mut self) -> u32 {
        let offset = self.next_ephemeral_vsock_port.unwrap_or(0) % EPHEMERAL_VSOCK_PORTS;
        self.next_ephemeral_vsock_port = Some((offset + 1) % EPHEMERAL_VSOCK_PORTS);
        FIRST_EPHEMERAL_VSOCK_PORT + offset
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
    /// A guest's vsock port, which only stream sockets hold.
    Vsock(u32),
    /// The host connector, which no address names.
    VsockHost,
}

/// One Unix socket.
///
/// Dropping a socket tears nothing down: [`Socket::close`] does once nothing
/// reaches the socket through a reference or a backlog, so temporary handles
/// to it may drop anywhere.
struct Socket {
    kind: SocketType,
    /// Whether the socket was created as a vsock socket ([`create_vsock`]);
    /// one named by a vsock address is one too (see [`Socket::is_vsock`]).
    vsock: bool,
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
    /// How a vsock socket's own shutdown, not its peer's, stopped it.
    local_shutdown: Option<LocalShutdown>,
    /// Why the socket's last connect failed, if no call reported it yet;
    /// only while it is unconnected.
    error: Option<UnixSocketError>,
    /// Whether the socket was torn down.
    closed: bool,
    connection: Connection,
}

impl State {
    /// Checks that a stream or sequenced-packet socket in this state may
    /// connect to a vsock address; else fails as Linux does, taking the
    /// pending error, if any.
    fn check_vsock_connect(&mut self) -> UnixSocketResult<()> {
        match self.connection {
            Connection::Connected { .. } if self.local_shutdown.is_some() => {
                Err(UnixSocketError::InvalidArgument)
            }
            Connection::Connected { .. } => Err(UnixSocketError::AlreadyConnected),
            Connection::Connecting { .. } => Err(UnixSocketError::AlreadyInProgress),
            Connection::Listening { .. } => Err(UnixSocketError::InvalidArgument),
            Connection::None => self.error.take().map_or(Ok(()), Err),
        }
    }

    /// Returns the outcome of a vsock connect as [`check_connect`] reports
    /// it, and whether it took the pending error.
    fn connect_outcome(&mut self) -> (UnixSocketResult<SocketConnectionStatus>, bool) {
        let result = match self.connection {
            Connection::Connecting { .. } => Ok(SocketConnectionStatus::Connecting),
            Connection::Connected { .. } => Ok(SocketConnectionStatus::Connected),
            Connection::Listening { .. } => Err(UnixSocketError::InvalidArgument),
            Connection::None => match self.error {
                Some(UnixSocketError::TimedOut) => {
                    self.error = None;
                    return (Err(UnixSocketError::TimedOut), true);
                }
                Some(error) => Err(error),
                None => Ok(SocketConnectionStatus::Unconnected),
            },
        };
        (result, false)
    }
}

/// What a vsock socket's own shutdown stopped.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalShutdown {
    /// Sending only.
    Write,
    /// Receiving, and maybe sending.
    Read,
}

enum Connection {
    None,
    /// Connecting to the host's vsock port through the host connector (see
    /// the module docs), as a connected socket would be but for its readiness
    /// and operations.
    Connecting {
        /// The connector's socket for the connection, which completes it.
        peer: Weak<Socket>,
        /// The host's name, which the connection will have.
        peer_name: UnixSocketName,
    },
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
#[derive(Default)]
struct Queue {
    /// Bytes queued for a stream socket.
    bytes: VecDeque<u8>,
    /// Datagrams queued for a datagram socket, or records for a
    /// sequenced-packet socket.
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
    /// Copies `data` into a datagram sent by the socket named `source`.
    fn new(data: &dyn WriteBuffer, source: UnixSocketName) -> Result<Self> {
        let mut copy = Vec::new();
        copy.try_reserve_exact(data.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        copy.resize(data.len(), 0);
        data.copy_to_slice_at(0, &mut copy)?;
        Ok(Self { data: copy, source })
    }

    fn charge(&self) -> usize {
        self.data.len() + DATAGRAM_OVERHEAD
    }
}

/// Returns whether `weak` refers to `socket`.
///
/// A weak reference keeps its allocation, so no other socket can take its
/// address while it exists.
fn refers_to(weak: &Weak<Socket>, socket: &Socket) -> bool {
    core::ptr::eq(weak.as_ptr(), socket)
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
    /// Whether the socket, whose state is `state`, has vsock semantics.
    fn is_vsock(&self, state: &State) -> bool {
        self.vsock || matches!(state.name, UnixSocketName::Vsock { .. })
    }

    fn new(
        kind: SocketType,
        sockets: Arc<UnixSockets>,
        quota: Arc<AtomicUsize>,
        name: UnixSocketName,
        connection: Connection,
    ) -> Self {
        Self {
            kind,
            vsock: false,
            sockets,
            quota,
            state: Mutex::new(State {
                name,
                binding: false,
                name_key: None,
                marker: None,
                options: SocketOptions::default(),
                write_shut: false,
                local_shutdown: None,
                error: None,
                closed: false,
                connection,
            }),
            incoming: Channel::new(Queue::default(), CAPACITY),
            watchers: Mutex::new(ReadinessWatchers::default()),
        }
    }

    /// Makes the socket a vsock socket if `vsock` is set.
    fn with_vsock(self, vsock: bool) -> Self {
        Self { vsock, ..self }
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
        let (write_shut, error, vsock, connecting, connection) = {
            let state = self.state.lock();
            let connection = match &state.connection {
                Connection::None => None,
                Connection::Listening { backlog, .. } => Some(Err(!backlog.is_empty())),
                // Neither readable nor writable until it completes.
                Connection::Connecting { .. } => Some(Err(false)),
                Connection::Connected { peer, .. } => Some(Ok(peer.clone())),
            };
            let vsock = self.is_vsock(&state);
            let connecting = matches!(state.connection, Connection::Connecting { .. });
            (
                state.write_shut,
                state.error.is_some(),
                vsock,
                connecting,
                connection,
            )
        };
        let mut readiness = ReadinessFlags::default();
        if error {
            readiness = readiness | ReadinessFlags::ERROR;
        }
        {
            let channel = self.incoming.lock();
            if channel.is_shut() {
                readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
                if write_shut {
                    readiness = readiness | ReadinessFlags::CLOSED;
                }
            }
            // A connecting socket receives nothing until it connects.
            if !connecting && !channel.queue.is_empty() {
                readiness = readiness | ReadinessFlags::READ;
            }
        }
        let peer = match connection {
            None => {
                // An unconnected vsock socket is not hung up (see the module
                // docs).
                if self.is_connection_oriented() && !vsock {
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
        let mut registry = self.sockets.registry.write();
        if registry.names.contains_key(&key) {
            return Ok(Err(UnixSocketError::AddressInUse));
        }
        self.hold_name(&mut registry.names, state, key, name)
            .map(Ok)
    }

    /// Records that the socket holds an unused ephemeral vsock port.
    fn register_ephemeral_vsock_port(
        self: &Arc<Self>,
        state: &mut State,
    ) -> Result<UnixSocketResult<()>> {
        let mut registry = self.sockets.registry.write();
        for _ in 0..MAX_EPHEMERAL_VSOCK_PORT_ATTEMPTS {
            let port = registry.take_ephemeral_vsock_port();
            let key = NameKey::Vsock(port);
            if !registry.names.contains_key(&key) {
                let name = UnixSocketName::Vsock {
                    cid: VMADDR_CID_ANY,
                    port,
                };
                return self
                    .hold_name(&mut registry.names, state, key, name)
                    .map(Ok);
            }
        }
        Ok(Err(UnixSocketError::AddressNotAvailable))
    }

    /// Records that the socket holds the unused name `name` identified by
    /// `key` in `names`, the locked registry.
    fn hold_name(
        self: &Arc<Self>,
        names: &mut HashMap<NameKey, Weak<Socket>>,
        state: &mut State,
        key: NameKey,
        name: UnixSocketName,
    ) -> Result<()> {
        names.try_reserve(1).map_err(|_| BrokerError::OutOfMemory)?;
        names.insert(key.clone(), Arc::downgrade(self));
        state.name = name;
        state.name_key = Some(key);
        Ok(())
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
                Connection::Connecting { .. } => UnixSocketError::AlreadyInProgress,
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
                Connection::Connecting { .. } => {
                    return Ok(Err(UnixSocketError::AlreadyInProgress));
                }
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
            let peer = self.queue_on(&state, listener, backlog, listener_name.clone())?;
            state.connection = Connection::Connected {
                peer,
                peer_name: listener_name,
            };
        }
        listener.publish();
        self.publish();
        Ok(Ok(()))
    }

    /// Starts this stream or sequenced-packet socket's connect to vsock
    /// address `cid`:`port` (see [`connect`]).
    fn connect_to_vsock_host(
        self: &Arc<Self>,
        process: &BrokerProcess,
        cid: u32,
        port: u32,
    ) -> Result<UnixSocketResult<SocketConnectionStatus>> {
        let unnamed = {
            let mut state = self.state.lock();
            if let Err(error) = state.check_vsock_connect() {
                return Ok(Err(error));
            }
            state.name == UnixSocketName::Unnamed
        };
        if self.kind != SocketType::Stream || cid != VMADDR_CID_HOST {
            return Ok(Err(UnixSocketError::Unreachable));
        }
        let connector = match self.sockets.find(&NameKey::VsockHost, SocketType::Stream) {
            // The connector listens, so this socket is not it.
            Ok(connector) if !Arc::ptr_eq(self, &connector) => connector,
            _ => return Ok(Err(UnixSocketError::Unreachable)),
        };
        if unnamed {
            self.sockets.seed_ephemeral_vsock_ports(process);
        }
        {
            let (mut state, mut connecting) = lock_both(self, &connector);
            // Another call may have connected or named it meanwhile.
            if let Err(error) = state.check_vsock_connect() {
                return Ok(Err(error));
            }
            match state.name {
                UnixSocketName::Unnamed if !state.binding => {
                    if let Err(error) = self.register_ephemeral_vsock_port(&mut state)? {
                        return Ok(Err(error));
                    }
                }
                UnixSocketName::Vsock {
                    cid: VMADDR_CID_ANY,
                    ..
                } => {}
                // Not a vsock socket.
                _ => return Ok(Err(UnixSocketError::Unreachable)),
            }
            if connecting.closed {
                return Ok(Err(UnixSocketError::Unreachable));
            }
            let Connection::Listening { backlog, limit } = &mut connecting.connection else {
                return Ok(Err(UnixSocketError::Unreachable));
            };
            if backlog.len() > *limit {
                return Err(BrokerError::ResourceExhausted);
            }
            let peer_name = UnixSocketName::Vsock {
                cid: VMADDR_CID_HOST,
                port,
            };
            let peer = self.queue_on(&state, &connector, backlog, peer_name.clone())?;
            state.connection = Connection::Connecting { peer, peer_name };
        }
        connector.publish();
        self.publish();
        Ok(Ok(SocketConnectionStatus::Connecting))
    }

    /// Queues on `backlog`, `listener`'s, a new socket named `name` and
    /// connected to this one, whose state is `state`; returns it.
    fn queue_on(
        self: &Arc<Self>,
        state: &State,
        listener: &Socket,
        backlog: &mut VecDeque<Arc<Socket>>,
        name: UnixSocketName,
    ) -> Result<Weak<Socket>> {
        backlog
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.sockets.charge(&listener.quota, CONNECTION_OVERHEAD)?;
        let server = Arc::new(Socket::new(
            self.kind,
            Arc::clone(&listener.sockets),
            Arc::clone(&listener.quota),
            name,
            Connection::Connected {
                peer: Arc::downgrade(self),
                peer_name: state.name.clone(),
            },
        ));
        let peer = Arc::downgrade(&server);
        backlog.push_back(server);
        Ok(peer)
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
        data: &dyn WriteBuffer,
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
            if let Err(error) = append_to_queue(&mut channel.queue.bytes, length, data) {
                self.sockets.refund(&peer.quota, length);
                return Err(error);
            }
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
        data: &dyn WriteBuffer,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<usize>> {
        let (peer, write_shut, source) = {
            let state = self.state.lock();
            let peer = match &state.connection {
                Connection::Connected { peer, .. } => Some(peer.clone()),
                Connection::None | Connection::Connecting { .. } | Connection::Listening { .. } => {
                    None
                }
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
        let datagram = Datagram::new(data, source)?;
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
                    self.queue_datagram(&target, &mut channel, datagram, nonblocking)?
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
        let record = Datagram::new(data, source)?;
        {
            let mut channel = peer.incoming.lock();
            if let Err(error) = self.queue_datagram(&peer, &mut channel, record, nonblocking)? {
                return Ok(Err(error));
            }
        }
        peer.publish();
        Ok(Ok(data.len()))
    }

    /// Queues `datagram` in `channel`, the incoming channel of `receiver`.
    ///
    /// A datagram may overrun the capacity, so a receiver that is not full
    /// accepts any datagram, as its readiness reports.
    fn queue_datagram(
        self: &Arc<Self>,
        receiver: &Socket,
        channel: &mut ChannelState<Queue, Socket>,
        datagram: Datagram,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<()>> {
        if channel.is_shut() {
            return Ok(Err(UnixSocketError::BrokenPipe));
        }
        if channel.room() == 0 {
            channel.wait(self)?;
            return Err(BrokerError::would_block(nonblocking));
        }
        let charge = datagram.charge();
        self.sockets.charge(&receiver.quota, charge)?;
        if channel.queue.datagrams.try_reserve(1).is_err() {
            self.sockets.refund(&receiver.quota, charge);
            return Err(BrokerError::OutOfMemory);
        }
        channel.queue.datagrams.push_back(datagram);
        channel.add(charge);
        Ok(Ok(()))
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
        output: &mut dyn ReadBuffer,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<Received>> {
        let (source, read_shut) = {
            let state = self.state.lock();
            let source = match &state.connection {
                Connection::Connected { peer_name, .. } => source.then(|| peer_name.clone()),
                Connection::Connecting { .. } => return Ok(Err(UnixSocketError::NotConnected)),
                Connection::None | Connection::Listening { .. } => {
                    return Ok(Err(UnixSocketError::InvalidArgument));
                }
            };
            (source, state.local_shutdown == Some(LocalShutdown::Read))
        };
        // Its incoming channel is shut too, so it reports itself readable.
        if output.is_empty() || read_shut {
            return Ok(Ok(Received {
                source,
                ..Received::default()
            }));
        }
        let (length, wakeups) = {
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
            let length = output.len().min(channel.queue.bytes.len());
            if peek {
                copy_from_queue(&channel.queue.bytes, 0..length, output)?;
                (length, Wakeups::default())
            } else {
                take_from_queue(&mut channel.queue.bytes, length, output)?;
                if channel.queue.bytes.is_empty() {
                    channel.queue.bytes = VecDeque::new();
                }
                channel.remove(length);
                self.sockets.refund(&self.quota, length);
                // Senders waiting for room retry.
                (length, channel.wake())
            }
        };
        wakeups.wake();
        Ok(Ok(Received {
            received: length,
            length,
            source,
        }))
    }

    fn receive_datagram(
        &self,
        output: &mut dyn ReadBuffer,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<Received>> {
        let (received, wakeups) = {
            let mut channel = self.incoming.lock();
            let Some(datagram) = channel.queue.datagrams.front() else {
                // Like Linux, a sequenced-packet socket reports the end of
                // data even to a receive that would not wait; a datagram
                // socket does not.
                return if channel.is_shut() && (!nonblocking || self.kind == SocketType::SeqPacket)
                {
                    Ok(Ok(Received {
                        source: source.then_some(UnixSocketName::Unnamed),
                        ..Received::default()
                    }))
                } else {
                    Err(BrokerError::would_block(nonblocking))
                };
            };
            let length = datagram.data.len();
            let received = output.len().min(length);
            output.copy_from_slice_at(0, &datagram.data[..received])?;
            if peek {
                let received = Received {
                    received,
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
                let received = Received {
                    received,
                    length,
                    source: source.then_some(datagram.source),
                };
                // Senders waiting for room retry.
                (received, channel.wake())
            }
        };
        wakeups.wake();
        Ok(Ok(received))
    }

    /// Receives one record from the connected peer.
    fn receive_record(
        &self,
        output: &mut dyn ReadBuffer,
        peek: bool,
        source: bool,
        nonblocking: bool,
    ) -> Result<UnixSocketResult<Received>> {
        if !matches!(self.state.lock().connection, Connection::Connected { .. }) {
            return Ok(Err(UnixSocketError::NotConnected));
        }
        self.receive_datagram(output, peek, source, nonblocking)
    }

    /// Records that a vsock socket's own shutdown stops it receiving if `read`
    /// is set, or else sending. Fails, recording nothing, if it is a vsock
    /// socket that is not connected.
    fn shut_down_locally(&self, read: bool) -> UnixSocketResult<()> {
        let mut state = self.state.lock();
        if !self.is_vsock(&state) {
            return Ok(());
        }
        // A connected stream socket stays connected while referenced, so the
        // shutdown that follows the check finds it so.
        if !matches!(state.connection, Connection::Connected { .. }) {
            return Err(UnixSocketError::NotConnected);
        }
        if read {
            state.local_shutdown = Some(LocalShutdown::Read);
        } else {
            state.local_shutdown.get_or_insert(LocalShutdown::Write);
        }
        Ok(())
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
    /// `from` closed; a connect still in progress fails instead.
    ///
    /// Does nothing unless `from` is still its peer: a hang-up sent after the
    /// connection was detached (see [`cancel_vsock_connect`]) must leave the
    /// unconnected socket, or its next connection, alone.
    fn hang_up(self: &Arc<Self>, from: &Socket) {
        let wakeups = {
            let mut state = self.state.lock();
            match &state.connection {
                Connection::Connecting { peer, .. } if refers_to(peer, from) => {
                    self.end_connect(&mut state, Some(UnixSocketError::ConnectionReset))
                }
                Connection::Connected { peer, .. } if refers_to(peer, from) => {
                    self.end_connection(&mut state)
                }
                _ => return,
            }
        };
        wakeups.wake();
        self.publish();
    }

    /// Ends this socket's connection, whose state is `state`, after its peer
    /// left: it no longer sends, and receives the end of data once its queue
    /// drains.
    fn end_connection(&self, state: &mut State) -> Wakeups<Socket> {
        state.write_shut = true;
        if let Connection::Connected { peer, .. } = &mut state.connection {
            *peer = Weak::new();
        }
        let mut channel = self.incoming.lock();
        channel.shut();
        channel.wake()
    }

    /// Leaves this connecting socket, whose state is `state`, unconnected,
    /// with the pending error `error`, if any, and discards the data its peer
    /// queued for it meanwhile, which no later connection may receive.
    fn end_connect(&self, state: &mut State, error: Option<UnixSocketError>) -> Wakeups<Socket> {
        state.connection = Connection::None;
        state.error = error;
        let mut channel = self.incoming.lock();
        self.purge(&mut channel);
        // Senders waiting for room retry.
        channel.wake()
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
            Connection::Connected { peer, .. } | Connection::Connecting { peer, .. }
                if self.is_connection_oriented() =>
            {
                if let Some(peer) = peer.upgrade() {
                    peer.hang_up(self);
                }
            }
            Connection::None | Connection::Connecting { .. } | Connection::Connected { .. } => {}
        }
        wakeups.wake();
    }
}

#[cfg(test)]
mod tests;
