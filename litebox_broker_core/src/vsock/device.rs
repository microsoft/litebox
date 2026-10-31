// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker vsock sockets on a transport of stream connections with the host:
//! a [`VsockProvider`] for brokers whose guests' `AF_VSOCK` stream sockets
//! reach the host, e.g., the LiteBox VM kernel's (on its virtio-vsock
//! device).
//!
//! [`VsockDeviceProvider`] implements the sockets as Linux's (ports and
//! ephemeral binding, listeners and their backlogs, connects and their
//! timeout, pending errors, shutdowns, closes that linger, readiness), on a
//! [`Vsock`] device: whatever transport holds the connections with the host
//! (see the trait for what it must do). Each socket's connection is one of
//! the device's.
//!
//! The host's requests go to the listener on their guest port while its
//! backlog has room, and are refused otherwise. A guest's connect asks the
//! device for a connection from its socket's port to the host's port, and
//! fails if the host refuses it, if the device cannot hold it
//! ([`Vsock::connect`]), or if the host does not answer within
//! [`CONNECT_TIMEOUT`]. A device that ends its connections at once (e.g., a
//! transport reset) fails the connects in progress and ends the live
//! connections.
//!
//! Sends and receives go straight to the device, which holds what the host
//! sent until it is read, and takes as much as the host takes now: nothing
//! is buffered here. A closed connection is shut down both ways, and the
//! device keeps it until it is closed ([`Vsock::is_closed`], e.g., the host
//! reset it), or for at most [`CLOSE_TIMEOUT`]; its port stays in use
//! meanwhile, as on Linux.
//!
//! The host is not trusted: each poll answers at most
//! `MAX_REQUESTS_PER_POLL` requests and drops at most `MAX_DISCARD_PER_POLL`
//! bytes nothing reads, and each operation moves at most its buffer. The
//! host sees a guest socket's port as its source port; guests bind any port,
//! with no privilege check, so the host must not trust it.
//!
//! The provider has no thread of its own: the broker calls
//! [`VsockDeviceProvider::poll`] when the device changes, if it
//! [interrupts](Vsock::interrupts), and must not wait past
//! [`VsockDeviceProvider::next_deadline`], on the clock the provider is given.
//! Readiness is a snapshot per socket, recomputed after each operation and
//! for every socket on each poll, and published, under the provider's lock,
//! when it changes; a connect's outcome is republished even if the flags
//! did not change.
//!
//! Locks: the provider's, then the device's (each [`Vsock`] call), never
//! the reverse. A caller that finds another polling does not wait for it.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::ops::Bound;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::time::Duration;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    ShutdownMode, SocketConnectionStatus, SocketError, SocketOutcome,
};
use litebox_broker_protocol::vsock::{
    VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_PORT_ANY, VsockAddress,
};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::time::Instant;

use crate::readiness::ReadinessRegistration;
use crate::socket::PlatformStreamReceive;
use crate::vsock::{AcceptedPlatformVsockSocket, PlatformVsockSocket, VsockProvider};
use crate::{BrokerError, Result};

/// A device's connection, by its ends' ports, whichever end connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId {
    /// The guest's end's port.
    pub guest_port: u32,
    /// The host's end's port.
    pub host_port: u32,
}

/// What became of a connection the guest asked the host for
/// ([`Vsock::connect`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectState {
    /// The host has yet to answer.
    Connecting,
    /// The host accepted it; it is live, or gone since.
    Established,
    /// The host refused it, or it was reset, or it is unknown, or the host
    /// requested it (the guest's was forgotten).
    Failed,
}

/// What reads and writes on a connection would do now ([`Vsock::status`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionStatus {
    /// Received data waits to be read.
    pub readable: bool,
    /// The host sends no more: it shut down sending, or the connection is
    /// gone or unknown. Data already received can still be read.
    pub host_sending_ended: bool,
    /// A write takes data now, or fails: the connection takes no more.
    pub writable: bool,
}

impl ConnectionStatus {
    /// A connection the device no longer has (ended, its data read), or
    /// never had: nothing to read, the host sends no more, and a write
    /// fails rather than waits.
    pub const ENDED: Self = Self {
        readable: false,
        host_sending_ended: true,
        writable: true,
    };
}

/// A vsock device, as the provider drives it: a transport of stream
/// connections between the guest and the host (CID 2), which may be a
/// virtual device (e.g., the VM's virtio-vsock device) or the host's own
/// sockets. The host requests connections to any guest port, which the
/// provider accepts or refuses; the guest asks for connections to the
/// host's ports.
///
/// An implementation:
/// - holds what the host sent on a connection until it is read, within a
///   bound of its own (the host is not trusted), and drops what the host
///   sends after the guest shut down receiving;
/// - may refuse a guest's connect it cannot hold (e.g., beyond a share of
///   its connections it keeps for the host's requests), and fail one the
///   host does not answer; the provider times connects out on its own;
/// - may end every connection at once (e.g., a transport reset): its
///   connects in progress fail, its live connections end, and its guest CID
///   may change;
/// - keeps a closed connection until the host has its end, if it can, and
///   frees it only when forgotten;
/// - never calls back into the provider, which may hold its lock across a
///   call.
///
/// Only [`Self::take_request`], [`Self::connect_state`], [`Self::read`],
/// [`Self::write`], [`Self::is_closed`] and [`Self::forget`] first take in
/// what the host sent; the others take nothing new, so a request just taken
/// is still one when it is accepted.
pub trait Vsock: Send + Sync {
    /// The guest's CID, which may change as the device ends every
    /// connection.
    fn guest_cid(&self) -> u64;

    /// The next connection the host requested, to accept or refuse.
    fn take_request(&self) -> Option<ConnectionId>;

    /// Accepts a requested connection; false if it is not one.
    fn accept(&self, id: ConnectionId) -> bool;

    /// Refuses a requested connection.
    fn refuse(&self, id: ConnectionId);

    /// Asks the host for a connection; false if it is in use, or the device
    /// holds too many.
    fn connect(&self, id: ConnectionId) -> bool;

    /// What became of a connection [`Self::connect`] asked for; one that
    /// failed is forgotten.
    fn connect_state(&self, id: ConnectionId) -> ConnectState;

    /// Copies received data into `output`: how much, or `None` at the end of
    /// the stream.
    fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize>;

    /// Queues as much of `bytes` as the host takes now: how much, or `None`
    /// if the connection takes no more.
    fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize>;

    /// What reads and writes would do now.
    fn status(&self, id: ConnectionId) -> ConnectionStatus;

    /// Shuts down sending, after what was written.
    fn shutdown_sending(&self, id: ConnectionId);

    /// Shuts down receiving: the host's sends fail. Data already received
    /// can still be read; data the host sent before it knew is dropped.
    fn shutdown_receiving(&self, id: ConnectionId);

    /// Shuts the connection down both ways, after what was written; it is
    /// closed once the host has its end.
    fn close(&self, id: ConnectionId);

    /// Whether the connection is gone and its data read, or unknown.
    fn is_closed(&self, id: ConnectionId) -> bool;

    /// Ends the connection, resetting it unless it is gone, and frees its
    /// slot.
    fn forget(&self, id: ConnectionId);

    /// Takes whether the calls since the last of these took something in,
    /// or stopped at a budget with more left, which the device does not
    /// wake the broker for again (e.g., data for another connection).
    fn take_backlog(&self) -> bool;

    /// Whether the device wakes the broker as it changes; else the provider
    /// polls it.
    fn interrupts(&self) -> bool;
}

/// How long the host has to answer a guest's connect, as Linux's
/// `VSOCK_DEFAULT_CONNECT_TIMEOUT`.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a closed connection waits to be closed (e.g., for the host's
/// reset) before it is forgotten (reset) anyway, as Linux's
/// `VSOCK_CLOSE_TIMEOUT`.
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);

/// How often a device that does not interrupt is polled.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How soon a poll that left work follows the last: soon, but not at once,
/// as a deadline that is due interrupts every running process.
const BUSY_INTERVAL: Duration = Duration::from_millis(1);

/// Host requests answered per poll; the rest wait for the next.
const MAX_REQUESTS_PER_POLL: usize = 8;

/// Bytes dropped per poll from connections nothing reads (closed, or shut
/// down receiving); the rest wait for the next.
const MAX_DISCARD_PER_POLL: usize = 64 * 1024;

/// Bytes staged on the stack per device call, between a caller's buffer
/// (which may fault) and the device.
const STAGE: usize = 4096;

/// Ports up to this one are not ephemeral, as Linux's `LAST_RESERVED_PORT`.
const LAST_RESERVED_PORT: u32 = 1023;

/// Ephemeral ports tried per bind, as Linux's `MAX_PORT_RETRIES`.
const MAX_EPHEMERAL_TRIES: usize = 24;

/// The broker's vsock sockets on a [`Vsock`] device, on a clock whose
/// instants are `I` (see the [module](self) docs).
pub struct VsockDeviceProvider<I>(Arc<Shared<I>>);

struct Shared<I> {
    device: Arc<dyn Vsock>,
    /// The broker's clock.
    now: Box<dyn Fn() -> I + Send + Sync>,
    state: spin::Mutex<State<I>>,
    /// A poll was asked for and not yet started, or an operation left the
    /// device with a backlog: [`VsockDeviceProvider::next_deadline`] reports
    /// a poll due.
    repoll: AtomicBool,
}

struct State<I> {
    device: Arc<dyn Vsock>,
    /// Live sockets, by ID; retired ones are gone.
    sockets: BTreeMap<u64, Socket>,
    next_socket: u64,
    /// Ports in use: a bound socket's, or a closed connection's that its
    /// socket bound.
    ports: BTreeMap<u32, Port>,
    /// The device connections the provider holds.
    connections: BTreeMap<ConnectionId, Holder<I>>,
    /// Where the next ephemeral port search starts.
    next_ephemeral: u32,
    /// The last poll stopped at a budget with more to do, or left the device
    /// with a backlog.
    busy: bool,
    last_poll: Option<I>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Port {
    Socket(u64),
    Closing(ConnectionId),
}

/// Who holds a device connection. A deadline of `None` is past the clock's
/// end: never.
enum Holder<I> {
    /// A connected socket, or a listener's backlog.
    Socket,
    /// A connecting socket, until `deadline`.
    Connecting { deadline: Option<I> },
    /// No socket: it was closed, and waits to be closed (e.g., for the
    /// host's reset) until `deadline`.
    Closing { deadline: Option<I> },
}

struct Socket {
    registration: ReadinessRegistration,
    /// The readiness last published, which [`PlatformVsockSocket::readiness`]
    /// reads without the lock.
    snapshot: Arc<AtomicU32>,
    /// As `getsockname` reports it, once bound. A socket that bound it holds
    /// its port in [`State::ports`]; an accepted one does not.
    local: Option<VsockAddress>,
    phase: Phase,
    error: Option<SocketError>,
}

enum Phase {
    Unconnected,
    /// `backlog` holds connections the device accepted, oldest first; one
    /// more than `max` may wait, as on Linux.
    Listening {
        backlog: VecDeque<ConnectionId>,
        max: usize,
    },
    Connecting(ConnectionId),
    Connected(Connected),
}

struct Connected {
    /// `None` once the device forgot it: it ended, and its data was read or
    /// dropped.
    id: Option<ConnectionId>,
    peer_port: u32,
    read_shut: bool,
    write_shut: bool,
}

impl Connected {
    fn new(id: ConnectionId) -> Self {
        Self {
            id: Some(id),
            peer_port: id.host_port,
            read_shut: false,
            write_shut: false,
        }
    }

    /// As Linux's `vsock_poll`, but a connection that takes no more data is
    /// writable, as a send fails rather than waits.
    fn readiness(&self, device: &dyn Vsock) -> ReadinessFlags {
        let status = self
            .id
            .map_or(ConnectionStatus::ENDED, |id| device.status(id));
        let read_ended = self.read_shut || status.host_sending_ended;
        let mut flags = ReadinessFlags::default();
        if read_ended || status.readable {
            flags = flags | ReadinessFlags::READ;
        }
        if read_ended {
            flags = flags | ReadinessFlags::HANGUP;
        }
        if self.write_shut && read_ended {
            flags = flags | ReadinessFlags::CLOSED;
        }
        if !self.write_shut && status.writable {
            flags = flags | ReadinessFlags::WRITE;
        }
        flags
    }
}

impl Socket {
    fn readiness(&self, device: &dyn Vsock) -> ReadinessFlags {
        let flags = match &self.phase {
            Phase::Unconnected => ReadinessFlags::WRITE,
            Phase::Listening { backlog, .. } if !backlog.is_empty() => ReadinessFlags::READ,
            Phase::Listening { .. } | Phase::Connecting(_) => ReadinessFlags::default(),
            Phase::Connected(connected) => connected.readiness(device),
        };
        if self.error.is_some() {
            flags | ReadinessFlags::ERROR
        } else {
            flags
        }
    }
}

impl<I: Instant> VsockDeviceProvider<I> {
    /// The provider for `device`, on the clock `now`; `seed` (e.g., from a
    /// CSPRNG) starts the ephemeral ports.
    pub fn new(device: Arc<dyn Vsock>, now: Box<dyn Fn() -> I + Send + Sync>, seed: u64) -> Self {
        Self(Arc::new(Shared {
            device: Arc::clone(&device),
            now,
            state: spin::Mutex::new(State {
                device,
                sockets: BTreeMap::new(),
                next_socket: 0,
                ports: BTreeMap::new(),
                connections: BTreeMap::new(),
                next_ephemeral: u32::try_from(seed % u64::from(u32::MAX)).unwrap_or(0),
                busy: false,
                last_poll: None,
            }),
            repoll: AtomicBool::new(false),
        }))
    }

    /// Answers the host's requests, settles connects and closed
    /// connections, and publishes the sockets' readiness; a bounded amount.
    /// Never waits for another caller's poll.
    pub fn poll(&self) {
        self.0.repoll.store(true, Ordering::SeqCst);
        // Once more for a caller that asked meanwhile; then, the deadline.
        for _ in 0..2 {
            let Some(mut state) = self.0.state.try_lock() else {
                return;
            };
            if !self.0.repoll.swap(false, Ordering::SeqCst) {
                return;
            }
            state.poll((self.0.now)());
            drop(state);
            if !self.0.repoll.load(Ordering::SeqCst) {
                return;
            }
        }
    }

    /// When the provider must next poll, if before the device changes: soon
    /// if a poll is asked for or left work, at the earliest connect or close
    /// timeout, or, for a device that does not interrupt, its poll interval.
    pub fn next_deadline(&self) -> Option<I> {
        let soon = || after((self.0.now)(), BUSY_INTERVAL);
        if self.0.repoll.load(Ordering::SeqCst) {
            return soon();
        }
        // Another caller polls, or operates, and then has its own deadline.
        let Some(state) = self.0.state.try_lock() else {
            return soon();
        };
        if let Some(last_poll) = state.last_poll
            && state.busy
        {
            return after(last_poll, BUSY_INTERVAL);
        }
        let interval = state
            .last_poll
            .filter(|_| !self.0.device.interrupts())
            .and_then(|last_poll| after(last_poll, POLL_INTERVAL));
        state
            .connections
            .values()
            .filter_map(|holder| match holder {
                Holder::Socket => None,
                Holder::Connecting { deadline } | Holder::Closing { deadline } => *deadline,
            })
            .chain(interval)
            .min()
    }
}

impl<I: Instant + 'static> VsockProvider for VsockDeviceProvider<I> {
    fn create(&self, readiness: ReadinessRegistration) -> Result<Arc<dyn PlatformVsockSocket>> {
        let mut state = self.0.state.lock();
        let (id, snapshot) = state.insert(readiness, None, Phase::Unconnected);
        Ok(Arc::new(DeviceSocket {
            id,
            shared: Arc::clone(&self.0),
            snapshot,
        }))
    }
}

impl<I: Instant> State<I> {
    /// Adds a socket, publishing its initial readiness if any.
    fn insert(
        &mut self,
        registration: ReadinessRegistration,
        local: Option<VsockAddress>,
        phase: Phase,
    ) -> (u64, Arc<AtomicU32>) {
        let id = self.next_socket;
        self.next_socket += 1;
        let snapshot = Arc::new(AtomicU32::new(0));
        self.sockets.insert(
            id,
            Socket {
                registration,
                snapshot: Arc::clone(&snapshot),
                local,
                phase,
                error: None,
            },
        );
        self.publish(id, false);
        (id, snapshot)
    }

    fn socket(&mut self, id: u64) -> Result<&mut Socket> {
        self.sockets.get_mut(&id).ok_or(BrokerError::Internal)
    }

    /// The guest's CID, if a valid one.
    fn guest_cid(&self) -> Option<u32> {
        u32::try_from(self.device.guest_cid())
            .ok()
            .filter(|&cid| cid != VMADDR_CID_ANY)
    }

    /// Recomputes socket `id`'s readiness, and publishes it if it changed,
    /// or else if `republish`.
    fn publish(&self, id: u64, republish: bool) {
        let Some(socket) = self.sockets.get(&id) else {
            return;
        };
        let flags = socket.readiness(&*self.device);
        if socket.snapshot.swap(flags.0, Ordering::Relaxed) != flags.0 {
            socket.registration.publish(flags);
        } else if republish {
            socket.registration.republish(flags);
        }
    }

    /// An unused port at or after [`Self::next_ephemeral`], as Linux's
    /// `__vsock_bind_connectible`; `None` after [`MAX_EPHEMERAL_TRIES`].
    fn ephemeral_port(&mut self) -> Option<u32> {
        for _ in 0..MAX_EPHEMERAL_TRIES {
            if self.next_ephemeral == VMADDR_PORT_ANY || self.next_ephemeral <= LAST_RESERVED_PORT {
                self.next_ephemeral = LAST_RESERVED_PORT + 1;
            }
            let port = self.next_ephemeral;
            self.next_ephemeral += 1;
            if !self.ports.contains_key(&port) {
                return Some(port);
            }
        }
        None
    }

    /// Settles socket `id`'s connect, if the host answered or its time is
    /// up, republishing its readiness.
    fn settle_connect(&mut self, id: u64, now: I) {
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        let Phase::Connecting(connection) = socket.phase else {
            return;
        };
        let due = match self.connections.get(&connection) {
            Some(Holder::Connecting { deadline }) => {
                deadline.is_some_and(|deadline| now >= deadline)
            }
            _ => true,
        };
        let error = match self.device.connect_state(connection) {
            ConnectState::Established => None,
            ConnectState::Failed => Some(SocketError::ConnectionReset),
            ConnectState::Connecting if due => Some(SocketError::TimedOut),
            ConnectState::Connecting => return,
        };
        if let Some(error) = error {
            self.device.forget(connection);
            self.connections.remove(&connection);
            socket.phase = Phase::Unconnected;
            socket.error = Some(error);
        } else {
            self.connections.insert(connection, Holder::Socket);
            socket.phase = Phase::Connected(Connected::new(connection));
        }
        self.publish(id, true);
    }

    /// Forgets a device connection the provider held, and frees the port it
    /// kept in use once closed.
    fn forget(&mut self, connection: ConnectionId) {
        self.device.forget(connection);
        self.connections.remove(&connection);
        if self.ports.get(&connection.guest_port) == Some(&Port::Closing(connection)) {
            self.ports.remove(&connection.guest_port);
        }
    }

    /// Takes the host's request for `connection` to a listener, or refuses
    /// it.
    fn dispatch(&mut self, connection: ConnectionId) {
        // E.g., a guest's connect the host refused, then requested with the
        // same ports, before the connect was settled.
        if self.connections.contains_key(&connection) {
            self.device.refuse(connection);
            return;
        }
        let listener = self
            .ports
            .get(&connection.guest_port)
            .and_then(|port| match *port {
                Port::Socket(listener) => Some(listener),
                Port::Closing(_) => None,
            });
        let backlog = listener.and_then(|listener| match self.sockets.get_mut(&listener) {
            Some(Socket {
                phase: Phase::Listening { backlog, max },
                ..
            }) if backlog.len() <= *max => Some(backlog),
            _ => None,
        });
        let (Some(listener), Some(backlog)) = (listener, backlog) else {
            self.device.refuse(connection);
            return;
        };
        // The device takes nothing new before `accept`: still a request,
        // unless the host gave up on it, which leaves nothing to do.
        if self.device.accept(connection) {
            backlog.push_back(connection);
            self.connections.insert(connection, Holder::Socket);
            self.publish(listener, false);
        }
    }

    /// Drops up to `budget` bytes the host sent on `connection`, counting
    /// them against it.
    fn discard(&self, connection: ConnectionId, budget: &mut usize) {
        let mut scratch = [0; STAGE];
        while *budget > 0 {
            let len = scratch.len().min(*budget);
            match self.device.read(connection, &mut scratch[..len]) {
                Some(read) if read != 0 => *budget -= read.min(len),
                _ => break,
            }
        }
    }

    fn poll(&mut self, now: I) {
        self.last_poll = Some(now);
        let mut requests = 0;
        while requests < MAX_REQUESTS_PER_POLL
            && let Some(connection) = self.device.take_request()
        {
            requests += 1;
            self.dispatch(connection);
        }
        let mut budget = MAX_DISCARD_PER_POLL;
        let mut cursor = Bound::Unbounded;
        while let Some((&connection, holder)) =
            self.connections.range((cursor, Bound::Unbounded)).next()
        {
            cursor = Bound::Excluded(connection);
            let Holder::Closing { deadline } = *holder else {
                continue;
            };
            self.discard(connection, &mut budget);
            if deadline.is_some_and(|deadline| now >= deadline) || self.device.is_closed(connection)
            {
                self.forget(connection);
            }
        }
        let mut cursor = Bound::Unbounded;
        while let Some(&id) = self
            .sockets
            .range((cursor, Bound::Unbounded))
            .next()
            .map(|(id, _)| id)
        {
            cursor = Bound::Excluded(id);
            self.settle_connect(id, now);
            if let Some(Socket {
                phase:
                    Phase::Connected(Connected {
                        id: Some(connection),
                        read_shut,
                        ..
                    }),
                ..
            }) = self.sockets.get(&id)
            {
                let connection = *connection;
                if *read_shut {
                    self.discard(connection, &mut budget);
                }
                // Ended, and its data read: the socket reads the end of the
                // stream without it, and its slot is free.
                if self.device.is_closed(connection) {
                    if let Some(Socket {
                        phase: Phase::Connected(connected),
                        ..
                    }) = self.sockets.get_mut(&id)
                    {
                        connected.id = None;
                    }
                    self.forget(connection);
                }
            }
            self.publish(id, false);
        }
        // Taken even after a busy poll, so the next idle one does not see it.
        let backlog = self.device.take_backlog();
        self.busy = requests == MAX_REQUESTS_PER_POLL || budget == 0 || backlog;
    }

    /// Ends socket `id`, as Linux's close: a connect is cancelled, and a
    /// connection, including each in a listener's backlog, is shut down both
    /// ways and kept until the host resets it, or [`CLOSE_TIMEOUT`]; a
    /// connected socket's port stays in use as long, and a listener's is
    /// freed. Whether a connection lingers.
    fn retire(&mut self, id: u64, now: I) -> bool {
        let Some(socket) = self.sockets.remove(&id) else {
            return false;
        };
        let port = socket
            .local
            .map(|local| local.port)
            .filter(|port| self.ports.get(port) == Some(&Port::Socket(id)));
        if let Some(port) = port {
            self.ports.remove(&port);
        }
        match socket.phase {
            Phase::Unconnected | Phase::Connected(Connected { id: None, .. }) => false,
            Phase::Listening { backlog, .. } => {
                let lingers = !backlog.is_empty();
                for connection in backlog {
                    self.device.close(connection);
                    self.connections.insert(
                        connection,
                        Holder::Closing {
                            deadline: after(now, CLOSE_TIMEOUT),
                        },
                    );
                }
                lingers
            }
            Phase::Connecting(connection) => {
                self.forget(connection);
                false
            }
            Phase::Connected(Connected {
                id: Some(connection),
                ..
            }) => {
                self.device.close(connection);
                self.connections.insert(
                    connection,
                    Holder::Closing {
                        deadline: after(now, CLOSE_TIMEOUT),
                    },
                );
                if let Some(port) = port {
                    self.ports.insert(port, Port::Closing(connection));
                }
                true
            }
        }
    }
}

/// A socket of a [`VsockDeviceProvider`], by ID: one retired is gone from
/// the provider's state, so its operations fail and it publishes nothing.
struct DeviceSocket<I> {
    id: u64,
    shared: Arc<Shared<I>>,
    snapshot: Arc<AtomicU32>,
}

#[expect(clippy::unnecessary_wraps, reason = "for operations' early returns")]
fn failed<T>(error: SocketError) -> Result<SocketOutcome<T>> {
    Ok(SocketOutcome::Failed(error))
}

impl<I: Instant> DeviceSocket<I> {
    /// `f`, with the state, on the live socket; then its readiness is
    /// published if it changed. If the device was left with a backlog, a
    /// poll is due soon.
    fn run<R>(&self, f: impl FnOnce(&mut State<I>) -> Result<R>) -> Result<R> {
        let mut state = self.shared.state.lock();
        if !state.sockets.contains_key(&self.id) {
            return Err(BrokerError::Internal);
        }
        let result = f(&mut state);
        state.publish(self.id, false);
        drop(state);
        if self.shared.device.take_backlog() {
            self.shared.repoll.store(true, Ordering::SeqCst);
        }
        result
    }

    fn now(&self) -> I {
        (self.shared.now)()
    }

    /// The socket's connect outcome once settled, as
    /// [`PlatformVsockSocket::check_connect`] reports it.
    fn check(socket: &mut Socket) -> Result<SocketOutcome<SocketConnectionStatus>> {
        let status = match socket.phase {
            Phase::Listening { .. } => return failed(SocketError::InvalidArgument),
            Phase::Connecting(_) => SocketConnectionStatus::Connecting,
            Phase::Connected(_) => SocketConnectionStatus::Connected,
            Phase::Unconnected => match socket.error {
                // Linux's blocking connect times out without an error.
                Some(SocketError::TimedOut) => {
                    socket.error = None;
                    return failed(SocketError::TimedOut);
                }
                Some(error) => return failed(error),
                None => SocketConnectionStatus::Unconnected,
            },
        };
        Ok(SocketOutcome::Completed(status))
    }
}

impl<I: Instant + 'static> PlatformVsockSocket for DeviceSocket<I> {
    fn bind(&self, address: VsockAddress) -> Result<SocketOutcome<()>> {
        self.run(|state| {
            let guest_cid = state.guest_cid();
            if state.socket(self.id)?.local.is_some() {
                return failed(SocketError::InvalidArgument);
            }
            if address.cid != VMADDR_CID_ANY && Some(address.cid) != guest_cid {
                return failed(SocketError::AddressNotAvailable);
            }
            let port = if address.port == VMADDR_PORT_ANY {
                let Some(port) = state.ephemeral_port() else {
                    return failed(SocketError::AddressNotAvailable);
                };
                port
            } else if state.ports.contains_key(&address.port) {
                return failed(SocketError::AddressInUse);
            } else {
                address.port
            };
            state.ports.insert(port, Port::Socket(self.id));
            state.socket(self.id)?.local = Some(VsockAddress {
                cid: address.cid,
                port,
            });
            Ok(SocketOutcome::Completed(()))
        })
    }

    fn listen(&self, backlog: u32) -> Result<SocketOutcome<()>> {
        self.run(|state| {
            let socket = state.socket(self.id)?;
            let max = usize::try_from(backlog).unwrap_or(usize::MAX);
            match &mut socket.phase {
                _ if socket.local.is_none() => return failed(SocketError::InvalidArgument),
                Phase::Unconnected => {
                    socket.phase = Phase::Listening {
                        backlog: VecDeque::new(),
                        max,
                    };
                }
                Phase::Listening { max: old, .. } => *old = max,
                Phase::Connecting(_) | Phase::Connected(_) => {
                    return failed(SocketError::InvalidArgument);
                }
            }
            Ok(SocketOutcome::Completed(()))
        })
    }

    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> Result<SocketOutcome<AcceptedPlatformVsockSocket>> {
        self.run(|state| {
            let cid = state.guest_cid().unwrap_or(VMADDR_CID_ANY);
            let Phase::Listening { backlog, .. } = &mut state.socket(self.id)?.phase else {
                return failed(SocketError::InvalidArgument);
            };
            let connection = backlog.pop_front().ok_or(BrokerError::WouldBlock)?;
            let local = VsockAddress {
                cid,
                port: connection.guest_port,
            };
            let (id, snapshot) = state.insert(
                readiness,
                Some(local),
                Phase::Connected(Connected::new(connection)),
            );
            Ok(SocketOutcome::Completed(AcceptedPlatformVsockSocket {
                socket: Arc::new(DeviceSocket {
                    id,
                    shared: Arc::clone(&self.shared),
                    snapshot,
                }),
                peer_address: VsockAddress {
                    cid: VMADDR_CID_HOST,
                    port: connection.host_port,
                },
            }))
        })
    }

    fn connect(&self, address: VsockAddress) -> Result<SocketOutcome<SocketConnectionStatus>> {
        let now = self.now();
        self.run(|state| {
            state.settle_connect(self.id, now);
            let socket = state.socket(self.id)?;
            match &socket.phase {
                Phase::Unconnected => {}
                Phase::Listening { .. } => return failed(SocketError::InvalidArgument),
                Phase::Connected(connected) if connected.read_shut || connected.write_shut => {
                    return failed(SocketError::InvalidArgument);
                }
                Phase::Connected(_) => return failed(SocketError::AlreadyConnected),
                Phase::Connecting(_) => return failed(SocketError::AlreadyInProgress),
            }
            if address.cid != VMADDR_CID_HOST {
                return failed(SocketError::NetworkUnreachable);
            }
            if let Some(error) = socket.error.take() {
                return failed(error);
            }
            let port = if let Some(local) = socket.local {
                local.port
            } else {
                let Some(port) = state.ephemeral_port() else {
                    return failed(SocketError::AddressNotAvailable);
                };
                state.ports.insert(port, Port::Socket(self.id));
                state.socket(self.id)?.local = Some(VsockAddress {
                    cid: VMADDR_CID_ANY,
                    port,
                });
                port
            };
            let connection = ConnectionId {
                guest_port: port,
                host_port: address.port,
            };
            if state.connections.contains_key(&connection) || !state.device.connect(connection) {
                return failed(SocketError::ConnectionReset);
            }
            state.connections.insert(
                connection,
                Holder::Connecting {
                    deadline: after(now, CONNECT_TIMEOUT),
                },
            );
            state.socket(self.id)?.phase = Phase::Connecting(connection);
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        })
    }

    fn check_connect(&self) -> Result<SocketOutcome<SocketConnectionStatus>> {
        let now = self.now();
        self.run(|state| {
            state.settle_connect(self.id, now);
            Self::check(state.socket(self.id)?)
        })
    }

    fn cancel_connect(&self) -> Result<SocketOutcome<()>> {
        let now = self.now();
        self.run(|state| {
            state.settle_connect(self.id, now);
            let socket = state.socket(self.id)?;
            if let Phase::Connecting(connection) = socket.phase {
                socket.phase = Phase::Unconnected;
                state.forget(connection);
                return Ok(SocketOutcome::Completed(()));
            }
            Ok(match Self::check(socket)? {
                SocketOutcome::Completed(SocketConnectionStatus::Connected) => {
                    SocketOutcome::Failed(SocketError::AlreadyConnected)
                }
                SocketOutcome::Completed(_) => SocketOutcome::Completed(()),
                SocketOutcome::Failed(error) => SocketOutcome::Failed(error),
            })
        })
    }

    fn take_error(&self) -> Option<SocketError> {
        let now = self.now();
        self.run(|state| {
            state.settle_connect(self.id, now);
            Ok(state.socket(self.id)?.error.take())
        })
        .ok()
        .flatten()
    }

    fn send(&self, data: &dyn WriteBuffer) -> Result<SocketOutcome<usize>> {
        self.run(|state| {
            let connection = match &state.socket(self.id)?.phase {
                Phase::Connected(connected) if connected.write_shut => {
                    return failed(SocketError::Shutdown);
                }
                Phase::Connected(connected) => connected.id,
                _ => return failed(SocketError::NotConnected),
            };
            let Some(connection) = connection else {
                return failed(SocketError::Shutdown);
            };
            let mut stage = [0; STAGE];
            let mut sent = 0;
            loop {
                let len = stage.len().min(data.len() - sent);
                if let Err(fault) = data.copy_to_slice_at(sent, &mut stage[..len]) {
                    if sent == 0 {
                        return Err(fault.into());
                    }
                    break;
                }
                let Some(written) = state.device.write(connection, &stage[..len]) else {
                    if sent == 0 {
                        return failed(SocketError::Shutdown);
                    }
                    break;
                };
                let written = written.min(len);
                sent += written;
                if written < len || sent == data.len() {
                    break;
                }
            }
            if sent == 0 && data.len() != 0 {
                return Err(BrokerError::WouldBlock);
            }
            Ok(SocketOutcome::Completed(sent))
        })
    }

    fn receive(&self, output: &mut dyn ReadBuffer) -> Result<SocketOutcome<PlatformStreamReceive>> {
        self.run(|state| {
            let Phase::Connected(connected) = &state.socket(self.id)?.phase else {
                return failed(SocketError::NotConnected);
            };
            let Some(connection) = connected.id.filter(|_| !connected.read_shut) else {
                return Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream));
            };
            if output.len() == 0 {
                return Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(0)));
            }
            let mut stage = [0; STAGE];
            let mut received = 0;
            let mut ended = false;
            while received < output.len() {
                let len = stage.len().min(output.len() - received);
                match state.device.read(connection, &mut stage[..len]) {
                    None => {
                        ended = true;
                        break;
                    }
                    Some(0) => break,
                    Some(read) => {
                        let read = read.min(len);
                        output.copy_from_slice_at(received, &stage[..read])?;
                        received += read;
                    }
                }
            }
            match received {
                0 if ended => Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream)),
                0 => Err(BrokerError::WouldBlock),
                received => Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                    received,
                ))),
            }
        })
    }

    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>> {
        self.run(|state| {
            let Phase::Connected(connected) = &mut state.socket(self.id)?.phase else {
                return failed(SocketError::NotConnected);
            };
            match mode {
                ShutdownMode::Read => connected.read_shut = true,
                ShutdownMode::Write => connected.write_shut = true,
                ShutdownMode::Both => (connected.read_shut, connected.write_shut) = (true, true),
                // The core rejects the others.
                _ => return Err(BrokerError::UnsupportedOperation),
            }
            if let Some(connection) = connected.id {
                match mode {
                    ShutdownMode::Read => state.device.shutdown_receiving(connection),
                    ShutdownMode::Write => state.device.shutdown_sending(connection),
                    _ => state.device.close(connection),
                }
            }
            Ok(SocketOutcome::Completed(()))
        })
    }

    fn local_address(&self) -> Option<VsockAddress> {
        self.run(|state| Ok(state.socket(self.id)?.local))
            .ok()
            .flatten()
    }

    fn peer_address(&self) -> Option<VsockAddress> {
        self.run(|state| {
            Ok(match &state.socket(self.id)?.phase {
                Phase::Connected(connected) if !connected.read_shut && !connected.write_shut => {
                    Some(VsockAddress {
                        cid: VMADDR_CID_HOST,
                        port: connected.peer_port,
                    })
                }
                _ => None,
            })
        })
        .ok()
        .flatten()
    }

    fn readiness(&self) -> ReadinessFlags {
        ReadinessFlags(self.snapshot.load(Ordering::Relaxed))
    }

    fn retire(&self) {
        let now = self.now();
        let mut state = self.shared.state.lock();
        // A lingering connection may be gone already, and its data left to
        // drop: the next poll forgets it. Forgetting a connect takes what the
        // device returned, as `run` sees after other operations.
        let lingers = state.retire(self.id, now);
        if lingers || self.shared.device.take_backlog() {
            self.shared.repoll.store(true, Ordering::SeqCst);
        }
    }
}

/// `duration` after `instant`; `None` past the clock's end: never. The
/// deadline then never expires, which only a clock near its end can see (the
/// VM's counts nanoseconds in a `u64`: centuries).
fn after<I: Instant>(instant: I, duration: Duration) -> Option<I> {
    instant.checked_add(duration)
}

#[cfg(test)]
mod tests;
