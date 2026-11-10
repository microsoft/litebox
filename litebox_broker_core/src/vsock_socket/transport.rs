// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [`VsockProvider`] over a [`VsockTransport`] of stream connections with
//! the host, e.g., the VM kernel's virtio-vsock device, or Unix sockets on
//! the host (hybrid vsock).
//!
//! [`VsockTransportProvider`] implements Linux's stream socket semantics
//! (ports and ephemeral binding, listener backlogs, the connect timeout,
//! pending errors, shutdowns, lingering closes, readiness); each socket's
//! connection is one of the transport's, and no data is buffered here.
//!
//! - The host's requests go to the listener on their guest port while its
//!   backlog has room, and are refused otherwise. A guest's connect fails if
//!   the host refuses it, the transport cannot hold it
//!   ([`VsockTransport::connect`]), or the host does not answer within
//!   [`CONNECT_TIMEOUT`].
//! - A closed connection is shut down both ways and kept until the transport
//!   reports it closed ([`VsockTransport::is_closed`]) or [`CLOSE_TIMEOUT`];
//!   a port its socket bound stays in use meanwhile, as on Linux.
//! - A transport reset (e.g., after a migration) ends live connections as
//!   the host's reset of each does: their data, then end of stream. Linux
//!   fails them with `ECONNRESET` instead; the transport can't tell the two
//!   apart.
//! - Trust: the host's traffic is untrusted input (for robustness; see
//!   [`super`]), so each poll answers at most
//!   `MAX_REQUESTS_PER_POLL` requests and drops at most
//!   `MAX_DISCARD_PER_POLL` unread bytes. Guests bind any port without a
//!   privilege check, so the host must not trust a source port.
//! - No thread of its own: the broker calls [`VsockTransportProvider::poll`]
//!   when the transport [interrupts](VsockTransport::interrupts) and by
//!   [`VsockTransportProvider::next_deadline`]. Readiness is recomputed after
//!   each operation and on each poll, and published under the provider's
//!   lock when it changes; a connect's outcome is always republished.
//! - Lock order: the provider's, then the transport's (each [`VsockTransport`]
//!   call). A caller that finds another polling does not wait for it.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::ops::Bound;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::time::Duration;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    ShutdownMode, SocketConnectionStatus, SocketError, SocketOutcome, SocketType,
};
use litebox_broker_protocol::vsock_socket::{VsockAddress, VsockCid, VsockPort};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::time::Instant;

use crate::readiness::ReadinessRegistration;
use crate::socket::PlatformStreamReceive;
use crate::vsock_socket::{AcceptedPlatformVsockSocket, PlatformVsockSocket, VsockProvider};
use crate::{BrokerError, Result};

/// A transport's connection, by its ends' ports, whichever end connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId {
    /// The guest's end's port.
    pub guest_port: VsockPort,
    /// The host's end's port.
    pub host_port: VsockPort,
}

/// What became of a guest's [`VsockTransport::connect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectState {
    /// The host has yet to answer.
    Connecting,
    /// The host accepted it; it is live, or gone since.
    Established,
    /// Refused, reset, unknown, or requested by the host (the guest's was
    /// forgotten).
    Failed,
}

/// What reads and writes on a connection would do now
/// ([`VsockTransport::status`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// TODO: report connections lost to a transport reset (here and in the HAL),
// so they fail with `ECONNRESET` and drop their data, as on Linux.
pub struct ConnectionStatus {
    /// Received data waits to be read.
    pub readable: bool,
    /// The host sends no more (shut down, gone, or unknown); received data
    /// stays readable.
    pub host_sending_ended: bool,
    /// A write takes data now, or fails: the connection takes no more.
    pub writable: bool,
}

impl ConnectionStatus {
    /// A connection the transport no longer has, or never had: a write fails
    /// rather than waits.
    pub const ENDED: Self = Self {
        readable: false,
        host_sending_ended: true,
        writable: true,
    };
}

/// A transport of stream connections between the guest and the host (CID
/// 2), e.g., a virtio-vsock device or the host's own sockets. An
/// implementation:
/// - holds what the host sent until it is read, within its own bound (the
///   host's traffic is untrusted);
/// - may refuse a guest's connect it cannot hold, and fail one the host does
///   not answer (the provider also times connects out);
/// - may end every connection at once (e.g., a transport reset): connects in
///   progress fail, live connections end as if the host reset them, and the
///   guest CID may change;
/// - keeps a closed connection until the host has its end, if it can, and
///   frees it only when forgotten;
/// - never calls back into the provider, which may hold its lock across a
///   call.
///
/// Only [`Self::take_request`], [`Self::connect_state`], [`Self::read`],
/// [`Self::write`], [`Self::is_closed`] and [`Self::forget`] take in what the
/// host sent, so a request just taken is still one when it is accepted.
pub trait VsockTransport: Send + Sync {
    /// The guest's CID, which may change when every connection ends.
    fn guest_cid(&self) -> u64;

    /// The next connection the host requested, to accept or refuse.
    fn take_request(&self) -> Option<ConnectionId>;

    /// Accepts a requested connection; false if it is not one.
    fn accept(&self, id: ConnectionId) -> bool;

    /// Refuses a requested connection.
    fn refuse(&self, id: ConnectionId);

    /// Asks the host for a connection; false if it is in use, or the
    /// transport holds too many.
    fn connect(&self, id: ConnectionId) -> bool;

    /// What became of a [`Self::connect`]; one that failed is forgotten.
    fn connect_state(&self, id: ConnectionId) -> ConnectState;

    /// Copies received data into `output`: how much, or `None` at the end of
    /// the stream.
    fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize>;

    /// Queues as much of `bytes` as the host takes now: how much, or `None`
    /// if the connection takes no more.
    fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize>;

    /// What reads and writes would do now.
    fn status(&self, id: ConnectionId) -> ConnectionStatus;

    /// Shuts down sending, after what was written, telling the host if the
    /// transport can (hybrid vsock cannot).
    fn shutdown_sending(&self, id: ConnectionId);

    /// Shuts down receiving, telling the host if the transport can (hybrid
    /// vsock cannot); the provider then drops whatever is received.
    fn shutdown_receiving(&self, id: ConnectionId);

    /// Shuts down both ways, after what was written; closed once the host
    /// has its end.
    fn close(&self, id: ConnectionId);

    /// Whether the connection is gone and its data read, or unknown.
    fn is_closed(&self, id: ConnectionId) -> bool;

    /// Ends the connection, resetting it unless gone, and frees its slot.
    fn forget(&self, id: ConnectionId);

    /// Takes whether calls since the last one took in, or left behind at a
    /// budget, something the transport will not wake the broker for again.
    fn take_backlog(&self) -> bool;

    /// Whether the transport wakes the broker as it changes, else is polled.
    fn interrupts(&self) -> bool;
}

/// How long the host has to answer a guest's connect, as Linux's
/// `VSOCK_DEFAULT_CONNECT_TIMEOUT`.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a closed connection waits for the host before it is reset, as
/// Linux's `VSOCK_CLOSE_TIMEOUT`.
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);

/// How often a transport that does not interrupt is polled.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How soon a poll that left work follows: not at once, as a due deadline
/// interrupts every running process.
const BUSY_INTERVAL: Duration = Duration::from_millis(1);

/// Host requests answered per poll.
const MAX_REQUESTS_PER_POLL: usize = 8;

/// Bytes dropped per poll from connections nothing reads.
const MAX_DISCARD_PER_POLL: usize = 64 * 1024;

/// Bytes staged on the stack per transport call, as a caller's buffer may fault.
const STAGE: usize = 4096;

/// Ports up to this one are not ephemeral, as Linux's `LAST_RESERVED_PORT`.
const LAST_RESERVED_PORT: u32 = 1023;

/// Ephemeral ports tried per bind, as Linux's `MAX_PORT_RETRIES`.
const MAX_EPHEMERAL_TRIES: usize = 24;

/// The broker's vsock stream sockets on a [`VsockTransport`], on a clock of
/// `I`.
pub struct VsockTransportProvider<I>(Arc<Shared<I>>);

struct Shared<I> {
    transport: Arc<dyn VsockTransport>,
    now: Box<dyn Fn() -> I + Send + Sync>,
    state: spin::Mutex<State<I>>,
    /// A poll is due: asked for and not started, or an operation left a
    /// transport backlog.
    repoll: AtomicBool,
}

struct State<I> {
    transport: Arc<dyn VsockTransport>,
    sockets: BTreeMap<u64, Socket>,
    next_socket: u64,
    /// Ports held by a bound socket or its lingering connection.
    ports: BTreeMap<VsockPort, Port>,
    connections: BTreeMap<ConnectionId, Holder<I>>,
    next_ephemeral: u32,
    /// The last poll left work.
    busy: bool,
    last_poll: Option<I>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Port {
    Socket(u64),
    Closing(ConnectionId),
}

/// Who holds a transport connection; a `None` deadline is never.
enum Holder<I> {
    /// A connected socket, or a listener's backlog.
    Socket,
    /// A connecting socket, until `deadline`.
    Connecting { deadline: Option<I> },
    /// A closed socket's, waiting for the host until `deadline`.
    Closing { deadline: Option<I> },
}

struct Socket {
    registration: ReadinessRegistration,
    /// The readiness last published, read without the lock.
    snapshot: Arc<AtomicU32>,
    /// As `getsockname` reports it; only a socket that bound it holds the
    /// port in [`State::ports`], not an accepted one.
    local: Option<VsockAddress>,
    phase: Phase,
    error: Option<SocketError>,
}

enum Phase {
    Unconnected,
    /// `backlog` holds connections the transport accepted, oldest first; one
    /// more than `max` may wait, as on Linux.
    Listening {
        backlog: VecDeque<ConnectionId>,
        max: usize,
    },
    Connecting(ConnectionId),
    Connected(Connected),
}

struct Connected {
    /// `None` once ended, its data read or dropped, and forgotten.
    id: Option<ConnectionId>,
    peer_port: VsockPort,
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
    fn readiness(&self, transport: &dyn VsockTransport) -> ReadinessFlags {
        let status = self
            .id
            .map_or(ConnectionStatus::ENDED, |id| transport.status(id));
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
    fn readiness(&self, transport: &dyn VsockTransport) -> ReadinessFlags {
        let flags = match &self.phase {
            Phase::Unconnected => ReadinessFlags::WRITE,
            Phase::Listening { backlog, .. } if !backlog.is_empty() => ReadinessFlags::READ,
            Phase::Listening { .. } | Phase::Connecting(_) => ReadinessFlags::default(),
            Phase::Connected(connected) => connected.readiness(transport),
        };
        if self.error.is_some() {
            flags | ReadinessFlags::ERROR
        } else {
            flags
        }
    }
}

impl<I: Instant> VsockTransportProvider<I> {
    /// Drives `transport` on the clock `now`; `seed` (e.g., from a CSPRNG)
    /// starts the ephemeral ports.
    pub fn new(
        transport: Arc<dyn VsockTransport>,
        now: Box<dyn Fn() -> I + Send + Sync>,
        seed: u64,
    ) -> Self {
        Self(Arc::new(Shared {
            transport: Arc::clone(&transport),
            now,
            state: spin::Mutex::new(State {
                transport,
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

    /// Answers the host's requests, settles connects and closed connections,
    /// and publishes readiness, within budgets; never waits for another poll.
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

    /// When the provider must next poll, if before the transport changes.
    ///
    /// Poll once before relying on it: a transport that does not interrupt
    /// gets its poll interval only from the last poll.
    pub fn next_deadline(&self) -> Option<I> {
        let soon = || after((self.0.now)(), BUSY_INTERVAL);
        if self.0.repoll.load(Ordering::SeqCst) {
            return soon();
        }
        // Another caller polls or operates, and then reports its deadline.
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
            .filter(|_| !self.0.transport.interrupts())
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

impl<I: Instant + 'static> VsockProvider for VsockTransportProvider<I> {
    fn create(
        &self,
        socket_type: SocketType,
        readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformVsockSocket>> {
        if socket_type != SocketType::Stream {
            return Err(BrokerError::UnsupportedOperation);
        }
        let mut state = self.0.state.lock();
        let (id, snapshot) = state.insert(readiness, None, Phase::Unconnected);
        Ok(Arc::new(TransportSocket {
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

    fn guest_cid(&self) -> Option<VsockCid> {
        u32::try_from(self.transport.guest_cid())
            .ok()
            .map(VsockCid)
            .filter(|&cid| cid != VsockCid::ANY)
    }

    /// Publishes socket `id`'s readiness if it changed or `republish`.
    fn publish(&self, id: u64, republish: bool) {
        let Some(socket) = self.sockets.get(&id) else {
            return;
        };
        let flags = socket.readiness(&*self.transport);
        if socket.snapshot.swap(flags.0, Ordering::Relaxed) != flags.0 {
            socket.registration.publish(flags);
        } else if republish {
            socket.registration.republish(flags);
        }
    }

    /// An unused port from [`Self::next_ephemeral`] on, as Linux's
    /// `__vsock_bind_connectible`; `None` after [`MAX_EPHEMERAL_TRIES`].
    fn ephemeral_port(&mut self) -> Option<VsockPort> {
        for _ in 0..MAX_EPHEMERAL_TRIES {
            if self.next_ephemeral == VsockPort::ANY.0 || self.next_ephemeral <= LAST_RESERVED_PORT
            {
                self.next_ephemeral = LAST_RESERVED_PORT + 1;
            }
            let port = VsockPort(self.next_ephemeral);
            self.next_ephemeral += 1;
            if !self.ports.contains_key(&port) {
                return Some(port);
            }
        }
        None
    }

    /// Settles socket `id`'s connect if the host answered or it timed out.
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
        let error = match self.transport.connect_state(connection) {
            ConnectState::Established => None,
            ConnectState::Failed => Some(SocketError::ConnectionReset),
            ConnectState::Connecting if due => Some(SocketError::TimedOut),
            ConnectState::Connecting => return,
        };
        if let Some(error) = error {
            self.transport.forget(connection);
            self.connections.remove(&connection);
            socket.phase = Phase::Unconnected;
            socket.error = Some(error);
        } else {
            self.connections.insert(connection, Holder::Socket);
            socket.phase = Phase::Connected(Connected::new(connection));
        }
        self.publish(id, true);
    }

    /// Forgets a transport connection, freeing any port it kept in use.
    fn forget(&mut self, connection: ConnectionId) {
        self.transport.forget(connection);
        self.connections.remove(&connection);
        if self.ports.get(&connection.guest_port) == Some(&Port::Closing(connection)) {
            self.ports.remove(&connection.guest_port);
        }
    }

    /// Queues the host's request on its listener, or refuses it.
    fn dispatch(&mut self, connection: ConnectionId) {
        // E.g., a guest's connect the host refused, then requested with the
        // same ports, before the connect was settled.
        if self.connections.contains_key(&connection) {
            self.transport.refuse(connection);
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
            self.transport.refuse(connection);
            return;
        };
        // The transport takes nothing new before `accept`: still a request,
        // unless the host gave up on it, which leaves nothing to do.
        if self.transport.accept(connection) {
            backlog.push_back(connection);
            self.connections.insert(connection, Holder::Socket);
            self.publish(listener, false);
        }
    }

    /// Drops up to `budget` bytes the host sent on `connection`.
    fn discard(&self, connection: ConnectionId, budget: &mut usize) {
        let mut scratch = [0; STAGE];
        while *budget > 0 {
            let len = scratch.len().min(*budget);
            match self.transport.read(connection, &mut scratch[..len]) {
                Some(read) if read != 0 => *budget -= read.min(len),
                _ => break,
            }
        }
    }

    fn poll(&mut self, now: I) {
        self.last_poll = Some(now);
        let mut requests = 0;
        while requests < MAX_REQUESTS_PER_POLL
            && let Some(connection) = self.transport.take_request()
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
            if deadline.is_some_and(|deadline| now >= deadline)
                || self.transport.is_closed(connection)
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
                // Ended and read: the socket reads end of stream without it.
                if self.transport.is_closed(connection) {
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
        let backlog = self.transport.take_backlog();
        self.busy = requests == MAX_REQUESTS_PER_POLL || budget == 0 || backlog;
    }

    /// Ends socket `id` as Linux's close (see the module docs), returning
    /// whether a connection lingers; a listener's port is freed at once.
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
                    self.transport.close(connection);
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
                self.transport.close(connection);
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

/// A [`VsockTransportProvider`] socket; once retired, its operations fail.
struct TransportSocket<I> {
    id: u64,
    shared: Arc<Shared<I>>,
    snapshot: Arc<AtomicU32>,
}

#[expect(clippy::unnecessary_wraps, reason = "for operations' early returns")]
fn failed<T>(error: SocketError) -> Result<SocketOutcome<T>> {
    Ok(SocketOutcome::Failed(error))
}

impl<I: Instant> TransportSocket<I> {
    /// Runs `f` for the live socket, then publishes its readiness; a
    /// transport backlog makes a poll due.
    fn run<R>(&self, f: impl FnOnce(&mut State<I>) -> Result<R>) -> Result<R> {
        let mut state = self.shared.state.lock();
        if !state.sockets.contains_key(&self.id) {
            return Err(BrokerError::Internal);
        }
        let result = f(&mut state);
        state.publish(self.id, false);
        drop(state);
        if self.shared.transport.take_backlog() {
            self.shared.repoll.store(true, Ordering::SeqCst);
        }
        result
    }

    fn now(&self) -> I {
        (self.shared.now)()
    }

    /// The connect outcome, as [`PlatformVsockSocket::check_connect`].
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

impl<I: Instant + 'static> PlatformVsockSocket for TransportSocket<I> {
    fn bind(&self, address: VsockAddress) -> Result<SocketOutcome<()>> {
        self.run(|state| {
            let guest_cid = state.guest_cid();
            if state.socket(self.id)?.local.is_some() {
                return failed(SocketError::InvalidArgument);
            }
            if address.cid != VsockCid::ANY && Some(address.cid) != guest_cid {
                return failed(SocketError::AddressNotAvailable);
            }
            let port = if address.port == VsockPort::ANY {
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
            let cid = state.guest_cid().unwrap_or(VsockCid::ANY);
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
                socket: Arc::new(TransportSocket {
                    id,
                    shared: Arc::clone(&self.shared),
                    snapshot,
                }),
                remote_address: VsockAddress {
                    cid: VsockCid::HOST,
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
            if address.cid != VsockCid::HOST {
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
                    cid: VsockCid::ANY,
                    port,
                });
                port
            };
            let connection = ConnectionId {
                guest_port: port,
                host_port: address.port,
            };
            if state.connections.contains_key(&connection) || !state.transport.connect(connection) {
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
                let Some(written) = state.transport.write(connection, &stage[..len]) else {
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
                // The end of the stream once nothing is left, as a nonempty receive
                // would report, so an empty one probes without taking data.
                let status = state.transport.status(connection);
                return Ok(SocketOutcome::Completed(
                    if status.host_sending_ended && !status.readable {
                        PlatformStreamReceive::EndOfStream
                    } else {
                        PlatformStreamReceive::Received(0)
                    },
                ));
            }
            let mut stage = [0; STAGE];
            let mut received = 0;
            let mut ended = false;
            while received < output.len() {
                let len = stage.len().min(output.len() - received);
                match state.transport.read(connection, &mut stage[..len]) {
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
                    ShutdownMode::Read => state.transport.shutdown_receiving(connection),
                    ShutdownMode::Write => state.transport.shutdown_sending(connection),
                    _ => state.transport.close(connection),
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
                        cid: VsockCid::HOST,
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
        // The next poll forgets a lingering connection; forgetting a connect
        // may leave a transport backlog, as after `run`.
        let lingers = state.retire(self.id, now);
        if lingers || self.shared.transport.take_backlog() {
            self.shared.repoll.store(true, Ordering::SeqCst);
        }
    }
}

/// `duration` after `instant`, or `None` (never) past the clock's end, which
/// a `u64` nanosecond clock reaches only after centuries.
fn after<I: Instant>(instant: I, duration: Duration) -> Option<I> {
    instant.checked_add(duration)
}

#[cfg(test)]
mod tests {
    //! The provider through the broker core, as runner processes use it, on a
    //! transport the test plays: the host behind it.

    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicU64;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::fs::FileOpenFlags;
    use litebox_broker_protocol::socket::SendFlags;
    use litebox_broker_protocol::vsock_socket::CreateVsockSocketRequest;

    use crate::readiness::ReadinessSink;
    use crate::test_support::TestBrokerBuilder;
    use crate::vsock_socket::{self as core_vsock, AcceptedBrokerVsockSocket};
    use crate::{BrokerProcess, CallerCredential, ObjectRights, PolicyEngine, VsockPolicy};

    const GUEST_CID: VsockCid = VsockCid(7);
    /// The first ephemeral port.
    const SEED: u32 = 50_000;
    const PORT: u32 = 1024;
    /// The guest's connects the transport holds at once, as the VM's.
    const MAX_USER_CONNECTIONS: usize = 16;

    const READ: ReadinessFlags = ReadinessFlags::READ;
    const WRITE: ReadinessFlags = ReadinessFlags::WRITE;
    const HANGUP: ReadinessFlags = ReadinessFlags::HANGUP;
    const ERROR: ReadinessFlags = ReadinessFlags::ERROR;
    const CLOSED: ReadinessFlags = ReadinessFlags::CLOSED;
    const NONE: ReadinessFlags = ReadinessFlags(0);

    const fn id(guest_port: u32, host_port: u32) -> ConnectionId {
        ConnectionId {
            guest_port: VsockPort(guest_port),
            host_port: VsockPort(host_port),
        }
    }

    /// A connection to [`PORT`].
    const fn on(host_port: u32) -> ConnectionId {
        id(PORT, host_port)
    }

    /// The host's end of a connection, and the transport's state of it.
    #[derive(Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "independent ends of a connection, set by the tests"
    )]
    struct HostConnection {
        by_guest: bool,
        /// The guest asked for it, and the host has yet to answer.
        connecting: bool,
        live: bool,
        /// Reset by either end, or lost to a transport reset.
        gone: bool,
        /// Sent by the host, not yet read.
        sent: VecDeque<u8>,
        /// The host sends no more.
        sent_all: bool,
        /// The host receives no more.
        receives_no_more: bool,
        received: Vec<u8>,
        /// How much more the host takes.
        credit: usize,
        shut_down_sending: bool,
        shut_down_receiving: bool,
    }

    impl HostConnection {
        fn takes_no_more(&self) -> bool {
            !self.live || self.gone || self.receives_no_more || self.shut_down_sending
        }
    }

    #[derive(Default)]
    struct HostState {
        guest_cid: u64,
        requests: VecDeque<ConnectionId>,
        connections: BTreeMap<ConnectionId, HostConnection>,
        refused: Vec<ConnectionId>,
        /// Forgotten, and whether they were reset then (not gone).
        forgotten: Vec<(ConnectionId, bool)>,
        asked: Vec<ConnectionId>,
        backlog: bool,
    }

    /// The test's clock: nanoseconds since its start.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct TestInstant(u64);

    impl Instant for TestInstant {
        fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
            self.0.checked_sub(earlier.0).map(Duration::from_nanos)
        }

        fn checked_add(&self, duration: Duration) -> Option<Self> {
            let nanos = u64::try_from(duration.as_nanos()).ok()?;
            self.0.checked_add(nanos).map(Self)
        }

        fn saturating_add(&self, duration: Duration) -> Self {
            self.checked_add(duration).unwrap_or(Self(u64::MAX))
        }
    }

    /// The host, behind a transport that takes what it is given at once.
    struct Host(spin::Mutex<HostState>);

    impl Host {
        fn new() -> Arc<Self> {
            Arc::new(Self(spin::Mutex::new(HostState {
                guest_cid: GUEST_CID.0.into(),
                ..HostState::default()
            })))
        }

        /// The host requests connection `id`.
        fn connect(&self, id: ConnectionId) {
            let mut state = self.0.lock();
            state.requests.push_back(id);
            state.connections.insert(
                id,
                HostConnection {
                    credit: usize::MAX,
                    ..HostConnection::default()
                },
            );
        }

        /// A transport reset.
        fn reset_all(&self) {
            let mut state = self.0.lock();
            let requests: Vec<_> = state.requests.drain(..).collect();
            for id in requests {
                state.connections.remove(&id);
            }
            state
                .connections
                .retain(|_, connection| !connection.connecting);
            for connection in state.connections.values_mut() {
                connection.gone = true;
            }
        }

        /// The host answers a connection the guest asked for.
        fn answer(&self, id: ConnectionId) {
            self.with(id, |connection| {
                connection.connecting = false;
                connection.live = true;
            });
        }

        /// The host refuses a connection the guest asked for.
        fn refuse_connect(&self, id: ConnectionId) {
            self.0.lock().connections.remove(&id);
        }

        fn with<T>(&self, id: ConnectionId, f: impl FnOnce(&mut HostConnection) -> T) -> T {
            f(self.0.lock().connections.get_mut(&id).unwrap())
        }

        /// The host sends `bytes`; the transport drops them once the guest
        /// shut down receiving.
        fn send(&self, id: ConnectionId, bytes: &[u8]) {
            self.with(id, |connection| {
                if !connection.shut_down_receiving {
                    connection.sent.extend(bytes);
                }
            });
        }

        fn take_received(&self, id: ConnectionId) -> Vec<u8> {
            self.with(id, |connection| core::mem::take(&mut connection.received))
        }

        fn take_forgotten(&self) -> Vec<(ConnectionId, bool)> {
            core::mem::take(&mut self.0.lock().forgotten)
        }

        fn take_refused(&self) -> Vec<ConnectionId> {
            core::mem::take(&mut self.0.lock().refused)
        }

        fn asked(&self) -> Vec<ConnectionId> {
            self.0.lock().asked.clone()
        }
    }

    impl VsockTransport for Host {
        fn guest_cid(&self) -> u64 {
            self.0.lock().guest_cid
        }

        fn take_request(&self) -> Option<ConnectionId> {
            self.0.lock().requests.pop_front()
        }

        fn accept(&self, id: ConnectionId) -> bool {
            self.with(id, |connection| {
                connection.live = !connection.gone;
                connection.live
            })
        }

        fn refuse(&self, id: ConnectionId) {
            let mut state = self.0.lock();
            state.connections.remove(&id);
            state.refused.push(id);
        }

        fn connect(&self, id: ConnectionId) -> bool {
            let mut state = self.0.lock();
            let by_guest = state
                .connections
                .values()
                .filter(|connection| connection.by_guest)
                .count();
            if by_guest >= MAX_USER_CONNECTIONS || state.connections.contains_key(&id) {
                return false;
            }
            state.asked.push(id);
            state.connections.insert(
                id,
                HostConnection {
                    by_guest: true,
                    connecting: true,
                    credit: usize::MAX,
                    ..HostConnection::default()
                },
            );
            true
        }

        fn connect_state(&self, id: ConnectionId) -> ConnectState {
            match self.0.lock().connections.get(&id) {
                Some(connection) if connection.by_guest && connection.connecting => {
                    ConnectState::Connecting
                }
                Some(connection) if connection.by_guest && connection.live => {
                    ConnectState::Established
                }
                _ => ConnectState::Failed,
            }
        }

        fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
            let mut state = self.0.lock();
            let connection = state.connections.get_mut(&id)?;
            if connection.sent.is_empty() {
                let ended =
                    connection.gone || connection.sent_all || connection.shut_down_receiving;
                return (!ended).then_some(0);
            }
            let len = output.len().min(connection.sent.len());
            for (byte, sent) in output.iter_mut().zip(connection.sent.drain(..len)) {
                *byte = sent;
            }
            Some(len)
        }

        fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
            let mut state = self.0.lock();
            let connection = state.connections.get_mut(&id)?;
            if connection.takes_no_more() {
                return None;
            }
            let len = bytes.len().min(connection.credit);
            connection.received.extend_from_slice(&bytes[..len]);
            connection.credit -= len;
            Some(len)
        }

        fn status(&self, id: ConnectionId) -> ConnectionStatus {
            match self.0.lock().connections.get(&id) {
                None => ConnectionStatus::ENDED,
                Some(connection) => ConnectionStatus {
                    readable: !connection.sent.is_empty(),
                    host_sending_ended: connection.gone || connection.sent_all,
                    writable: connection.takes_no_more() || connection.credit > 0,
                },
            }
        }

        fn shutdown_sending(&self, id: ConnectionId) {
            self.with(id, |connection| connection.shut_down_sending = true);
        }

        fn shutdown_receiving(&self, id: ConnectionId) {
            self.with(id, |connection| connection.shut_down_receiving = true);
        }

        fn close(&self, id: ConnectionId) {
            self.with(id, |connection| {
                connection.shut_down_sending = true;
                connection.shut_down_receiving = true;
            });
        }

        fn is_closed(&self, id: ConnectionId) -> bool {
            self.0
                .lock()
                .connections
                .get(&id)
                .is_none_or(|connection| connection.gone && connection.sent.is_empty())
        }

        fn forget(&self, id: ConnectionId) {
            let mut state = self.0.lock();
            let gone = state
                .connections
                .remove(&id)
                .is_none_or(|connection| connection.gone);
            state.forgotten.push((id, !gone));
        }

        fn take_backlog(&self) -> bool {
            core::mem::take(&mut self.0.lock().backlog)
        }

        fn interrupts(&self) -> bool {
            true
        }
    }

    /// Every readiness publication, by handle.
    #[derive(Default)]
    struct Sink(spin::Mutex<Vec<(ObjectHandle, ReadinessFlags)>>);

    impl ReadinessSink for Sink {
        fn max_tracked_objects(&self) -> usize {
            usize::MAX
        }

        fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
            self.0.lock().push((handle, readiness));
            Ok(())
        }

        fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
            self.publish(handle, readiness)
        }

        fn retire(&self, _handle: ObjectHandle) {}
    }

    /// The provider in a broker core, its transport's host, and a guest process.
    struct Fixture {
        provider: Arc<VsockTransportProvider<TestInstant>>,
        host: Arc<Host>,
        guest: Arc<BrokerProcess>,
        sink: Arc<Sink>,
        clock: Arc<AtomicU64>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_seed(SEED.into())
        }

        fn with_seed(seed: u64) -> Self {
            let host = Host::new();
            let clock = Arc::new(AtomicU64::new(1));
            let now = Arc::clone(&clock);
            let provider = Arc::new(VsockTransportProvider::new(
                host.clone(),
                Box::new(move || TestInstant(now.load(Ordering::SeqCst))),
                seed,
            ));
            let core = TestBrokerBuilder::new(
                PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
                    .with_vsock_policy(VsockPolicy::any()),
            )
            .with_vsock_provider(provider.clone())
            .build()
            .unwrap();
            let guest = core
                .create_process(CallerCredential::HostGuaranteed)
                .unwrap();
            Self {
                provider,
                host,
                guest,
                sink: Arc::default(),
                clock,
            }
        }

        fn now(&self) -> TestInstant {
            TestInstant(self.clock.load(Ordering::SeqCst))
        }

        fn advance(&self, duration: Duration) {
            let nanos = u64::try_from(duration.as_nanos()).unwrap();
            self.clock.fetch_add(nanos, Ordering::SeqCst);
        }

        fn poll(&self) {
            self.provider.poll();
        }

        fn socket(&self) -> ObjectHandle {
            let request = CreateVsockSocketRequest {
                socket_type: SocketType::Stream,
                flags: FileOpenFlags::NONBLOCKING,
            };
            core_vsock::create(&self.guest, request, self.sink.clone()).unwrap()
        }

        fn bind(&self, socket: ObjectHandle, cid: VsockCid, port: u32) -> SocketOutcome<()> {
            let port = VsockPort(port);
            core_vsock::bind(&self.guest, socket, VsockAddress { cid, port }).unwrap()
        }

        fn listen(&self, port: u32, backlog: u32) -> ObjectHandle {
            let listener = self.socket();
            assert_eq!(
                self.bind(listener, VsockCid::ANY, port),
                SocketOutcome::Completed(())
            );
            assert_eq!(
                core_vsock::listen(&self.guest, listener, backlog).unwrap(),
                SocketOutcome::Completed(())
            );
            listener
        }

        fn accept(&self, listener: ObjectHandle) -> Result<AcceptedBrokerVsockSocket> {
            core_vsock::accept(
                &self.guest,
                listener,
                FileOpenFlags::NONBLOCKING,
                self.sink.clone(),
            )
            .map(|accepted| match accepted {
                SocketOutcome::Completed(accepted) => accepted,
                SocketOutcome::Failed(error) => panic!("accept: {error:?}"),
            })
        }

        /// A socket the host connected to `listener` from `host_port`, accepted.
        fn accepted(&self, listener: ObjectHandle, host_port: u32) -> ObjectHandle {
            self.host.connect(on(host_port));
            self.poll();
            self.accept(listener).unwrap().handle
        }

        fn connect(
            &self,
            socket: ObjectHandle,
            port: u32,
        ) -> SocketOutcome<SocketConnectionStatus> {
            let address = VsockAddress {
                cid: VsockCid::HOST,
                port: VsockPort(port),
            };
            core_vsock::connect(&self.guest, socket, address).unwrap()
        }

        /// A socket connected to the host's `port`, from the returned connection.
        fn connected(&self, port: u32) -> (ObjectHandle, ConnectionId) {
            let socket = self.socket();
            assert_eq!(
                self.connect(socket, port),
                SocketOutcome::Completed(SocketConnectionStatus::Connecting)
            );
            let connection = id(self.local(socket).unwrap().port.0, port);
            self.host.answer(connection);
            self.poll();
            (socket, connection)
        }

        fn check_connect(&self, socket: ObjectHandle) -> SocketOutcome<SocketConnectionStatus> {
            core_vsock::check_connect(&self.guest, socket).unwrap()
        }

        fn cancel_connect(&self, socket: ObjectHandle) -> SocketOutcome<()> {
            core_vsock::cancel_connect(&self.guest, socket).unwrap()
        }

        fn take_error(&self, socket: ObjectHandle) -> Option<SocketError> {
            core_vsock::take_error(&self.guest, socket).unwrap()
        }

        fn send(&self, socket: ObjectHandle, bytes: &[u8]) -> Result<SocketOutcome<usize>> {
            core_vsock::send(&self.guest, socket, &bytes, SendFlags::NONE)
        }

        /// Receives up to `len` bytes: `None` at the end of the stream.
        fn receive(
            &self,
            socket: ObjectHandle,
            len: usize,
        ) -> Result<SocketOutcome<Option<Vec<u8>>>> {
            let mut buffer = vec![0; len];
            Ok(
                match core_vsock::receive(&self.guest, socket, &mut buffer)? {
                    SocketOutcome::Completed(PlatformStreamReceive::Received(received)) => {
                        buffer.truncate(received);
                        SocketOutcome::Completed(Some(buffer))
                    }
                    SocketOutcome::Completed(PlatformStreamReceive::EndOfStream) => {
                        SocketOutcome::Completed(None)
                    }
                    SocketOutcome::Failed(error) => SocketOutcome::Failed(error),
                },
            )
        }

        fn received(&self, socket: ObjectHandle, len: usize) -> Option<Vec<u8>> {
            match self.receive(socket, len).unwrap() {
                SocketOutcome::Completed(received) => received,
                SocketOutcome::Failed(error) => panic!("receive: {error:?}"),
            }
        }

        fn shutdown(&self, socket: ObjectHandle, mode: ShutdownMode) -> SocketOutcome<()> {
            core_vsock::shutdown(&self.guest, socket, mode).unwrap()
        }

        fn local(&self, socket: ObjectHandle) -> Option<VsockAddress> {
            core_vsock::get_name(&self.guest, socket, false).unwrap()
        }

        fn peer(&self, socket: ObjectHandle) -> Option<VsockAddress> {
            core_vsock::get_name(&self.guest, socket, true).unwrap()
        }

        fn readiness(&self, socket: ObjectHandle) -> ReadinessFlags {
            self.guest.check_readiness(socket).unwrap()
        }

        /// Takes the readiness published for `socket`.
        fn published(&self, socket: ObjectHandle) -> Vec<ReadinessFlags> {
            let mut published = self.sink.0.lock();
            let (taken, kept) = published
                .drain(..)
                .partition(|(handle, _)| *handle == socket);
            *published = kept;
            taken.into_iter().map(|(_, flags)| flags).collect()
        }

        fn close(&self, socket: ObjectHandle) {
            self.guest.close_object_reference(socket).unwrap();
        }
    }

    fn host(port: u32) -> VsockAddress {
        VsockAddress {
            cid: VsockCid::HOST,
            port: VsockPort(port),
        }
    }

    #[test]
    fn requests_go_to_listeners_with_room_and_are_refused_otherwise() {
        let f = Fixture::new();
        // One more than the backlog waits, as on Linux.
        let listener = f.listen(PORT, 1);
        let bound = f.socket();
        assert_eq!(
            f.bind(bound, VsockCid::ANY, PORT + 1),
            SocketOutcome::Completed(())
        );
        assert_eq!(f.published(listener), [WRITE, NONE]);
        for request in [id(PORT + 1, 1), id(PORT + 2, 2), on(3), on(4), on(5)] {
            f.host.connect(request);
        }
        f.poll();
        assert_eq!(
            f.host.take_refused(),
            [id(PORT + 1, 1), id(PORT + 2, 2), on(5)]
        );
        assert!(f.host.with(on(3), |connection| connection.live));
        assert_eq!(f.published(listener), [READ]);
        let accepted = f.accept(listener).unwrap();
        assert_eq!(accepted.remote_address, host(3));
        assert_eq!(
            f.local(accepted.handle),
            Some(VsockAddress {
                cid: GUEST_CID,
                port: VsockPort(PORT)
            })
        );
        assert_eq!(f.peer(accepted.handle), Some(host(3)));
        assert_eq!(f.published(accepted.handle), [WRITE]);
        assert_eq!(f.readiness(listener), READ);
        assert_eq!(f.accept(listener).unwrap().remote_address, host(4));
        assert_eq!(f.published(listener), [NONE]);
        assert_eq!(
            f.accept(listener).err(),
            Some(BrokerError::NonBlockingWouldBlock)
        );
        // Room again; a listener that listens again keeps its backlog.
        f.host.connect(on(6));
        f.host.connect(on(7));
        f.poll();
        assert_eq!(
            core_vsock::listen(&f.guest, listener, 0).unwrap(),
            SocketOutcome::Completed(())
        );
        f.host.connect(on(8));
        f.poll();
        assert_eq!(f.host.take_refused(), [on(8)]);
        assert_eq!(f.accept(listener).unwrap().remote_address, host(6));
        assert_eq!(f.accept(listener).unwrap().remote_address, host(7));
    }

    #[test]
    fn requests_are_answered_a_few_per_poll() {
        let f = Fixture::new();
        for host_port in 0..20 {
            f.host.connect(on(host_port));
        }
        f.poll();
        assert_eq!(f.host.take_refused().len(), MAX_REQUESTS_PER_POLL);
        assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
        f.poll();
        f.poll();
        assert_eq!(f.host.take_refused().len(), 20 - MAX_REQUESTS_PER_POLL);
        f.poll();
        assert_eq!(f.provider.next_deadline(), None);
        // An operation that left the transport with a backlog has a poll due.
        let socket = f.socket();
        f.host.0.lock().backlog = true;
        assert_eq!(
            f.bind(socket, VsockCid::ANY, PORT),
            SocketOutcome::Completed(())
        );
        assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
        f.poll();
        assert_eq!(f.provider.next_deadline(), None);
        // So has closing a connecting socket, whose connect the transport forgets.
        let connecting = f.socket();
        assert_eq!(
            f.connect(connecting, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        f.host.0.lock().backlog = true;
        f.close(connecting);
        assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
        f.poll();
        assert_eq!(f.provider.next_deadline(), None);
    }

    #[test]
    fn data_moves_straight_to_and_from_the_transport_with_backpressure() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let socket = f.accepted(listener, 7);
        assert_eq!(f.published(socket), [WRITE]);
        assert_eq!(
            f.receive(socket, 16).err(),
            Some(BrokerError::NonBlockingWouldBlock)
        );
        f.host.send(on(7), b"ping");
        f.poll();
        assert_eq!(f.published(socket), [READ | WRITE]);
        assert_eq!(f.received(socket, 2), Some(b"pi".to_vec()));
        assert_eq!(f.published(socket), []);
        assert_eq!(f.received(socket, 16), Some(b"ng".to_vec()));
        assert_eq!(f.published(socket), [WRITE]);
        // More than a staging chunk each way.
        let bulk: Vec<u8> = (0..3 * STAGE + 5)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        f.host.send(on(7), &bulk);
        assert_eq!(f.received(socket, bulk.len() + 1), Some(bulk.clone()));
        assert_eq!(
            f.send(socket, &bulk),
            Ok(SocketOutcome::Completed(bulk.len()))
        );
        assert_eq!(f.host.take_received(on(7)), bulk);
        // The host's credit runs out: a partial send, then none, until it gives
        // more.
        f.host.with(on(7), |connection| connection.credit = 5);
        assert_eq!(
            f.send(socket, b"pong pong"),
            Ok(SocketOutcome::Completed(5))
        );
        assert_eq!(f.published(socket), [NONE]);
        assert_eq!(
            f.send(socket, b"pong"),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        f.poll();
        assert_eq!(f.published(socket), []);
        f.host.with(on(7), |connection| connection.credit = 100);
        f.poll();
        assert_eq!(f.published(socket), [WRITE]);
        assert_eq!(f.send(socket, b"pong"), Ok(SocketOutcome::Completed(4)));
        assert_eq!(f.host.take_received(on(7)), b"pong pong");
        // Empty transfers check the state only.
        assert_eq!(f.send(socket, b""), Ok(SocketOutcome::Completed(0)));
        assert_eq!(
            f.receive(socket, 0),
            Ok(SocketOutcome::Completed(Some(Vec::new())))
        );
        let unconnected = f.socket();
        assert_eq!(
            f.send(unconnected, b""),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            f.receive(unconnected, 0),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
    }

    #[test]
    fn the_hosts_shutdowns_end_each_direction() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let socket = f.accepted(listener, 7);
        // The host sends no more: its data is read first.
        f.host.send(on(7), b"bye");
        f.host.with(on(7), |connection| connection.sent_all = true);
        f.poll();
        assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
        // An empty receive takes nothing, and tells waiting data from the end.
        assert_eq!(f.received(socket, 0), Some(Vec::new()));
        assert_eq!(f.received(socket, 16), Some(b"bye".to_vec()));
        assert_eq!(f.received(socket, 0), None);
        assert_eq!(f.received(socket, 16), None);
        // The guest still sends until it shuts down sending too.
        assert_eq!(f.send(socket, b"ok"), Ok(SocketOutcome::Completed(2)));
        assert_eq!(
            f.shutdown(socket, ShutdownMode::Write),
            SocketOutcome::Completed(())
        );
        assert!(
            f.host
                .with(on(7), |connection| connection.shut_down_sending)
        );
        assert_eq!(f.readiness(socket), READ | HANGUP | CLOSED);
        assert_eq!(
            f.send(socket, b"more"),
            Ok(SocketOutcome::Failed(SocketError::Shutdown))
        );
        // The host receives no more: sends fail, rather than wait.
        let socket = f.accepted(listener, 8);
        f.host.with(on(8), |connection| {
            connection.receives_no_more = true;
            connection.credit = 0;
        });
        f.poll();
        assert_eq!(f.readiness(socket), WRITE);
        assert_eq!(
            f.send(socket, b"x"),
            Ok(SocketOutcome::Failed(SocketError::Shutdown))
        );
        // Its reset ends the stream after its data; then the transport forgets it.
        f.host.send(on(8), b"last");
        f.host.with(on(8), |connection| connection.gone = true);
        f.poll();
        assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
        assert_eq!(f.host.take_forgotten(), []);
        assert_eq!(f.received(socket, 16), Some(b"last".to_vec()));
        f.poll();
        assert_eq!(f.host.take_forgotten(), [(on(8), false)]);
        assert_eq!(f.received(socket, 16), None);
        assert_eq!(
            f.send(socket, b"x"),
            Ok(SocketOutcome::Failed(SocketError::Shutdown))
        );
        assert_eq!(f.peer(socket), Some(host(8)));
        assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
    }

    #[test]
    fn the_guests_shutdowns_end_each_direction() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        // Shutting down receiving drops what is queued and what comes.
        let socket = f.accepted(listener, 7);
        f.host.send(on(7), b"queued");
        assert_eq!(
            f.shutdown(socket, ShutdownMode::Read),
            SocketOutcome::Completed(())
        );
        assert!(
            f.host
                .with(on(7), |connection| connection.shut_down_receiving)
        );
        assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
        assert_eq!(f.received(socket, 16), None);
        f.poll();
        assert!(f.host.with(on(7), |connection| connection.sent.is_empty()));
        assert_eq!(f.send(socket, b"reply"), Ok(SocketOutcome::Completed(5)));
        assert_eq!(f.host.take_received(on(7)), b"reply");
        // A shut-down socket has no peer, and does not connect, as on Linux.
        assert_eq!(f.peer(socket), None);
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Failed(SocketError::InvalidArgument)
        );
        // Both ways: the host is told at once.
        let socket = f.accepted(listener, 8);
        assert_eq!(
            f.shutdown(socket, ShutdownMode::Both),
            SocketOutcome::Completed(())
        );
        f.host.with(on(8), |connection| {
            assert!(connection.shut_down_sending && connection.shut_down_receiving);
        });
        assert_eq!(f.readiness(socket), READ | HANGUP | CLOSED);
        // Only connected sockets shut down.
        for socket in [f.socket(), listener] {
            assert_eq!(
                f.shutdown(socket, ShutdownMode::Both),
                SocketOutcome::Failed(SocketError::NotConnected)
            );
        }
    }

    #[test]
    fn closed_connections_linger_until_the_host_resets_them() {
        let f = Fixture::new();
        let (socket, connection) = f.connected(5000);
        f.host.with(connection, |connection| connection.credit = 0);
        assert_eq!(
            f.send(socket, b"reply"),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        f.close(socket);
        f.host.with(connection, |connection| {
            assert!(connection.shut_down_sending && connection.shut_down_receiving);
        });
        // Its port stays in use meanwhile.
        let other = f.socket();
        assert_eq!(
            f.bind(other, VsockCid::ANY, connection.guest_port.0),
            SocketOutcome::Failed(SocketError::AddressInUse)
        );
        f.poll();
        assert_eq!(f.provider.next_deadline(), after(f.now(), CLOSE_TIMEOUT));
        // What the host sent before it knew is dropped.
        f.host.with(connection, |connection| {
            connection.sent.extend(b"late");
            connection.gone = true;
        });
        f.poll();
        assert_eq!(f.host.take_forgotten(), [(connection, false)]);
        assert_eq!(f.provider.next_deadline(), None);
        assert_eq!(
            f.bind(other, VsockCid::ANY, connection.guest_port.0),
            SocketOutcome::Completed(())
        );
    }

    #[test]
    fn closed_accepted_connections_leave_the_port_to_the_listener() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let socket = f.accepted(listener, 7);
        f.close(socket);
        f.host.connect(on(8));
        f.poll();
        assert_eq!(f.accept(listener).unwrap().remote_address, host(8));
        f.close(listener);
        // Free, although the connection still lingers on it.
        let listener = f.listen(PORT, 4);
        assert!(
            f.host
                .with(on(7), |connection| connection.shut_down_sending)
        );
        assert_eq!(f.host.take_forgotten(), []);
        f.host.connect(on(9));
        f.poll();
        assert_eq!(f.accept(listener).unwrap().remote_address, host(9));
    }

    #[test]
    fn retired_listeners_close_their_backlogs_and_free_their_ports() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let accepted = f.accepted(listener, 1);
        f.host.connect(on(2));
        f.host.connect(on(3));
        f.poll();
        f.close(listener);
        // Closed as a connected socket is, lingering until the host resets them.
        for connection in [on(2), on(3)] {
            f.host.with(connection, |connection| {
                assert!(connection.shut_down_sending && connection.shut_down_receiving);
            });
        }
        assert_eq!(f.host.take_forgotten(), []);
        assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
        // The accepted connection goes on; the port is free.
        assert_eq!(f.send(accepted, b"x"), Ok(SocketOutcome::Completed(1)));
        let listener = f.listen(PORT, 4);
        f.host.connect(on(4));
        f.poll();
        assert_eq!(f.accept(listener).unwrap().remote_address, host(4));
        assert_eq!(f.host.take_refused(), []);
        f.host.with(on(2), |connection| connection.gone = true);
        f.poll();
        assert_eq!(f.host.take_forgotten(), [(on(2), false)]);
        f.advance(CLOSE_TIMEOUT);
        f.poll();
        assert_eq!(f.host.take_forgotten(), [(on(3), true)]);
    }

    #[test]
    fn connects_reach_the_host_and_complete_on_its_answer() {
        let f = Fixture::new();
        let socket = f.socket();
        assert_eq!(f.published(socket), [WRITE]);
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        // Bound to an ephemeral port, for any CID.
        assert_eq!(
            f.local(socket),
            Some(VsockAddress {
                cid: VsockCid::ANY,
                port: VsockPort(SEED)
            })
        );
        let connection = id(SEED, 5000);
        assert_eq!(f.host.asked(), [connection]);
        assert_eq!(f.published(socket), [NONE]);
        assert_eq!(f.peer(socket), None);
        assert_eq!(
            f.send(socket, b"x"),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Failed(SocketError::AlreadyInProgress)
        );
        assert_eq!(
            f.check_connect(socket),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        f.poll();
        assert_eq!(f.provider.next_deadline(), after(f.now(), CONNECT_TIMEOUT));
        // Without credit, the connected socket is no more ready than the
        // connecting one: the change is republished.
        f.host.answer(connection);
        f.host.with(connection, |connection| connection.credit = 0);
        f.poll();
        assert_eq!(f.published(socket), [NONE]);
        assert_eq!(
            f.check_connect(socket),
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        );
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Failed(SocketError::AlreadyConnected)
        );
        assert_eq!(f.peer(socket), Some(host(5000)));
        assert_eq!(f.provider.next_deadline(), None);
        f.host
            .with(connection, |connection| connection.credit = 100);
        f.host.send(connection, b"pong");
        f.poll();
        assert_eq!(f.published(socket), [READ | WRITE]);
        assert_eq!(f.send(socket, b"ping"), Ok(SocketOutcome::Completed(4)));
        assert_eq!(f.host.take_received(connection), b"ping");
        assert_eq!(f.received(socket, 16), Some(b"pong".to_vec()));
    }

    #[test]
    fn connects_check_their_state_then_the_address() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        assert_eq!(
            f.connect(listener, 5000),
            SocketOutcome::Failed(SocketError::InvalidArgument)
        );
        assert_eq!(
            f.check_connect(listener),
            SocketOutcome::Failed(SocketError::InvalidArgument)
        );
        let socket = f.socket();
        let address = VsockAddress {
            cid: GUEST_CID,
            port: VsockPort(5000),
        };
        assert_eq!(
            core_vsock::connect(&f.guest, socket, address).unwrap(),
            SocketOutcome::Failed(SocketError::NetworkUnreachable)
        );
        assert_eq!(f.local(socket), None);
        assert_eq!(
            f.check_connect(socket),
            SocketOutcome::Completed(SocketConnectionStatus::Unconnected)
        );
        assert_eq!(f.cancel_connect(socket), SocketOutcome::Completed(()));
        // A bound socket connects from its port.
        let bound = f.socket();
        assert_eq!(f.bind(bound, GUEST_CID, 4000), SocketOutcome::Completed(()));
        assert_eq!(
            f.connect(bound, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        assert_eq!(f.host.asked(), [id(4000, 5000)]);
    }

    #[test]
    fn refused_connects_leave_a_pending_error() {
        let f = Fixture::new();
        let socket = f.socket();
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        let connection = id(SEED, 5000);
        f.poll();
        f.published(socket);
        f.host.refuse_connect(connection);
        f.poll();
        assert_eq!(f.published(socket), [WRITE | ERROR]);
        assert_eq!(f.host.take_forgotten(), [(connection, false)]);
        // Checks, and connects to an address that is not the host's, leave it
        // pending; the next connect takes it.
        for _ in 0..2 {
            assert_eq!(
                f.check_connect(socket),
                SocketOutcome::Failed(SocketError::ConnectionReset)
            );
        }
        for cid in [GUEST_CID, VsockCid::ANY] {
            let address = VsockAddress {
                cid,
                port: VsockPort(5000),
            };
            assert_eq!(
                core_vsock::connect(&f.guest, socket, address).unwrap(),
                SocketOutcome::Failed(SocketError::NetworkUnreachable)
            );
        }
        assert_eq!(f.readiness(socket), WRITE | ERROR);
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Failed(SocketError::ConnectionReset)
        );
        assert_eq!(f.readiness(socket), WRITE);
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        f.host.refuse_connect(connection);
        assert_eq!(f.take_error(socket), Some(SocketError::ConnectionReset));
        assert_eq!(f.take_error(socket), None);
        assert_eq!(f.readiness(socket), WRITE);
        assert_eq!(f.host.asked(), [connection, connection]);
    }

    #[test]
    fn connects_the_host_does_not_answer_time_out() {
        let f = Fixture::new();
        let socket = f.socket();
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        let connection = id(SEED, 5000);
        f.advance(
            CONNECT_TIMEOUT
                .checked_sub(Duration::from_nanos(1))
                .unwrap(),
        );
        f.poll();
        assert_eq!(f.host.take_forgotten(), []);
        f.advance(Duration::from_nanos(1));
        f.poll();
        assert_eq!(f.readiness(socket), WRITE | ERROR);
        assert_eq!(f.host.take_forgotten(), [(connection, true)]);
        assert_eq!(f.provider.next_deadline(), None);
        // A blocking connect's check takes it.
        assert_eq!(
            f.check_connect(socket),
            SocketOutcome::Failed(SocketError::TimedOut)
        );
        assert_eq!(
            f.check_connect(socket),
            SocketOutcome::Completed(SocketConnectionStatus::Unconnected)
        );
        assert_eq!(f.readiness(socket), WRITE);
    }

    #[test]
    fn cancelled_connects_end_the_attempt() {
        let f = Fixture::new();
        let socket = f.socket();
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        let connection = id(SEED, 5000);
        assert_eq!(f.cancel_connect(socket), SocketOutcome::Completed(()));
        assert_eq!(f.host.take_forgotten(), [(connection, true)]);
        assert_eq!(f.readiness(socket), WRITE);
        assert_eq!(f.take_error(socket), None);
        assert_eq!(f.local(socket).unwrap().port, VsockPort(SEED));
        assert_eq!(f.provider.next_deadline(), None);
        // Connected meanwhile: the connect stands.
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        f.host.answer(connection);
        assert_eq!(
            f.cancel_connect(socket),
            SocketOutcome::Failed(SocketError::AlreadyConnected)
        );
        assert_eq!(f.send(socket, b"x"), Ok(SocketOutcome::Completed(1)));
        // Failed meanwhile: its error.
        let socket = f.socket();
        assert_eq!(
            f.connect(socket, 5001),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        f.host.refuse_connect(id(SEED + 1, 5001));
        assert_eq!(
            f.cancel_connect(socket),
            SocketOutcome::Failed(SocketError::ConnectionReset)
        );
        // Closing a connecting socket cancels it.
        let socket = f.socket();
        assert_eq!(
            f.connect(socket, 5002),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        f.close(socket);
        assert_eq!(
            f.host.take_forgotten(),
            [(id(SEED + 1, 5001), false), (id(SEED + 2, 5002), true)]
        );
    }

    #[test]
    fn connects_beyond_the_guests_share_of_the_transport_fail() {
        let f = Fixture::new();
        let sockets: Vec<_> = (0..MAX_USER_CONNECTIONS)
            .map(|_| f.connected(5000).0)
            .collect();
        let socket = f.socket();
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Failed(SocketError::ConnectionReset)
        );
        // Bound, unconnected, without an error.
        assert_eq!(f.readiness(socket), WRITE);
        assert!(f.local(socket).is_some());
        // The host's requests still get through.
        let listener = f.listen(PORT, 4);
        let accepted = f.accepted(listener, 6000);
        assert_eq!(f.send(accepted, b"x"), Ok(SocketOutcome::Completed(1)));
        // A guest connection ends: room again.
        f.close(sockets[0]);
        let connection = id(SEED, 5000);
        f.host.with(connection, |connection| connection.gone = true);
        f.poll();
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
    }

    #[test]
    fn host_requests_on_a_connects_connection_are_refused() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let socket = f.socket();
        assert_eq!(
            f.bind(socket, VsockCid::ANY, PORT + 1),
            SocketOutcome::Completed(())
        );
        assert_eq!(
            f.connect(socket, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        let connection = id(PORT + 1, 5000);
        // The host refuses the connect, and requests the same connection before
        // the provider sees the refusal.
        f.host.refuse_connect(connection);
        f.host.connect(connection);
        f.poll();
        assert_eq!(f.host.take_refused(), [connection]);
        assert_eq!(f.take_error(socket), Some(SocketError::ConnectionReset));
        assert!(!f.host.0.lock().connections.contains_key(&connection));
        assert_eq!(
            f.accept(listener).err(),
            Some(BrokerError::NonBlockingWouldBlock)
        );
    }

    #[test]
    fn a_transport_reset_fails_connects_and_ends_connections() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let accepted = f.accepted(listener, 7);
        f.host.send(on(7), b"last");
        let connecting = f.socket();
        assert_eq!(
            f.connect(connecting, 5000),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        f.host.reset_all();
        f.poll();
        assert_eq!(f.take_error(connecting), Some(SocketError::ConnectionReset));
        assert_eq!(f.received(accepted, 16), Some(b"last".to_vec()));
        assert_eq!(f.received(accepted, 16), None);
        assert_eq!(
            f.send(accepted, b"lost"),
            Ok(SocketOutcome::Failed(SocketError::Shutdown))
        );
        f.poll();
        assert_eq!(
            f.host.take_forgotten(),
            [(id(SEED, 5000), false), (on(7), false)]
        );
    }

    #[test]
    fn binds_take_the_guests_cids_and_unused_ports() {
        let f = Fixture::new();
        let socket = f.socket();
        assert_eq!(
            f.bind(socket, VsockCid(GUEST_CID.0 + 1), PORT),
            SocketOutcome::Failed(SocketError::AddressNotAvailable)
        );
        assert_eq!(f.local(socket), None);
        assert_eq!(
            f.bind(socket, GUEST_CID, PORT),
            SocketOutcome::Completed(())
        );
        assert_eq!(
            f.local(socket),
            Some(VsockAddress {
                cid: GUEST_CID,
                port: VsockPort(PORT)
            })
        );
        assert_eq!(
            f.bind(socket, VsockCid::ANY, PORT + 1),
            SocketOutcome::Failed(SocketError::InvalidArgument)
        );
        let other = f.socket();
        assert_eq!(
            f.bind(other, VsockCid::ANY, PORT),
            SocketOutcome::Failed(SocketError::AddressInUse)
        );
        assert_eq!(
            core_vsock::listen(&f.guest, other, 1).unwrap(),
            SocketOutcome::Failed(SocketError::InvalidArgument)
        );
        f.close(socket);
        assert_eq!(
            f.bind(other, VsockCid::ANY, PORT),
            SocketOutcome::Completed(())
        );
    }

    /// The port an ephemeral bind of a new socket takes, if any.
    fn ephemeral(f: &Fixture) -> Option<u32> {
        let socket = f.socket();
        match f.bind(socket, VsockCid::ANY, VsockPort::ANY.0) {
            SocketOutcome::Completed(()) => Some(f.local(socket).unwrap().port.0),
            SocketOutcome::Failed(error) => {
                assert_eq!(error, SocketError::AddressNotAvailable);
                None
            }
        }
    }

    #[test]
    fn ephemeral_ports_follow_the_seed_and_skip_those_in_use() {
        let f = Fixture::new();
        assert_eq!(ephemeral(&f), Some(SEED));
        let taken = f.socket();
        assert_eq!(
            f.bind(taken, VsockCid::ANY, SEED + 1),
            SocketOutcome::Completed(())
        );
        assert_eq!(ephemeral(&f), Some(SEED + 2));
        let tries = u32::try_from(MAX_EPHEMERAL_TRIES).unwrap();
        for port in SEED + 3..SEED + 3 + tries {
            assert_eq!(
                f.bind(f.socket(), VsockCid::ANY, port),
                SocketOutcome::Completed(())
            );
        }
        assert_eq!(ephemeral(&f), None);
        assert_eq!(ephemeral(&f), Some(SEED + 3 + tries));
    }

    #[test]
    fn ephemeral_ports_wrap_above_the_reserved_ones() {
        let f = Fixture::with_seed(u64::from(u32::MAX - 1));
        assert_eq!(ephemeral(&f), Some(u32::MAX - 1));
        assert_eq!(ephemeral(&f), Some(LAST_RESERVED_PORT + 1));
    }
}
