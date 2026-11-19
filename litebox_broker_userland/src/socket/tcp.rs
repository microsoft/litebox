// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TCP socket state and transport-specific helpers.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, Result as IoResult};
use std::net::{Shutdown, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use litebox_broker_core::socket::GUEST_IPV4_ADDRESS;
use litebox_broker_core::socket::stream::{StreamEnd, StreamError, stream_pair};
use litebox_broker_core::socket::{
    GuestSocketBinding, GuestSourceLease, HostBindRequest, PlatformConnectError,
    PlatformSocketStatus, SocketAddressing, SocketEgress, host_socket_destination,
    is_internal_socket_address, normalize_socket_destination,
};
use litebox_broker_core::{BrokerError, ProcessKey, Result as BrokerResult};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE, ReceiveFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOptionName, SocketOptionValue, SocketOutcome,
};
use litebox_platform::buffer::RawBytes;

use crate::publish::{Protocol, Publish};

use super::direct::RawParts;
use super::host::{
    Errno, HostErrno as _, HostPoller as _, HostSocket as _, Interest, Poller, ReceiveMode, Socket,
    SocketEvents,
};
use super::{
    HookPoint, SocketEntry, SocketInbox, SocketKind, SocketState, SocketTransportState, Topology,
    UserlandSocket, broker_error_from_errno, lock, republish_own_readiness, reserve_published,
    set_own_readiness, socket_error_from_errno, socket_operation_error_from_errno, sources_contain,
    zeroed_vec,
};

pub(super) struct AcceptedEndpoints {
    pub(super) local_address: SocketAddrV4,
    pub(super) guest_source_lease: GuestSourceLease,
}

pub(super) enum ReceiveOutcome {
    /// Bytes received into the start of the output.
    Received(usize),
    EndOfStream,
    Failed(SocketError),
}

impl ReceiveOutcome {
    /// Returns how many bytes the receive copied into its output.
    pub(super) fn received(&self) -> usize {
        match self {
            Self::Received(received) => *received,
            Self::EndOfStream | Self::Failed(_) => 0,
        }
    }
}

/// Bytes a multi-window peek read at offset zero, served to its later windows.
struct PeekCache {
    requested_length: usize,
    data: Vec<u8>,
}

/// How long the data of a `MSG_PEEK | MSG_WAITALL` peek is watched for after
/// the peek last waited. Its waiters are then woken, and a peek still waiting
/// retries, so only a peek that no one waits for any longer, such as one
/// whose guest thread exited, stops being watched.
pub(super) const PEEK_WAITALL_INTEREST: Duration = Duration::from_secs(1);

/// Marks the event tokens of published ports' host sockets that no guest listener holds; the
/// rest of the token is the rule's index. Socket IDs stay below it.
pub(super) const PUBLISHED_EVENT_TOKEN_FLAG: u64 = 1 << 62;

/// Marks the event tokens of mirrored listeners' host sockets; the rest of the token is the
/// socket's ID, which stays below it. Such a host socket is watched from before it listens, so
/// that a failed watch leaves no listener, and events from before it listened would describe a
/// socket that does not; under their own token, they reach no connect the socket makes after a
/// failed listen.
pub(super) const LISTENER_EVENT_TOKEN_FLAG: u64 = 1 << 61;

/// Most clients that one accept or one event of an idle host socket resets.
const MAX_RESETS_AT_ONCE: usize = 64;

/// Most times a mirrored bind at port 0 has the host choose again a port that another socket
/// took before the bind could.
const MAX_PORT_CHOICES: usize = 8;

/// The data that waiting `MSG_PEEK | MSG_WAITALL` peeks need.
#[derive(Clone, Copy)]
pub(super) struct PeekWaitAll {
    /// The queued bytes the peeks need before their waiters are woken.
    length: usize,
    /// When a peek last waited.
    since: Instant,
}

/// Retains an error's source so a guest reset remains distinguishable from an
/// independent socket `ConnectionReset` even though both have the same public value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TcpPendingError {
    Socket(SocketError),
    GuestReset,
}

impl TcpPendingError {
    pub(super) fn error(self) -> SocketError {
        match self {
            Self::Socket(error) => error,
            Self::GuestReset => SocketError::ConnectionReset,
        }
    }
}

#[derive(Default)]
pub(super) struct TcpPendingErrors {
    current: Option<TcpPendingError>,
    next: Option<TcpPendingError>,
}

impl TcpPendingErrors {
    pub(super) fn append(&mut self, error: TcpPendingError) {
        if error == TcpPendingError::GuestReset && self.contains_guest_reset() {
            return;
        }
        if self.current.is_none() {
            self.current = Some(error);
        } else if self.next.is_none() {
            self.next = Some(error);
        }
    }

    pub(super) fn take(&mut self) -> Option<TcpPendingError> {
        let error = self.current.take();
        self.current = self.next.take();
        error
    }

    pub(super) fn contains_guest_reset(&self) -> bool {
        matches!(self.current, Some(TcpPendingError::GuestReset))
            || matches!(self.next, Some(TcpPendingError::GuestReset))
    }

    pub(super) fn remove_guest_reset(&mut self) {
        if matches!(self.next, Some(TcpPendingError::GuestReset)) {
            self.next = None;
        } else if matches!(self.current, Some(TcpPendingError::GuestReset)) {
            self.take();
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.current.is_none()
    }
}

/// TCP descriptor and transport-specific state guarded by the socket's `state`.
#[expect(
    clippy::struct_excessive_bools,
    reason = "socket lifecycle latches are independent"
)]
pub(super) struct TcpSocketState {
    pub(super) descriptor: TcpDescriptor,
    /// The socket is a listener; its queue lives in [`TcpTopology`].
    listening: bool,
    pub(super) guest_endpoint: Option<GuestTcpEndpoint>,
    /// The data that waiting `MSG_PEEK | MSG_WAITALL` peeks need. Cleared
    /// once it is queued, once another receive shows the guest stopped
    /// waiting, or once [`PEEK_WAITALL_INTEREST`] passes.
    pub(super) peek_waitall: Option<PeekWaitAll>,
    /// The reader whose peek the next request past offset zero may continue,
    /// as [`continue_peek`] describes.
    peek_reader: Option<ObjectHandle>,
    peek_cache: Option<PeekCache>,
    pub(super) pending_errors: TcpPendingErrors,
    pub(super) abortive_close: bool,
    /// An established external connection's failure was reported, after
    /// which receives end the stream and sends fail as not connected,
    /// whatever the host socket still reports.
    pub(super) connection_failed: bool,
    options: TcpOptions,
    /// A mirrored socket was bound at a port the guest named, rather than one the host chose,
    /// which, as on Linux, stays bound when the socket stops listening or connecting.
    named_port: bool,
    /// A mirrored socket's share of the port that its in-memory connections name: a
    /// connector's own, or a listener's, which the connections it accepts share.
    port_share: Option<PortShare>,
    /// Names a mirrored socket's connection through the host in [`MirroredTcpPairs`].
    host_connection: Option<Arc<HostConnection>>,
}

/// The host port that a mirrored socket's in-memory connections name, which no other host
/// socket may take while one of them, or the socket itself if it still names the port, is open,
/// as no other could take the port of a host connection.
///
/// The port's host socket, bound but neither listening nor connected, holds it here once its
/// guest socket stops using it: a connector's when it connects in memory, and a listener's when
/// it stops listening. A listener at the wildcard address thus holds its port at every host
/// address for the connections it accepted, more than their own host sockets would. Each guest
/// socket that names the port holds a [`PortShare`], and the lease that names a connector to
/// its peer holds the port alone; the port is released once the last of these closes.
///
/// `state` is a leaf lock. No drop of a [`HeldPort`] takes a lock, so its last holder may drop
/// it under any.
struct HeldPort {
    state: Mutex<HeldPortState>,
}

struct HeldPortState {
    /// The port's host socket, once its guest socket stopped using it.
    socket: Option<Socket>,
    /// How many of the [`PortShare`]s of the port do not share it with others, by
    /// `SO_REUSEADDR`, as their sockets last set it. A share counts while its socket is open,
    /// and a connector's until the port is released, as a host socket's closed connection keeps
    /// the port, as the socket last set it, while its peer is open.
    exclusive: usize,
}

impl HeldPort {
    /// Holds a stopped listener's host socket, which stops listening here, resetting the host
    /// clients it did not accept, but stays bound, sharing its port as the guest sockets that
    /// share it do. A host that fails to stop it closes it, which releases the port early,
    /// rather than leave a listener nobody serves.
    fn hold_listener(&self, listener: Socket) {
        let mut state = lock(&self.state);
        let stopped = listener
            .set_reuse_address(state.exclusive == 0)
            .and_then(|()| listener.disconnect());
        if stopped.is_ok() {
            state.socket = Some(listener);
        }
    }

    /// A new port that holds `socket`, if any, which already shares its address as one guest
    /// socket whose `SO_REUSEADDR` is `reuse_address` directs, for that socket's
    /// [`PortShare`], which counts it already.
    fn new(socket: Option<Socket>, reuse_address: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(HeldPortState {
                socket,
                exclusive: usize::from(!reuse_address),
            }),
        })
    }
}

/// A guest socket's share of a [`HeldPort`], as which its `SO_REUSEADDR` counts until it drops,
/// or, if it `lingers`, until the port is released.
///
/// A drop takes the port's leaf lock, so none happens under another leaf lock.
struct PortShare {
    port: Arc<HeldPort>,
    reuse_address: bool,
    lingers: bool,
}

impl PortShare {
    /// Shares a new [`HeldPort`] with the listener it serves, whose `SO_REUSEADDR` is
    /// `reuse_address`.
    fn first(reuse_address: bool) -> Self {
        Self {
            port: HeldPort::new(None, reuse_address),
            reuse_address,
            lingers: false,
        }
    }

    /// The share of the connector whose new `port` [`HeldPort::new`] counted with its
    /// `reuse_address`.
    fn connector(port: Arc<HeldPort>, reuse_address: bool) -> Self {
        Self {
            port,
            reuse_address,
            lingers: true,
        }
    }

    /// Shares `port` with a socket whose `SO_REUSEADDR` is `reuse_address`.
    fn new(port: &Arc<HeldPort>, reuse_address: bool) -> BrokerResult<Self> {
        let mut state = lock(&port.state);
        let exclusive = state.exclusive + usize::from(!reuse_address);
        if let Some(socket) = &state.socket {
            socket
                .set_reuse_address(exclusive == 0)
                .map_err(broker_error_from_errno)?;
        }
        state.exclusive = exclusive;
        drop(state);
        Ok(Self {
            port: Arc::clone(port),
            reuse_address,
            lingers: false,
        })
    }

    /// Changes the socket's `SO_REUSEADDR` to `reuse_address`.
    fn set_reuse_address(&mut self, reuse_address: bool) -> BrokerResult<()> {
        if reuse_address == self.reuse_address {
            return Ok(());
        }
        let mut state = lock(&self.port.state);
        let exclusive = if reuse_address {
            state.exclusive - 1
        } else {
            state.exclusive + 1
        };
        if let Some(socket) = &state.socket {
            socket
                .set_reuse_address(exclusive == 0)
                .map_err(broker_error_from_errno)?;
        }
        state.exclusive = exclusive;
        drop(state);
        self.reuse_address = reuse_address;
        Ok(())
    }
}

impl Drop for PortShare {
    /// Ends the share's refusal to share the port, if any, unless it lingers. The port's host
    /// socket then shares it once no other share refuses; a host that fails to make it share
    /// keeps the port as exclusive as it was.
    fn drop(&mut self) {
        if self.reuse_address || self.lingers {
            return;
        }
        let mut state = lock(&self.port.state);
        state.exclusive -= 1;
        if state.exclusive == 0
            && let Some(socket) = &state.socket
        {
            let _ = socket.set_reuse_address(true);
        }
    }
}

/// Socket options the broker applies to a TCP socket's host descriptor.
#[derive(Clone, Copy, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "socket options are independent"
)]
struct TcpOptions {
    no_delay: bool,
    keep_alive: bool,
    /// A mirrored socket's `SO_REUSEADDR`, which the provider rather than core keeps, so that
    /// a change reaches its host sockets in order with its bind.
    reuse_address: bool,
    /// The host socket refused the options, so it gets them if it connects.
    deferred: bool,
}

pub(super) enum TcpDescriptor {
    Unrealized,
    /// A mirrored socket's host socket, bound but neither listening nor connected.
    Bound(Socket),
    ExternalInet(Socket),
    /// This socket's end of an internal connection.
    Internal(StreamEnd),
    /// A published port's host socket, or a mirrored socket's own, listening while the socket
    /// listens.
    Listener(Socket),
}

impl TcpDescriptor {
    /// Returns an external connection's host socket.
    pub(super) fn socket(&self) -> BrokerResult<&Socket> {
        match self {
            Self::ExternalInet(socket) => Ok(socket),
            Self::Internal(_) | Self::Unrealized | Self::Bound(_) | Self::Listener(_) => {
                Err(BrokerError::Internal)
            }
        }
    }

    /// Returns an external connection's host socket for the poller.
    fn socket_mut(&mut self) -> BrokerResult<&mut Socket> {
        match self {
            Self::ExternalInet(socket) => Ok(socket),
            Self::Internal(_) | Self::Unrealized | Self::Bound(_) | Self::Listener(_) => {
                Err(BrokerError::Internal)
            }
        }
    }

    pub(super) fn is_external(&self) -> bool {
        matches!(self, Self::ExternalInet(_))
    }

    fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_))
    }

    /// Returns how many bytes a receive could take now.
    pub(super) fn queued_bytes(&self) -> BrokerResult<usize> {
        match self {
            Self::ExternalInet(socket) => socket.queued_bytes().map_err(broker_error_from_errno),
            Self::Internal(end) => Ok(end.available()),
            Self::Unrealized | Self::Bound(_) | Self::Listener(_) => Err(BrokerError::Internal),
        }
    }

    /// Reports whether a receive would return data or the end of the stream
    /// now.
    pub(super) fn readable(&self) -> BrokerResult<bool> {
        match self {
            Self::ExternalInet(socket) => socket.stream_readable().map_err(broker_error_from_errno),
            Self::Internal(end) => Ok(end.readiness().readable),
            Self::Unrealized | Self::Bound(_) | Self::Listener(_) => Err(BrokerError::Internal),
        }
    }

    /// Sends `data` without blocking.
    ///
    /// An internal endpoint fails the way an `AF_UNIX` socket would, so both
    /// kinds of connection share their error handling.
    fn send(&self, data: RawParts<'_>) -> BrokerResult<Result<usize, Errno>> {
        match self {
            Self::ExternalInet(socket) => Ok(socket.send(data, None)),
            Self::Internal(end) => errno_from_stream(end.write(data.parts())),
            Self::Unrealized | Self::Bound(_) | Self::Listener(_) => Err(BrokerError::Internal),
        }
    }

    /// Receives into `output` without blocking, keeping the data if `mode`
    /// peeks.
    fn receive(
        &self,
        output: RawParts<'_>,
        mode: ReceiveMode,
    ) -> BrokerResult<Result<usize, Errno>> {
        match self {
            Self::ExternalInet(socket) => Ok(socket.receive(output, mode)),
            Self::Internal(end) if mode.is_peek() => errno_from_stream(end.peek(output.parts())),
            Self::Internal(end) => errno_from_stream(end.read(output.parts())),
            Self::Unrealized | Self::Bound(_) | Self::Listener(_) => Err(BrokerError::Internal),
        }
    }
}

/// The event token of the idle host socket of the rule at `index`.
fn idle_token(index: usize) -> u64 {
    PUBLISHED_EVENT_TOKEN_FLAG | index as u64
}

/// The event token of the host socket of the mirrored listener `id`.
fn listener_token(id: u64) -> u64 {
    LISTENER_EVENT_TOKEN_FLAG | id
}

/// Returns `address` at a port that the host chooses as it would bind a TCP socket there at
/// port 0, and leaves free, or the error of that bind.
fn host_chosen_port(address: SocketAddrV4) -> BrokerResult<Result<SocketAddrV4, Errno>> {
    let probe = Socket::tcp().map_err(broker_error_from_errno)?;
    if let Err(error) = probe.bind_as_guest(address, false) {
        return Ok(Err(error));
    }
    probe
        .local_address()
        .map(Ok)
        .map_err(broker_error_from_errno)
}

/// Opens each rule's host socket; a TCP one listening, watched under its idle token.
pub(super) fn listen_published(
    poller: &Poller,
    rules: Vec<Publish>,
) -> IoResult<Vec<(Publish, Option<Socket>)>> {
    let listen = |(index, rule): (usize, Publish)| {
        let opened = reserve_published(rule.protocol, rule.host).and_then(|mut socket| {
            if rule.protocol == Protocol::Tcp {
                poller.add(&mut socket, idle_token(index), Interest::Stream)?;
            }
            Ok(socket)
        });
        match opened {
            Ok(socket) => Ok((rule, Some(socket))),
            Err(error) => Err(Error::other(format!("cannot publish {rule}: {error}"))),
        }
    };
    rules.into_iter().enumerate().map(listen).collect()
}

impl super::ProviderCore {
    /// Takes the idle host socket of the rule publishing `guest_port`, unwatched; without a rule,
    /// opens one at `guest_port` of the mirroring IP, if any and free.
    pub(super) fn take_published(&self, protocol: Protocol, guest_port: u16) -> Option<Socket> {
        let mut published = lock(&self.published);
        if let Some((_, socket)) = published
            .iter_mut()
            .find(|(rule, _)| (rule.protocol, rule.guest_port) == (protocol, guest_port))
        {
            let mut socket = socket.take()?;
            self.unwatch_host_socket(&mut socket);
            return Some(socket);
        }
        drop(published);
        let address = SocketAddrV4::new(self.published_listener_ip?, guest_port);
        match reserve_published(protocol, address) {
            Ok(socket) => Some(socket),
            Err(error) => {
                // A guest can listen or bind again and again.
                if lock(&self.unmirrored).insert((protocol, guest_port)) {
                    std::eprintln!("broker cannot mirror {protocol:?} port {address}: {error}");
                }
                None
            }
        }
    }

    /// Unwatches a guest socket's host socket and gives a rule's back: a TCP one resets its
    /// clients while no guest listens, a UDP one holds its port; a mirror's closes.
    pub(super) fn release_published(
        &self,
        protocol: Protocol,
        guest_port: u16,
        mut socket: Socket,
    ) {
        self.unwatch_host_socket(&mut socket);
        if protocol == Protocol::Udp {
            // Idle, it queues few datagrams for the next bind to discard.
            let _ = socket.set_receive_buffer_size(1);
        }
        let mut published = lock(&self.published);
        if let Some(index) = published
            .iter()
            .position(|(rule, _)| (rule.protocol, rule.guest_port) == (protocol, guest_port))
        {
            if protocol == Protocol::Tcp {
                // If the watch fails, the next guest listener watches it again.
                let _ = self.watch_host_socket(&mut socket, idle_token(index), Interest::Stream);
            }
            published[index].1 = Some(socket);
        }
    }

    /// Resets the clients waiting on the idle host socket of the rule that `token` names, and
    /// returns whether more may wait.
    pub(super) fn reset_idle_clients(&self, token: u64) -> bool {
        let published = lock(&self.published);
        let index = usize::try_from(token & !PUBLISHED_EVENT_TOKEN_FLAG);
        let Some((_, Some(socket))) = index.ok().and_then(|index| published.get(index)) else {
            return false;
        };
        for _ in 0..MAX_RESETS_AT_ONCE {
            match socket.accept() {
                Ok((client, _)) => {
                    let _ = client.set_linger_zero();
                }
                Err(Errno::INTR | Errno::CONNABORTED | Errno::CONNRESET) => {}
                // Freed resources raise no event, so the clients wait for a retry.
                Err(error) if error.broker_resource_error().is_some() => return true,
                Err(_) => return false,
            }
        }
        true
    }
}

/// Maps a stream result to the `errno` an `AF_UNIX` socket reports.
fn errno_from_stream(result: Result<usize, StreamError>) -> BrokerResult<Result<usize, Errno>> {
    match result {
        Ok(count) => Ok(Ok(count)),
        Err(StreamError::WouldBlock) => Ok(Err(Errno::AGAIN)),
        Err(StreamError::Closed) => Ok(Err(Errno::PIPE)),
        Err(StreamError::OutOfMemory) => Err(BrokerError::OutOfMemory),
    }
}

/// Synthesizes the host events an internal endpoint's stream would raise.
fn stream_events(end: &StreamEnd) -> SocketEvents {
    let readiness = end.readiness();
    let mut events = SocketEvents::empty();
    if readiness.readable {
        events |= SocketEvents::READABLE;
    }
    if readiness.writable {
        events |= SocketEvents::WRITABLE;
    }
    if readiness.peer_finished {
        events |= SocketEvents::READ_CLOSED;
    }
    if readiness.peer_closed {
        events |= SocketEvents::HANGUP;
    }
    events
}

/// A guest listener's backlog and the internal connections queued on it.
struct TcpListener {
    inbox: Arc<SocketInbox>,
    backlog: usize,
    queue: VecDeque<QueuedGuestTcpConnection>,
    /// A mirrored listener's port, which its connections share from when they are queued.
    port: Option<ListenerPort>,
}

/// A mirrored listener's [`HeldPort`], and its `SO_REUSEADDR` as it last set it, which a
/// connection queued on it takes then, as a host connection takes its listener's when the host
/// connects it, whatever the listener sets before the accept.
struct ListenerPort {
    port: Arc<HeldPort>,
    reuse_address: bool,
}

struct QueuedGuestTcpConnection {
    socket: StreamEnd,
    connector_socket_id: u64,
    connector_process_key: ProcessKey,
    local_address: SocketAddrV4,
    guest_source_lease: GuestSourceLease,
    /// The connection's share of its mirrored listener's port, with the `SO_REUSEADDR` it took.
    port_share: Option<PortShare>,
}

/// One end of an internal connection, identified by its connector's socket ID.
pub(super) struct GuestTcpEndpoint {
    connector_socket_id: u64,
    reset_state: GuestTcpResetState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestTcpResetState {
    None,
    Pending,
    Reported,
}

/// The live ends of an internal connection, keyed in [`TcpTopology`] by its
/// connector's socket ID, so whichever end closes can reach the other.
struct TcpLink {
    connector: Arc<SocketInbox>,
    peer: TcpLinkPeer,
}

/// The pairs of addresses of the mirrored sockets' connections, in memory or through the host,
/// which no other of their connections shares, in either direction, while one lives, as the host
/// keeps its connections' pairs distinct. A connection through the host names its pair from the
/// start of its connect, or its accept, until it fails before it connected, or its socket aborts
/// or closes; the host decides for itself whether it shares a pair with another such one.
///
/// Pairs that ended are swept once their map fills, so that sweeps take constant time per
/// connection over time.
#[derive(Default)]
struct MirroredTcpPairs {
    /// Each in-memory connection's pair, which lives as long as its connector's [`HeldPort`],
    /// which the connector and the lease that names it to its peer share, so no close needs
    /// `topology` to end one.
    memory: HashMap<TcpPair, Weak<HeldPort>>,
    /// Each connection's pair through the host, which lives as long as its socket's
    /// [`TcpSocketState::host_connection`].
    host: HashMap<TcpPair, Weak<HostConnection>>,
}

/// The two ends of a connection, in order, so that each connection has one whichever end
/// connected.
type TcpPair = (SocketAddrV4, SocketAddrV4);

fn tcp_pair(one: SocketAddrV4, other: SocketAddrV4) -> TcpPair {
    (one.min(other), one.max(other))
}

/// Names a mirrored socket's connection through the host in [`MirroredTcpPairs`] while the
/// socket holds it.
struct HostConnection;

impl MirroredTcpPairs {
    /// Whether a live connection of the mirrored sockets, in memory or through the host, connects
    /// `one` and `other`.
    fn in_use(&self, one: SocketAddrV4, other: SocketAddrV4) -> bool {
        let pair = tcp_pair(one, other);
        self.memory_in_use(pair)
            || self
                .host
                .get(&pair)
                .is_some_and(|connection| connection.strong_count() > 0)
    }

    /// Whether a live in-memory connection connects the ends of `pair`.
    fn memory_in_use(&self, pair: TcpPair) -> bool {
        self.memory
            .get(&pair)
            .is_some_and(|held_port| held_port.strong_count() > 0)
    }

    /// Makes room for one more in-memory pair, so that inserting it next cannot fail. A full map
    /// first sweeps the pairs whose connections closed, and then makes room for as many again as
    /// remain.
    fn try_reserve_memory(&mut self) -> BrokerResult<()> {
        if self.memory.len() < self.memory.capacity() {
            return Ok(());
        }
        self.memory.retain(|_, port| port.strong_count() > 0);
        self.memory
            .try_reserve(self.memory.len().max(1))
            .map_err(|_| BrokerError::OutOfMemory)
    }

    /// Makes room for one more host pair, as [`Self::try_reserve_memory`] does.
    fn try_reserve_host(&mut self) -> BrokerResult<()> {
        if self.host.len() < self.host.capacity() {
            return Ok(());
        }
        self.host
            .retain(|_, connection| connection.strong_count() > 0);
        self.host
            .try_reserve(self.host.len().max(1))
            .map_err(|_| BrokerError::OutOfMemory)
    }

    /// Records an in-memory connection of `source` to `destination` until `held_port` drops,
    /// after [`Self::try_reserve_memory`] made room for it and [`Self::in_use`] found its pair
    /// free.
    fn insert_memory(
        &mut self,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        held_port: &Arc<HeldPort>,
    ) {
        self.memory
            .insert(tcp_pair(source, destination), Arc::downgrade(held_port));
    }

    /// Records a connection through the host of `local` and `peer`, after
    /// [`Self::try_reserve_host`] made room for it, and returns what keeps it recorded. Both ends
    /// of a connection of the provider's own sockets keep the same one.
    fn insert_host(&mut self, local: SocketAddrV4, peer: SocketAddrV4) -> Arc<HostConnection> {
        let entry = self.host.entry(tcp_pair(local, peer));
        if let Entry::Occupied(entry) = &entry
            && let Some(connection) = entry.get().upgrade()
        {
            return connection;
        }
        let connection = Arc::new(HostConnection);
        entry.insert_entry(Arc::downgrade(&connection));
        connection
    }

    /// Records a connection through the host of `local` and `peer`, as [`Self::insert_host`]
    /// does, unless a live in-memory connection connects them, which the host, knowing nothing of
    /// it, lets one through it take too; then returns `None`.
    fn try_insert_host(
        &mut self,
        local: SocketAddrV4,
        peer: SocketAddrV4,
    ) -> BrokerResult<Option<Arc<HostConnection>>> {
        if self.memory_in_use(tcp_pair(local, peer)) {
            return Ok(None);
        }
        self.try_reserve_host()?;
        Ok(Some(self.insert_host(local, peer)))
    }
}

enum TcpLinkPeer {
    /// The peer end is still queued on this listener, not yet accepted.
    Queued {
        listener_id: u64,
    },
    Accepted(Arc<SocketInbox>),
}

impl SocketState {
    pub(super) fn tcp_state(&self) -> BrokerResult<&TcpSocketState> {
        match &self.transport {
            SocketTransportState::Tcp(tcp) => Ok(tcp),
            SocketTransportState::Udp(_) => Err(BrokerError::Internal),
        }
    }

    pub(super) fn tcp_state_mut(&mut self) -> BrokerResult<&mut TcpSocketState> {
        match &mut self.transport {
            SocketTransportState::Tcp(tcp) => Ok(tcp),
            SocketTransportState::Udp(_) => Err(BrokerError::Internal),
        }
    }
}

fn tcp_socket_state(
    descriptor: TcpDescriptor,
    guest_endpoint: Option<GuestTcpEndpoint>,
    options: TcpOptions,
) -> TcpSocketState {
    TcpSocketState {
        descriptor,
        listening: false,
        guest_endpoint,
        peek_waitall: None,
        peek_reader: None,
        peek_cache: None,
        pending_errors: TcpPendingErrors::default(),
        abortive_close: false,
        connection_failed: false,
        options,
        named_port: false,
        port_share: None,
        host_connection: None,
    }
}

pub(super) fn create_tcp_transport() -> SocketTransportState {
    SocketTransportState::Tcp(tcp_socket_state(
        TcpDescriptor::Unrealized,
        None,
        TcpOptions::default(),
    ))
}

/// Guest TCP bindings, listener queues, and internal connection links.
#[derive(Default)]
pub(super) struct TcpTopology {
    bindings: TcpBindings,
    listeners: HashMap<u64, TcpListener>,
    links: HashMap<u64, TcpLink>,
    mirrored_pairs: MirroredTcpPairs,
    pub(super) queued_guest_connection_count: usize,
}

#[derive(Default)]
struct TcpBindings {
    wildcard: HashMap<u16, TcpBinding>,
    exact: HashMap<SocketAddrV4, TcpBinding>,
}

impl TcpBindings {
    fn values(&self) -> impl Iterator<Item = &TcpBinding> {
        self.wildcard.values().chain(self.exact.values())
    }
}

fn readiness_from_events(socket: &SocketEntry<'_>, events: SocketEvents) -> ReadinessFlags {
    // `own` changes only under the socket's `state`, which the caller holds.
    let previous = socket.own();
    let mut readiness = ReadinessFlags::default();
    // A receive may already have taken the data an edge reports: the edge can
    // wait in the poller's batch, or be deferred while a call holds the socket.
    // READ for drained data would make a guest that trusts `select` or `poll`
    // block in its next read, so an edge raises READ only while a receive may
    // still return something. READ already set stays, and the end of the
    // stream raises it below.
    if events.contains(SocketEvents::READABLE)
        && !previous.contains(ReadinessFlags::READ)
        && !nothing_to_receive(socket)
    {
        readiness = readiness | ReadinessFlags::READ;
    }
    if events.contains(SocketEvents::WRITABLE) && !socket.write_shutdown {
        readiness = readiness | ReadinessFlags::WRITE;
    }
    if !socket.read_shutdown && events.intersects(SocketEvents::READ_CLOSED | SocketEvents::HANGUP)
    {
        readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
    }
    // A host hang-up closes both directions of an external connection, but on
    // an internal endpoint it only reports that the peer closed.
    if events.contains(SocketEvents::HANGUP)
        && socket
            .tcp_state()
            .is_ok_and(|tcp| tcp.descriptor.is_external())
    {
        readiness = readiness | ReadinessFlags::CLOSED;
    }
    if events.contains(SocketEvents::ERROR) {
        readiness = readiness | ReadinessFlags::ERROR;
    }
    with_tcp_closed(socket, ReadinessFlags(readiness.0 | previous.0))
}

/// Whether the host reports that a receive would return nothing: neither data
/// nor the end of the stream.
///
/// This asks the host rather than counting queued bytes, as Linux counts only
/// the bytes before urgent data, though a receive skips the urgent byte and
/// returns the data behind it. An unknown answer counts as receivable: a
/// needless READ only costs a receive that finds nothing and clears it, but a
/// missing one leaves a reader waiting.
fn nothing_to_receive(socket: &SocketEntry<'_>) -> bool {
    socket.tcp_state().and_then(|tcp| tcp.descriptor.readable()) == Ok(false)
}

/// Adds [`ReadinessFlags::CLOSED`] once both directions of a TCP socket are shut down.
fn with_tcp_closed(socket: &SocketEntry<'_>, readiness: ReadinessFlags) -> ReadinessFlags {
    if socket.write_shutdown && (socket.read_shutdown || readiness.contains(ReadinessFlags::HANGUP))
    {
        readiness | ReadinessFlags::CLOSED
    } else {
        readiness
    }
}

pub(super) const fn can_consume_synchronous_error(status: SocketConnectionStatus) -> bool {
    matches!(status, SocketConnectionStatus::Connected)
}

fn add_readiness(socket: &SocketEntry<'_>, readiness: ReadinessFlags) {
    let current = socket.own();
    set_own_readiness(socket, ReadinessFlags(current.0 | readiness.0));
}

fn clear_readiness(socket: &SocketEntry<'_>, readiness: ReadinessFlags) {
    let current = socket.own();
    set_own_readiness(socket, ReadinessFlags(current.0 & !readiness.0));
}

/// Clears the ERROR readiness of a connected socket once a call reported its
/// error, unless another error is pending.
fn consume_synchronous_error(socket: &mut SocketEntry<'_>) -> BrokerResult<()> {
    if !can_consume_synchronous_error(socket.connection_status) {
        return Ok(());
    }
    let current = socket.own();
    let readiness = if socket.tcp_state()?.pending_errors.is_empty() {
        ReadinessFlags(current.0 & !ReadinessFlags::ERROR.0)
    } else {
        current | ReadinessFlags::ERROR
    };
    set_own_readiness(socket, readiness);
    Ok(())
}

#[derive(Clone)]
struct TcpBinding {
    socket_id: u64,
    address: TcpBindingAddress,
}

/// Where a [`TcpBinding`] binds.
#[derive(Clone)]
enum TcpBindingAddress {
    /// The guest address that core reserved for an isolated socket.
    Guest(GuestSocketBinding),
    /// The host address at which a mirrored socket listens. Only listeners are recorded, as the
    /// host lets sockets that do not listen share an address, and only a listener serves one.
    Host(SocketAddrV4),
}

impl TcpBinding {
    fn local_address(&self) -> SocketAddrV4 {
        match &self.address {
            TcpBindingAddress::Guest(binding) => binding.local_address(),
            TcpBindingAddress::Host(address) => *address,
        }
    }

    fn is_wildcard(&self) -> bool {
        match &self.address {
            TcpBindingAddress::Guest(binding) => binding.is_wildcard(),
            TcpBindingAddress::Host(address) => address.ip().is_unspecified(),
        }
    }

    fn is_valid(&self) -> bool {
        match &self.address {
            TcpBindingAddress::Guest(binding) => binding.is_valid(),
            TcpBindingAddress::Host(address) => address.port() != 0,
        }
    }

    /// Returns an isolated socket's guest binding.
    fn guest(&self) -> Option<&GuestSocketBinding> {
        match &self.address {
            TcpBindingAddress::Guest(binding) => Some(binding),
            TcpBindingAddress::Host(_) => None,
        }
    }
}

enum ResolvedTcpDestination {
    Internal {
        listener_id: u64,
        concrete_address: SocketAddrV4,
    },
    External(SocketAddrV4),
}

impl TcpTopology {
    fn insert_binding(&mut self, binding: TcpBinding) -> BrokerResult<()> {
        if !self.admits_binding(&binding) {
            return Err(BrokerError::Internal);
        }
        self.reserve_binding(&binding)?;
        self.insert_reserved_binding(binding);
        Ok(())
    }

    /// Whether `binding` is valid and overlaps no other.
    fn admits_binding(&self, binding: &TcpBinding) -> bool {
        let local_address = binding.local_address();
        binding.is_valid()
            && if binding.is_wildcard() {
                !self.bindings.wildcard.contains_key(&local_address.port())
                    && !self
                        .bindings
                        .exact
                        .keys()
                        .any(|address| address.port() == local_address.port())
            } else {
                !self.bindings.wildcard.contains_key(&local_address.port())
                    && !self.bindings.exact.contains_key(&local_address)
            }
    }

    /// Makes room for `binding`, so that inserting it next cannot fail.
    fn reserve_binding(&mut self, binding: &TcpBinding) -> BrokerResult<()> {
        if binding.is_wildcard() {
            self.bindings.wildcard.try_reserve(1)
        } else {
            self.bindings.exact.try_reserve(1)
        }
        .map_err(|_| BrokerError::OutOfMemory)
    }

    /// Inserts `binding`, which [`Self::admits_binding`] admits, after [`Self::reserve_binding`]
    /// made room for it.
    fn insert_reserved_binding(&mut self, binding: TcpBinding) {
        let local_address = binding.local_address();
        if binding.is_wildcard() {
            self.bindings.wildcard.insert(local_address.port(), binding);
        } else {
            self.bindings.exact.insert(local_address, binding);
        }
    }

    fn remove_binding(&mut self, port: u16, socket_id: u64) {
        if self
            .bindings
            .wildcard
            .get(&port)
            .is_some_and(|binding| binding.socket_id == socket_id)
        {
            self.bindings.wildcard.remove(&port);
            return;
        }
        if let Some(address) = self.bindings.exact.iter().find_map(|(address, binding)| {
            (address.port() == port && binding.socket_id == socket_id).then_some(*address)
        }) {
            self.bindings.exact.remove(&address);
        }
    }

    fn guest_binding(&self, address: SocketAddrV4) -> Option<TcpBinding> {
        self.bindings
            .exact
            .get(&address)
            .or_else(|| self.bindings.wildcard.get(&address.port()))
            .filter(|binding| binding.guest().is_some_and(|guest| guest.covers(address)))
            .cloned()
    }

    fn binding_for_socket(&self, socket_id: u64) -> Option<TcpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .cloned()
    }

    fn resolve_destination(
        &self,
        requested_destination: SocketAddrV4,
    ) -> SocketOutcome<ResolvedTcpDestination> {
        let destination = match normalize_socket_destination(requested_destination) {
            Ok(destination) => destination,
            Err(error) => return SocketOutcome::Failed(error),
        };
        if !is_internal_socket_address(destination) {
            return SocketOutcome::Completed(ResolvedTcpDestination::External(destination));
        }
        let Some(binding) = self.guest_binding(destination) else {
            return SocketOutcome::Failed(SocketError::ConnectionRefused);
        };
        if !self.listeners.contains_key(&binding.socket_id) {
            return SocketOutcome::Failed(SocketError::ConnectionRefused);
        }
        SocketOutcome::Completed(ResolvedTcpDestination::Internal {
            listener_id: binding.socket_id,
            concrete_address: destination,
        })
    }

    /// Resolves a mirrored socket's connect to `destination`: to the listener of the provider's
    /// own that serves it, if any, and otherwise as `egress` lets it reach the host. A listener
    /// serves only a destination that is one of the host's own addresses, as `local` says: one at
    /// the wildcard address serves each, and one at an exact address that one, which a host that
    /// lets sockets bind addresses it does not own reaches by its routes instead. A host refuses
    /// rather than policy denies an unserved destination only if it is its own. Returns `None` if
    /// the answer depends on whether `destination` is the host's own, and `local` does not say.
    fn resolve_mirrored(
        &self,
        destination: SocketAddrV4,
        egress: SocketEgress,
        local: Option<bool>,
    ) -> Option<MirroredTcpDestination> {
        let listening = |binding: &TcpBinding| {
            self.listeners
                .contains_key(&binding.socket_id)
                .then_some(binding.socket_id)
        };
        if let Some(listener_id) = self
            .bindings
            .exact
            .get(&destination)
            .and_then(listening)
            .or_else(|| {
                self.bindings
                    .wildcard
                    .get(&destination.port())
                    .and_then(listening)
            })
            && local != Some(false)
        {
            return local.map(|_| MirroredTcpDestination::Internal(listener_id));
        }
        Some(match egress {
            SocketEgress::Permitted => MirroredTcpDestination::External,
            SocketEgress::ServedOnly if local? => MirroredTcpDestination::Refused,
            SocketEgress::ServedOnly => MirroredTcpDestination::Denied,
        })
    }
}

/// Where a mirrored socket's connect goes.
enum MirroredTcpDestination {
    /// In memory, to the provider's own listener with this ID.
    Internal(u64),
    /// To the host, from the socket's host socket.
    External,
    /// Nowhere: the host would refuse it, as at a local port nobody listens at.
    Refused,
    /// Nowhere: policy denies it.
    Denied,
}

/// What a mirrored connect asks the host, as [`SocketEntry::connect_mirrored_tcp`] describes.
enum HostQuestion {
    /// Whether the destination is one of the host's own addresses.
    DestinationOwned,
    /// Which source address the host's route to the destination selects.
    RouteSource,
    /// Whether the exact address the socket is bound to is one of the host's own.
    SourceOwned,
}

impl Topology {
    /// Checks that `process_key` may queue one more internal
    /// connection, which counts against the socket quotas until it is
    /// accepted or discarded.
    fn check_queued_connection(
        &self,
        process_key: ProcessKey,
        max_sockets: usize,
        max_sockets_per_process: usize,
    ) -> BrokerResult<()> {
        let combined_count = self
            .tcp
            .queued_guest_connection_count
            .checked_add(1)
            .and_then(|count| count.checked_add(self.socket_count))
            .ok_or(BrokerError::ResourceExhausted)?;
        let process = self
            .processes
            .get(&process_key)
            .ok_or(BrokerError::Internal)?;
        let process_count = process
            .pending_guest_connection_count
            .checked_add(1)
            .and_then(|count| count.checked_add(process.live_socket_count))
            .ok_or(BrokerError::ResourceExhausted)?;
        if combined_count > max_sockets || process_count > max_sockets_per_process {
            return Err(BrokerError::ResourceExhausted);
        }
        Ok(())
    }

    fn charge_queued_connection(&mut self, process_key: ProcessKey) {
        self.tcp.queued_guest_connection_count += 1;
        self.process_mut(process_key).pending_guest_connection_count += 1;
    }

    fn release_queued_connections(&mut self, process_key: ProcessKey, count: usize) {
        self.tcp.queued_guest_connection_count = self
            .tcp
            .queued_guest_connection_count
            .checked_sub(count)
            .expect("queued guest connection count underflow");
        let process = self.process_mut(process_key);
        process.pending_guest_connection_count = process
            .pending_guest_connection_count
            .checked_sub(count)
            .expect("process queued guest connection count underflow");
    }

    /// Turns a connection queued by `connector_process_key` into a
    /// socket accepted by `listener_process_key`, if the listener's
    /// process quota allows it.
    ///
    /// The global count is unchanged: one queued connection becomes one
    /// socket.
    fn accept_queued_connection(
        &mut self,
        connector_process_key: ProcessKey,
        listener_process_key: ProcessKey,
        max_sockets_per_process: usize,
    ) -> BrokerResult<()> {
        let listener_process = self
            .processes
            .get(&listener_process_key)
            .ok_or(BrokerError::Internal)?;
        let transferred_pending = usize::from(connector_process_key == listener_process_key);
        let next_listener_total = listener_process
            .live_socket_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?
            .checked_add(listener_process.pending_guest_connection_count)
            .and_then(|count| count.checked_sub(transferred_pending))
            .ok_or(BrokerError::Internal)?;
        if next_listener_total > max_sockets_per_process {
            return Err(BrokerError::ResourceExhausted);
        }
        self.release_queued_connections(connector_process_key, 1);
        self.process_mut(listener_process_key).live_socket_count += 1;
        self.socket_count += 1;
        Ok(())
    }

    /// Removes a connector's queued connection from its listener without
    /// resetting the connector.
    fn remove_queued_connection(&mut self, listener_id: u64, connector_socket_id: u64) {
        let Some(listener) = self.tcp.listeners.get_mut(&listener_id) else {
            return;
        };
        let Some(connection) = listener
            .queue
            .iter()
            .position(|connection| connection.connector_socket_id == connector_socket_id)
            .and_then(|index| listener.queue.remove(index))
        else {
            return;
        };
        publish_listener_queue(listener);
        self.release_queued_connections(connection.connector_process_key, 1);
    }

    /// Discards a closed listener's queue, resetting each live connector.
    fn discard_listener_queue(&mut self, queue: VecDeque<QueuedGuestTcpConnection>) {
        for connection in queue {
            self.release_queued_connections(connection.connector_process_key, 1);
            if let Some(link) = self.tcp.links.remove(&connection.connector_socket_id) {
                post_guest_reset(&link.connector);
            }
            // Dropping `connection` closes the connector's peer end only
            // after its reset is posted.
        }
    }

    /// Removes every connection `process_key` queued, after all of its
    /// sockets retired.
    pub(super) fn purge_connector_process_queues(&mut self, process_key: ProcessKey) {
        let mut purged = 0;
        for listener in self.tcp.listeners.values_mut() {
            let queued = listener.queue.len();
            listener
                .queue
                .retain(|connection| connection.connector_process_key != process_key);
            if listener.queue.len() != queued {
                purged += queued - listener.queue.len();
                publish_listener_queue(listener);
            }
        }
        if purged != 0 {
            self.release_queued_connections(process_key, purged);
        }
    }
}

/// Recomputes a listener's READ from its queue, waking waiters while
/// connections remain queued.
///
/// A listener's queue and its READ change together under `topology`.
fn publish_listener_queue(listener: &TcpListener) {
    let mut inbox = listener.inbox.lock();
    inbox.queue_ready = !listener.queue.is_empty();
    if inbox.queue_ready {
        inbox.republish();
    } else {
        inbox.publish();
    }
}

/// Posts a guest reset to an internal endpoint, which applies it on its next
/// call or event.
fn post_guest_reset(inbox: &SocketInbox) {
    let mut inbox = inbox.lock();
    inbox.reset_posted = true;
    inbox.republish();
}

fn confirm_tcp_connected(socket: &mut SocketEntry<'_>) {
    if socket.connection_status != SocketConnectionStatus::Connecting {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Connected;
    apply_deferred_tcp_options(socket);
}

/// Gives a newly connected host socket the options it refused earlier.
fn apply_deferred_tcp_options(socket: &mut SocketEntry<'_>) {
    if !socket.tcp_state().is_ok_and(|tcp| tcp.options.deferred) {
        return;
    }
    // The guest's set already succeeded, so a host that still refuses the
    // options only keeps its earlier ones.
    let taken = socket
        .tcp_state()
        .is_ok_and(|tcp| give_host_tcp_options(socket, tcp.options).unwrap_or(false));
    if let Ok(tcp) = socket.tcp_state_mut() {
        tcp.options.deferred = !taken;
    }
}

/// Gives the socket's host socket the guest's `options`, and reports whether
/// it took them. A host may refuse them only while a connect is pending or
/// after a connection failed; any other failure is an error. A connect counts
/// as pending until the provider sees it complete, which gives the options
/// again, even if the host completed it since it refused them.
fn give_host_tcp_options(socket: &SocketEntry<'_>, options: TcpOptions) -> BrokerResult<bool> {
    let tcp = socket.tcp_state()?;
    let TcpDescriptor::ExternalInet(host) = &tcp.descriptor else {
        return Ok(true);
    };
    let Err(error) = apply_tcp_options(host, options) else {
        return Ok(true);
    };
    if let Some(error) = error.broker_resource_error() {
        return Err(error);
    }
    socket.core().hook(HookPoint::OptionsRefused(socket.id()));
    let may_refuse = matches!(
        socket.connection_status,
        SocketConnectionStatus::Connecting | SocketConnectionStatus::Failed(_)
    ) || tcp.connection_failed
        || host.error_pending().map_err(broker_error_from_errno)?;
    if may_refuse {
        Ok(false)
    } else {
        Err(broker_error_from_errno(error))
    }
}

/// Records the failure that an external operation reported: a pending
/// connect fails with `error`, and an established external connection is
/// marked failed, as [`TcpSocketState::connection_failed`] describes, and
/// can neither receive nor send, whatever events its host raises.
fn fail_connection(socket: &mut SocketEntry<'_>, error: SocketError) {
    match socket.connection_status {
        SocketConnectionStatus::Connecting => {
            socket.connection_status = SocketConnectionStatus::Failed(error);
            // The host's failed connect holds its pair of addresses no longer.
            if let Ok(tcp) = socket.tcp_state_mut() {
                tcp.host_connection = None;
            }
            let readiness = socket.own() | ReadinessFlags::ERROR;
            set_own_readiness(socket, readiness);
        }
        SocketConnectionStatus::Connected => {
            let Ok(tcp) = socket.tcp_state_mut() else {
                return;
            };
            if !tcp.descriptor.is_external() {
                return;
            }
            tcp.connection_failed = true;
            let readiness = readiness_from_events(socket, SocketEvents::HANGUP);
            set_own_readiness(socket, readiness);
        }
        _ => {}
    }
}

/// Whether a host error shows that its connection counts as established:
/// as the host contract states, a reset, or a stream that can no longer
/// send, is reported only of a connection that the peer took part in. So a
/// pending connect that reports one completed, even if no event has shown
/// it yet. A simultaneous open that the peer resets before it completes
/// counts too, as its socket then behaves as any reset connection's does. A
/// guest's abort of its own pending connect also resets, but the shutdown
/// that aborts it fails the connect first.
const fn shows_established(error: Errno) -> bool {
    matches!(error, Errno::CONNRESET | Errno::PIPE)
}

/// Records the failure that a host call reported with `error`, as
/// [`fail_connection`] describes, and returns the error the call reports.
fn fail_with_call_error(socket: &mut SocketEntry<'_>, error: Errno) -> BrokerResult<SocketError> {
    let reported = socket_operation_error_from_errno(error)?;
    if shows_established(error) {
        confirm_tcp_connected(socket);
    }
    fail_connection(socket, reported);
    Ok(reported)
}

/// Records the failure whose `error` the host socket's `take_error` took, as
/// [`fail_connection`] describes. An established connection keeps the error
/// for the guest's next error report.
fn fail_with_taken_error(socket: &mut SocketEntry<'_>, error: Errno) -> BrokerResult<()> {
    if shows_established(error) {
        confirm_tcp_connected(socket);
    }
    let error = socket_error_from_errno(error);
    fail_connection(socket, error);
    if socket.connection_status == SocketConnectionStatus::Connected {
        socket
            .tcp_state_mut()?
            .pending_errors
            .append(TcpPendingError::Socket(error));
        add_readiness(socket, ReadinessFlags::ERROR);
    }
    Ok(())
}

/// Aborts a pending external connect, as shutting it down does: closes its
/// host socket, which resets the connection should the host complete it
/// first, and fails the connect with a reset.
fn abort_pending_connect(socket: &mut SocketEntry<'_>) -> BrokerResult<()> {
    let core = socket.core();
    let tcp = socket.tcp_state_mut()?;
    // As on Linux, a mirrored socket keeps a port the guest named until it closes.
    let keep_port = core.mirrored() && tcp.named_port;
    if !keep_port {
        tcp.descriptor
            .socket()?
            .set_linger_zero()
            .map_err(broker_error_from_errno)?;
    }
    if let TcpDescriptor::ExternalInet(mut host_socket) =
        core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized)
    {
        core.unwatch_host_socket(&mut host_socket);
        tcp.host_connection = None;
        if keep_port {
            // A host that cannot stop the connect so closes the socket, which releases the port.
            match host_socket.disconnect() {
                Ok(()) => tcp.descriptor = TcpDescriptor::Bound(host_socket),
                Err(_) => {
                    let _ = host_socket.set_linger_zero();
                }
            }
        }
    }
    socket.connection_status = SocketConnectionStatus::Failed(SocketError::ConnectionReset);
    set_own_readiness(socket, ReadinessFlags::ERROR);
    Ok(())
}

/// Records the receive by `reader` for the peek continuation check, failing
/// with `WouldBlock` if it is a request past offset zero that does not
/// continue `reader`'s peek.
///
/// A peek longer than one transfer takes one request at each offset. A
/// receive by another reader between them may consume bytes the earlier
/// requests returned, so the rest of the peek would not follow them. The
/// interrupted reader then returns the bytes it already has.
fn continue_peek(
    tcp: &mut TcpSocketState,
    reader: ObjectHandle,
    flags: ReceiveFlags,
    peek_offset: usize,
) -> BrokerResult<()> {
    if !flags.contains(ReceiveFlags::PEEK) {
        tcp.peek_reader = None;
    } else if peek_offset == 0 {
        tcp.peek_reader = Some(reader);
    } else if tcp.peek_reader != Some(reader) {
        return Err(BrokerError::WouldBlock);
    }
    Ok(())
}

fn validate_peek_window(
    length: usize,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<usize> {
    let peek_end = peek_offset
        .checked_add(length)
        .ok_or(BrokerError::UnsupportedOperation)?;
    let canonical_length = peek_length
        .checked_sub(peek_offset)
        .map(|remaining| remaining.min(MAX_SOCKET_TRANSFER_SIZE as usize));
    if !peek_offset.is_multiple_of(MAX_SOCKET_TRANSFER_SIZE as usize)
        || canonical_length != Some(length)
        || peek_length > MAX_SOCKET_PEEK_SIZE as usize
    {
        return Err(BrokerError::UnsupportedOperation);
    }
    Ok(peek_end)
}

/// Returns whether a peek is one window, which reads straight into its
/// output, rather than one of several served from the peek cache.
fn single_window_peek(length: usize, peek_offset: usize, peek_length: usize) -> bool {
    peek_offset == 0 && peek_length == length
}

/// Allocates the peek cache a multi-window peek at offset zero reads into,
/// before its socket is locked, so the lock is not held while zeroing a
/// large peek window.
///
/// Any other receive reads straight into its output or is served from the
/// cache, and gets an empty buffer. So does an invalid peek window, whose
/// receive reports the error after its other checks.
pub(super) fn tcp_peek_buffer(
    length: usize,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<Vec<u8>> {
    if !flags.contains(ReceiveFlags::PEEK)
        || peek_offset != 0
        || single_window_peek(length, peek_offset, peek_length)
        || validate_peek_window(length, peek_offset, peek_length).is_err()
    {
        return Ok(Vec::new());
    }
    zeroed_vec(peek_length)
}

fn receive_socket(
    socket: &mut SocketEntry<'_>,
    output: RawParts<'_>,
    peek_buffer: Vec<u8>,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<ReceiveOutcome> {
    let length = output.len();
    if socket.kind() != SocketKind::Tcp {
        return Ok(ReceiveOutcome::Failed(SocketError::InvalidArgument));
    }
    if guest_reset_pending(socket)? && socket.tcp_state()?.descriptor.queued_bytes()? == 0 {
        if !consume_pending_guest_reset(socket, true)? {
            return Err(BrokerError::Internal);
        }
        return Ok(ReceiveOutcome::Failed(SocketError::ConnectionReset));
    }
    match socket.connection_status {
        SocketConnectionStatus::Unconnected => {
            return Ok(ReceiveOutcome::Failed(SocketError::NotConnected));
        }
        SocketConnectionStatus::Failed(error) => {
            return Ok(ReceiveOutcome::Failed(error));
        }
        _ => {}
    }
    let peek = flags.contains(ReceiveFlags::PEEK);
    if !peek {
        if peek_offset != 0 || peek_length != 0 {
            return Err(BrokerError::UnsupportedOperation);
        }
        socket.tcp_state_mut()?.peek_cache = None;
        return receive_socket_once(socket, output, ReceiveMode::Read);
    }

    let peek_end = validate_peek_window(length, peek_offset, peek_length)?;
    if flags.contains(ReceiveFlags::WAITALL)
        && !receive_closed(socket)
        && socket.tcp_state()?.descriptor.queued_bytes()? < peek_length
    {
        let tcp = socket.tcp_state_mut()?;
        tcp.peek_waitall = Some(PeekWaitAll {
            length: tcp
                .peek_waitall
                .map_or(peek_length, |wait| wait.length.min(peek_length)),
            since: Instant::now(),
        });
        // The host reports no arrival while data is queued, so the event
        // thread polls until the peek's data arrives.
        if !Poller::REPORTS_EVERY_ARRIVAL && tcp.descriptor.is_external() {
            socket.core().posted.post(socket.id());
        }
        return Err(BrokerError::WouldBlock);
    }
    let peek_mode = if flags.contains(ReceiveFlags::WAITALL) {
        ReceiveMode::PeekAll
    } else {
        ReceiveMode::Peek
    };
    if single_window_peek(length, peek_offset, peek_length) {
        socket.tcp_state_mut()?.peek_cache = None;
        return receive_socket_once(socket, output, peek_mode);
    }

    let refresh_exhausted_cache = match socket.tcp_state()?.peek_cache.as_ref() {
        Some(cache) if cache.requested_length == peek_length && cache.data.len() <= peek_offset => {
            socket.tcp_state()?.descriptor.queued_bytes()? > cache.data.len()
        }
        _ => false,
    };
    let refresh = peek_offset == 0
        || socket
            .tcp_state()?
            .peek_cache
            .as_ref()
            .is_none_or(|cache| cache.requested_length != peek_length)
        || refresh_exhausted_cache;
    if refresh {
        socket.tcp_state_mut()?.peek_cache = None;
        let mut data = if peek_buffer.len() == peek_length {
            peek_buffer
        } else {
            zeroed_vec(peek_length)?
        };
        let part = [RawBytes::from(data.as_mut_slice())];
        match receive_socket_once(socket, RawParts::from(&part), peek_mode)? {
            ReceiveOutcome::Received(received) => {
                data.truncate(received);
                socket.tcp_state_mut()?.peek_cache = Some(PeekCache {
                    requested_length: peek_length,
                    data,
                });
            }
            outcome => return Ok(outcome),
        }
    }

    let exhausted = socket
        .tcp_state()?
        .peek_cache
        .as_ref()
        .ok_or(BrokerError::Internal)?
        .data
        .len()
        <= peek_offset;
    if exhausted {
        socket.tcp_state_mut()?.peek_cache = None;
        return if receive_closed(socket) {
            Ok(ReceiveOutcome::EndOfStream)
        } else {
            Err(BrokerError::WouldBlock)
        };
    }
    let tcp = socket.tcp_state_mut()?;
    let cache = tcp.peek_cache.as_ref().ok_or(BrokerError::Internal)?;
    let end = peek_end.min(cache.data.len());
    output.copy_from_slice(&cache.data[peek_offset..end]);
    if end < peek_end || end == peek_length {
        tcp.peek_cache = None;
    }
    Ok(ReceiveOutcome::Received(end - peek_offset))
}

fn receive_socket_once(
    socket: &mut SocketEntry<'_>,
    output: RawParts<'_>,
    mode: ReceiveMode,
) -> BrokerResult<ReceiveOutcome> {
    socket.core().hook(HookPoint::Receiving(socket.id()));
    loop {
        let received = match socket.tcp_state()?.descriptor.receive(output, mode)? {
            Ok(received) => received,
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => {
                socket.core().hook(HookPoint::Eagain(socket.id()));
                clear_readiness(socket, ReadinessFlags::READ);
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                if take_late_guest_reset(socket)? {
                    return Ok(ReceiveOutcome::Failed(SocketError::ConnectionReset));
                }
                // A connection's failure, once reported, ends the stream.
                if !socket.tcp_state()?.connection_failed {
                    let error = fail_with_call_error(socket, error)?;
                    let _ = consume_synchronous_error(socket);
                    return Ok(ReceiveOutcome::Failed(error));
                }
                socket_operation_error_from_errno(error)?;
                0
            }
        };
        if received == 0 {
            if take_late_guest_reset(socket)? {
                return Ok(ReceiveOutcome::Failed(SocketError::ConnectionReset));
            }
            confirm_tcp_connected(socket);
            let readiness = if socket.read_shutdown {
                ReadinessFlags::READ
            } else {
                ReadinessFlags::READ | ReadinessFlags::HANGUP
            };
            add_readiness(socket, readiness);
            return Ok(ReceiveOutcome::EndOfStream);
        }
        confirm_tcp_connected(socket);
        let terminal_readable =
            socket.read_shutdown || socket.own().contains(ReadinessFlags::HANGUP);
        if !mode.is_peek() && !terminal_readable && nothing_to_receive(socket) {
            clear_readiness(socket, ReadinessFlags::READ);
        }
        return Ok(ReceiveOutcome::Received(received));
    }
}

fn apply_tcp_options(socket: &Socket, options: TcpOptions) -> Result<(), Errno> {
    socket.set_no_delay(options.no_delay)?;
    socket.set_keep_alive(options.keep_alive)
}

fn shutdown_tcp_stream(
    socket: &mut SocketEntry<'_>,
    mode: ShutdownMode,
) -> BrokerResult<SocketOutcome<()>> {
    if mode == ShutdownMode::Abort {
        if socket.tcp_state()?.descriptor.is_external() {
            socket
                .tcp_state()?
                .descriptor
                .socket()?
                .set_linger_zero()
                .map_err(broker_error_from_errno)?;
        }
        socket.tcp_state_mut()?.abortive_close = true;
        return Ok(SocketOutcome::Completed(()));
    }
    if socket.tcp_state()?.listening {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    // A failed socket has no connection to shut down.
    if matches!(
        socket.tcp_state()?.descriptor,
        TcpDescriptor::Unrealized | TcpDescriptor::Bound(_) | TcpDescriptor::Listener(_)
    ) || matches!(socket.connection_status, SocketConnectionStatus::Failed(_))
    {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let (add, clear, shuts_down_read, shuts_down_write) = match mode {
        ShutdownMode::Read => (
            ReadinessFlags::READ | ReadinessFlags::HANGUP,
            ReadinessFlags::default(),
            true,
            false,
        ),
        ShutdownMode::Write => (
            ReadinessFlags::default(),
            ReadinessFlags::WRITE,
            false,
            true,
        ),
        ShutdownMode::Both => (
            ReadinessFlags::READ | ReadinessFlags::HANGUP,
            ReadinessFlags::WRITE,
            true,
            true,
        ),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    if let TcpDescriptor::Internal(end) = &socket.tcp_state()?.descriptor {
        // A stream keeps the data queued before a read shutdown readable and
        // discards later data. This is the broker's choice for its own
        // streams; hosts differ in what data a read shutdown lets arrive.
        if shuts_down_read {
            end.shutdown_read();
        }
        if shuts_down_write {
            end.finish();
        }
    } else {
        if socket.connection_status == SocketConnectionStatus::Connecting {
            let host = socket.tcp_state()?.descriptor.socket()?;
            if let Some(error) = host.take_error().map_err(broker_error_from_errno)? {
                // The connect already failed, or completed and then its
                // connection failed, so there is nothing to abort or shut
                // down.
                fail_with_taken_error(socket, error)?;
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            if host.connect_pending().map_err(broker_error_from_errno)? {
                abort_pending_connect(socket)?;
                return Ok(SocketOutcome::Completed(()));
            }
        }
        // A failed connection has nothing to shut down, and an error not yet
        // reported stays pending.
        if socket.tcp_state()?.connection_failed
            || socket
                .tcp_state()?
                .descriptor
                .socket()?
                .error_pending()
                .map_err(broker_error_from_errno)?
        {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let host_shutdown = match (shuts_down_read, shuts_down_write) {
            (true, true) => Shutdown::Both,
            (true, false) => Shutdown::Read,
            (false, _) => Shutdown::Write,
        };
        loop {
            match socket
                .tcp_state()?
                .descriptor
                .socket()?
                .shutdown(host_shutdown)
            {
                Ok(()) => break,
                Err(Errno::INTR) => {}
                // The connection failed or is not yet connected, which an
                // event or a later call reports, whatever error the shutdown
                // fails with.
                Err(error) => {
                    socket_operation_error_from_errno(error)?;
                    return Ok(SocketOutcome::Failed(SocketError::NotConnected));
                }
            }
        }
    }
    socket.read_shutdown |= shuts_down_read;
    socket.write_shutdown |= shuts_down_write;
    let republish_readiness =
        shuts_down_read && socket.tcp_state_mut()?.peek_waitall.take().is_some();
    let current = socket.own();
    let readiness = with_tcp_closed(socket, ReadinessFlags((current.0 & !clear.0) | add.0));
    if republish_readiness {
        republish_own_readiness(socket, readiness);
    } else {
        set_own_readiness(socket, readiness);
    }
    Ok(SocketOutcome::Completed(()))
}

/// Applies host `events`, raised under `token`, to the socket.
///
/// Returns whether the event thread should apply an empty event soon,
/// because a peek waits for more data than the socket holds and its host
/// does not report each arrival.
pub(super) fn handle_socket_event(
    socket: &mut SocketEntry<'_>,
    token: u64,
    events: SocketEvents,
) -> BrokerResult<bool> {
    let listener_event = token & LISTENER_EVENT_TOKEN_FLAG != 0;
    // An internal endpoint's wakeups carry no events; its stream's state is
    // the source of truth.
    let (mut events, polled) = match &socket.tcp_state()?.descriptor {
        // A host listener's event may mean a connection to accept, or an error the accept reports.
        // An accept may have taken the connection since, so an edge counts only while one waits.
        // A mirrored listener's host socket polled as hung up before it listened, so its hang-up
        // means nothing.
        TcpDescriptor::Listener(listener) => {
            let failed = events.contains(SocketEvents::ERROR)
                || (!listener_event && events.contains(SocketEvents::HANGUP));
            let readable = events.contains(SocketEvents::READABLE);
            if failed || (readable && listener.stream_readable() != Ok(false)) {
                add_readiness(socket, ReadinessFlags::READ);
            }
            return Ok(false);
        }
        // An event of a host socket from a listen that failed.
        _ if listener_event => return Ok(false),
        TcpDescriptor::Internal(end) => (stream_events(end), false),
        TcpDescriptor::ExternalInet(_) => (events, !Poller::REPORTS_EVERY_ARRIVAL),
        TcpDescriptor::Unrealized | TcpDescriptor::Bound(_) => (events, false),
    };
    // A connection's failure, once reported, raises no more errors.
    if socket.tcp_state()?.connection_failed {
        events.remove(SocketEvents::ERROR);
    }
    let (republish_readiness, wait_pending) = if (polled || events.contains(SocketEvents::READABLE))
        && let Some(wait) = socket.tcp_state().ok().and_then(|tcp| tcp.peek_waitall)
    {
        let wait_ended = wait.since.elapsed() >= PEEK_WAITALL_INTEREST
            || socket
                .tcp_state()
                .and_then(|tcp| tcp.descriptor.queued_bytes())
                .ok()
                .is_none_or(|available| available >= wait.length);
        if wait_ended {
            socket.tcp_state_mut()?.peek_waitall = None;
        }
        (wait_ended, !wait_ended)
    } else {
        (false, false)
    };
    match socket.connection_status {
        SocketConnectionStatus::Connecting => {
            complete_connect(socket, events)?;
        }
        SocketConnectionStatus::Connected => {
            set_own_readiness(socket, readiness_from_events(socket, events));
        }
        SocketConnectionStatus::Failed(SocketError::NotConnected) if socket.read_shutdown => {
            set_own_readiness(socket, ReadinessFlags::WRITE | ReadinessFlags::HANGUP);
        }
        SocketConnectionStatus::Failed(_) => {
            set_own_readiness(socket, ReadinessFlags::ERROR);
        }
        // A stale event of a host listener that a failed listen closed.
        SocketConnectionStatus::Unconnected => {}
        _ => return Err(BrokerError::Internal),
    }
    if republish_readiness {
        socket.inbox().republish();
    }
    Ok(polled && wait_pending && !peek_waitall_ended(socket))
}

/// Whether a socket's peek waiting for data can no longer receive more.
fn peek_waitall_ended(socket: &SocketEntry<'_>) -> bool {
    socket.connection_status != SocketConnectionStatus::Connected || receive_closed(socket)
}

/// Whether the socket's receive side is closed, so no data will arrive
/// beyond what it already holds.
fn receive_closed(socket: &SocketEntry<'_>) -> bool {
    let readiness = socket.own();
    socket.read_shutdown
        || readiness.contains(ReadinessFlags::HANGUP)
        || readiness.contains(ReadinessFlags::ERROR)
        || socket.tcp_state().is_ok_and(|tcp| tcp.connection_failed)
}

fn complete_connect(socket: &mut SocketEntry<'_>, events: SocketEvents) -> BrokerResult<()> {
    if !socket.tcp_state()?.descriptor.is_external() {
        return Err(BrokerError::Internal);
    }
    match socket.tcp_state()?.descriptor.socket()?.take_error() {
        Ok(Some(error)) => {
            fail_with_taken_error(socket, error)?;
            // A connection that the host established applies the event as
            // any established connection's does.
            if socket.connection_status == SocketConnectionStatus::Connected {
                set_own_readiness(socket, readiness_from_events(socket, events));
            }
            Ok(())
        }
        Ok(None) if events.contains(SocketEvents::WRITABLE) => {
            confirm_tcp_connected(socket);
            set_own_readiness(socket, readiness_from_events(socket, events));
            Ok(())
        }
        Ok(None) => {
            set_own_readiness(socket, ReadinessFlags::default());
            Ok(())
        }
        Err(error) => Err(broker_error_from_errno(error)),
    }
}

impl SocketEntry<'_> {
    /// Applies a guest reset another socket posted to this socket's inbox.
    pub(super) fn drain_guest_reset(&mut self) -> BrokerResult<()> {
        let mut inbox = self.inbox();
        if !inbox.reset_posted {
            return Ok(());
        }
        inbox.reset_posted = false;
        let tcp = self.tcp_state_mut()?;
        if let Some(endpoint) = tcp.guest_endpoint.as_mut()
            && endpoint.reset_state == GuestTcpResetState::None
        {
            endpoint.reset_state = GuestTcpResetState::Pending;
            tcp.pending_errors.append(TcpPendingError::GuestReset);
            inbox.own = inbox.own
                | ReadinessFlags::READ
                | ReadinessFlags::ERROR
                | ReadinessFlags::HANGUP
                | ReadinessFlags::CLOSED;
        }
        inbox.publish();
        Ok(())
    }

    pub(super) fn send_tcp_socket(
        &mut self,
        data: RawParts<'_>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        if self.kind() != SocketKind::Tcp {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if self.write_shutdown {
            return Ok(SocketOutcome::Failed(SocketError::Shutdown));
        }
        if guest_reset_pending(self)? {
            if !consume_pending_guest_reset(self, true)? {
                return Err(BrokerError::Internal);
            }
            return Ok(SocketOutcome::Failed(SocketError::ConnectionReset));
        }
        match self.connection_status {
            SocketConnectionStatus::Unconnected => {
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            SocketConnectionStatus::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            _ => {}
        }
        if self.tcp_state()?.connection_failed {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        loop {
            match self.tcp_state()?.descriptor.send(data)? {
                Ok(sent) => {
                    if sent != 0 {
                        confirm_tcp_connected(self);
                    }
                    return Ok(SocketOutcome::Completed(sent));
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    clear_readiness(self, ReadinessFlags::WRITE);
                    return Err(BrokerError::WouldBlock);
                }
                Err(error) => {
                    if take_late_guest_reset(self)? {
                        return Ok(SocketOutcome::Failed(SocketError::ConnectionReset));
                    }
                    let error = fail_with_call_error(self, error)?;
                    let _ = consume_synchronous_error(self);
                    return Ok(SocketOutcome::Failed(error));
                }
            }
        }
    }

    /// Receives into `output`; a multi-window peek at offset zero reads into
    /// `peek_buffer`, which [`tcp_peek_buffer`] allocated for this request.
    pub(super) fn receive_tcp_socket(
        &mut self,
        reader: ObjectHandle,
        output: RawParts<'_>,
        peek_buffer: Vec<u8>,
        flags: ReceiveFlags,
        peek_offset: usize,
        peek_length: usize,
    ) -> BrokerResult<ReceiveOutcome> {
        let mut ended_peek_wait = false;
        if self.kind() == SocketKind::Tcp {
            let tcp = self.tcp_state_mut()?;
            continue_peek(tcp, reader, flags, peek_offset)?;
            // Any other receive may mean the guest stopped waiting for a
            // `MSG_PEEK | MSG_WAITALL` peek's data, so stop watching for it.
            // Republishing readiness lets a peek another thread still waits
            // in retry, which watches for its data again.
            if !(flags.contains(ReceiveFlags::PEEK) && flags.contains(ReceiveFlags::WAITALL)) {
                ended_peek_wait = tcp.peek_waitall.take().is_some();
            }
        }
        let outcome = receive_socket(self, output, peek_buffer, flags, peek_offset, peek_length);
        if ended_peek_wait {
            self.inbox().republish();
        }
        outcome
    }

    pub(super) fn set_tcp_socket_option(&mut self, value: SocketOptionValue) -> BrokerResult<()> {
        if self.kind() != SocketKind::Tcp {
            return Err(BrokerError::UnsupportedOperation);
        }
        if let SocketOptionValue::ReuseAddress(value) = value {
            return self.set_mirrored_reuse_address(value);
        }
        let mut options = self.tcp_state()?.options;
        match value {
            SocketOptionValue::NoDelay(value) => options.no_delay = value,
            SocketOptionValue::KeepAlive(value) => options.keep_alive = value,
            _ => return Err(BrokerError::UnsupportedOperation),
        }
        // A host socket that refuses the options gets them if it connects.
        options.deferred = !give_host_tcp_options(self, options)?;
        self.tcp_state_mut()?.options = options;
        Ok(())
    }

    pub(super) fn get_tcp_socket_option(
        &self,
        name: SocketOptionName,
    ) -> BrokerResult<SocketOptionValue> {
        if self.kind() != SocketKind::Tcp {
            return Err(BrokerError::UnsupportedOperation);
        }
        // The host socket gets these options when it is created, on each set,
        // and when a connect completes after it refused them, so they are
        // answered here, where a host that refused them still has them.
        let options = self.tcp_state()?.options;
        match name {
            SocketOptionName::NoDelay => Ok(SocketOptionValue::NoDelay(options.no_delay)),
            SocketOptionName::KeepAlive => Ok(SocketOptionValue::KeepAlive(options.keep_alive)),
            SocketOptionName::ReuseAddress if self.core().mirrored() => {
                Ok(SocketOptionValue::ReuseAddress(options.reuse_address))
            }
            _ => Err(BrokerError::UnsupportedOperation),
        }
    }

    /// Sets a mirrored socket's `SO_REUSEADDR` on its host socket, if any, for the host's binds
    /// and listens that follow and the connections it accepts, on the port it shares with
    /// its in-memory connections, if any, and, for a listener, for the connections queued on it
    /// next.
    fn set_mirrored_reuse_address(&mut self, value: bool) -> BrokerResult<()> {
        if !self.core().mirrored() {
            return Err(BrokerError::UnsupportedOperation);
        }
        let tcp = self.tcp_state_mut()?;
        let host = match &tcp.descriptor {
            TcpDescriptor::Bound(host)
            | TcpDescriptor::ExternalInet(host)
            | TcpDescriptor::Listener(host) => Some(host),
            TcpDescriptor::Unrealized | TcpDescriptor::Internal(_) => None,
        };
        if let Some(host) = host {
            host.set_reuse_address(value)
                .map_err(broker_error_from_errno)?;
        }
        if let Some(share) = &mut tcp.port_share
            && let Err(error) = share.set_reuse_address(value)
        {
            if let Some(host) = host {
                // Best effort: the host just took the option, so it takes it back.
                let _ = host.set_reuse_address(tcp.options.reuse_address);
            }
            return Err(error);
        }
        tcp.options.reuse_address = value;
        if tcp.listening {
            // The connections queued on the listener from now on take the option.
            let id = self.id();
            if let Some(port) = self
                .topology()
                .tcp
                .listeners
                .get_mut(&id)
                .and_then(|listener| listener.port.as_mut())
            {
                port.reuse_address = value;
            }
        }
        Ok(())
    }

    pub(super) fn shutdown_tcp_socket(
        &mut self,
        mode: ShutdownMode,
    ) -> BrokerResult<SocketOutcome<()>> {
        if self.kind() != SocketKind::Tcp {
            return Err(BrokerError::Internal);
        }
        self.tcp_state_mut()?.peek_cache = None;
        if mode != ShutdownMode::StopListening {
            return shutdown_tcp_stream(self, mode);
        }
        if !self.tcp_state()?.listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let mut topology = self.topology();
        let listener = topology
            .tcp
            .listeners
            .remove(&self.id())
            .ok_or(BrokerError::Internal)?;
        if self.core().mirrored()
            && let Some(address) = self.guest_local_address
        {
            topology.tcp.remove_binding(address.port(), self.id());
            // As on Linux, the socket keeps a port the guest named until it closes.
            let named_port = self.tcp_state()?.named_port;
            self.stop_mirrored_listener(named_port);
        }
        let tcp = self.tcp_state_mut()?;
        tcp.listening = false;
        tcp.peek_waitall = None;
        self.read_shutdown = true;
        self.connection_status = SocketConnectionStatus::Failed(SocketError::NotConnected);
        {
            let mut inbox = listener.inbox.lock();
            inbox.queue_ready = false;
            inbox.set_own(ReadinessFlags::WRITE | ReadinessFlags::HANGUP);
        }
        topology.discard_listener_queue(listener.queue);
        drop(topology);
        self.close_host_listener();
        Ok(SocketOutcome::Completed(()))
    }

    /// Stops a mirrored listener's host socket, which stops listening and leaves no client of
    /// the host's to accept, but stays bound in the listener's [`HeldPort`] for the connections
    /// the listener accepted in memory, and, if `keep_port`, for the listener itself.
    ///
    /// Runs under `topology`, once the listener's binding is gone from it, so that from then on
    /// no connect, in memory or through the host, reaches the listener.
    fn stop_mirrored_listener(&mut self, keep_port: bool) {
        let core = self.core();
        let Ok(tcp) = self.tcp_state_mut() else {
            return;
        };
        if let TcpDescriptor::Listener(_) = tcp.descriptor
            && let TcpDescriptor::Listener(mut host) =
                core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized)
        {
            core.unwatch_host_socket(&mut host);
            if let Some(share) = &tcp.port_share {
                share.port.hold_listener(host);
            }
        }
        if !keep_port {
            tcp.port_share = None;
        }
    }

    /// Hands back a listener's host socket, if any: a rule's resets its clients until a guest
    /// listens again, and a mirror's closes.
    fn close_host_listener(&mut self) {
        let core = self.core();
        let port = self.guest_local_address.map_or(0, |address| address.port());
        if let Ok(tcp) = self.tcp_state_mut()
            && matches!(tcp.descriptor, TcpDescriptor::Listener(_))
            && let TcpDescriptor::Listener(host) =
                core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized)
        {
            core.release_published(Protocol::Tcp, port, host);
        }
    }

    pub(super) fn bind_tcp_socket(
        &mut self,
        binding: GuestSocketBinding,
        already_bound: bool,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if already_bound {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = binding.local_address();
        self.topology().tcp.insert_binding(TcpBinding {
            socket_id: self.id(),
            address: TcpBindingAddress::Guest(binding),
        })?;
        self.guest_local_address = Some(guest_address);
        Ok(SocketOutcome::Completed(guest_address))
    }

    /// Binds a mirrored socket's host socket as `request` asks and the socket's `SO_REUSEADDR`
    /// directs, and returns the address the host bound. A failed bind leaves the socket unbound.
    ///
    /// For port 0, the host chooses a port as it would for its own socket, but the socket then
    /// binds it as one the guest named, which, unlike one the host chose, stays bound when the
    /// socket stops listening or connecting, as the connections it served in memory need. The
    /// port is the guest's only once bound so; if another socket takes it in between, the host
    /// chooses again.
    pub(super) fn bind_mirrored_tcp(
        &mut self,
        request: HostBindRequest,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if self.guest_local_address.is_some()
            || !matches!(self.tcp_state()?.descriptor, TcpDescriptor::Unrealized)
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        // Read under the socket's `state`, as a set of the option is, so that the bind follows
        // the latest.
        let reuse_address = self.tcp_state()?.options.reuse_address;
        let named_port = request.address().port() != 0;
        let mut choices = 0;
        let bound = loop {
            let address = if named_port {
                request.address()
            } else {
                match host_chosen_port(request.address())? {
                    Ok(address) => address,
                    Err(error) => break Err(error),
                }
            };
            let host = Socket::tcp().map_err(broker_error_from_errno)?;
            // A port the host chose binds exclusively, as it would, and shares only after.
            match host.bind_as_guest(address, named_port && reuse_address) {
                Ok(()) => break Ok(host),
                Err(Errno::ADDRINUSE) if !named_port && choices < MAX_PORT_CHOICES => choices += 1,
                Err(error) => break Err(error),
            }
        };
        let host = match bound {
            Ok(host) => host,
            // The guest sees the host's refusal as Linux's `EACCES`, which only a denial reports.
            Err(Errno::ACCES) => return Ok(SocketOutcome::Failed(SocketError::PolicyDenied)),
            Err(error) => {
                return socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
            }
        };
        if !named_port && reuse_address {
            host.set_reuse_address(true)
                .map_err(broker_error_from_errno)?;
        }
        let local_address = host.local_address().map_err(broker_error_from_errno)?;
        let tcp = self.tcp_state_mut()?;
        tcp.descriptor = TcpDescriptor::Bound(host);
        tcp.named_port = named_port;
        self.guest_local_address = Some(local_address);
        Ok(SocketOutcome::Completed(local_address))
    }

    pub(super) fn release_mirrored_connect_bind(
        &mut self,
        address: SocketAddrV4,
    ) -> BrokerResult<()> {
        if !self.core().mirrored()
            || self.guest_local_address != Some(address)
            || self.connection_status != SocketConnectionStatus::Unconnected
        {
            return Err(BrokerError::Internal);
        }
        let tcp = self.tcp_state_mut()?;
        if tcp.named_port || !matches!(tcp.descriptor, TcpDescriptor::Bound(_)) {
            return Err(BrokerError::Internal);
        }
        // A bound non-listener has neither a topology entry nor a poller watch.
        tcp.descriptor = TcpDescriptor::Unrealized;
        self.guest_local_address = None;
        Ok(())
    }

    pub(super) fn connect_tcp_destination(
        &mut self,
        requested_destination: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
        egress: SocketEgress,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        if self.core().mirrored() {
            // The provider names a mirrored socket's port itself.
            drop(guest_source_lease);
            return self.connect_mirrored_tcp(requested_destination, egress);
        }
        debug_assert_eq!(egress, SocketEgress::Permitted);
        if self.guest_local_address.is_none() {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let mut topology = self.topology();
        let binding = topology
            .tcp
            .binding_for_socket(self.id())
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let destination = match topology.tcp.resolve_destination(requested_destination) {
            SocketOutcome::Completed(destination) => destination,
            SocketOutcome::Failed(error) => {
                drop(topology);
                drop(guest_source_lease);
                let status = SocketConnectionStatus::Failed(error);
                self.connection_status = status;
                set_own_readiness(self, ReadinessFlags::ERROR);
                return Ok(status);
            }
        };
        match destination {
            ResolvedTcpDestination::Internal {
                listener_id,
                concrete_address,
            } => {
                let source_address = binding
                    .guest()
                    .and_then(|guest| guest.source_address_for_destination(concrete_address))
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                let guest_source_lease = guest_source_lease
                    .filter(|lease| lease.source_address() == source_address)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                self.connect_internal_tcp(
                    &mut topology,
                    listener_id,
                    concrete_address,
                    guest_source_lease,
                )
            }
            ResolvedTcpDestination::External(external_destination) => {
                drop(topology);
                drop(guest_source_lease);
                let guest_local_address = binding
                    .guest()
                    .and_then(|guest| guest.source_address_for_destination(external_destination))
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                self.connect_external_tcp_socket(
                    host_socket_destination(external_destination),
                    guest_local_address,
                    None,
                )
            }
        }
    }

    /// Connects a mirrored socket to `requested_destination`: in memory if a listener of the
    /// provider's own serves it, and otherwise from its host socket, if `egress` lets it. One that
    /// policy denies, or whose addresses another connection uses, leaves the socket as it was, as
    /// does one that cannot learn what it needs of the host.
    fn connect_mirrored_tcp(
        &mut self,
        requested_destination: SocketAddrV4,
        egress: SocketEgress,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let local_address = self
            .guest_local_address
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        if self.connection_status != SocketConnectionStatus::Unconnected
            || !matches!(
                self.tcp_state()
                    .map_err(PlatformConnectError::PeerUnchanged)?
                    .descriptor,
                TcpDescriptor::Bound(_)
            )
        {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let destination = match SocketAddressing::Host.normalize_destination(requested_destination)
        {
            Ok(destination) => destination,
            Err(error) => return Ok(self.fail_mirrored_connect(error)),
        };
        // What the host says: whether the destination is one of the host's own addresses; for a
        // socket bound to the wildcard address, which source address the host's route to it
        // selects; and for one bound to an exact address, whether that is the host's own, as a
        // host that lets sockets bind others sends from no route from them. Asking takes system
        // calls, made outside `topology` and only once an answer matters. None depends on the
        // provider's sockets, while whether a listener serves the destination, and which pairs
        // of addresses their connections hold, do, so those are decided under `topology`, along
        // with the connect, so that neither changes in between. Each pass but the last learns
        // one answer, so there are at most three.
        let bound_ip = *local_address.ip();
        let mut local = None;
        let mut route_source = None;
        let mut source_owned = None;
        let (mut topology, resolved) = loop {
            let topology = self.topology();
            let resolved = topology.tcp.resolve_mirrored(destination, egress, local);
            let source_unknown = bound_ip.is_unspecified() && route_source.is_none();
            let question = match resolved {
                None => HostQuestion::DestinationOwned,
                Some(MirroredTcpDestination::Internal(_)) if source_unknown => {
                    HostQuestion::RouteSource
                }
                Some(MirroredTcpDestination::Internal(_))
                    if !bound_ip.is_unspecified() && source_owned.is_none() =>
                {
                    HostQuestion::SourceOwned
                }
                Some(resolved) => break (topology, resolved),
            };
            drop(topology);
            match question {
                HostQuestion::DestinationOwned => {
                    let owned = Socket::owns_address(*destination.ip());
                    local = Some(owned.map_err(rejected_from_errno)?);
                }
                HostQuestion::RouteSource => {
                    // This local listener's concrete IP is a valid source even without a UDP
                    // route hint. The connection itself never leaves broker memory.
                    route_source = Some(
                        Socket::preferred_source_for(destination)
                            .map_err(rejected_from_errno)?
                            .unwrap_or(*destination.ip()),
                    );
                }
                HostQuestion::SourceOwned => {
                    source_owned = Some(match local {
                        Some(owned) if bound_ip == *destination.ip() => owned,
                        _ => Socket::owns_address(bound_ip).map_err(rejected_from_errno)?,
                    });
                }
            }
        };
        match resolved {
            MirroredTcpDestination::Internal(listener_id) => {
                // As the host fails a connect from no route, without changing the socket.
                if source_owned == Some(false) {
                    return Err(PlatformConnectError::Rejected(
                        SocketError::NetworkUnreachable,
                    ));
                }
                let source =
                    SocketAddrV4::new(route_source.unwrap_or(bound_ip), local_address.port());
                self.connect_mirrored_internal(&mut topology, listener_id, source, destination)
            }
            // The connect starts under `topology`, so that a listener of the provider's own that
            // starts listening at the destination meanwhile cannot take it as a host client, and
            // no in-memory connection takes its pair. As the host would, it fails if one holds
            // the pair already; one through the host the host checks itself.
            MirroredTcpDestination::External => {
                let pairs = &mut topology.tcp.mirrored_pairs;
                // Only an exact bind identifies the source before TCP connects. For a wildcard
                // bind the actual pair is checked below, still under the same topology lock.
                if !bound_ip.is_unspecified()
                    && pairs.memory_in_use(tcp_pair(local_address, destination))
                {
                    return Err(PlatformConnectError::Rejected(
                        SocketError::AddressNotAvailable,
                    ));
                }
                pairs
                    .try_reserve_host()
                    .map_err(PlatformConnectError::PeerUnchanged)?;
                let status =
                    self.connect_external_tcp_socket(destination, local_address, Some(topology))?;
                adopt_host_local_address(self);
                Ok(status)
            }
            MirroredTcpDestination::Refused => {
                drop(topology);
                Ok(self.fail_mirrored_connect(SocketError::ConnectionRefused))
            }
            // A denial leaves the socket as it was, for another attempt.
            MirroredTcpDestination::Denied => {
                Err(PlatformConnectError::Rejected(SocketError::PolicyDenied))
            }
        }
    }

    /// Fails a mirrored socket's connect with `error`, keeping its host socket bound.
    fn fail_mirrored_connect(&mut self, error: SocketError) -> SocketConnectionStatus {
        let status = SocketConnectionStatus::Failed(error);
        self.connection_status = status;
        set_own_readiness(self, ReadinessFlags::ERROR);
        status
    }

    /// Fails a mirrored socket's connect from its host socket with `error`, as one the host
    /// rejected, leaving the socket bound as it was for another attempt. A connect the host
    /// `started` stops first, which keeps the host socket's binding, as the provider always names
    /// its port; a host that cannot stop it closes it, which ends the socket's connect.
    fn reject_mirrored_connect(
        &mut self,
        started: bool,
        error: SocketError,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let tcp = self
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        let TcpDescriptor::ExternalInet(host) =
            core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized)
        else {
            return Err(PlatformConnectError::PeerIndeterminate(
                BrokerError::Internal,
            ));
        };
        if !started || host.disconnect().is_ok() {
            tcp.descriptor = TcpDescriptor::Bound(host);
            self.connection_status = SocketConnectionStatus::Unconnected;
            return Err(PlatformConnectError::Rejected(error));
        }
        let _ = host.set_linger_zero();
        drop(host);
        let status = SocketConnectionStatus::Failed(error);
        self.connection_status = status;
        set_own_readiness(self, ReadinessFlags::ERROR);
        Ok(status)
    }

    /// Connects a mirrored socket in memory from `source_address`, its bound port at the address
    /// the host would send from, to `destination`, at which the provider's own listener
    /// `listener_id` listens. The socket's bound host socket keeps its port until both ends of the
    /// connection close, so that no host socket takes the port that names the connector.
    fn connect_mirrored_internal(
        &mut self,
        topology: &mut Topology,
        listener_id: u64,
        source_address: SocketAddrV4,
        destination: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        // Sockets sharing a port by SO_REUSEADDR could otherwise connect the same pair of
        // addresses, in either direction; as the host would, the later one finds it taken.
        let pairs = &mut topology.tcp.mirrored_pairs;
        if pairs.in_use(source_address, destination) {
            return Err(PlatformConnectError::Rejected(
                SocketError::AddressNotAvailable,
            ));
        }
        pairs
            .try_reserve_memory()
            .map_err(PlatformConnectError::PeerUnchanged)?;
        let tcp = self
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerUnchanged)?;
        let reuse_address = tcp.options.reuse_address;
        let TcpDescriptor::Bound(host) =
            core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized)
        else {
            return Err(PlatformConnectError::PeerIndeterminate(
                BrokerError::Internal,
            ));
        };
        let port = HeldPort::new(Some(host), reuse_address);
        let guest_source_lease =
            GuestSourceLease::retaining(source_address, Arc::clone(&port) as _);
        let result =
            self.connect_internal_tcp(topology, listener_id, destination, guest_source_lease);
        let tcp = self
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        if matches!(result, Ok(SocketConnectionStatus::Connected)) {
            topology
                .tcp
                .mirrored_pairs
                .insert_memory(source_address, destination, &port);
            tcp.port_share = Some(PortShare::connector(port, reuse_address));
        } else if let Ok(port) = Arc::try_unwrap(port)
            && let Ok(HeldPortState {
                socket: Some(host), ..
            }) = port.state.into_inner()
            && matches!(tcp.descriptor, TcpDescriptor::Unrealized)
        {
            // The connect failed, and dropped its lease, so the socket stays bound.
            tcp.descriptor = TcpDescriptor::Bound(host);
        }
        result
    }

    /// Connects the socket from a host socket to `address`, the one it bound or a new one, and
    /// names it `guest_local_address`. Holds `topology`, if given, until the connect starts.
    fn connect_external_tcp_socket(
        &mut self,
        address: SocketAddrV4,
        guest_local_address: SocketAddrV4,
        topology: Option<MutexGuard<'_, Topology>>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        if self.connection_status != SocketConnectionStatus::Unconnected {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let (options, bound) = {
            let tcp = self
                .tcp_state()
                .map_err(PlatformConnectError::PeerUnchanged)?;
            let bound = match tcp.descriptor {
                TcpDescriptor::Unrealized => false,
                TcpDescriptor::Bound(_) => true,
                _ => return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal)),
            };
            (tcp.options, bound)
        };
        // A mirrored socket connects from the host socket it bound, and any other from a new one.
        let external_socket = if bound {
            let tcp = self
                .tcp_state_mut()
                .map_err(PlatformConnectError::PeerUnchanged)?;
            let TcpDescriptor::Bound(socket) =
                core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized)
            else {
                return Err(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ));
            };
            socket
        } else {
            Socket::tcp().map_err(|error| {
                PlatformConnectError::PeerUnchanged(broker_error_from_errno(error))
            })?
        };
        if let Err(error) = apply_tcp_options(&external_socket, options) {
            if bound {
                self.tcp_state_mut()
                    .map_err(PlatformConnectError::PeerIndeterminate)?
                    .descriptor = TcpDescriptor::Bound(external_socket);
            }
            return Err(PlatformConnectError::PeerUnchanged(
                broker_error_from_errno(error),
            ));
        }
        self.tcp_state_mut()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .descriptor = TcpDescriptor::ExternalInet(external_socket);
        self.connection_status = SocketConnectionStatus::Connecting;
        let host = self
            .tcp_state()
            .and_then(|tcp| tcp.descriptor.socket())
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        let status = loop {
            match host.connect(address) {
                Ok(()) | Err(Errno::ISCONN) => break Ok(SocketConnectionStatus::Connected),
                Err(Errno::INTR) => {}
                Err(Errno::INPROGRESS | Errno::ALREADY) => {
                    break Ok(SocketConnectionStatus::Connecting);
                }
                // The host fails a bound socket's connect whose pair of addresses another of its
                // connections holds before the socket changes, so it stays bound.
                Err(Errno::ADDRNOTAVAIL) if bound => {
                    drop(topology);
                    return self.reject_mirrored_connect(false, SocketError::AddressNotAvailable);
                }
                Err(error) => {
                    break socket_operation_error_from_errno(error)
                        .map(SocketConnectionStatus::Failed);
                }
            }
        };
        // A mirrored socket's connection names its pair of addresses, as the host chose them,
        // before any in-memory connect can take the pair. A wildcard socket acquires its concrete
        // source only here; stop rather than publish a pair that a live in-memory stream holds.
        let mut host_connection = None;
        let status = match (status, topology) {
            (
                Ok(
                    status @ (SocketConnectionStatus::Connected
                    | SocketConnectionStatus::Connecting),
                ),
                Some(mut topology),
            ) => match host.local_address() {
                Ok(local_address) => {
                    let pairs = &mut topology.tcp.mirrored_pairs;
                    if pairs.memory_in_use(tcp_pair(local_address, address)) {
                        drop(topology);
                        return self
                            .reject_mirrored_connect(true, SocketError::AddressNotAvailable);
                    }
                    host_connection = Some(pairs.insert_host(local_address, address));
                    Ok(status)
                }
                Err(error) => Err(broker_error_from_errno(error)),
            },
            (status, _) => status,
        };
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                self.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
                set_own_readiness(self, ReadinessFlags::ERROR);
                return Err(PlatformConnectError::PeerIndeterminate(error));
            }
        };
        if host_connection.is_some() {
            self.tcp_state_mut()
                .map_err(PlatformConnectError::PeerIndeterminate)?
                .host_connection = host_connection;
        }
        self.connection_status = status;
        let readiness = match status {
            SocketConnectionStatus::Connected => ReadinessFlags::WRITE,
            SocketConnectionStatus::Connecting => ReadinessFlags::default(),
            SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
            _ => {
                return Err(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ));
            }
        };
        if matches!(
            status,
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ) {
            self.guest_local_address = Some(guest_local_address);
        }
        set_own_readiness(self, readiness);
        // Watching the socket only after `connect()` and the initial
        // publication means every event describes it after the connect: a
        // fresh socket polls as writable and hung up, which would otherwise
        // mark a pending handshake connected.
        let core = self.core();
        let id = self.id();
        core.watch_host_socket(
            self.tcp_state_mut()
                .and_then(|tcp| tcp.descriptor.socket_mut())
                .map_err(PlatformConnectError::PeerIndeterminate)?,
            id,
            Interest::Stream,
        )
        .map_err(PlatformConnectError::PeerIndeterminate)?;
        Ok(status)
    }

    fn connect_internal_tcp(
        &mut self,
        topology: &mut Topology,
        listener_id: u64,
        local_address: SocketAddrV4,
        guest_source_lease: GuestSourceLease,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let source_address = guest_source_lease.source_address();
        let core = self.core();
        topology
            .check_queued_connection(
                self.process_key(),
                core.max_sockets,
                core.max_sockets_per_process,
            )
            .map_err(PlatformConnectError::PeerUnchanged)?;
        if self.connection_status != SocketConnectionStatus::Unconnected
            || !matches!(
                self.tcp_state()
                    .map_err(PlatformConnectError::PeerUnchanged)?
                    .descriptor,
                TcpDescriptor::Unrealized
            )
        {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let listener = topology
            .tcp
            .listeners
            .get_mut(&listener_id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        if listener.queue.len() >= listener.backlog {
            drop(guest_source_lease);
            let status = SocketConnectionStatus::Failed(SocketError::ConnectionRefused);
            self.connection_status = status;
            set_own_readiness(self, ReadinessFlags::ERROR);
            return Ok(status);
        }
        listener
            .queue
            .try_reserve(1)
            .map_err(|_| PlatformConnectError::PeerUnchanged(BrokerError::OutOfMemory))?;
        // The connection shares a mirrored listener's port from now on, with the listener's
        // `SO_REUSEADDR` as it is now.
        let port_share = listener
            .port
            .as_ref()
            .map(|port| PortShare::new(&port.port, port.reuse_address))
            .transpose()
            .map_err(PlatformConnectError::PeerUnchanged)?;
        topology
            .tcp
            .links
            .try_reserve(1)
            .map_err(|_| PlatformConnectError::PeerUnchanged(BrokerError::OutOfMemory))?;
        let (connector_end, accepted_end) = stream_pair();
        let connector_socket_id = self.id();
        connector_end.set_waker(Some(core.stream_waker(connector_socket_id)));

        let tcp = self
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        tcp.descriptor = TcpDescriptor::Internal(connector_end);
        tcp.guest_endpoint = Some(GuestTcpEndpoint {
            connector_socket_id,
            reset_state: GuestTcpResetState::None,
        });
        self.guest_local_address = Some(source_address);
        self.connection_status = SocketConnectionStatus::Connected;
        set_own_readiness(self, ReadinessFlags::WRITE);

        let listener = topology
            .tcp
            .listeners
            .get_mut(&listener_id)
            .expect("validated guest listener missing");
        listener.queue.push_back(QueuedGuestTcpConnection {
            socket: accepted_end,
            connector_socket_id,
            connector_process_key: self.process_key(),
            local_address,
            guest_source_lease,
            port_share,
        });
        publish_listener_queue(listener);
        topology.charge_queued_connection(self.process_key());
        topology.tcp.links.insert(
            connector_socket_id,
            TcpLink {
                connector: Arc::clone(&self.socket.inbox),
                peer: TcpLinkPeer::Queued { listener_id },
            },
        );
        core.watch_internal(connector_socket_id);
        Ok(SocketConnectionStatus::Connected)
    }

    pub(super) fn listen_socket(
        &mut self,
        backlog: u32,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if self.kind() != SocketKind::Tcp {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = self.guest_local_address.ok_or(BrokerError::Internal)?;
        // A listen again passes the new backlog to the host listener, which Linux applies and
        // Winsock ignores.
        if let TcpDescriptor::Listener(host) = &self.tcp_state()?.descriptor
            && let Err(error) = host.listen(backlog)
        {
            return socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
        }
        if self.core().mirrored() && !self.tcp_state()?.listening {
            return self.listen_mirrored(guest_address, backlog);
        }
        let mut topology = self.topology();
        let binding = topology
            .tcp
            .binding_for_socket(self.id())
            .filter(|binding| binding.local_address() == guest_address)
            .ok_or(BrokerError::Internal)?;
        let host_backlog = backlog;
        let backlog = usize::try_from(backlog)
            .map_err(|_| BrokerError::UnsupportedOperation)?
            .max(1);
        let descriptor = &self.tcp_state()?.descriptor;
        if self.connection_status != SocketConnectionStatus::Unconnected
            || descriptor.is_external()
            || descriptor.is_internal()
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if let Some(listener) = topology.tcp.listeners.get_mut(&self.id()) {
            listener.backlog = backlog;
        } else {
            let core = self.core();
            let port = guest_address.port();
            if binding
                .guest()
                .is_some_and(|guest| guest.covers(SocketAddrV4::new(GUEST_IPV4_ADDRESS, port)))
            {
                // Host calls run outside `topology`; a failure fails the listen.
                drop(topology);
                if let Some(mut host) = core.take_published(Protocol::Tcp, port) {
                    if let Err(error) = host.listen(host_backlog) {
                        core.release_published(Protocol::Tcp, port, host);
                        return socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
                    }
                    if let Err(error) =
                        core.watch_host_socket(&mut host, self.id(), Interest::Stream)
                    {
                        core.release_published(Protocol::Tcp, port, host);
                        return Err(error);
                    }
                    self.tcp_state_mut()?.descriptor = TcpDescriptor::Listener(host);
                }
                topology = self.topology();
            }
            if topology.tcp.listeners.try_reserve(1).is_err() {
                drop(topology);
                self.close_host_listener();
                return Err(BrokerError::OutOfMemory);
            }
            topology.tcp.listeners.insert(
                self.id(),
                TcpListener {
                    inbox: Arc::clone(&self.socket.inbox),
                    backlog,
                    queue: VecDeque::new(),
                    port: None,
                },
            );
        }
        self.tcp_state_mut()?.listening = true;
        Ok(SocketOutcome::Completed(guest_address))
    }

    /// Makes a mirrored socket's bound host socket at `local_address` a listener, which both host
    /// clients and the provider's own sockets reach.
    ///
    /// A host socket cannot stop listening, so it listens last, once all else that can fail has,
    /// and a listen that fails leaves it bound and unwatched. Its watch is thus the poller's from
    /// before it listens, when it polls as writable and hung up, so the watch has a token of its
    /// own, which tells [`handle_socket_event`] which events to take as a listener's, rather than
    /// complete a later connect early.
    fn listen_mirrored(
        &mut self,
        local_address: SocketAddrV4,
        backlog: u32,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let queue_backlog = usize::try_from(backlog)
            .map_err(|_| BrokerError::UnsupportedOperation)?
            .max(1);
        if self.connection_status != SocketConnectionStatus::Unconnected
            || !matches!(self.tcp_state()?.descriptor, TcpDescriptor::Bound(_))
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let (core, id) = (self.core(), self.id());
        let inbox = Arc::clone(&self.socket.inbox);
        let binding = TcpBinding {
            socket_id: id,
            address: TcpBindingAddress::Host(local_address),
        };
        // Neither the watch nor `listen` blocks. Under `topology`, the provider's own sockets find
        // the listener as soon as host clients can.
        let mut topology = self.topology();
        if !topology.tcp.admits_binding(&binding) {
            // Another of the provider's listeners listens at an overlapping address, so the host
            // would refuse this one.
            return Ok(SocketOutcome::Failed(SocketError::AddressInUse));
        }
        topology
            .tcp
            .listeners
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        topology.tcp.reserve_binding(&binding)?;
        let tcp = self.tcp_state_mut()?;
        let TcpDescriptor::Bound(host) = &mut tcp.descriptor else {
            return Err(BrokerError::Internal);
        };
        core.watch_host_socket(host, listener_token(id), Interest::Stream)?;
        if let Err(error) = host.listen(backlog) {
            core.unwatch_host_socket(host);
            return socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
        }
        topology.tcp.insert_reserved_binding(binding);
        // The port that the connections the listener accepts in memory name.
        let port_share = PortShare::first(tcp.options.reuse_address);
        topology.tcp.listeners.insert(
            id,
            TcpListener {
                inbox,
                backlog: queue_backlog,
                queue: VecDeque::new(),
                port: Some(ListenerPort {
                    port: Arc::clone(&port_share.port),
                    reuse_address: port_share.reuse_address,
                }),
            },
        );
        drop(topology);
        if let TcpDescriptor::Bound(host) =
            core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized)
        {
            tcp.descriptor = TcpDescriptor::Listener(host);
        }
        tcp.listening = true;
        tcp.port_share = Some(port_share);
        Ok(SocketOutcome::Completed(local_address))
    }

    /// Accepts the first queued connection into `accepted`, a new closed
    /// socket.
    ///
    /// No other thread can reach `accepted` before it is registered, so
    /// holding its `state` along with the listener's cannot deadlock.
    pub(super) fn accept_socket(
        &mut self,
        accepted: &Arc<UserlandSocket>,
    ) -> BrokerResult<SocketOutcome<AcceptedEndpoints>> {
        if !self.tcp_state()?.listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let options = self.tcp_state()?.options;
        let mut state = lock(&accepted.state);
        let mut topology = self.topology();
        let listener = topology
            .tcp
            .listeners
            .get(&self.id())
            .ok_or(BrokerError::Internal)?;
        let Some(connector_process_key) = listener
            .queue
            .front()
            .map(|connection| connection.connector_process_key)
        else {
            publish_listener_queue(listener);
            drop(topology);
            return self.accept_host_connection(accepted, &mut state, options);
        };
        let core = self.core();
        core.register(accepted)?;
        if let Err(error) = topology.accept_queued_connection(
            connector_process_key,
            self.process_key(),
            core.max_sockets_per_process,
        ) {
            core.unregister(accepted.id);
            return Err(error);
        }
        let listener = topology
            .tcp
            .listeners
            .get_mut(&self.id())
            .ok_or(BrokerError::Internal)?;
        let QueuedGuestTcpConnection {
            socket,
            connector_socket_id,
            local_address,
            guest_source_lease,
            port_share,
            ..
        } = listener.queue.pop_front().ok_or(BrokerError::Internal)?;
        publish_listener_queue(listener);
        if let Some(link) = topology.tcp.links.get_mut(&connector_socket_id) {
            link.peer = TcpLinkPeer::Accepted(Arc::clone(&accepted.inbox));
        }
        drop(topology);
        socket.set_waker(Some(core.stream_waker(accepted.id)));
        // A mirrored connection's SO_REUSEADDR is the one it took as it was queued.
        let reuse_address = port_share
            .as_ref()
            .map_or(options.reuse_address, |share| share.reuse_address);
        let mut tcp = tcp_socket_state(
            TcpDescriptor::Internal(socket),
            Some(GuestTcpEndpoint {
                connector_socket_id,
                reset_state: GuestTcpResetState::None,
            }),
            TcpOptions {
                reuse_address,
                ..options
            },
        );
        tcp.port_share = port_share;
        *state = SocketState {
            closed: false,
            transport: SocketTransportState::Tcp(tcp),
            connection_status: SocketConnectionStatus::Connected,
            read_shutdown: false,
            write_shutdown: false,
            guest_local_address: Some(local_address),
        };
        let accepted = SocketEntry {
            socket: accepted,
            state,
        };
        set_own_readiness(&accepted, ReadinessFlags::WRITE);
        // Data sent before the accept is already queued, so have the event
        // thread report it once this entry is released.
        core.watch_internal(accepted.id());
        Ok(SocketOutcome::Completed(AcceptedEndpoints {
            local_address,
            guest_source_lease,
        }))
    }

    /// Accepts a published listener's host connection into `accepted`, charged to its process.
    fn accept_host_connection(
        &mut self,
        accepted: &Arc<UserlandSocket>,
        state: &mut SocketState,
        options: TcpOptions,
    ) -> BrokerResult<SocketOutcome<AcceptedEndpoints>> {
        let TcpDescriptor::Listener(listener) = &self.tcp_state()?.descriptor else {
            return Err(BrokerError::WouldBlock);
        };
        let (core, process_key) = (self.core(), self.process_key());
        let port = self.guest_local_address.map_or(0, |address| address.port());
        // A mirrored connection's local address is its host socket's; a published one's is the
        // guest's own. A mirrored connection's SO_REUSEADDR is the one its host socket took from
        // the listener as the host connected it, which a later change of the listener's misses.
        let local_address_of = |host: &Socket| {
            if core.mirrored() {
                host.local_address()
            } else {
                Ok(SocketAddrV4::new(GUEST_IPV4_ADDRESS, port))
            }
        };
        let reuse_address_of = |host: &Socket| {
            if core.mirrored() {
                host.reuse_address()
            } else {
                Ok(options.reuse_address)
            }
        };
        core.charge_socket(process_key)?;
        // Resets a client unseen, and tells whether the accept goes on to the next client. One
        // that stops early announces READ again for the clients it left.
        let mut refused = 0;
        let mut refuse = |host: &Socket| {
            let _ = host.set_linger_zero();
            refused += 1;
            refused < MAX_RESETS_AT_ONCE
        };
        let admitted = loop {
            let error = match listener.accept() {
                // A client from outside the allowed sources is refused.
                Ok((host, peer))
                    if !sources_contain(&core.tcp_sources, core.guest_client(peer)) =>
                {
                    if refuse(&host) {
                        continue;
                    }
                    break None;
                }
                Ok((host, peer)) => {
                    let accepted = apply_tcp_options(&host, options)
                        .and_then(|()| local_address_of(&host))
                        .and_then(|local_address| Ok((local_address, reuse_address_of(&host)?)));
                    match accepted {
                        Ok((local_address, reuse_address)) if !core.mirrored() => {
                            break Some((host, peer, local_address, reuse_address, None));
                        }
                        // A mirrored connection names its pair of addresses before the guest can
                        // use it. One whose pair an in-memory connection holds already is refused:
                        // the host knows nothing of that connection, so a client's host socket
                        // that shares the port of one of its ends can connect it again.
                        Ok((local_address, reuse_address)) => {
                            let named = self
                                .topology()
                                .tcp
                                .mirrored_pairs
                                .try_insert_host(local_address, peer);
                            match named {
                                Ok(connection @ Some(_)) => {
                                    break Some((
                                        host,
                                        peer,
                                        local_address,
                                        reuse_address,
                                        connection,
                                    ));
                                }
                                Ok(None) => {
                                    if refuse(&host) {
                                        continue;
                                    }
                                    break None;
                                }
                                Err(error) => {
                                    let _ = host.set_linger_zero();
                                    core.release_socket_charge(process_key);
                                    return Err(error);
                                }
                            }
                        }
                        // The client reset since the accept (Windows reports it here).
                        Err(Errno::NOTCONN | Errno::CONNRESET | Errno::CONNABORTED) => continue,
                        Err(error) => error,
                    }
                }
                // Windows reports a client that reset before the accept to it.
                Err(Errno::INTR | Errno::CONNABORTED | Errno::CONNRESET) => continue,
                Err(error) => error,
            };
            core.release_socket_charge(process_key);
            if error == Errno::AGAIN {
                clear_readiness(self, ReadinessFlags::READ);
                return Err(BrokerError::WouldBlock);
            }
            return socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
        };
        let Some((host, peer, local_address, reuse_address, host_connection)) = admitted else {
            core.release_socket_charge(process_key);
            super::republish_own_readiness(self, self.own() | ReadinessFlags::READ);
            return Err(BrokerError::WouldBlock);
        };
        // With the last waiting connection taken, READ goes. Windows reports the next one only once
        // the listener is watched again, as an accept that would block does.
        let token = if core.mirrored() {
            listener_token(self.id())
        } else {
            self.id()
        };
        if let TcpDescriptor::Listener(listener) = &mut self.tcp_state_mut()?.descriptor
            && listener.stream_readable() == Ok(false)
            && core
                .poller
                .modify(listener, token, Interest::Stream)
                .is_ok()
        {
            clear_readiness(self, ReadinessFlags::READ);
        }
        state.closed = false;
        state.connection_status = SocketConnectionStatus::Connected;
        state.guest_local_address = Some(local_address);
        let tcp = state.tcp_state_mut()?;
        tcp.descriptor = TcpDescriptor::ExternalInet(host);
        tcp.options = TcpOptions {
            reuse_address,
            ..options
        };
        tcp.host_connection = host_connection;
        core.register(accepted)?;
        accepted.inbox.lock().set_own(ReadinessFlags::WRITE);
        // Adding the socket to the poller reports the data that arrived before.
        let host = state.tcp_state_mut()?.descriptor.socket_mut()?;
        core.watch_host_socket(host, accepted.id, Interest::Stream)?;
        Ok(SocketOutcome::Completed(AcceptedEndpoints {
            local_address,
            guest_source_lease: GuestSourceLease::external(core.guest_client(peer)),
        }))
    }

    /// Unbinds and unlinks a retiring TCP socket, then closes its descriptor.
    pub(super) fn retire_tcp(&mut self) {
        let id = self.id();
        {
            let mut topology = self.topology();
            if let Some(address) = self.guest_local_address {
                topology.tcp.remove_binding(address.port(), id);
            }
            if let Some(listener) = topology.tcp.listeners.remove(&id) {
                topology.discard_listener_queue(listener.queue);
            }
            if self.core().mirrored() {
                self.stop_mirrored_listener(false);
            }
            self.unlink_guest_endpoint(&mut topology);
            topology.release_socket(self.process_key());
        }
        let core = self.core();
        core.hook(HookPoint::Unlinked(id));
        core.unregister(id);
        let port = self.guest_local_address.map_or(0, |address| address.port());
        let Ok(tcp) = self.tcp_state_mut() else {
            return;
        };
        match core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized) {
            TcpDescriptor::Listener(socket) => {
                core.release_published(Protocol::Tcp, port, socket);
            }
            TcpDescriptor::ExternalInet(mut socket) => {
                if tcp.abortive_close {
                    // Abort may be requested before lazy external realization,
                    // so enforce it again at close.
                    let _ = socket.set_linger_zero();
                }
                core.unwatch_host_socket(&mut socket);
            }
            TcpDescriptor::Internal(end) => {
                drop(end);
                core.hook(HookPoint::EndpointClosed(id));
            }
            TcpDescriptor::Bound(socket) => drop(socket),
            TcpDescriptor::Unrealized => {}
        }
        // The port stays held while another holder of it remains.
        tcp.port_share = None;
        tcp.host_connection = None;
    }

    /// Detaches a retiring internal endpoint from its connection, posting a
    /// reset to the other end if this close loses data.
    ///
    /// A gracefully closed connector that is still queued stays queued, so
    /// its listener can accept the data it sent; an abortive one is removed.
    fn unlink_guest_endpoint(&mut self, topology: &mut Topology) {
        let Ok(tcp) = self.tcp_state() else {
            return;
        };
        let Some(connector_socket_id) = tcp
            .guest_endpoint
            .as_ref()
            .map(|endpoint| endpoint.connector_socket_id)
        else {
            return;
        };
        let Some(link) = topology.tcp.links.remove(&connector_socket_id) else {
            return;
        };
        let peer = if connector_socket_id == self.id() {
            match link.peer {
                TcpLinkPeer::Queued { listener_id } => {
                    if tcp.abortive_close {
                        topology.remove_queued_connection(listener_id, connector_socket_id);
                    } else if let TcpDescriptor::Internal(end) = &tcp.descriptor {
                        // The listener can accept before this end closes, so
                        // fail its writes now, as they fail once it closes.
                        end.stop_receiving();
                    }
                    return;
                }
                TcpLinkPeer::Accepted(peer) => peer,
            }
        } else {
            debug_assert!(matches!(link.peer, TcpLinkPeer::Accepted(_)));
            link.connector
        };
        let mut inbox = peer.lock();
        // Stop the peer's writes first, so no data arrives after the check;
        // the peer then finds the reset when its write fails.
        let unread = match &tcp.descriptor {
            TcpDescriptor::Internal(end) => end.stop_receiving(),
            _ => false,
        };
        if tcp.abortive_close || unread {
            inbox.reset_posted = true;
            inbox.republish();
        }
    }
}

/// Reports whether a guest reset is pending, applying a newly posted one
/// first.
pub(super) fn status_tcp_socket(
    socket: &mut SocketEntry<'_>,
) -> BrokerResult<PlatformSocketStatus> {
    // A connection's failure is reported once, after which the host socket's
    // error is no longer the guest's.
    let query_socket_error = socket.connection_status == SocketConnectionStatus::Connected
        && socket.own().contains(ReadinessFlags::ERROR)
        && !socket.tcp_state()?.connection_failed;
    if query_socket_error && let Some(error) = take_socket_error(socket)? {
        fail_with_taken_error(socket, error)?;
    }
    adopt_host_local_address(socket);
    let pending_guest_reset = guest_reset_pending(socket)?;
    let status = socket.connection_status;
    let local_address = socket.guest_local_address;
    if pending_guest_reset && !socket.tcp_state()?.pending_errors.contains_guest_reset() {
        socket
            .tcp_state_mut()?
            .pending_errors
            .append(TcpPendingError::GuestReset);
    }
    let pending_error = socket.tcp_state_mut()?.pending_errors.take();
    let mut readiness = socket.own();
    if pending_error.is_some() && socket.tcp_state()?.pending_errors.is_empty() {
        readiness = ReadinessFlags(readiness.0 & !ReadinessFlags::ERROR.0);
        socket.inbox().own = readiness;
    }
    let response = PlatformSocketStatus {
        status,
        local_address,
        pending_error: pending_error.map(TcpPendingError::error),
    };
    let republish_error = !socket.tcp_state()?.pending_errors.is_empty();
    if pending_guest_reset
        && matches!(pending_error, Some(TcpPendingError::GuestReset))
        && !consume_pending_guest_reset(socket, false)?
    {
        return Err(BrokerError::Internal);
    }
    if republish_error {
        socket.inbox().republish();
    } else if response.pending_error.is_some() {
        socket.inbox().publish();
    }
    Ok(response)
}

/// Gives a mirrored socket that connected from the wildcard address the local address its host
/// socket connected from, once the host reports one.
fn adopt_host_local_address(socket: &mut SocketEntry<'_>) {
    if !socket.core().mirrored()
        || !socket
            .guest_local_address
            .is_some_and(|address| address.ip().is_unspecified())
    {
        return;
    }
    let observed = socket
        .tcp_state()
        .and_then(|tcp| tcp.descriptor.socket())
        .map(Socket::local_address);
    if let Ok(Ok(address)) = observed
        && !address.ip().is_unspecified()
    {
        socket.guest_local_address = Some(address);
    }
}

/// The failure of a connect that could not learn what it needed of the host, which leaves the
/// socket as it was.
fn rejected_from_errno(error: Errno) -> PlatformConnectError {
    match socket_operation_error_from_errno(error) {
        Ok(error) => PlatformConnectError::Rejected(error),
        Err(error) => PlatformConnectError::PeerUnchanged(error),
    }
}

fn take_socket_error(socket: &SocketEntry<'_>) -> BrokerResult<Option<Errno>> {
    let tcp = socket.tcp_state()?;
    if !tcp.descriptor.is_external() {
        return Ok(None);
    }
    tcp.descriptor
        .socket()?
        .take_error()
        .map_err(broker_error_from_errno)
}

fn guest_reset_pending(socket: &mut SocketEntry<'_>) -> BrokerResult<bool> {
    socket.drain_guest_reset()?;
    Ok(socket
        .tcp_state()?
        .guest_endpoint
        .as_ref()
        .is_some_and(|endpoint| endpoint.reset_state == GuestTcpResetState::Pending))
}

fn consume_pending_guest_reset(
    socket: &mut SocketEntry<'_>,
    remove_queued_error: bool,
) -> BrokerResult<bool> {
    let tcp = socket.tcp_state_mut()?;
    let Some(endpoint) = tcp.guest_endpoint.as_mut() else {
        return Ok(false);
    };
    if endpoint.reset_state != GuestTcpResetState::Pending {
        return Ok(false);
    }
    endpoint.reset_state = GuestTcpResetState::Reported;
    if remove_queued_error {
        tcp.pending_errors.remove_guest_reset();
    }
    if tcp.pending_errors.is_empty() {
        let mut inbox = socket.inbox();
        if inbox.own.contains(ReadinessFlags::ERROR) {
            inbox.own = ReadinessFlags(inbox.own.0 & !ReadinessFlags::ERROR.0);
            // The synchronous operation reports the reset even if its
            // readiness notification cannot be delivered.
            inbox.publish();
        }
    }
    Ok(true)
}

/// Reports a guest reset in place of the end of stream or error that the
/// peer's close caused during this call.
///
/// The peer posts its reset before dropping its stream end, so a terminal
/// result that the close caused always finds the reset.
fn take_late_guest_reset(socket: &mut SocketEntry<'_>) -> BrokerResult<bool> {
    if !socket.tcp_state()?.descriptor.is_internal() || !guest_reset_pending(socket)? {
        return Ok(false);
    }
    if !consume_pending_guest_reset(socket, true)? {
        return Err(BrokerError::Internal);
    }
    Ok(true)
}

#[cfg(test)]
impl super::ProviderCore {
    pub(super) fn queued_guest_connection_count(&self) -> usize {
        lock(&self.topology).tcp.queued_guest_connection_count
    }

    /// Counts live TCP sockets as (unrealized, external, internal).
    pub(super) fn tcp_descriptor_counts(&self) -> (usize, usize, usize) {
        let sockets: Vec<_> = super::read_lock(&self.registry)
            .sockets
            .values()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        let mut counts = (0, 0, 0);
        for socket in &sockets {
            let descriptor = socket.call(|socket| {
                Ok(match socket.tcp_state()?.descriptor {
                    TcpDescriptor::Unrealized => &mut counts.0,
                    TcpDescriptor::Bound(_)
                    | TcpDescriptor::ExternalInet(_)
                    | TcpDescriptor::Listener(_) => &mut counts.1,
                    TcpDescriptor::Internal(_) => &mut counts.2,
                })
            });
            if let Ok(count) = descriptor {
                *count += 1;
            }
        }
        counts
    }

    /// Applies host `events` to a TCP socket, as the event thread does.
    pub(super) fn apply_tcp_events(&self, id: u64, events: SocketEvents) {
        let socket = super::read_lock(&self.registry)
            .sockets
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
            .unwrap();
        socket
            .call(|socket| handle_socket_event(socket, id, events))
            .unwrap();
    }

    /// Reads a TCP socket's options from its host socket, as (no delay,
    /// keep alive).
    pub(super) fn host_tcp_options(&self, id: u64) -> (bool, bool) {
        let socket = super::read_lock(&self.registry)
            .sockets
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
            .unwrap();
        socket
            .call(|socket| {
                let host = socket.tcp_state()?.descriptor.socket()?;
                Ok((host.no_delay().unwrap(), host.keep_alive().unwrap()))
            })
            .unwrap()
    }

    /// Reports whether a TCP socket's host socket has a pending error.
    pub(super) fn host_error_pending(&self, id: u64) -> bool {
        let socket = super::read_lock(&self.registry)
            .sockets
            .get(&id)
            .and_then(std::sync::Weak::upgrade)
            .unwrap();
        socket
            .call(|socket| {
                Ok(socket
                    .tcp_state()?
                    .descriptor
                    .socket()?
                    .error_pending()
                    .unwrap())
            })
            .unwrap()
    }
}
