// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TCP sockets: a guest socket is unrealized until it listens (on the
//! loopback interface, with a pool of smoltcp listening sockets that become
//! its pending connections) or connects (one smoltcp socket, on the
//! interface its destination chose).
//!
//! A guest connection's source lease (see `PlatformSocket::connect`) waits
//! in [`Stack::leases`] until the listener accepts the connection, matched
//! by the connection's remote endpoint.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddrV4;
use core::sync::atomic::AtomicU32;
use core::time::Duration;
use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{
    GuestSocketBinding, GuestSourceLease, PlatformConnectError, PlatformSocketStatus,
    PlatformStreamReceive, is_internal_socket_address, normalize_socket_destination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    ReceiveFlags, ShutdownMode, SocketConnectionStatus, SocketError, SocketOutcome, TcpOptionName,
    TcpOptionValue,
};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, State};
use smoltcp::storage::RingBuffer;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use super::device::ListenerRoom;
use super::{CONNECT_TIMEOUT, Closing, Entry, Kind, Lease, Side, Sockets, Stack, socket_address};

/// Each direction's buffer.
const BUFFER_SIZE: usize = 64 * 1024;

/// At most this many listening sockets wait for connections per listener,
/// refilled as they take them (see `ListenerRoom`). A listener whose backlog
/// is full has none: a connection to it is refused (reset), as on the
/// userland broker.
const LISTEN_POOL: usize = 4;

const KEEP_ALIVE_INTERVAL: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(75);

/// How long sent data may go unacknowledged before the connection is
/// aborted: Linux's default (`tcp_retries2` = 15). Set only while data
/// waits to be sent, or keep-alive is on (see [`apply_timeout`]): smoltcp
/// counts it from the last packet received, so it would also end an idle
/// connection, which Linux keeps open.
const UNACKNOWLEDGED_TIMEOUT: Duration = Duration::from_millis(924_600);

/// While data waits to be sent, e.g., to a peer whose window is closed, a
/// probe (smoltcp's keep-alive, which the peer acknowledges with its
/// window) at least this often: as Linux's persist timer, a peer that
/// answers keeps the connection, however long its window stays closed.
/// Linux's backs off to this.
const ZERO_WINDOW_PROBE_INTERVAL: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(120);

#[expect(
    clippy::struct_excessive_bools,
    reason = "the directions' and connection's states are independent"
)]
pub(super) struct Tcp {
    binding: Option<GuestSocketBinding>,
    phase: Phase,
    status: SocketConnectionStatus,
    /// The guest-visible local address, once listening or connecting.
    local: Option<SocketAddrV4>,
    no_delay: bool,
    keep_alive: bool,
    /// Retiring resets the connection.
    abort_on_close: bool,
    /// After a read shutdown: what was received before it and is not yet
    /// read. Later data is discarded.
    read_shutdown: Option<Vec<u8>>,
    write_shutdown: bool,
    /// The peer closed its write side (sent FIN).
    peer_closed: bool,
    /// The connection ended other than by both sides closing (e.g., a
    /// reset, or a timeout).
    reset: bool,
    pending_error: Option<SocketError>,
    /// A peek with `WAITALL` waits for this much data; its waiters are
    /// woken once it arrives or the stream ends.
    waitall: Option<usize>,
    connect_deadline: Option<Duration>,
    /// Data waits to be sent, so the socket probes (see
    /// [`ZERO_WINDOW_PROBE_INTERVAL`]).
    probing: bool,
    /// When the connection last made progress (data acknowledged or
    /// received, or nothing waiting), and the queues then: a connection that
    /// ends [`UNACKNOWLEDGED_TIMEOUT`] after it timed out.
    progress: (Duration, usize, usize),
}

enum Phase {
    Unrealized,
    Listening(Listener),
    Stream(Side, SocketHandle),
}

struct Listener {
    endpoint: IpListenEndpoint,
    backlog: usize,
    /// Listening sockets and those that took connections, oldest first.
    pending: Vec<SocketHandle>,
}

impl Listener {
    /// Drops failed connections and keeps listening sockets ready while the
    /// backlog has room.
    fn refill(&mut self, sockets: &mut SocketSet<'static>, no_delay: bool, keep_alive: bool) {
        self.pending.retain(|&handle| {
            let closed = sockets.get::<tcp::Socket>(handle).state() == State::Closed;
            if closed {
                sockets.remove(handle);
            }
            !closed
        });
        let idle = self
            .pending
            .iter()
            .filter(|&&handle| sockets.get::<tcp::Socket>(handle).is_listening())
            .count();
        let wanted = LISTEN_POOL.min(self.backlog.saturating_sub(self.pending.len() - idle));
        for _ in idle..wanted {
            let mut socket = new_socket(Side::Internal, no_delay, keep_alive);
            socket
                .listen(self.endpoint)
                .expect("a new socket with a nonzero port can listen");
            self.pending.push(sockets.add(socket));
        }
    }

    fn abort(self, stack: &mut Stack) {
        for handle in self.pending {
            stack.close_tcp(Side::Internal, handle, true);
        }
    }
}

/// Whether a pending connection can be accepted: established, perhaps
/// already half-closed by the peer.
fn acceptable(socket: &tcp::Socket) -> bool {
    matches!(socket.state(), State::Established | State::CloseWait)
}

fn new_socket(side: Side, no_delay: bool, keep_alive: bool) -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        RingBuffer::new(vec![0; BUFFER_SIZE]),
        RingBuffer::new(vec![0; BUFFER_SIZE]),
    );
    if side == Side::Internal {
        // Delayed acknowledgments only add latency in memory.
        socket.set_ack_delay(None);
    }
    apply_options(&mut socket, no_delay, keep_alive, false);
    socket
}

/// For a connected socket: the timeout while data waits to be sent
/// (`probing`) or keep-alive is on, as Linux aborts then; none otherwise.
fn apply_timeout(socket: &mut tcp::Socket, keep_alive: bool, probing: bool) {
    socket.set_timeout((probing || keep_alive).then(|| smoltcp_duration(UNACKNOWLEDGED_TIMEOUT)));
}

/// The guest's options, and probing (see [`ZERO_WINDOW_PROBE_INTERVAL`]).
fn apply_options(socket: &mut tcp::Socket, no_delay: bool, keep_alive: bool, probing: bool) {
    socket.set_nagle_enabled(!no_delay);
    let keep_alive = keep_alive.then_some(KEEP_ALIVE_INTERVAL);
    socket.set_keep_alive(if probing {
        Some(keep_alive.map_or(ZERO_WINDOW_PROBE_INTERVAL, |interval| {
            interval.min(ZERO_WINDOW_PROBE_INTERVAL)
        }))
    } else {
        keep_alive
    });
}

fn smoltcp_duration(duration: Duration) -> smoltcp::time::Duration {
    smoltcp::time::Duration::from_micros(
        u64::try_from(duration.as_micros()).expect("a short duration"),
    )
}

impl Tcp {
    pub(super) fn new() -> Self {
        Self {
            binding: None,
            phase: Phase::Unrealized,
            status: SocketConnectionStatus::Unconnected,
            local: None,
            no_delay: false,
            keep_alive: false,
            abort_on_close: false,
            read_shutdown: None,
            write_shutdown: false,
            peer_closed: false,
            reset: false,
            pending_error: None,
            waitall: None,
            connect_deadline: None,
            probing: false,
            progress: (Duration::ZERO, 0, 0),
        }
    }

    pub(super) fn bind(&mut self, binding: GuestSocketBinding) -> SocketOutcome<SocketAddrV4> {
        if self.binding.is_some() || !binding.is_tcp() {
            return SocketOutcome::Failed(SocketError::InvalidArgument);
        }
        let address = binding.local_address();
        self.binding = Some(binding);
        SocketOutcome::Completed(address)
    }

    pub(super) fn listen(
        &mut self,
        sockets: &mut Sockets,
        backlog: u32,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let binding = self.binding.as_ref().ok_or(BrokerError::Internal)?;
        let address = binding.local_address();
        if self.status != SocketConnectionStatus::Unconnected {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let backlog = usize::try_from(backlog)
            .map_err(|_| BrokerError::UnsupportedOperation)?
            .max(1);
        match &mut self.phase {
            Phase::Listening(listener) => listener.backlog = backlog,
            Phase::Unrealized => {
                let endpoint = if binding.is_wildcard() {
                    IpListenEndpoint::from(address.port())
                } else {
                    IpListenEndpoint::from(address)
                };
                self.phase = Phase::Listening(Listener {
                    endpoint,
                    backlog,
                    pending: Vec::new(),
                });
            }
            Phase::Stream(..) => return Ok(SocketOutcome::Failed(SocketError::InvalidArgument)),
        }
        if let Phase::Listening(listener) = &mut self.phase {
            listener.refill(&mut sockets.internal, self.no_delay, self.keep_alive);
        }
        self.local = Some(address);
        Ok(SocketOutcome::Completed(address))
    }

    /// Follows the connection's progress; returns the readiness, and whether
    /// to republish it (a `WAITALL` peek may now complete).
    pub(super) fn update(
        &mut self,
        sockets: &mut Sockets,
        now: Duration,
    ) -> (ReadinessFlags, bool) {
        let (side, handle) = match &mut self.phase {
            Phase::Unrealized => {
                let flags = if matches!(self.status, SocketConnectionStatus::Failed(_)) {
                    ReadinessFlags::ERROR
                } else {
                    ReadinessFlags::default()
                };
                return (flags, false);
            }
            Phase::Listening(listener) => {
                listener.refill(&mut sockets.internal, self.no_delay, self.keep_alive);
                let ready = listener
                    .pending
                    .iter()
                    .any(|&handle| acceptable(sockets.internal.get(handle)));
                let flags = if ready {
                    ReadinessFlags::READ
                } else {
                    ReadinessFlags::default()
                };
                return (flags, false);
            }
            Phase::Stream(side, handle) => (*side, *handle),
        };
        let socket = sockets.tcp(side, handle);
        let state = socket.state();
        if self.status == SocketConnectionStatus::Connecting {
            match state {
                State::SynSent | State::SynReceived => {}
                State::Closed => {
                    // A reset (refusal) ends the attempt early; a timeout
                    // at its deadline.
                    let timed_out = self.connect_deadline.is_some_and(|deadline| {
                        now.saturating_add(Duration::from_secs(1)) >= deadline
                    });
                    self.status = SocketConnectionStatus::Failed(if timed_out {
                        SocketError::TimedOut
                    } else {
                        SocketError::ConnectionRefused
                    });
                }
                _ => {
                    self.status = SocketConnectionStatus::Connected;
                    apply_timeout(socket, self.keep_alive, self.probing);
                    self.progress = (now, 0, 0);
                }
            }
        }
        match self.status {
            SocketConnectionStatus::Connected => {}
            SocketConnectionStatus::Failed(_) => return (ReadinessFlags::ERROR, false),
            _ => return (ReadinessFlags::default(), false),
        }
        if matches!(
            state,
            State::CloseWait | State::LastAck | State::Closing | State::TimeWait
        ) {
            self.peer_closed = true;
        }
        let (queued, received) = (socket.send_queue(), socket.recv_queue());
        let (_, last_queued, last_received) = self.progress;
        if queued == 0 || queued < last_queued || received > last_received {
            self.progress.0 = now;
        }
        (self.progress.1, self.progress.2) = (queued, received);
        let probing = queued != 0 && state != State::Closed;
        if probing != self.probing {
            self.probing = probing;
            apply_options(socket, self.no_delay, self.keep_alive, probing);
            apply_timeout(socket, self.keep_alive, probing);
        }
        if state == State::Closed && !self.reset && !(self.peer_closed && self.write_shutdown) {
            // Without progress for the timeout, smoltcp aborted it; else the
            // peer reset it.
            let timed_out = now.saturating_add(Duration::from_secs(1))
                >= self.progress.0 + UNACKNOWLEDGED_TIMEOUT;
            self.reset = true;
            self.pending_error = Some(if timed_out {
                SocketError::TimedOut
            } else {
                SocketError::ConnectionReset
            });
        }
        if self.read_shutdown.is_some() {
            while socket.recv_queue() != 0 && socket.recv(|data| (data.len(), ())).is_ok() {}
        }

        let available = self
            .read_shutdown
            .as_ref()
            .map_or_else(|| socket.recv_queue(), Vec::len);
        let ended = self.read_shutdown.is_some() || self.peer_closed || self.reset;
        let mut flags = ReadinessFlags::default();
        if available != 0 || ended {
            flags = flags | ReadinessFlags::READ;
        }
        if (self.peer_closed || self.reset) && self.read_shutdown.is_none() {
            flags = flags | ReadinessFlags::HANGUP;
        }
        if !self.write_shutdown && (socket.can_send() || self.reset) {
            flags = flags | ReadinessFlags::WRITE;
        }
        if self.pending_error.is_some() {
            flags = flags | ReadinessFlags::ERROR;
        }
        let waited = self
            .waitall
            .is_some_and(|threshold| available >= threshold || ended);
        if waited {
            self.waitall = None;
        }
        (flags, waited)
    }

    /// The stream's end: a reset reports itself once, then the end.
    fn end_of_stream(&mut self) -> SocketOutcome<PlatformStreamReceive> {
        if self.reset
            && let Some(error) = self.pending_error.take()
        {
            return SocketOutcome::Failed(error);
        }
        SocketOutcome::Completed(PlatformStreamReceive::EndOfStream)
    }

    /// The broker core validated the peek window.
    pub(super) fn receive(
        &mut self,
        sockets: &mut Sockets,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> BrokerResult<SocketOutcome<PlatformStreamReceive>> {
        let Phase::Stream(side, handle) = self.phase else {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        };
        match self.status {
            SocketConnectionStatus::Connected => {}
            SocketConnectionStatus::Connecting => return Err(BrokerError::WouldBlock),
            SocketConnectionStatus::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            _ => return Ok(SocketOutcome::Failed(SocketError::NotConnected)),
        }
        let socket = sockets.tcp(side, handle);
        let available = self
            .read_shutdown
            .as_ref()
            .map_or_else(|| socket.recv_queue(), Vec::len);
        let ended =
            self.read_shutdown.is_some() || self.peer_closed || self.reset || !socket.may_recv();
        let peek = flags.contains(ReceiveFlags::PEEK);
        let (start, end) = if peek {
            let peek_offset =
                usize::try_from(peek_offset).map_err(|_| BrokerError::UnsupportedOperation)?;
            let peek_length =
                usize::try_from(peek_length).map_err(|_| BrokerError::UnsupportedOperation)?;
            // As on Linux TCP, a peek beyond what the receive buffer holds
            // waits for the end of the stream: peeking frees no room.
            if flags.contains(ReceiveFlags::WAITALL) && !ended && available < peek_length {
                self.waitall = Some(
                    self.waitall
                        .map_or(peek_length, |threshold| threshold.min(peek_length)),
                );
                return Err(BrokerError::WouldBlock);
            }
            (peek_offset, (peek_offset + length).min(available))
        } else {
            self.waitall = None;
            (0, length.min(available))
        };
        if start >= end {
            return if ended {
                Ok(self.end_of_stream())
            } else {
                Err(BrokerError::WouldBlock)
            };
        }
        let data = match &mut self.read_shutdown {
            Some(saved) if peek => saved[start..end].to_vec(),
            Some(saved) => saved.drain(..end).collect(),
            None => {
                let mut data = vec![0; end];
                let copied = if peek {
                    socket.peek_slice(&mut data)
                } else {
                    socket.recv_slice(&mut data)
                }
                .map_err(|_| BrokerError::Internal)?;
                data.truncate(copied);
                data.split_off(start)
            }
        };
        if data.is_empty() {
            return Err(BrokerError::Internal);
        }
        Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
            data,
        )))
    }

    pub(super) fn send(
        &mut self,
        sockets: &mut Sockets,
        data: &[u8],
    ) -> BrokerResult<SocketOutcome<usize>> {
        let Phase::Stream(side, handle) = self.phase else {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        };
        match self.status {
            SocketConnectionStatus::Connected => {}
            SocketConnectionStatus::Connecting => return Err(BrokerError::WouldBlock),
            SocketConnectionStatus::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            _ => return Ok(SocketOutcome::Failed(SocketError::NotConnected)),
        }
        if self.reset {
            let error = self
                .pending_error
                .take()
                .unwrap_or(SocketError::ConnectionReset);
            return Ok(SocketOutcome::Failed(error));
        }
        let socket = sockets.tcp(side, handle);
        if self.write_shutdown || !socket.may_send() {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        match socket.send_slice(data) {
            Ok(0) => Err(BrokerError::WouldBlock),
            Ok(sent) => Ok(SocketOutcome::Completed(sent)),
            Err(_) => Ok(SocketOutcome::Failed(SocketError::NotConnected)),
        }
    }

    pub(super) fn set_option(
        &mut self,
        sockets: &mut Sockets,
        value: TcpOptionValue,
    ) -> BrokerResult<()> {
        match value {
            TcpOptionValue::NoDelay(enabled) => self.no_delay = enabled,
            TcpOptionValue::KeepAlive(enabled) => self.keep_alive = enabled,
            _ => return Err(BrokerError::UnsupportedOperation),
        }
        if let Phase::Stream(side, handle) = self.phase {
            let socket = sockets.tcp(side, handle);
            apply_options(socket, self.no_delay, self.keep_alive, self.probing);
            if self.status == SocketConnectionStatus::Connected {
                apply_timeout(socket, self.keep_alive, self.probing);
            }
        }
        Ok(())
    }

    pub(super) fn option(&self, name: TcpOptionName) -> BrokerResult<TcpOptionValue> {
        match name {
            TcpOptionName::NoDelay => Ok(TcpOptionValue::NoDelay(self.no_delay)),
            TcpOptionName::KeepAlive => Ok(TcpOptionValue::KeepAlive(self.keep_alive)),
            _ => Err(BrokerError::UnsupportedOperation),
        }
    }

    /// For a listener: keeps its pool of listening sockets filled, and
    /// returns how many more connections it can take, now and in all.
    pub(super) fn refill(&mut self, internal: &mut SocketSet<'static>) -> Option<ListenerRoom> {
        let Phase::Listening(listener) = &mut self.phase else {
            return None;
        };
        listener.refill(internal, self.no_delay, self.keep_alive);
        let idle = listener
            .pending
            .iter()
            .filter(|&&handle| internal.get::<tcp::Socket>(handle).is_listening())
            .count();
        Some(ListenerRoom {
            endpoint: listener.endpoint,
            idle,
            backlog: listener
                .backlog
                .saturating_sub(listener.pending.len() - idle),
        })
    }

    /// Drops pending connections from `sources`, not yet accepted.
    pub(super) fn discard_pending(&mut self, sockets: &mut Sockets, sources: &[IpEndpoint]) {
        if let Phase::Listening(listener) = &mut self.phase {
            listener.pending.retain(|&handle| {
                let socket = sockets.internal.get::<tcp::Socket>(handle);
                let discard = socket
                    .remote_endpoint()
                    .is_some_and(|remote| sources.contains(&remote));
                if discard {
                    sockets.internal.remove(handle);
                }
                !discard
            });
        }
    }

    pub(super) fn status(&mut self) -> PlatformSocketStatus {
        PlatformSocketStatus {
            status: self.status,
            local_address: self.local,
            pending_error: self.pending_error.take(),
        }
    }

    /// Ends the socket: listening sockets reset their connections; a
    /// connection closes gracefully unless aborted, still connecting, or
    /// with unread data (which, as on Linux, resets it).
    pub(super) fn retire(self, stack: &mut Stack) {
        match self.phase {
            Phase::Unrealized => {}
            Phase::Listening(listener) => listener.abort(stack),
            Phase::Stream(side, handle) => {
                let unread = stack.sockets.tcp(side, handle).recv_queue() != 0;
                let abort = self.abort_on_close
                    || self.status == SocketConnectionStatus::Connecting
                    || unread;
                stack.close_tcp(side, handle, abort);
            }
        }
    }
}

/// An accepted connection, for the provider to wrap.
pub(super) struct Accepted {
    pub(super) id: u64,
    pub(super) snapshot: Arc<AtomicU32>,
    pub(super) local_address: SocketAddrV4,
    pub(super) guest_source_lease: GuestSourceLease,
}

impl Stack {
    fn tcp_entry(&mut self, id: u64) -> Option<&mut Tcp> {
        match &mut self.entries.get_mut(&id)?.kind {
            Kind::Tcp(tcp) => Some(tcp),
            Kind::Udp(_) => None,
        }
    }

    /// Connects on the destination's interface. A connection to a guest
    /// listener completes (or is refused) at once.
    pub(super) fn connect_tcp(
        &mut self,
        id: u64,
        address: SocketAddrV4,
        lease: Option<GuestSourceLease>,
    ) -> Result<SocketConnectionStatus, PlatformConnectError> {
        let unchanged = PlatformConnectError::PeerUnchanged(BrokerError::Internal);
        let now = self.now();
        let has_link = self.has_link();
        let process = self.entries.get(&id).ok_or(unchanged)?.process;
        let (process_sockets, sockets) = self.socket_counts(process);
        let (max_process_sockets, max_sockets) = (self.max_sockets_per_process, self.max_sockets);
        let tcp = self.tcp_entry(id).ok_or(unchanged)?;
        if !matches!(tcp.phase, Phase::Unrealized)
            || tcp.status != SocketConnectionStatus::Unconnected
        {
            return Err(unchanged);
        }
        let binding = tcp.binding.clone().ok_or(unchanged)?;
        let destination = match normalize_socket_destination(address) {
            Ok(destination) => destination,
            Err(error) => {
                tcp.status = SocketConnectionStatus::Failed(error);
                return Ok(tcp.status);
            }
        };
        let source = binding
            .source_address_for_destination(destination)
            .ok_or(unchanged)?;
        let side = if is_internal_socket_address(destination) {
            Side::Internal
        } else {
            Side::External
        };
        let lease = match side {
            Side::Internal => {
                let lease = lease
                    .filter(|lease| lease.source_address() == source)
                    .ok_or(unchanged)?;
                // Until accepted, the connection is the connecting
                // process's: the listener's side of it costs a socket.
                if process_sockets >= max_process_sockets || sockets >= max_sockets {
                    return Err(PlatformConnectError::PeerUnchanged(
                        BrokerError::ResourceExhausted,
                    ));
                }
                Some(lease)
            }
            Side::External => {
                drop(lease);
                if !has_link {
                    tcp.status = SocketConnectionStatus::Failed(SocketError::NetworkUnreachable);
                    return Ok(tcp.status);
                }
                None
            }
        };
        let mut socket = new_socket(side, tcp.no_delay, tcp.keep_alive);
        socket.set_timeout(Some(smoltcp_duration(CONNECT_TIMEOUT)));
        let context = match side {
            Side::Internal => self.loopback_interface.context(),
            Side::External => self
                .ethernet
                .as_mut()
                .map(|(interface, _)| interface.context())
                .ok_or(unchanged)?,
        };
        if let Err(error) = socket.connect(context, destination, source) {
            log::debug!("tcp connect to {destination} from {source}: {error:?}");
            return Err(unchanged);
        }
        let handle = self.sockets.set(side).add(socket);
        if let Some(lease) = lease {
            self.leases.push(Lease { lease, process });
        }
        let tcp = self.tcp_entry(id).expect("the entry is still there");
        tcp.phase = Phase::Stream(side, handle);
        tcp.status = SocketConnectionStatus::Connecting;
        tcp.local = Some(source);
        tcp.connect_deadline = Some(now.saturating_add(CONNECT_TIMEOUT));
        self.poll();
        Ok(self.tcp_entry(id).expect("the entry is still there").status)
    }

    /// The oldest established connection of listener `id`, as a new socket
    /// with `registration`.
    pub(super) fn accept_tcp(
        &mut self,
        id: u64,
        registration: ReadinessRegistration,
    ) -> BrokerResult<SocketOutcome<Accepted>> {
        let deadline = self.now().saturating_add(super::CLOSE_TIMEOUT);
        let Some(Entry {
            process,
            kind: Kind::Tcp(listener),
            ..
        }) = self.entries.get_mut(&id)
        else {
            return Err(BrokerError::Internal);
        };
        let process = *process;
        let (no_delay, keep_alive) = (listener.no_delay, listener.keep_alive);
        let Phase::Listening(pending) = &mut listener.phase else {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        };
        let mut refused = Vec::new();
        let accepted = loop {
            let Some(index) = pending
                .pending
                .iter()
                .position(|&handle| acceptable(self.sockets.internal.get(handle)))
            else {
                break None;
            };
            let handle = pending.pending.remove(index);
            let socket = self.sockets.internal.get_mut::<tcp::Socket>(handle);
            let (Some(local), Some(remote)) = (socket.local_endpoint(), socket.remote_endpoint())
            else {
                return Err(BrokerError::Internal);
            };
            let lease = self
                .leases
                .iter()
                .position(|lease| IpEndpoint::from(lease.lease.source_address()) == remote)
                .map(|index| self.leases.swap_remove(index).lease);
            if let Some(lease) = lease {
                apply_options(socket, no_delay, keep_alive, false);
                apply_timeout(socket, keep_alive, false);
                break Some((handle, local, lease));
            }
            // Not a guest connection with a lease: refuse it.
            socket.abort();
            refused.push(handle);
        };
        for handle in refused {
            self.push_closing(Closing {
                side: Side::Internal,
                handle,
                deadline,
            });
        }
        let (handle, local, lease) = accepted.ok_or(BrokerError::WouldBlock)?;
        let local_address = socket_address(local);
        let mut tcp = Tcp::new();
        tcp.phase = Phase::Stream(Side::Internal, handle);
        tcp.status = SocketConnectionStatus::Connected;
        tcp.local = Some(local_address);
        tcp.no_delay = no_delay;
        tcp.keep_alive = keep_alive;
        tcp.progress = (self.now(), 0, 0);
        let (id, snapshot) = self.insert(
            Entry::new(process, registration, Kind::Tcp(tcp)),
            ReadinessFlags::default(),
        );
        Ok(SocketOutcome::Completed(Accepted {
            id,
            snapshot,
            local_address,
            guest_source_lease: lease,
        }))
    }

    pub(super) fn shutdown_tcp(
        &mut self,
        id: u64,
        mode: ShutdownMode,
    ) -> BrokerResult<SocketOutcome<()>> {
        let Some(Entry {
            kind: Kind::Tcp(tcp),
            ..
        }) = self.entries.get_mut(&id)
        else {
            return Err(BrokerError::Internal);
        };
        let (read, write) = match mode {
            ShutdownMode::Abort => {
                tcp.abort_on_close = true;
                return Ok(SocketOutcome::Completed(()));
            }
            ShutdownMode::StopListening => {
                if !matches!(tcp.phase, Phase::Listening(_)) {
                    return Ok(SocketOutcome::Failed(SocketError::NotConnected));
                }
                let Phase::Listening(listener) =
                    core::mem::replace(&mut tcp.phase, Phase::Unrealized)
                else {
                    unreachable!("checked above");
                };
                listener.abort(self);
                return Ok(SocketOutcome::Completed(()));
            }
            ShutdownMode::Read => (true, false),
            ShutdownMode::Write => (false, true),
            ShutdownMode::Both => (true, true),
            _ => return Err(BrokerError::UnsupportedOperation),
        };
        let Phase::Stream(side, handle) = tcp.phase else {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        };
        if tcp.status != SocketConnectionStatus::Connected {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let socket = self.sockets.tcp(side, handle);
        if read && tcp.read_shutdown.is_none() {
            let mut saved = vec![0; socket.recv_queue()];
            let copied = socket.recv_slice(&mut saved).unwrap_or(0);
            saved.truncate(copied);
            tcp.read_shutdown = Some(saved);
        }
        if write && !tcp.write_shutdown {
            socket.close();
            tcp.write_shutdown = true;
        }
        Ok(SocketOutcome::Completed(()))
    }
}
