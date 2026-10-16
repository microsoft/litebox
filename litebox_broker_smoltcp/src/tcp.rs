// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TCP sockets: a guest socket is unrealized until it listens or connects.
//! As on the userland broker, a listener keeps a queue of guest
//! connections, up to its backlog, each a socket pair (see
//! [`super::socket_pair`]) whose connector is connected at once; accepting
//! one takes it, with the source lease its connector's connect brought. A connection beyond the guest is
//! one smoltcp socket on the Ethernet interface.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
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
    ReceiveFlags, ShutdownMode, SocketConnectionStatus, SocketError, SocketOptionName,
    SocketOptionValue, SocketOutcome,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{self, State};
use smoltcp::storage::RingBuffer;

use super::{CONNECT_TIMEOUT, Entry, Kind, Run, Sockets, Stack, socket_address, zeroed};

/// Each direction's buffer.
const BUFFER_SIZE: usize = 64 * 1024;

const KEEP_ALIVE_INTERVAL: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(75);

/// How long sent data may go unacknowledged before the connection is
/// aborted: Linux's default (`tcp_retries2` = 15). Set only while data or
/// a FIN waits to be acknowledged, or keep-alive is on (see
/// [`Tcp::arm_timeout`]): smoltcp counts it from the last packet received,
/// so it would also end an idle connection, which Linux keeps open.
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
    /// Unread data held apart, which reads then take: after a read
    /// shutdown, what was received before it; for an external connection
    /// in TIME-WAIT, what is left (smoltcp clears its buffers as TIME-WAIT
    /// ends; Linux keeps it). In the stack's memory budget until all read
    /// (see [`Tcp::save`]).
    saved: Option<Vec<u8>>,
    /// After a read shutdown, later data is discarded.
    read_shutdown: bool,
    /// Data was discarded after a read shutdown: unread data (Linux queues
    /// it), which a close resets the connection for.
    discarded: bool,
    write_shutdown: bool,
    /// The peer closed its write side.
    peer_closed: bool,
    /// The connection ended other than by both sides closing (e.g., a
    /// reset, or a timeout).
    reset: bool,
    pending_error: Option<SocketError>,
    /// A peek with `WAITALL` waits for this much data; its waiters are
    /// woken once it arrives or the stream ends.
    waitall: Option<usize>,
    /// The reader whose peek started at offset zero, unless a receive came
    /// after it (see [`Tcp::continue_peek`]).
    peek_reader: Option<ObjectHandle>,
    /// Data waits to be sent, so the socket probes (see
    /// [`ZERO_WINDOW_PROBE_INTERVAL`]).
    probing: bool,
    /// Data or a FIN waits to be acknowledged, so the connection times out
    /// (see [`UNACKNOWLEDGED_TIMEOUT`]).
    unacknowledged: bool,
    /// When smoltcp last heard from the peer, as far as the stack saw.
    heard: Duration,
    /// Since when the timeout is armed (see [`Tcp::arm_timeout`]).
    armed: Option<Duration>,
}

enum Phase {
    Unrealized,
    Listening(Listener),
    /// A guest connection: a socket pair, and the end of it.
    Internal(u64, usize),
    /// A connection beyond the guest.
    External(SocketHandle),
}

struct Listener {
    backlog: usize,
    /// Guest connections not yet accepted, oldest first.
    queue: VecDeque<Queued>,
}

/// A guest connection waiting at its listener.
pub(super) struct Queued {
    pair: u64,
    /// The connecting process, which it counts against until accepted.
    pub(super) process: ProcessId,
    /// The destination it connected to: the accepted socket's address.
    local: SocketAddrV4,
    lease: GuestSourceLease,
}

/// Fails if the stack's memory budget (see `MAX_BUFFER_BYTES`), or memory,
/// has no room for its buffers.
fn new_socket(
    sockets: &Sockets,
    no_delay: bool,
    keep_alive: bool,
) -> BrokerResult<tcp::Socket<'static>> {
    if sockets.room() < 2 * BUFFER_SIZE {
        return Err(BrokerError::OutOfMemory);
    }
    let mut socket = tcp::Socket::new(
        RingBuffer::new(zeroed(BUFFER_SIZE)?),
        RingBuffer::new(zeroed(BUFFER_SIZE)?),
    );
    apply_options(&mut socket, no_delay, keep_alive, false);
    Ok(socket)
}

fn take_received(socket: &mut tcp::Socket) -> BrokerResult<Vec<u8>> {
    let mut data = zeroed(socket.recv_queue())?;
    let copied = socket.recv_slice(&mut data).unwrap_or(0);
    data.truncate(copied);
    Ok(data)
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

/// Whether the guest may write, as Linux's `sk_stream_is_writeable`: the
/// send buffer's free space is at least half of what it holds, so a writer
/// woken by acknowledgments writes in bulk, not a few bytes at a time.
fn writable(socket: &tcp::Socket) -> bool {
    let queued = socket.send_queue();
    socket.can_send() && socket.send_capacity() - queued >= queued / 2
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
            saved: None,
            read_shutdown: false,
            discarded: false,
            write_shutdown: false,
            peer_closed: false,
            reset: false,
            pending_error: None,
            waitall: None,
            peek_reader: None,
            probing: false,
            unacknowledged: false,
            heard: Duration::ZERO,
            armed: None,
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

    pub(super) fn listen(&mut self, backlog: u32) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let address = self
            .binding
            .as_ref()
            .ok_or(BrokerError::Internal)?
            .local_address();
        if self.status != SocketConnectionStatus::Unconnected {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let backlog = usize::try_from(backlog)
            .map_err(|_| BrokerError::UnsupportedOperation)?
            .max(1);
        match &mut self.phase {
            Phase::Listening(listener) => listener.backlog = backlog,
            Phase::Unrealized => {
                self.phase = Phase::Listening(Listener {
                    backlog,
                    queue: VecDeque::new(),
                });
            }
            Phase::Internal(..) | Phase::External(_) => {
                return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
            }
        }
        self.local = Some(address);
        Ok(SocketOutcome::Completed(address))
    }

    /// For a listener: whether it takes connections to `destination`.
    fn listens_at(&self, destination: SocketAddrV4) -> bool {
        matches!(self.phase, Phase::Listening(_))
            && self
                .binding
                .as_ref()
                .is_some_and(|binding| binding.covers(destination))
    }

    /// For a listener: the guest connections waiting to be accepted.
    pub(super) fn queued(&self) -> impl Iterator<Item = &Queued> {
        match &self.phase {
            Phase::Listening(listener) => Some(listener.queue.iter()),
            _ => None,
        }
        .into_iter()
        .flatten()
    }

    /// For a listener: drops the queued connections `discard` picks (e.g.,
    /// of a process that ended), without resetting their connectors.
    pub(super) fn discard_queued(
        &mut self,
        sockets: &mut Sockets,
        discard: impl Fn(&Queued) -> bool,
    ) {
        if let Phase::Listening(listener) = &mut self.phase {
            listener.queue.retain(|queued| {
                let dropped = discard(queued);
                if dropped {
                    sockets.close_pair(queued.pair, 1, false);
                }
                !dropped
            });
        }
    }

    /// Follows the connection's progress; returns the readiness, and whether
    /// to republish it (a `WAITALL` peek may now complete).
    pub(super) fn update(&mut self, sockets: &mut Sockets, run: &Run) -> (ReadinessFlags, bool) {
        match &self.phase {
            Phase::Unrealized => {
                let flags = if matches!(self.status, SocketConnectionStatus::Failed(_)) {
                    ReadinessFlags::ERROR
                } else {
                    ReadinessFlags::default()
                };
                (flags, false)
            }
            Phase::Listening(listener) => {
                let flags = if listener.queue.is_empty() {
                    ReadinessFlags::default()
                } else {
                    ReadinessFlags::READ
                };
                (flags, false)
            }
            &Phase::Internal(id, end) => {
                let Ok(pair) = sockets.pair(id) else {
                    return (ReadinessFlags::default(), false);
                };
                self.observe(pair, end);
                let writable = pair.writable(end, run.room) || pair.peer_closed(end);
                if self.read_shutdown && sockets.discard_pair(id, end) != 0 {
                    self.discarded = true;
                }
                let available = self.available(sockets);
                self.readiness(available, writable)
            }
            &Phase::External(handle) => self.update_external(sockets, handle, run),
        }
    }

    /// For a guest connection's `end`: takes in a reset, or the end of the
    /// stream, from its peer.
    fn observe(&mut self, pair: &mut super::socket_pair::SocketPair, end: usize) {
        if pair.take_reset(end) && !self.reset {
            self.reset = true;
            self.pending_error = Some(SocketError::ConnectionReset);
        }
        if pair.peer_finished(end) {
            self.peer_closed = true;
        }
    }

    fn update_external(
        &mut self,
        sockets: &mut Sockets,
        handle: SocketHandle,
        run: &Run,
    ) -> (ReadinessFlags, bool) {
        let timed_out = run.timed_out.contains(&handle);
        let socket = sockets.tcp(handle);
        let state = socket.state();
        if self.status == SocketConnectionStatus::Connecting {
            match state {
                State::SynSent | State::SynReceived => {}
                // A reset (refusal) ends the attempt early; else a timeout.
                State::Closed => {
                    self.status = SocketConnectionStatus::Failed(if timed_out {
                        SocketError::TimedOut
                    } else {
                        SocketError::ConnectionRefused
                    });
                }
                _ => {
                    self.status = SocketConnectionStatus::Connected;
                    self.heard = run.now;
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
        if state == State::TimeWait
            && self.saved.is_none()
            && let Ok(data) = take_received(socket)
        {
            self.save(sockets, data);
        }
        let socket = sockets.tcp(handle);
        if let (Some(local), Some(remote)) = (socket.local_endpoint(), socket.remote_endpoint())
            && run
                .heard
                .binary_search(&(socket_address(local), socket_address(remote)))
                .is_ok()
        {
            self.heard = run.now;
        }
        let probing = socket.send_queue() != 0 && state != State::Closed;
        if probing && !self.probing {
            // smoltcp starts counting anew as data is queued to send.
            self.heard = run.now;
        }
        if probing != self.probing {
            self.probing = probing;
            apply_options(socket, self.no_delay, self.keep_alive, probing);
        }
        // As Linux retransmits a FIN as data, within the same timeout.
        let unacknowledged =
            probing || matches!(state, State::FinWait1 | State::Closing | State::LastAck);
        self.unacknowledged = unacknowledged;
        self.arm_timeout(socket, run.now);
        if state == State::Closed && !self.reset {
            // smoltcp timed it out, or the peer reset it, unless both sides
            // closed: smoltcp ends that only with all sent acknowledged, so
            // unacknowledged data means a reset (that of only the FIN looks
            // as an end).
            if timed_out {
                self.reset = true;
                self.pending_error = Some(SocketError::TimedOut);
            } else if !(self.peer_closed && self.write_shutdown) || socket.send_queue() != 0 {
                self.reset = true;
                self.pending_error = Some(SocketError::ConnectionReset);
            }
        }
        if self.read_shutdown && socket.recv_queue() != 0 {
            if matches!(state, State::FinWait1 | State::FinWait2) {
                // Data after both directions' shutdowns: as Linux (per
                // RFC 1122), a reset.
                socket.abort();
                self.reset = true;
                self.pending_error = Some(SocketError::ConnectionReset);
            }
            while socket.recv_queue() != 0 && socket.recv(|data| (data.len(), ())).is_ok() {}
            self.discarded = true;
        }
        let writable = writable(socket);
        let available = self.available(sockets);
        self.readiness(available, writable)
    }

    /// Holds `data` apart (see [`Self::saved`]), in the stack's memory
    /// budget.
    fn save(&mut self, sockets: &mut Sockets, data: Vec<u8>) {
        sockets.queued += data.capacity();
        self.saved = Some(data);
    }

    /// Frees what is held apart, once all read.
    fn release_saved(&mut self, sockets: &mut Sockets) {
        if let Some(saved) = &mut self.saved
            && saved.is_empty()
        {
            sockets.queued -= saved.capacity();
            *saved = Vec::new();
        }
    }

    /// What a receive would take now.
    fn available(&self, sockets: &mut Sockets) -> usize {
        if let Some(saved) = &self.saved {
            return saved.len();
        }
        match self.phase {
            Phase::Internal(id, end) => sockets.pair(id).map_or(0, |pair| pair.available(end)),
            Phase::External(handle) => sockets.tcp(handle).recv_queue(),
            _ => 0,
        }
    }

    /// A connection's readiness, with `available` to read and, if
    /// `writable`, room to write; and whether a `WAITALL` peek may now
    /// complete.
    fn readiness(&mut self, available: usize, writable: bool) -> (ReadinessFlags, bool) {
        let ended = self.read_shutdown || self.peer_closed || self.reset;
        let mut flags = ReadinessFlags::default();
        if available != 0 || ended {
            flags = flags | ReadinessFlags::READ;
        }
        if (self.peer_closed || self.reset) && !self.read_shutdown {
            flags = flags | ReadinessFlags::HANGUP;
        }
        if !self.write_shutdown && (writable || self.reset) {
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

    /// For a connection: the timeout while data or a FIN waits to be
    /// acknowledged, or keep-alive is on, as Linux aborts then; none
    /// otherwise. smoltcp counts it from when it last heard from the peer,
    /// which, on a connection idle until it is armed, may be long before;
    /// Linux counts from then (its retransmissions, or keep-alive probes).
    /// So it is extended by the silence before.
    fn arm_timeout(&mut self, socket: &mut tcp::Socket, now: Duration) {
        let armed = (self.unacknowledged || self.keep_alive).then(|| self.armed.unwrap_or(now));
        self.armed = armed;
        socket.set_timeout(
            armed.map(|armed| (UNACKNOWLEDGED_TIMEOUT + armed.saturating_sub(self.heard)).into()),
        );
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

    /// A peek's later chunk continues only the same reader's peek, with no
    /// receive since: otherwise its bytes might not follow those returned.
    fn continue_peek(
        &mut self,
        reader: ObjectHandle,
        flags: ReceiveFlags,
        peek_offset: u32,
    ) -> BrokerResult<()> {
        if !flags.contains(ReceiveFlags::PEEK) {
            self.peek_reader = None;
        } else if peek_offset == 0 {
            self.peek_reader = Some(reader);
        } else if self.peek_reader != Some(reader) {
            return Err(BrokerError::WouldBlock);
        }
        Ok(())
    }

    /// The broker core validated the peek window.
    pub(super) fn receive(
        &mut self,
        sockets: &mut Sockets,
        reader: ObjectHandle,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> BrokerResult<SocketOutcome<PlatformStreamReceive>> {
        self.continue_peek(reader, flags, peek_offset)?;
        if !matches!(self.phase, Phase::Internal(..) | Phase::External(_)) {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        match self.status {
            SocketConnectionStatus::Connected => {}
            SocketConnectionStatus::Connecting => return Err(BrokerError::WouldBlock),
            SocketConnectionStatus::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            _ => return Ok(SocketOutcome::Failed(SocketError::NotConnected)),
        }
        let mut ended = self.read_shutdown || self.reset;
        match self.phase {
            Phase::Internal(id, end) => {
                let pair = sockets.pair(id)?;
                self.observe(pair, end);
                ended |= self.reset || self.peer_closed;
            }
            Phase::External(handle) => {
                ended |= self.peer_closed || !sockets.tcp(handle).may_recv();
            }
            _ => {}
        }
        let available = self.available(sockets);
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
            (0, length.min(available))
        };
        if start >= end {
            return if !ended {
                Err(BrokerError::WouldBlock)
            } else if start != 0 {
                // A peek's later chunk: the earlier ones took data, after
                // which Linux leaves an error pending.
                Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream))
            } else {
                Ok(self.end_of_stream())
            };
        }
        let data = match (&mut self.saved, &self.phase) {
            (Some(saved), _) if peek => saved[start..end].to_vec(),
            (Some(saved), _) => {
                let data = saved.drain(..end).collect();
                self.release_saved(sockets);
                data
            }
            (None, &Phase::Internal(id, pair_end)) => {
                sockets.read_pair(id, pair_end, start, end, peek)?
            }
            (None, &Phase::External(handle)) => {
                let socket = sockets.tcp(handle);
                let mut data = zeroed(end)?;
                let copied = if peek {
                    socket.peek_slice(&mut data)
                } else {
                    socket.recv_slice(&mut data)
                }
                .map_err(|_| BrokerError::Internal)?;
                data.truncate(copied);
                data.split_off(start)
            }
            (None, _) => return Err(BrokerError::Internal),
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
        if self.write_shutdown {
            return Ok(SocketOutcome::Failed(SocketError::Shutdown));
        }
        if !matches!(self.phase, Phase::Internal(..) | Phase::External(_)) {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        match self.status {
            SocketConnectionStatus::Connected => {}
            SocketConnectionStatus::Connecting => return Err(BrokerError::WouldBlock),
            SocketConnectionStatus::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            _ => return Ok(SocketOutcome::Failed(SocketError::NotConnected)),
        }
        if let Phase::Internal(id, end) = self.phase {
            let pair = sockets.pair(id)?;
            self.observe(pair, end);
        }
        if self.reset {
            let error = self
                .pending_error
                .take()
                .unwrap_or(SocketError::ConnectionReset);
            return Ok(SocketOutcome::Failed(error));
        }
        let sent = match self.phase {
            Phase::Internal(id, end) => {
                // As on the userland broker, whose socket pair fails the write
                // (`EPIPE`), which it reports as a reset.
                if sockets.pair(id)?.peer_closed(end) {
                    return Ok(SocketOutcome::Failed(SocketError::ConnectionReset));
                }
                sockets.write_pair(id, end, data)?
            }
            Phase::External(handle) => {
                let socket = sockets.tcp(handle);
                if !socket.may_send() {
                    return Ok(SocketOutcome::Failed(SocketError::NotConnected));
                }
                match socket.send_slice(data) {
                    Ok(sent) => sent,
                    Err(_) => return Ok(SocketOutcome::Failed(SocketError::NotConnected)),
                }
            }
            _ => return Err(BrokerError::Internal),
        };
        if sent == 0 {
            return Err(BrokerError::WouldBlock);
        }
        Ok(SocketOutcome::Completed(sent))
    }

    pub(super) fn set_option(
        &mut self,
        sockets: &mut Sockets,
        value: SocketOptionValue,
    ) -> BrokerResult<()> {
        match value {
            SocketOptionValue::NoDelay(enabled) => self.no_delay = enabled,
            SocketOptionValue::KeepAlive(enabled) => self.keep_alive = enabled,
            _ => return Err(BrokerError::UnsupportedOperation),
        }
        if let Phase::External(handle) = self.phase {
            let socket = sockets.tcp(handle);
            // The timeout follows as the stack runs, after the operation.
            apply_options(socket, self.no_delay, self.keep_alive, self.probing);
        }
        Ok(())
    }

    pub(super) fn option(&self, name: SocketOptionName) -> BrokerResult<SocketOptionValue> {
        match name {
            SocketOptionName::NoDelay => Ok(SocketOptionValue::NoDelay(self.no_delay)),
            SocketOptionName::KeepAlive => Ok(SocketOptionValue::KeepAlive(self.keep_alive)),
            _ => Err(BrokerError::UnsupportedOperation),
        }
    }

    pub(super) fn status(&mut self) -> PlatformSocketStatus {
        PlatformSocketStatus {
            status: self.status,
            local_address: self.local,
            pending_error: self.pending_error.take(),
        }
    }

    /// Ends the socket. A listener resets its queued connections. A
    /// connection closes gracefully unless aborted, still connecting, or
    /// with unread data (which, as on Linux and the userland broker, resets
    /// it).
    pub(super) fn retire(self, stack: &mut Stack) {
        let unread = self.discarded || self.saved.as_ref().is_some_and(|saved| !saved.is_empty());
        if let Some(saved) = &self.saved {
            stack.sockets.queued -= saved.capacity();
        }
        match self.phase {
            Phase::Unrealized => {}
            Phase::Listening(listener) => {
                for queued in listener.queue {
                    stack.sockets.close_pair(queued.pair, 1, true);
                }
            }
            Phase::Internal(id, end) => {
                let Ok(pair) = stack.sockets.pair(id) else {
                    return;
                };
                let reset = self.abort_on_close || unread || pair.available(end) != 0;
                // As on the userland broker: aborting a connection its
                // listener has not accepted withdraws it.
                if let Some(listener) = pair.queued_at.filter(|_| self.abort_on_close)
                    && let Some(Entry {
                        kind: Kind::Tcp(listener),
                        ..
                    }) = stack.entries.get_mut(&listener)
                {
                    listener.discard_queued(&mut stack.sockets, |queued| queued.pair == id);
                }
                stack.sockets.close_pair(id, end, reset);
            }
            Phase::External(handle) => {
                let unread = unread || stack.sockets.tcp(handle).recv_queue() != 0;
                let abort = self.abort_on_close
                    || self.status == SocketConnectionStatus::Connecting
                    || unread;
                stack.close_tcp(handle, abort);
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

    /// Connects: to a guest listener, at once (or is refused, as on the
    /// userland broker), else on the Ethernet interface.
    pub(super) fn connect_tcp(
        &mut self,
        id: u64,
        address: SocketAddrV4,
        lease: Option<GuestSourceLease>,
    ) -> Result<SocketConnectionStatus, PlatformConnectError> {
        let unchanged = PlatformConnectError::PeerUnchanged(BrokerError::Internal);
        let process = self.entries.get(&id).ok_or(unchanged)?.process;
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
        let result = if is_internal_socket_address(destination) {
            let lease = lease
                .filter(|lease| lease.source_address() == source)
                .ok_or(unchanged)?;
            self.connect_internal(process, destination, lease)?
        } else {
            drop(lease);
            self.connect_external(id, source, destination)?
        };
        let tcp = self.tcp_entry(id).ok_or(unchanged)?;
        tcp.status = match result {
            Ok(phase) => {
                let connected = matches!(phase, Phase::Internal(..));
                tcp.phase = phase;
                tcp.local = Some(source);
                if connected {
                    SocketConnectionStatus::Connected
                } else {
                    SocketConnectionStatus::Connecting
                }
            }
            Err(error) => SocketConnectionStatus::Failed(error),
        };
        Ok(tcp.status)
    }

    /// Queues a connection at the listener for `destination`; refused if
    /// there is none, or its backlog is full.
    fn connect_internal(
        &mut self,
        process: ProcessId,
        destination: SocketAddrV4,
        lease: GuestSourceLease,
    ) -> Result<Result<Phase, SocketError>, PlatformConnectError> {
        // Until accepted, the connection is the connecting process's: the
        // listener's side of it costs a socket.
        let (process_sockets, sockets) = self.socket_counts(process);
        if process_sockets >= self.max_sockets_per_process || sockets >= self.max_sockets {
            return Err(PlatformConnectError::PeerUnchanged(
                BrokerError::ResourceExhausted,
            ));
        }
        let listener = self
            .entries
            .iter()
            .find_map(|(&listener, entry)| match &entry.kind {
                Kind::Tcp(tcp) if tcp.listens_at(destination) => Some(listener),
                _ => None,
            });
        let Some(listener) = listener else {
            return Ok(Err(SocketError::ConnectionRefused));
        };
        let pair = self.sockets.open_pair(listener);
        let Some(Phase::Listening(queue)) = self.tcp_entry(listener).map(|tcp| &mut tcp.phase)
        else {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        };
        if queue.queue.len() >= queue.backlog || queue.queue.try_reserve(1).is_err() {
            self.sockets.close_pair(pair, 0, false);
            self.sockets.close_pair(pair, 1, false);
            return Ok(Err(SocketError::ConnectionRefused));
        }
        queue.queue.push_back(Queued {
            pair,
            process,
            local: destination,
            lease,
        });
        Ok(Ok(Phase::Internal(pair, 0)))
    }

    fn connect_external(
        &mut self,
        id: u64,
        source: SocketAddrV4,
        destination: SocketAddrV4,
    ) -> Result<Result<Phase, SocketError>, PlatformConnectError> {
        let unchanged = PlatformConnectError::PeerUnchanged(BrokerError::Internal);
        // As Linux: no route, and no TCP to a broadcast address
        // (`tcp_v4_connect`).
        if !self.has_network() || super::is_broadcast(*destination.ip()) {
            return Ok(Err(SocketError::NetworkUnreachable));
        }
        // As Linux, which lets the port be bound again (with `SO_REUSEADDR`),
        // but not the connection be made twice.
        if self.connection_exists(source, destination) {
            return Ok(Err(SocketError::AddressNotAvailable));
        }
        let tcp = self.tcp_entry(id).ok_or(unchanged)?;
        let (no_delay, keep_alive) = (tcp.no_delay, tcp.keep_alive);
        let mut socket = new_socket(&self.sockets, no_delay, keep_alive)
            .map_err(PlatformConnectError::PeerUnchanged)?;
        socket.set_timeout(Some(CONNECT_TIMEOUT.into()));
        let (interface, _) = self.ethernet.as_mut().ok_or(unchanged)?;
        if let Err(error) = socket.connect(interface.context(), destination, source) {
            log::debug!("tcp connect to {destination} from {source}: {error:?}");
            return Err(unchanged);
        }
        Ok(Ok(Phase::External(self.sockets.set.add(socket))))
    }

    /// The oldest guest connection queued at listener `id`, as a new socket
    /// with `registration`.
    pub(super) fn accept_tcp(
        &mut self,
        id: u64,
        registration: ReadinessRegistration,
    ) -> BrokerResult<SocketOutcome<Accepted>> {
        let process = self.entries.get(&id).ok_or(BrokerError::Internal)?.process;
        let (process_sockets, _) = self.socket_counts(process);
        let max_sockets_per_process = self.max_sockets_per_process;
        let listener = self.tcp_entry(id).ok_or(BrokerError::Internal)?;
        let (no_delay, keep_alive) = (listener.no_delay, listener.keep_alive);
        let Phase::Listening(queue) = &mut listener.phase else {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        };
        let front = queue.queue.front().ok_or(BrokerError::WouldBlock)?;
        // As on the userland broker: the accepted socket counts against the
        // listener's process, where the connection, if the process made it,
        // no longer counts as pending.
        let own = usize::from(front.process == process);
        if process_sockets + 1 - own > max_sockets_per_process {
            return Err(BrokerError::ResourceExhausted);
        }
        let queued = queue.queue.pop_front().ok_or(BrokerError::Internal)?;
        self.sockets.pair(queued.pair)?.queued_at = None;
        let mut tcp = Tcp::new();
        tcp.phase = Phase::Internal(queued.pair, 1);
        tcp.status = SocketConnectionStatus::Connected;
        tcp.local = Some(queued.local);
        tcp.no_delay = no_delay;
        tcp.keep_alive = keep_alive;
        let (id, snapshot) = self.insert(
            Entry::new(process, registration, Kind::Tcp(tcp)),
            ReadinessFlags::default(),
        );
        Ok(SocketOutcome::Completed(Accepted {
            id,
            snapshot,
            local_address: queued.local,
            guest_source_lease: queued.lease,
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
                for queued in listener.queue {
                    self.sockets.close_pair(queued.pair, 1, true);
                }
                return Ok(SocketOutcome::Completed(()));
            }
            ShutdownMode::Read => (true, false),
            ShutdownMode::Write => (false, true),
            ShutdownMode::Both => (true, true),
            _ => return Err(BrokerError::UnsupportedOperation),
        };
        if let (Phase::External(handle), SocketConnectionStatus::Connecting) =
            (&tcp.phase, tcp.status)
        {
            // As Linux's `tcp_disconnect`: the attempt ends, without a reset,
            // and reports one. Linux's socket may connect again; as on the
            // userland broker, the broker core's has failed.
            self.sockets.set.remove(*handle);
            tcp.phase = Phase::Unrealized;
            tcp.status = SocketConnectionStatus::Failed(SocketError::ConnectionReset);
            tcp.pending_error = Some(SocketError::ConnectionReset);
            return Ok(SocketOutcome::Completed(()));
        }
        if !matches!(tcp.phase, Phase::Internal(..) | Phase::External(_))
            || tcp.status != SocketConnectionStatus::Connected
        {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        if read && !tcp.read_shutdown {
            if tcp.saved.is_none() {
                let data = match tcp.phase {
                    Phase::Internal(pair, end) => {
                        let available = self.sockets.pair(pair)?.available(end);
                        self.sockets.read_pair(pair, end, 0, available, false)?
                    }
                    Phase::External(handle) => take_received(self.sockets.tcp(handle))?,
                    _ => return Err(BrokerError::Internal),
                };
                tcp.save(&mut self.sockets, data);
            }
            tcp.read_shutdown = true;
        }
        if write && !tcp.write_shutdown {
            match tcp.phase {
                Phase::Internal(pair, end) => self.sockets.pair(pair)?.finish(end),
                Phase::External(handle) => self.sockets.tcp(handle).close(),
                _ => return Err(BrokerError::Internal),
            }
            tcp.write_shutdown = true;
        }
        Ok(SocketOutcome::Completed(()))
    }
}
