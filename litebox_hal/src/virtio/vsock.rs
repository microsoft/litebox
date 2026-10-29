// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio socket device (device type 19): QEMU's `vhost-vsock-pci`, e.g.:
//!
//! ```text
//! -device vhost-vsock-pci,guest-cid=3,disable-legacy=on
//! ```
//!
//! No features are negotiated, so only stream sockets exist. Each of the
//! host's requests, to any guest port, waits for the user to accept or refuse
//! it ([`VirtioVsock::take_request`]). The user connects to the host's ports
//! too ([`VirtioVsock::connect`]); the driver keeps no time, so the user gives
//! up on a connection the host does not answer, and forgets it. At most
//! [`MAX_CONNECTIONS`] connections, of either direction, exist at once, of
//! which at most [`MAX_USER_CONNECTIONS`] the user asked for, so the user
//! cannot keep the host from connecting; further requests are refused.
//! `Stream` is the protocol (connection states and credit), apart from the
//! queues, so it can be tested on its own.
//!
//! The host is not trusted. A packet (header and payload in one buffer) is
//! copied out of DMA memory once, then checked, and dropped if malformed, or
//! resets its connection. Received data is copied out at once, so control
//! packets never wait behind unread data; the host may send at most
//! `RX_CAPACITY` unread bytes per connection (its credit), else the
//! connection is reset. Resets for packets on no connection are bounded
//! (`MAX_RESETS`). Each look at the device takes at most a queue's worth of
//! returned buffers per queue, as a device can return them as fast as they
//! are lent back ([`VirtioVsock::take_backlog`]).
//!
//! Control packets queue behind data in the transmit queue, so the host gets
//! a connection's data before its `SHUTDOWN`. As on Linux, a closed
//! connection ([`VirtioVsock::close`]) stays until the host resets it, so
//! the host gets an orderly end; its user forgets it then, or after a
//! timeout of its own.

use super::Error;
use super::buffers::Buffers;
use super::pci::PciTransport;
use super::queue::VirtQueue;
use crate::dma::Hal;
use crate::interrupt::MsiMessage;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;

const DEVICE_TYPE: u16 = 19;
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const EVENT_QUEUE: u16 = 2;

/// `virtio_vsock_hdr`.
const HEADER_SIZE: usize = 44;
/// The most payload a buffer holds; vhost splits longer host writes.
const MAX_PAYLOAD: usize = 4096;
const BUFFER_SIZE: usize = HEADER_SIZE + MAX_PAYLOAD;
const RX_BUFFERS: u16 = 16;
const TX_BUFFERS: u16 = 16;
/// `virtio_vsock_event`: `le32 id`.
const EVENT_SIZE: usize = 4;
const EVENT_BUFFERS: u16 = 4;

/// The received data, not yet consumed, that the host may send on a
/// connection: the `buf_alloc` of every packet the driver sends.
const RX_CAPACITY: u32 = 64 * 1024;
/// `VMADDR_CID_HOST`: the only peer.
const HOST_CID: u64 = 2;
/// `VIRTIO_VSOCK_TYPE_STREAM`.
const TYPE_STREAM: u16 = 1;
/// `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET`.
const EVENT_TRANSPORT_RESET: u32 = 0;

/// Connections, requested by either end, live, or gone but not yet
/// forgotten, at once:
/// what bounds the memory the host can make the driver hold (each has up to
/// `RX_CAPACITY` bytes of received data).
pub const MAX_CONNECTIONS: usize = 32;

/// Of [`MAX_CONNECTIONS`], those the user asked for (connecting, live, or
/// gone but not yet forgotten), at once: the rest are kept for the host's
/// requests.
pub const MAX_USER_CONNECTIONS: usize = MAX_CONNECTIONS / 2;

/// `VIRTIO_VSOCK_OP_*`.
mod op {
    pub const REQUEST: u16 = 1;
    pub const RESPONSE: u16 = 2;
    pub const RST: u16 = 3;
    pub const SHUTDOWN: u16 = 4;
    pub const RW: u16 = 5;
    pub const CREDIT_UPDATE: u16 = 6;
    pub const CREDIT_REQUEST: u16 = 7;
}

/// `VIRTIO_VSOCK_SHUTDOWN_RCV`: the sender will receive no more.
const SHUTDOWN_RCV: u32 = 1;
/// `VIRTIO_VSOCK_SHUTDOWN_SEND`: the sender will send no more.
const SHUTDOWN_SEND: u32 = 2;
const SHUTDOWN_BOTH: u32 = SHUTDOWN_RCV | SHUTDOWN_SEND;

/// RSTs for packets on no connection (and refused requests beyond
/// [`MAX_CONNECTIONS`]) waiting for a transmit buffer; more are dropped.
const MAX_RESETS: usize = 8;
/// RSTs waiting for a transmit buffer in all: those of connections the
/// driver ends, beyond [`MAX_RESETS`]; past it, the oldest is dropped.
const MAX_QUEUED_RESETS: usize = MAX_RESETS + MAX_CONNECTIONS;

/// A connection, by its ends' ports, whichever end connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId {
    pub guest_port: u32,
    pub host_port: u32,
}

/// What became of a connection the user asked the host for
/// ([`VirtioVsock::connect`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectState {
    /// The host has yet to answer.
    Connecting,
    /// The host accepted it; it is live, or gone since.
    Established,
    /// The host refused it, or it was reset (e.g., the host sent anything
    /// but its answer, or the transport reset), or it is unknown.
    Failed,
}

/// `virtio_vsock_hdr`, little-endian and packed in a packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Header {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    /// The payload's length.
    len: u32,
    ty: u16,
    op: u16,
    flags: u32,
    /// The sender's receive buffer.
    buf_alloc: u32,
    /// The bytes the sender's reader consumed, ever (wrapping).
    fwd_cnt: u32,
}

impl Header {
    #[expect(clippy::cast_possible_truncation, reason = "fields of their width")]
    fn parse(bytes: &[u8; HEADER_SIZE]) -> Self {
        let field = |offset: usize, len: usize| {
            bytes[offset..offset + len]
                .iter()
                .rev()
                .fold(0u64, |value, &byte| value << 8 | u64::from(byte))
        };
        Self {
            src_cid: field(0, 8),
            dst_cid: field(8, 8),
            src_port: field(16, 4) as u32,
            dst_port: field(20, 4) as u32,
            len: field(24, 4) as u32,
            ty: field(28, 2) as u16,
            op: field(30, 2) as u16,
            flags: field(32, 4) as u32,
            buf_alloc: field(36, 4) as u32,
            fwd_cnt: field(40, 4) as u32,
        }
    }

    fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0; HEADER_SIZE];
        let fields: [&[u8]; 10] = [
            &self.src_cid.to_le_bytes(),
            &self.dst_cid.to_le_bytes(),
            &self.src_port.to_le_bytes(),
            &self.dst_port.to_le_bytes(),
            &self.len.to_le_bytes(),
            &self.ty.to_le_bytes(),
            &self.op.to_le_bytes(),
            &self.flags.to_le_bytes(),
            &self.buf_alloc.to_le_bytes(),
            &self.fwd_cnt.to_le_bytes(),
        ];
        let mut offset = 0;
        for field in fields {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        bytes
    }

    /// The connection a packet from the host is on.
    fn connection(&self) -> ConnectionId {
        ConnectionId {
            guest_port: self.dst_port,
            host_port: self.src_port,
        }
    }
}

/// The host's end of a connection.
struct Peer {
    buf_alloc: u32,
    fwd_cnt: u32,
    /// `SHUTDOWN_*` flags it sent.
    shutdown: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Requested by the host; the user has yet to accept or refuse it.
    Requested,
    /// Requested by the user; the host has yet to answer.
    Connecting,
    Live,
    /// Reset by either end, shut down both ways, or lost to a transport
    /// reset: nothing more is sent or received on it. Its data can still be
    /// read until the user forgets it.
    Gone,
}

/// Control packets for a connection, waiting for a transmit buffer.
#[derive(Default)]
struct Pending {
    /// The packet that opens the connection: a `REQUEST` if it is
    /// connecting, else a `RESPONSE`.
    opening: bool,
    credit_update: bool,
    /// A `SHUTDOWN` with [`Connection::shutdown`]'s flags.
    shutdown: bool,
}

struct Connection {
    phase: Phase,
    /// The user asked for it (it began [`Phase::Connecting`]).
    by_user: bool,
    peer: Peer,
    /// `SHUTDOWN_*` flags this end sent, or is to send.
    shutdown: u32,
    /// Received, not yet read; at most [`RX_CAPACITY`] bytes.
    rx: VecDeque<u8>,
    /// Bytes read, ever (wrapping).
    fwd_cnt: u32,
    /// The `fwd_cnt` the peer last got.
    reported_fwd_cnt: u32,
    /// Bytes sent, ever (wrapping).
    tx_cnt: u32,
    pending: Pending,
}

impl Connection {
    fn new(phase: Phase, peer: Peer, pending: Pending) -> Self {
        Self {
            phase,
            by_user: phase == Phase::Connecting,
            peer,
            shutdown: 0,
            rx: VecDeque::new(),
            fwd_cnt: 0,
            reported_fwd_cnt: 0,
            tx_cnt: 0,
            pending,
        }
    }
}

/// The connections' protocol: packets in, packets out. Its user accepts or
/// refuses requests, connects to the host, reads and writes stream data, and
/// ends connections; the transport sends what [`Self::next_control`] and
/// [`Self::data_header`] give it.
struct Stream {
    guest_cid: u64,
    /// At most [`MAX_CONNECTIONS`].
    connections: BTreeMap<ConnectionId, Connection>,
    /// Requested connections the user has not taken, oldest first.
    requests: VecDeque<ConnectionId>,
    /// RSTs waiting for a transmit buffer, oldest first; at most
    /// [`MAX_QUEUED_RESETS`].
    resets: VecDeque<Header>,
}

impl Stream {
    fn new(guest_cid: u64) -> Self {
        Self {
            guest_cid,
            connections: BTreeMap::new(),
            requests: VecDeque::new(),
            resets: VecDeque::new(),
        }
    }

    fn header(&self, op: u16, id: ConnectionId) -> Header {
        Header {
            src_cid: self.guest_cid,
            dst_cid: HOST_CID,
            src_port: id.guest_port,
            dst_port: id.host_port,
            ty: TYPE_STREAM,
            op,
            buf_alloc: RX_CAPACITY,
            ..Header::default()
        }
    }

    /// The live connection `id`, if any.
    fn live(&mut self, id: ConnectionId) -> Option<&mut Connection> {
        self.connections
            .get_mut(&id)
            .filter(|connection| connection.phase == Phase::Live)
    }

    /// A packet the device delivered: everything it wrote to the buffer.
    fn receive(&mut self, packet: &[u8]) {
        let Some((header, rest)) = packet.split_first_chunk::<HEADER_SIZE>() else {
            return;
        };
        let header = Header::parse(header);
        if header.ty != TYPE_STREAM
            || header.dst_cid != self.guest_cid
            || header.src_cid != HOST_CID
        {
            return;
        }
        let id = header.connection();
        let phase = self.connections.get(&id).map(|connection| connection.phase);
        let payload = usize::try_from(header.len)
            .ok()
            .and_then(|len| rest.get(..len));
        match (phase, payload) {
            (Some(Phase::Live), Some(payload)) => self.receive_on_connection(id, &header, payload),
            // Before the response, the host sends nothing but an RST.
            (Some(Phase::Requested), Some(_)) if header.op == op::RST => self.lose(id),
            (Some(Phase::Connecting), Some(_)) => self.receive_answer(id, &header),
            // Malformed, or out of order.
            (Some(Phase::Live | Phase::Requested | Phase::Connecting), _) => self.reset(id),
            (None | Some(Phase::Gone), Some(_)) => self.receive_other(&header),
            (None | Some(Phase::Gone), None) => {}
        }
    }

    fn receive_on_connection(&mut self, id: ConnectionId, header: &Header, payload: &[u8]) {
        let Some(connection) = self.live(id) else {
            return;
        };
        let peer = &mut connection.peer;
        peer.buf_alloc = header.buf_alloc;
        peer.fwd_cnt = header.fwd_cnt;
        match header.op {
            op::RW => {
                // Data after this end shut down only receiving was sent
                // before the peer knew: dropped, not a violation.
                if peer.shutdown & SHUTDOWN_SEND != 0 || connection.shutdown == SHUTDOWN_BOTH {
                    self.reset(id);
                } else if connection.shutdown & SHUTDOWN_RCV == 0 {
                    if connection.rx.len() + payload.len() > RX_CAPACITY as usize {
                        self.reset(id);
                    } else {
                        connection.rx.extend(payload);
                    }
                }
            }
            op::CREDIT_UPDATE => {}
            op::CREDIT_REQUEST => connection.pending.credit_update = true,
            op::SHUTDOWN => {
                peer.shutdown |= header.flags & SHUTDOWN_BOTH;
                // As Linux does, so the host's close completes promptly.
                if peer.shutdown == SHUTDOWN_BOTH {
                    self.reset(id);
                }
            }
            op::RST => self.lose(id),
            // A repeated request, a response to a request never sent, or an
            // unknown operation.
            _ => self.reset(id),
        }
    }

    /// The host's answer to connection `id`, which the user requested: its
    /// response makes it live, and its RST refuses it; anything else, or a
    /// response to a request not yet sent, resets it, as Linux does.
    fn receive_answer(&mut self, id: ConnectionId, header: &Header) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        match header.op {
            op::RESPONSE if !connection.pending.opening => {
                connection.phase = Phase::Live;
                connection.peer.buf_alloc = header.buf_alloc;
                connection.peer.fwd_cnt = header.fwd_cnt;
            }
            op::RST => self.lose(id),
            _ => self.reset(id),
        }
    }

    /// A packet on no connection, or a gone one.
    fn receive_other(&mut self, header: &Header) {
        let id = header.connection();
        match header.op {
            op::RST => {}
            op::REQUEST
                if !self.connections.contains_key(&id)
                    && self.connections.len() < MAX_CONNECTIONS =>
            {
                let peer = Peer {
                    buf_alloc: header.buf_alloc,
                    fwd_cnt: header.fwd_cnt,
                    shutdown: 0,
                };
                self.connections.insert(
                    id,
                    Connection::new(Phase::Requested, peer, Pending::default()),
                );
                self.requests.push_back(id);
            }
            _ => {
                if self.resets.len() < MAX_RESETS {
                    self.resets.push_back(self.header(op::RST, id));
                }
            }
        }
    }

    /// The connection is gone without an RST from this end; one not yet live
    /// is forgotten.
    fn lose(&mut self, id: ConnectionId) {
        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        match connection.phase {
            Phase::Requested | Phase::Connecting => self.remove(id),
            Phase::Live => {
                connection.phase = Phase::Gone;
                connection.pending = Pending::default();
            }
            Phase::Gone => {}
        }
    }

    /// Removes connection `id`, and the request for it, if any.
    fn remove(&mut self, id: ConnectionId) {
        self.connections.remove(&id);
        self.requests.retain(|request| *request != id);
    }

    /// Resets the connection, unless it is gone: data already received can
    /// still be read.
    fn reset(&mut self, id: ConnectionId) {
        let Some(connection) = self.connections.get(&id) else {
            return;
        };
        if connection.phase == Phase::Gone {
            return;
        }
        self.lose(id);
        if self.resets.len() >= MAX_QUEUED_RESETS {
            self.resets.pop_front();
        }
        self.resets.push_back(self.header(op::RST, id));
    }

    /// The device reset its transport: every connection is gone, and the
    /// guest's CID may have changed.
    fn transport_reset(&mut self, guest_cid: u64) {
        self.guest_cid = guest_cid;
        let ids: Vec<_> = self.connections.keys().copied().collect();
        for id in ids {
            self.lose(id);
        }
        self.resets.clear();
    }

    /// The next requested connection for the user to [`Self::accept`] or
    /// [`Self::refuse`].
    fn take_request(&mut self) -> Option<ConnectionId> {
        self.requests.pop_front()
    }

    /// Accepts a requested connection; false if it is not one (e.g., the
    /// host gave up on it).
    fn accept(&mut self, id: ConnectionId) -> bool {
        let Some(connection) = self
            .connections
            .get_mut(&id)
            .filter(|connection| connection.phase == Phase::Requested)
        else {
            return false;
        };
        connection.phase = Phase::Live;
        connection.pending.opening = true;
        self.requests.retain(|request| *request != id);
        true
    }

    /// Refuses a requested connection.
    fn refuse(&mut self, id: ConnectionId) {
        if self
            .connections
            .get(&id)
            .is_some_and(|connection| connection.phase == Phase::Requested)
        {
            self.reset(id);
        }
    }

    /// Asks the host for connection `id`; false if it is in use, or
    /// [`MAX_CONNECTIONS`] exist, or [`MAX_USER_CONNECTIONS`] the user asked
    /// for.
    fn connect(&mut self, id: ConnectionId) -> bool {
        let by_user = self
            .connections
            .values()
            .filter(|connection| connection.by_user)
            .count();
        if self.connections.contains_key(&id)
            || self.connections.len() >= MAX_CONNECTIONS
            || by_user >= MAX_USER_CONNECTIONS
        {
            return false;
        }
        // The host's credit comes with its response.
        let peer = Peer {
            buf_alloc: 0,
            fwd_cnt: 0,
            shutdown: 0,
        };
        let pending = Pending {
            opening: true,
            ..Pending::default()
        };
        self.connections
            .insert(id, Connection::new(Phase::Connecting, peer, pending));
        true
    }

    /// What became of connection `id`, which the user [`Self::connect`]ed.
    fn connect_state(&self, id: ConnectionId) -> ConnectState {
        match self.connections.get(&id).map(|connection| connection.phase) {
            Some(Phase::Connecting) => ConnectState::Connecting,
            Some(Phase::Live | Phase::Gone) => ConnectState::Established,
            Some(Phase::Requested) | None => ConnectState::Failed,
        }
    }

    /// A packet on connection `id`, live or connecting, carrying the reader's
    /// progress.
    fn connection_header(&mut self, id: ConnectionId, op: u16, len: u32) -> Option<Header> {
        let header = self.header(op, id);
        let connection = self
            .connections
            .get_mut(&id)
            .filter(|connection| matches!(connection.phase, Phase::Live | Phase::Connecting))?;
        connection.reported_fwd_cnt = connection.fwd_cnt;
        connection.pending.credit_update = false;
        Some(Header {
            len,
            fwd_cnt: connection.fwd_cnt,
            ..header
        })
    }

    /// The next control packet to send, if any.
    fn next_control(&mut self) -> Option<Header> {
        // RSTs first: their connections are no longer in the table.
        if let Some(reset) = self.resets.pop_front() {
            return Some(reset);
        }
        let (id, op, flags) = self.connections.iter_mut().find_map(|(id, connection)| {
            let pending = &mut connection.pending;
            // The opening packet first: nothing else may precede it.
            if core::mem::take(&mut pending.opening) {
                let op = if connection.phase == Phase::Connecting {
                    op::REQUEST
                } else {
                    op::RESPONSE
                };
                Some((*id, op, 0))
            } else if pending.credit_update {
                Some((*id, op::CREDIT_UPDATE, 0))
            } else if core::mem::take(&mut pending.shutdown) {
                Some((*id, op::SHUTDOWN, connection.shutdown))
            } else {
                None
            }
        })?;
        let header = self.connection_header(id, op, 0)?;
        Some(Header { flags, ..header })
    }

    /// How much data the peer takes now on connection `id`; `None` if it
    /// takes no more (no live connection, the peer receives no more, or this
    /// end shut down sending).
    fn send_budget(&mut self, id: ConnectionId) -> Option<usize> {
        let connection = self.live(id)?;
        if connection.peer.shutdown & SHUTDOWN_RCV != 0 || connection.shutdown & SHUTDOWN_SEND != 0
        {
            return None;
        }
        if connection.pending.opening {
            // Data must follow the response.
            return Some(0);
        }
        // Zero if the peer's numbers are bogus.
        let in_flight = connection.tx_cnt.wrapping_sub(connection.peer.fwd_cnt);
        Some(connection.peer.buf_alloc.saturating_sub(in_flight) as usize)
    }

    /// The header of `len` bytes of data on connection `id`, which
    /// [`Self::send_budget`] allowed.
    fn data_header(&mut self, id: ConnectionId, len: usize) -> Option<Header> {
        if self.send_budget(id)? < len {
            return None;
        }
        let len = u32::try_from(len).ok()?;
        let header = self.connection_header(id, op::RW, len)?;
        let connection = self.live(id)?;
        connection.tx_cnt = connection.tx_cnt.wrapping_add(len);
        Some(header)
    }

    /// Copies data received on connection `id` into `output`: how much, or
    /// `None` at the end of the stream (there is no such connection, or no
    /// more data will come).
    fn read(&mut self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
        let connection = self.connections.get_mut(&id)?;
        if connection.rx.is_empty() {
            let ended = connection.phase == Phase::Gone
                || connection.peer.shutdown & SHUTDOWN_SEND != 0
                || connection.shutdown & SHUTDOWN_RCV != 0;
            return if ended { None } else { Some(0) };
        }
        let len = output.len().min(connection.rx.len());
        for (byte, received) in output.iter_mut().zip(connection.rx.drain(..len)) {
            *byte = received;
        }
        #[expect(clippy::cast_possible_truncation, reason = "at most RX_CAPACITY")]
        let consumed = len as u32;
        connection.fwd_cnt = connection.fwd_cnt.wrapping_add(consumed);
        let unreported = connection.fwd_cnt.wrapping_sub(connection.reported_fwd_cnt);
        // Also once emptied, as Linux does (`SO_RCVLOWAT`): a sender may cap
        // what it has in flight below `RX_CAPACITY` (Linux caps it at its own
        // buffer size, e.g., `SO_VM_SOCKETS_BUFFER_SIZE`), and then waits
        // for an update before half of it is read.
        if connection.phase == Phase::Live
            && (unreported >= RX_CAPACITY / 2 || (connection.rx.is_empty() && unreported != 0))
        {
            connection.pending.credit_update = true;
        }
        Some(len)
    }

    /// Whether connection `id` is gone and its data read, or unknown: the
    /// user [`Self::forget`]s it then.
    fn is_closed(&self, id: ConnectionId) -> bool {
        self.connections
            .get(&id)
            .is_none_or(|connection| connection.phase == Phase::Gone && connection.rx.is_empty())
    }

    /// Shuts down this end's `flags` (`SHUTDOWN_*`) of live connection `id`,
    /// with a `SHUTDOWN` after what was sent.
    fn shut_down(&mut self, id: ConnectionId, flags: u32) {
        if let Some(connection) = self.live(id)
            && connection.shutdown | flags != connection.shutdown
        {
            connection.shutdown |= flags;
            connection.pending.shutdown = true;
        }
    }

    /// Ends connection `id`: resets it unless it is gone, and forgets it.
    fn forget(&mut self, id: ConnectionId) {
        self.reset(id);
        self.remove(id);
    }
}

/// A live socket device. Not internally synchronized.
///
/// [`Self::take_request`], [`Self::connect_state`], [`Self::read`],
/// [`Self::write`], [`Self::is_closed`] and [`Self::forget`] first take what
/// the device returned (see [`Self::take_backlog`]); the other methods take
/// nothing new, so a request just taken is still one when it is accepted or
/// refused.
///
/// Dropping it resets the device; if that fails, it leaks its queues and
/// buffers, which the device may still access (receive and event buffers
/// are always posted).
pub struct VirtioVsock {
    transport: PciTransport,
    rx: ManuallyDrop<VirtQueue>,
    rx_buffers: ManuallyDrop<Buffers>,
    tx: ManuallyDrop<VirtQueue>,
    tx_buffers: ManuallyDrop<Buffers>,
    event: ManuallyDrop<VirtQueue>,
    event_buffers: ManuallyDrop<Buffers>,
    stream: Stream,
    /// A received packet, copied out of DMA memory.
    scratch: Vec<u8>,
    /// See [`Self::take_backlog`].
    backlog: bool,
}

impl VirtioVsock {
    /// The first virtio socket device on bus 0, brought up, interrupting
    /// with `interrupt` (if it can; see [`PciTransport::interrupts`]); `None`
    /// if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven, e.g., its guest CID is not valid.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: Option<MsiMessage>,
    ) -> Option<Result<Self, Error>> {
        let function = super::find_pci_devices(DEVICE_TYPE).next()?;
        Some(
            PciTransport::new(hal, function, interrupt)
                .and_then(|transport| Self::bring_up(hal, transport)),
        )
    }

    fn bring_up(hal: &'static dyn Hal, transport: PciTransport) -> Result<Self, Error> {
        transport.init(0)?;
        let setup = || -> Result<_, Error> {
            let guest_cid = guest_cid(&transport)?;
            let rx = transport.setup_queue(hal, RX_QUEUE, RX_BUFFERS)?;
            let tx = transport.setup_queue(hal, TX_QUEUE, TX_BUFFERS)?;
            let event = transport.setup_queue(hal, EVENT_QUEUE, EVENT_BUFFERS)?;
            let rx_buffers = Buffers::new(hal, &rx, RX_BUFFERS, BUFFER_SIZE)?;
            let tx_buffers = Buffers::new(hal, &tx, TX_BUFFERS, BUFFER_SIZE)?;
            let event_buffers = Buffers::new(hal, &event, EVENT_BUFFERS, EVENT_SIZE)?;
            Ok((
                guest_cid,
                rx,
                rx_buffers,
                tx,
                tx_buffers,
                event,
                event_buffers,
            ))
        };
        let (guest_cid, mut rx, mut rx_buffers, tx, tx_buffers, mut event, mut event_buffers) =
            setup().inspect_err(|_| transport.fail())?;
        while let Some(buffer) = rx_buffers.free.pop() {
            rx_buffers.post(&mut rx, buffer, BUFFER_SIZE, true);
        }
        while let Some(buffer) = event_buffers.free.pop() {
            event_buffers.post(&mut event, buffer, EVENT_SIZE, true);
        }
        transport.start();
        transport.notify(&rx);
        transport.notify(&event);
        Ok(Self {
            transport,
            rx: ManuallyDrop::new(rx),
            rx_buffers: ManuallyDrop::new(rx_buffers),
            tx: ManuallyDrop::new(tx),
            tx_buffers: ManuallyDrop::new(tx_buffers),
            event: ManuallyDrop::new(event),
            event_buffers: ManuallyDrop::new(event_buffers),
            stream: Stream::new(guest_cid),
            scratch: vec![0; BUFFER_SIZE],
            backlog: false,
        })
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// The guest's CID, which the host connects to.
    pub fn guest_cid(&self) -> u64 {
        self.stream.guest_cid
    }

    /// The next connection the host requested; the caller must
    /// [`Self::accept`] or [`Self::refuse`] it.
    pub fn take_request(&mut self) -> Option<ConnectionId> {
        self.poll();
        self.stream.take_request()
    }

    /// Accepts a requested connection; false if it is not one (e.g., the
    /// host gave up on it meanwhile).
    pub fn accept(&mut self, id: ConnectionId) -> bool {
        let accepted = self.stream.accept(id);
        self.send_control();
        accepted
    }

    /// Refuses a requested connection.
    pub fn refuse(&mut self, id: ConnectionId) {
        self.stream.refuse(id);
        self.send_control();
    }

    /// Asks the host for connection `id`, from guest port `id.guest_port` to
    /// host port `id.host_port`; false if `id` is in use, or
    /// [`MAX_CONNECTIONS`] exist, or [`MAX_USER_CONNECTIONS`] the user asked
    /// for. [`Self::connect_state`] tells what became of it: one that
    /// failed is already forgotten; the caller forgets (resets) one the host
    /// takes too long to answer.
    pub fn connect(&mut self, id: ConnectionId) -> bool {
        let requested = self.stream.connect(id);
        self.send_control();
        requested
    }

    /// What became of connection `id`, which [`Self::connect`] asked for.
    pub fn connect_state(&mut self, id: ConnectionId) -> ConnectState {
        self.poll();
        self.stream.connect_state(id)
    }

    /// Copies data received on connection `id` into `output`: how much (zero
    /// if none has arrived), or `None` at the end of the stream: there is no
    /// such connection, or it will receive no more.
    pub fn read(&mut self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
        self.poll();
        let read = self.stream.read(id, output);
        self.send_control();
        read
    }

    /// Queues as much of `bytes` on connection `id` as the host's credit and
    /// free transmit buffers allow: how much (zero if either has none), or
    /// `None` if the connection takes no more: it is not live, the host
    /// receives no more, or this end shut down sending.
    pub fn write(&mut self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
        self.poll();
        let mut budget = self.stream.send_budget(id)?;
        let mut written = 0;
        while written < bytes.len() && budget > 0 {
            let Some(&buffer) = self.tx_buffers.free.last() else {
                break;
            };
            let chunk = &bytes[written..];
            let chunk = &chunk[..chunk.len().min(MAX_PAYLOAD).min(budget)];
            let Some(header) = self.stream.data_header(id, chunk.len()) else {
                break;
            };
            self.tx_buffers.free.pop();
            self.post(buffer, header, chunk);
            written += chunk.len();
            budget -= chunk.len();
        }
        if written != 0 {
            self.transport.notify(&self.tx);
        }
        self.send_control();
        Some(written)
    }

    /// Shuts down sending on connection `id`: the host gets a `SHUTDOWN`
    /// after what was written.
    pub fn shutdown(&mut self, id: ConnectionId) {
        self.stream.shut_down(id, SHUTDOWN_SEND);
        self.send_control();
    }

    /// Shuts down receiving on connection `id`: the host gets a `SHUTDOWN`
    /// (after what was written), so its sends fail. Data already received
    /// can still be read; data the host sent before it got the `SHUTDOWN` is
    /// dropped.
    pub fn shutdown_receiving(&mut self, id: ConnectionId) {
        self.stream.shut_down(id, SHUTDOWN_RCV);
        self.send_control();
    }

    /// Shuts connection `id` down both ways, after what was written; data
    /// from the host then resets it. It is gone once the host resets it (see
    /// [`Self::is_closed`]).
    pub fn close(&mut self, id: ConnectionId) {
        self.stream.shut_down(id, SHUTDOWN_BOTH);
        self.send_control();
    }

    /// Whether connection `id` is gone (reset, shut down both ways, or lost
    /// to a transport reset), and its data read, or unknown: forget it then.
    pub fn is_closed(&mut self, id: ConnectionId) -> bool {
        self.poll();
        self.stream.is_closed(id)
    }

    /// Ends connection `id`, if any, resetting it unless it is gone, and
    /// frees its slot.
    pub fn forget(&mut self, id: ConnectionId) {
        self.poll();
        self.stream.forget(id);
        self.send_control();
    }

    /// Takes what the device returned, at most a queue's worth of each kind
    /// (see [`Self::take_backlog`]), and sends what is pending.
    fn poll(&mut self) {
        let events = self.collect_events();
        let received = self.collect_received();
        // Bounded without a budget: only buffers lent and not yet returned
        // come back, and none is lent here.
        let mut returned = 0;
        while let Some((buffer, _)) = self.tx_buffers.take_used(&mut self.tx) {
            self.tx_buffers.free.push(buffer);
            returned += 1;
        }
        self.backlog |= events != 0 || received != 0 || returned != 0;
        self.send_control();
    }

    /// Takes whether the looks at the device since the last call took
    /// anything, or stopped at their budget: the device does not interrupt
    /// again for what they took (e.g., while reading one connection, data for
    /// another whose turn is over), so the user must call again soon.
    pub fn take_backlog(&mut self) -> bool {
        core::mem::take(&mut self.backlog)
    }

    /// Takes returned event buffers: how many.
    fn collect_events(&mut self) -> usize {
        let mut transport_reset = false;
        let taken = self.event_buffers.recycle_used(
            &mut self.event,
            usize::from(EVENT_BUFFERS),
            EVENT_SIZE,
            |buffers, buffer, len| {
                if len < EVENT_SIZE {
                    return;
                }
                let mut id = [0u8; EVENT_SIZE];
                let source = buffers.ptr(buffer, 0, EVENT_SIZE);
                // Safety: the device returned the buffer; `EVENT_SIZE` bytes
                // are in it, copied into a local.
                unsafe { core::ptr::copy_nonoverlapping(source, id.as_mut_ptr(), EVENT_SIZE) };
                transport_reset |= u32::from_le_bytes(id) == EVENT_TRANSPORT_RESET;
            },
        );
        if taken != 0 {
            self.transport.notify(&self.event);
        }
        // Once however many the device reported.
        if transport_reset {
            let guest_cid = guest_cid(&self.transport).unwrap_or_else(|_| {
                litebox_util_log::warn!("vsock transport reset to an invalid guest CID");
                self.stream.guest_cid
            });
            self.stream.transport_reset(guest_cid);
        }
        taken
    }

    /// Takes returned receive buffers: how many.
    fn collect_received(&mut self) -> usize {
        let scratch = &mut self.scratch;
        let stream = &mut self.stream;
        let taken = self.rx_buffers.recycle_used(
            &mut self.rx,
            usize::from(RX_BUFFERS),
            BUFFER_SIZE,
            |buffers, buffer, len| {
                // `take_used` clamps `len` to the buffer.
                let source = buffers.ptr(buffer, 0, len);
                // Safety: the device returned the buffer; `len` bytes are in
                // it, and in `scratch`, which is a buffer long.
                unsafe { core::ptr::copy_nonoverlapping(source, scratch.as_mut_ptr(), len) };
                stream.receive(&scratch[..len]);
            },
        );
        if taken != 0 {
            self.transport.notify(&self.rx);
        }
        taken
    }

    /// Sends pending control packets while transmit buffers are free; the
    /// rest wait.
    fn send_control(&mut self) {
        let mut sent = false;
        while let Some(&buffer) = self.tx_buffers.free.last() {
            let Some(header) = self.stream.next_control() else {
                break;
            };
            self.tx_buffers.free.pop();
            self.post(buffer, header, &[]);
            sent = true;
        }
        if sent {
            self.transport.notify(&self.tx);
        }
    }

    /// Lends a free transmit buffer, holding `header` and `payload`, to the
    /// device.
    fn post(&mut self, buffer: u16, header: Header, payload: &[u8]) {
        let len = HEADER_SIZE + payload.len();
        let destination = self.tx_buffers.ptr(buffer, 0, len);
        // Safety: a free buffer, which the device does not access; `len`
        // bytes of it.
        unsafe {
            core::ptr::copy_nonoverlapping(header.to_bytes().as_ptr(), destination, HEADER_SIZE);
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                destination.add(HEADER_SIZE),
                payload.len(),
            );
        }
        self.tx_buffers.post(&mut self.tx, buffer, len, false);
    }
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        if self.transport.reset().is_err() {
            return;
        }
        // Safety: dropped once, here; after the reset, the device accesses
        // none of them.
        unsafe {
            ManuallyDrop::drop(&mut self.rx);
            ManuallyDrop::drop(&mut self.rx_buffers);
            ManuallyDrop::drop(&mut self.tx);
            ManuallyDrop::drop(&mut self.tx_buffers);
            ManuallyDrop::drop(&mut self.event);
            ManuallyDrop::drop(&mut self.event_buffers);
        }
    }
}

/// The device configuration: `le64 guest_cid`, which must be a guest's
/// (3 through `u32::MAX - 1`).
fn guest_cid(transport: &PciTransport) -> Result<u64, Error> {
    let bad = Error::BadStructure("device");
    let config = transport.device_config().ok_or(bad)?;
    if config.len() < 8 {
        return Err(bad);
    }
    let cid = u64::from(config.read_u32(0)) | u64::from(config.read_u32(4)) << 32;
    if (3..u64::from(u32::MAX)).contains(&cid) {
        Ok(cid)
    } else {
        Err(bad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST: u64 = 7;
    const PORT: u32 = 1024;
    const PEER: u32 = 50000;
    const ID: ConnectionId = id(PORT, PEER);

    const fn id(guest_port: u32, host_port: u32) -> ConnectionId {
        ConnectionId {
            guest_port,
            host_port,
        }
    }

    /// A packet from the host on connection `id`.
    fn on(id: ConnectionId, op: u16) -> Header {
        Header {
            src_cid: HOST_CID,
            dst_cid: GUEST,
            src_port: id.host_port,
            dst_port: id.guest_port,
            ty: TYPE_STREAM,
            op,
            buf_alloc: 256 * 1024,
            ..Header::default()
        }
    }

    fn from_host(op: u16) -> Header {
        on(ID, op)
    }

    fn shutdown_from_host(flags: u32) -> Header {
        Header {
            flags,
            ..from_host(op::SHUTDOWN)
        }
    }

    fn packet(header: Header, payload: &[u8]) -> Vec<u8> {
        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(payload);
        packet
    }

    fn send(stream: &mut Stream, header: Header) {
        stream.receive(&packet(header, &[]));
    }

    fn send_data_on(stream: &mut Stream, id: ConnectionId, data: &[u8]) {
        let header = Header {
            len: u32::try_from(data.len()).unwrap(),
            ..on(id, op::RW)
        };
        stream.receive(&packet(header, data));
    }

    fn send_data(stream: &mut Stream, data: &[u8]) {
        send_data_on(stream, ID, data);
    }

    fn controls(stream: &mut Stream) -> Vec<Header> {
        core::iter::from_fn(|| stream.next_control()).collect()
    }

    fn ops(stream: &mut Stream) -> Vec<u16> {
        controls(stream).iter().map(|header| header.op).collect()
    }

    /// Connection `ID`, accepted, with the response sent.
    fn connected() -> Stream {
        let mut s = Stream::new(GUEST);
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(s.take_request(), Some(ID));
        assert!(s.accept(ID));
        assert_eq!(ops(&mut s), [op::RESPONSE]);
        s
    }

    fn read_all_on(stream: &mut Stream, id: ConnectionId) -> Vec<u8> {
        let mut output = vec![0; 2 * RX_CAPACITY as usize];
        let len = stream.read(id, &mut output).unwrap();
        output.truncate(len);
        output
    }

    fn read_all(stream: &mut Stream) -> Vec<u8> {
        read_all_on(stream, ID)
    }

    #[test]
    fn headers_are_little_endian_with_full_width_cids() {
        let header = Header {
            src_cid: 0x0102_0304_0506_0708,
            ty: 0x0a0b,
            fwd_cnt: 0xdead_beef,
            ..Header::default()
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes[..8], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(bytes[28..30], [0x0b, 0x0a]);
        assert_eq!(bytes[40..], [0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(Header::parse(&bytes), header);
    }

    #[test]
    fn a_request_waits_for_the_user_and_is_accepted() {
        let mut s = Stream::new(GUEST);
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.send_budget(ID), None);
        assert_eq!(s.take_request(), Some(ID));
        assert_eq!(s.take_request(), None);
        assert!(s.accept(ID));
        // Data must wait for the response.
        assert_eq!(s.send_budget(ID), Some(0));
        assert_eq!(
            controls(&mut s),
            [Header {
                src_cid: GUEST,
                dst_cid: HOST_CID,
                src_port: PORT,
                dst_port: PEER,
                ty: TYPE_STREAM,
                op: op::RESPONSE,
                buf_alloc: RX_CAPACITY,
                ..Header::default()
            }]
        );
        assert_eq!(s.send_budget(ID), Some(256 * 1024));
        assert!(!s.accept(ID));
    }

    #[test]
    fn a_refused_request_is_reset_and_forgotten() {
        let mut s = Stream::new(GUEST);
        send(&mut s, from_host(op::REQUEST));
        let request = s.take_request().unwrap();
        s.refuse(request);
        let refused = controls(&mut s);
        assert_eq!(refused.len(), 1);
        assert_eq!(
            (refused[0].op, refused[0].src_port, refused[0].dst_port),
            (op::RST, PORT, PEER)
        );
        assert!(s.connections.is_empty());
        // The host may ask again.
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(s.take_request(), Some(ID));
    }

    #[test]
    fn many_connections_on_any_ports_are_independent() {
        let mut s = Stream::new(GUEST);
        let ids = [id(PORT, PEER), id(PORT, PEER + 1), id(PORT + 1, PEER)];
        for id in ids {
            send(&mut s, on(id, op::REQUEST));
        }
        // Oldest first.
        for id in ids {
            assert_eq!(s.take_request(), Some(id));
            assert!(s.accept(id));
        }
        assert_eq!(ops(&mut s), [op::RESPONSE; 3]);
        for (i, id) in ids.iter().enumerate() {
            send_data_on(&mut s, *id, &[u8::try_from(i).unwrap(); 3]);
        }
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(read_all_on(&mut s, *id), [u8::try_from(i).unwrap(); 3]);
        }
        // Each is credited on its own.
        let updates = controls(&mut s);
        assert_eq!(updates.len(), 3);
        for (update, id) in updates.iter().zip(ids) {
            assert_eq!(
                (update.op, update.src_port, update.dst_port, update.fwd_cnt),
                (op::CREDIT_UPDATE, id.guest_port, id.host_port, 3)
            );
        }
        // One's end leaves the others.
        send(&mut s, on(ids[1], op::RST));
        assert!(s.is_closed(ids[1]));
        assert!(s.live(ids[0]).is_some() && s.live(ids[2]).is_some());
        s.forget(ids[1]);
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.connections.len(), 2);
    }

    #[test]
    fn requests_beyond_the_cap_are_refused() {
        let mut s = Stream::new(GUEST);
        for port in 0..u32::try_from(MAX_CONNECTIONS).unwrap() {
            send(&mut s, on(id(PORT, port), op::REQUEST));
        }
        assert_eq!(ops(&mut s), []);
        send(&mut s, on(id(PORT, PEER), op::REQUEST));
        let refused = controls(&mut s);
        assert_eq!(refused.len(), 1);
        assert_eq!((refused[0].op, refused[0].dst_port), (op::RST, PEER));
        assert_eq!(s.requests.len(), MAX_CONNECTIONS);
        // Gone connections count until forgotten.
        let first = s.take_request().unwrap();
        assert!(s.accept(first));
        send(&mut s, on(first, op::RST));
        send(&mut s, on(id(PORT, PEER), op::REQUEST));
        assert_eq!(ops(&mut s), [op::RST]);
        s.forget(first);
        send(&mut s, on(id(PORT, PEER), op::REQUEST));
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.requests.back(), Some(&id(PORT, PEER)));
    }

    #[test]
    fn a_request_the_host_resets_is_dropped() {
        let mut s = Stream::new(GUEST);
        send(&mut s, from_host(op::REQUEST));
        send(&mut s, from_host(op::RST));
        assert_eq!(s.take_request(), None);
        assert!(!s.accept(ID));
        assert_eq!(ops(&mut s), []);
        // Anything else before the response resets it.
        send(&mut s, from_host(op::REQUEST));
        send_data(&mut s, b"early");
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.take_request(), None);
        assert!(s.connections.is_empty());
    }

    #[test]
    fn foreign_and_short_packets_are_dropped() {
        let mut s = Stream::new(GUEST);
        for header in [
            Header {
                src_cid: 3,
                ..from_host(op::REQUEST)
            },
            Header {
                src_cid: 1 << 32 | HOST_CID,
                ..from_host(op::REQUEST)
            },
            Header {
                dst_cid: GUEST + 1,
                ..from_host(op::REQUEST)
            },
            Header {
                ty: 2,
                ..from_host(op::REQUEST)
            },
        ] {
            send(&mut s, header);
        }
        s.receive(&from_host(op::REQUEST).to_bytes()[..HEADER_SIZE - 1]);
        s.receive(&[]);
        assert_eq!(s.take_request(), None);
        assert_eq!(ops(&mut s), []);
    }

    #[test]
    fn rsts_are_never_answered() {
        let mut s = Stream::new(GUEST);
        send(&mut s, from_host(op::RST));
        assert_eq!(ops(&mut s), []);
        // Others for unknown connections are.
        send(&mut s, from_host(op::RW));
        assert_eq!(ops(&mut s), [op::RST]);
    }

    /// Connection `ID`, asked for, with the request sent.
    fn connecting() -> Stream {
        let mut s = Stream::new(GUEST);
        assert!(s.connect(ID));
        assert_eq!(ops(&mut s), [op::REQUEST]);
        s
    }

    #[test]
    fn a_connect_requests_the_connection_with_the_credit() {
        let mut s = Stream::new(GUEST);
        assert!(s.connect(ID));
        assert_eq!(s.connect_state(ID), ConnectState::Connecting);
        assert_eq!(
            controls(&mut s),
            [Header {
                src_cid: GUEST,
                dst_cid: HOST_CID,
                src_port: PORT,
                dst_port: PEER,
                ty: TYPE_STREAM,
                op: op::REQUEST,
                buf_alloc: RX_CAPACITY,
                ..Header::default()
            }]
        );
        // Nothing else until the host answers.
        assert_eq!(s.send_budget(ID), None);
        assert_eq!(s.data_header(ID, 1), None);
        assert_eq!(s.read(ID, &mut [0]), Some(0));
        assert!(!s.is_closed(ID));
        assert_eq!(s.take_request(), None);
        assert_eq!(s.connect_state(ID), ConnectState::Connecting);
    }

    #[test]
    fn the_hosts_response_makes_the_connection_live() {
        let mut s = connecting();
        send(&mut s, from_host(op::RESPONSE));
        assert_eq!(s.connect_state(ID), ConnectState::Established);
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.send_budget(ID), Some(256 * 1024));
        assert_eq!(s.data_header(ID, 5).map(|header| header.op), Some(op::RW));
        send_data(&mut s, b"reply");
        assert_eq!(read_all(&mut s), b"reply");
        assert_eq!(ops(&mut s), [op::CREDIT_UPDATE]);
        // Gone since, it was still established.
        send(&mut s, from_host(op::RST));
        assert_eq!(s.connect_state(ID), ConnectState::Established);
        assert!(s.is_closed(ID));
    }

    #[test]
    fn the_hosts_rst_refuses_the_connection() {
        let mut s = connecting();
        send(&mut s, from_host(op::RST));
        assert_eq!(s.connect_state(ID), ConnectState::Failed);
        // Not answered, and forgotten: the connection may be asked for again.
        assert_eq!(ops(&mut s), []);
        assert!(s.connections.is_empty());
        assert!(s.connect(ID));
        assert_eq!(ops(&mut s), [op::REQUEST]);
    }

    #[test]
    fn anything_but_an_answer_resets_a_connecting_connection() {
        for unexpected in [
            op::REQUEST,
            op::SHUTDOWN,
            op::RW,
            op::CREDIT_UPDATE,
            op::CREDIT_REQUEST,
            0,
            99,
        ] {
            let mut s = connecting();
            send(&mut s, from_host(unexpected));
            assert_eq!(ops(&mut s), [op::RST]);
            assert_eq!(s.connect_state(ID), ConnectState::Failed);
            assert!(s.connections.is_empty());
        }
        // Data, and a malformed answer.
        let mut s = connecting();
        send_data(&mut s, b"early");
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.connect_state(ID), ConnectState::Failed);
        let mut s = connecting();
        let header = Header {
            len: 1,
            ..from_host(op::RESPONSE)
        };
        s.receive(&packet(header, &[]));
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.connect_state(ID), ConnectState::Failed);
        // A response before the request went out.
        let mut s = Stream::new(GUEST);
        assert!(s.connect(ID));
        send(&mut s, from_host(op::RESPONSE));
        assert_eq!(s.connect_state(ID), ConnectState::Failed);
        assert_eq!(
            controls(&mut s)
                .iter()
                .map(|header| (header.op, header.dst_port))
                .collect::<Vec<_>>(),
            [(op::RST, PEER)]
        );
    }

    #[test]
    fn connects_on_ids_in_use_or_beyond_the_cap_fail() {
        let mut s = Stream::new(GUEST);
        send(&mut s, from_host(op::REQUEST));
        assert!(!s.connect(ID));
        // The request is untouched.
        assert_eq!(s.take_request(), Some(ID));
        assert_eq!(s.connect_state(ID), ConnectState::Failed);
        assert!(s.accept(ID));
        send(&mut s, from_host(op::RST));
        // Gone, not yet forgotten.
        assert!(!s.connect(ID));
        s.forget(ID);
        for port in 0..u32::try_from(MAX_USER_CONNECTIONS).unwrap() {
            assert!(s.connect(id(PORT, port)));
        }
        assert!(!s.connect(ID));
        assert_eq!(ops(&mut s), [op::REQUEST; MAX_USER_CONNECTIONS]);
        // Live, or gone but not forgotten, they still count.
        let live = id(PORT, 0);
        send(&mut s, on(live, op::RESPONSE));
        assert_eq!(s.connect_state(live), ConnectState::Established);
        assert!(!s.connect(ID));
        send(&mut s, on(live, op::RST));
        assert!(!s.connect(ID));
        s.forget(live);
        assert!(s.connect(ID));
        assert!(!s.connect(id(PORT + 1, PEER)));
    }

    #[test]
    fn the_hosts_requests_are_accepted_with_the_users_connections_at_their_cap() {
        let mut s = Stream::new(GUEST);
        for port in 0..u32::try_from(MAX_USER_CONNECTIONS).unwrap() {
            assert!(s.connect(id(PORT + 1, port)));
        }
        assert!(!s.connect(ID));
        let host = MAX_CONNECTIONS - MAX_USER_CONNECTIONS;
        for port in 0..u32::try_from(host).unwrap() {
            send(&mut s, on(id(PORT, port), op::REQUEST));
            assert_eq!(s.take_request(), Some(id(PORT, port)));
        }
        assert_eq!(s.connections.len(), MAX_CONNECTIONS);
        // Then the table is full: neither end gets more.
        send(&mut s, on(ID, op::REQUEST));
        assert_eq!(s.take_request(), None);
        assert!(!s.connect(id(PORT + 2, PEER)));
    }

    #[test]
    fn forgetting_a_connecting_connection_resets_it() {
        let mut s = connecting();
        s.forget(ID);
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.connect_state(ID), ConnectState::Failed);
        // Its answer is too late.
        send(&mut s, from_host(op::RESPONSE));
        assert_eq!(ops(&mut s), [op::RST]);
    }

    #[test]
    fn a_transport_reset_fails_connecting_connections_silently() {
        let mut s = connecting();
        s.transport_reset(GUEST + 1);
        assert_eq!(s.connect_state(ID), ConnectState::Failed);
        assert_eq!(ops(&mut s), []);
        assert!(s.connections.is_empty());
        // Asked again, from the new CID.
        assert!(s.connect(ID));
        assert_eq!(controls(&mut s)[0].src_cid, GUEST + 1);
    }

    #[test]
    fn data_is_read_and_credited() {
        let mut s = connected();
        send_data(&mut s, b"hello");
        send_data(&mut s, b" world");
        let mut output = [0; 8];
        assert_eq!(s.read(ID, &mut output), Some(8));
        assert_eq!(&output, b"hello wo");
        // Not yet emptied, nor half the capacity.
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.read(ID, &mut output), Some(3));
        let update = controls(&mut s);
        assert_eq!(update.len(), 1);
        assert_eq!((update[0].op, update[0].fwd_cnt), (op::CREDIT_UPDATE, 11));
        assert_eq!(s.read(ID, &mut output), Some(0));
        assert_eq!(ops(&mut s), []);
    }

    #[test]
    fn half_the_capacity_read_is_credited_at_once() {
        let mut s = connected();
        for _ in 0..15 {
            send_data(&mut s, &[1; MAX_PAYLOAD]);
        }
        let mut output = vec![0; RX_CAPACITY as usize / 2];
        assert_eq!(s.read(ID, &mut output), Some(output.len()));
        assert_eq!(ops(&mut s), [op::CREDIT_UPDATE]);
    }

    #[test]
    fn a_peer_beyond_its_credit_is_reset() {
        let mut s = connected();
        for _ in 0..16 {
            send_data(&mut s, &[1; MAX_PAYLOAD]);
        }
        assert!(s.live(ID).is_some());
        send_data(&mut s, &[1]);
        assert_eq!(ops(&mut s), [op::RST]);
        // What arrived in its credit can still be read.
        assert!(!s.is_closed(ID));
        assert_eq!(read_all(&mut s).len(), RX_CAPACITY as usize);
        assert!(s.is_closed(ID));
        assert_eq!(s.read(ID, &mut [0]), None);
    }

    #[test]
    fn a_payload_beyond_the_packet_is_malformed() {
        let mut s = connected();
        let header = Header {
            len: 6,
            ..from_host(op::RW)
        };
        s.receive(&packet(header, b"hello"));
        assert_eq!(ops(&mut s), [op::RST]);
        assert!(s.is_closed(ID));
        // Off a connection, it is dropped.
        let mut s = Stream::new(GUEST);
        s.receive(&packet(header, b"hello"));
        assert_eq!(ops(&mut s), []);
        // A packet may be longer than its header says.
        let mut s = connected();
        let header = Header {
            len: 2,
            ..from_host(op::RW)
        };
        s.receive(&packet(header, b"hello"));
        assert_eq!(read_all(&mut s), b"he");
    }

    #[test]
    fn a_peer_shutting_down_sending_ends_the_stream_after_its_data() {
        let mut s = connected();
        send_data(&mut s, b"bye");
        send(&mut s, shutdown_from_host(SHUTDOWN_SEND));
        assert_eq!(ops(&mut s), []);
        assert_eq!(read_all(&mut s), b"bye");
        assert_eq!(s.read(ID, &mut [0]), None);
        // It still receives.
        assert!(!s.is_closed(ID));
        assert!(s.send_budget(ID).is_some());
        // More data is a violation.
        send_data(&mut s, b"more");
        assert_eq!(ops(&mut s), [op::RST]);
        assert!(s.is_closed(ID));
    }

    #[test]
    fn a_peer_shutting_down_both_ways_is_reset_after_its_data() {
        let mut s = connected();
        send(&mut s, shutdown_from_host(SHUTDOWN_RCV));
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.send_budget(ID), None);
        assert_eq!(s.read(ID, &mut [0]), Some(0));
        send_data(&mut s, b"bye");
        // The flags accumulate.
        send(&mut s, shutdown_from_host(SHUTDOWN_SEND));
        assert_eq!(ops(&mut s), [op::RST]);
        assert!(!s.is_closed(ID));
        assert_eq!(read_all(&mut s), b"bye");
        assert!(s.is_closed(ID));
        // Already reset.
        s.forget(ID);
        assert_eq!(ops(&mut s), []);
        assert!(s.connections.is_empty());
    }

    #[test]
    fn shutting_down_sending_follows_the_data_and_stops_writes() {
        let mut s = connected();
        assert_eq!(s.data_header(ID, 5).unwrap().op, op::RW);
        s.shut_down(ID, SHUTDOWN_SEND);
        assert_eq!(s.send_budget(ID), None);
        assert_eq!(s.data_header(ID, 1), None);
        let shutdown = controls(&mut s);
        assert_eq!(
            shutdown
                .iter()
                .map(|header| (header.op, header.flags))
                .collect::<Vec<_>>(),
            [(op::SHUTDOWN, SHUTDOWN_SEND)]
        );
        // Once only.
        s.shut_down(ID, SHUTDOWN_SEND);
        assert_eq!(ops(&mut s), []);
        // It still receives.
        send_data(&mut s, b"reply");
        assert_eq!(read_all(&mut s), b"reply");
    }

    #[test]
    fn shutting_down_receiving_drops_data_until_shut_down_both_ways() {
        let mut s = connected();
        send_data(&mut s, b"early");
        s.shut_down(ID, SHUTDOWN_RCV);
        let shutdown = controls(&mut s);
        assert_eq!(
            shutdown
                .iter()
                .map(|header| (header.op, header.flags))
                .collect::<Vec<_>>(),
            [(op::SHUTDOWN, SHUTDOWN_RCV)]
        );
        // What the host sent before it knew is dropped, not a violation.
        send_data(&mut s, b"late");
        assert_eq!(ops(&mut s), []);
        assert!(s.live(ID).is_some());
        // What arrived before can still be read, then the stream ends.
        assert_eq!(read_all(&mut s), b"early");
        assert_eq!(s.read(ID, &mut [0]), None);
        // It still sends; its end of sending ends both ways.
        assert!(s.send_budget(ID).is_some());
        s.shut_down(ID, SHUTDOWN_SEND);
        let shutdown = controls(&mut s);
        assert_eq!(
            shutdown.last().map(|header| (header.op, header.flags)),
            Some((op::SHUTDOWN, SHUTDOWN_BOTH))
        );
        // Data then resets it.
        send_data(&mut s, b"later");
        assert_eq!(ops(&mut s), [op::RST]);
        assert!(s.is_closed(ID));
    }

    #[test]
    fn a_shutdown_waits_for_the_response() {
        let mut s = Stream::new(GUEST);
        send(&mut s, from_host(op::REQUEST));
        let request = s.take_request().unwrap();
        assert!(s.accept(request));
        s.shut_down(ID, SHUTDOWN_SEND);
        assert_eq!(ops(&mut s), [op::RESPONSE, op::SHUTDOWN]);
    }

    #[test]
    fn closing_shuts_down_both_ways_until_the_host_resets() {
        let mut s = connected();
        s.shut_down(ID, SHUTDOWN_BOTH);
        let shutdown = controls(&mut s);
        assert_eq!(
            (shutdown[0].op, shutdown[0].flags),
            (op::SHUTDOWN, SHUTDOWN_BOTH)
        );
        assert_eq!(s.read(ID, &mut [0]), None);
        assert!(!s.is_closed(ID));
        send(&mut s, from_host(op::RST));
        assert!(s.is_closed(ID));
        assert_eq!(ops(&mut s), []);
        // Data after the close resets it.
        let mut s = connected();
        s.shut_down(ID, SHUTDOWN_BOTH);
        send_data(&mut s, b"late");
        assert_eq!(ops(&mut s), [op::RST]);
        assert!(s.is_closed(ID));
    }

    #[test]
    fn packets_on_a_gone_connection_are_reset_until_it_is_forgotten() {
        let mut s = connected();
        send_data(&mut s, b"unread");
        send(&mut s, from_host(op::RST));
        assert_eq!(s.send_budget(ID), None);
        // Gone, not yet closed.
        assert!(!s.is_closed(ID));
        send_data(&mut s, b"more");
        send(&mut s, from_host(op::REQUEST));
        let resets = controls(&mut s);
        assert_eq!(
            resets
                .iter()
                .map(|header| (header.op, header.dst_port))
                .collect::<Vec<_>>(),
            [(op::RST, PEER); 2]
        );
        assert_eq!(s.take_request(), None);
        assert_eq!(read_all(&mut s), b"unread");
        assert!(s.is_closed(ID));
        s.forget(ID);
        assert_eq!(ops(&mut s), []);
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(s.take_request(), Some(ID));
    }

    #[test]
    fn forgetting_a_live_connection_resets_it() {
        let mut s = connected();
        send_data(&mut s, b"unread");
        s.forget(ID);
        let reset = controls(&mut s);
        assert_eq!(reset.len(), 1);
        assert_eq!((reset[0].op, reset[0].dst_port), (op::RST, PEER));
        assert!(s.is_closed(ID));
        assert_eq!(s.read(ID, &mut [0]), None);
    }

    #[test]
    fn unexpected_operations_reset_the_connection() {
        for unexpected in [0, op::REQUEST, op::RESPONSE, 99] {
            let mut s = connected();
            send(&mut s, from_host(unexpected));
            assert_eq!(ops(&mut s), [op::RST]);
            assert!(s.is_closed(ID));
        }
    }

    #[test]
    fn a_transport_reset_loses_the_connections_silently() {
        let mut s = connected();
        send(&mut s, on(id(PORT, PEER + 1), op::REQUEST));
        send(&mut s, from_host(op::CREDIT_REQUEST));
        s.transport_reset(GUEST + 1);
        assert_eq!(ops(&mut s), []);
        assert!(s.is_closed(ID));
        assert_eq!(s.take_request(), None);
        s.forget(ID);
        assert_eq!(ops(&mut s), []);
        // The new CID is used.
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(s.take_request(), None);
        send(
            &mut s,
            Header {
                dst_cid: GUEST + 1,
                ..from_host(op::REQUEST)
            },
        );
        let request = s.take_request().unwrap();
        assert!(s.accept(request));
        assert_eq!(controls(&mut s)[0].src_cid, GUEST + 1);
    }

    #[test]
    fn credit_follows_the_peer_with_wrapping_counters() {
        let mut s = connected();
        assert_eq!(s.data_header(ID, 1000).unwrap().len, 1000);
        assert_eq!(s.send_budget(ID), Some(256 * 1024 - 1000));
        send(
            &mut s,
            Header {
                fwd_cnt: 1000,
                ..from_host(op::CREDIT_UPDATE)
            },
        );
        assert_eq!(s.send_budget(ID), Some(256 * 1024));
        // Counters wrap.
        s.live(ID).unwrap().tx_cnt = u32::MAX - 9;
        send(
            &mut s,
            Header {
                buf_alloc: 100,
                fwd_cnt: u32::MAX - 9,
                ..from_host(op::CREDIT_UPDATE)
            },
        );
        assert_eq!(s.data_header(ID, 30).map(|header| header.len), Some(30));
        assert_eq!(s.live(ID).unwrap().tx_cnt, 20);
        assert_eq!(s.send_budget(ID), Some(70));
        assert_eq!(s.data_header(ID, 71), None);
        // Bogus numbers give no credit.
        send(
            &mut s,
            Header {
                buf_alloc: 100,
                fwd_cnt: 1000,
                ..from_host(op::CREDIT_UPDATE)
            },
        );
        assert_eq!(s.send_budget(ID), Some(0));
    }

    #[test]
    fn credit_requests_are_answered() {
        let mut s = connected();
        send(&mut s, from_host(op::CREDIT_REQUEST));
        let update = controls(&mut s);
        assert_eq!(
            (update[0].op, update[0].buf_alloc),
            (op::CREDIT_UPDATE, RX_CAPACITY)
        );
    }

    #[test]
    fn data_carries_the_reader_progress() {
        let mut s = connected();
        send_data(&mut s, b"request");
        assert_eq!(read_all(&mut s).len(), 7);
        let data = s.data_header(ID, 3).unwrap();
        assert_eq!((data.op, data.fwd_cnt, data.len), (op::RW, 7, 3));
        // A data packet built before the pending update is sent replaces it
        // (`VirtioVsock::read` sends updates at once, so there they still go
        // out).
        assert_eq!(ops(&mut s), []);
    }

    #[test]
    fn resets_for_unknown_connections_are_bounded() {
        let mut s = connected();
        for port in 0..2 * u32::try_from(MAX_RESETS).unwrap() {
            send(&mut s, on(id(PORT + 1, port), op::RW));
        }
        // The connection's own reset is kept.
        send(&mut s, from_host(op::RESPONSE));
        let resets = controls(&mut s);
        assert_eq!(resets.len(), MAX_RESETS + 1);
        assert_eq!(resets.last().unwrap().dst_port, PEER);
    }

    #[test]
    fn connection_resets_are_bounded_too() {
        let mut s = Stream::new(GUEST);
        for round in 0..3 {
            for port in 0..u32::try_from(MAX_CONNECTIONS).unwrap() {
                send(&mut s, on(id(PORT, round * 1000 + port), op::REQUEST));
                let request = s.take_request().unwrap();
                s.refuse(request);
            }
        }
        assert_eq!(controls(&mut s).len(), MAX_QUEUED_RESETS);
    }
}
