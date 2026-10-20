// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio socket device (device type 19): QEMU's `vhost-vsock-pci`, which
//! connects the guest to `AF_VSOCK` sockets on the host, e.g.:
//!
//! ```text
//! -device vhost-vsock-pci,guest-cid=3,disable-legacy=on
//! ```
//!
//! No device features are negotiated, so stream sockets are implied. The
//! driver is a guest-side listener on one port with at most one connection
//! at a time, which the host makes; it never connects out. `Stream` is the
//! protocol (the connection's state and credit), apart from the queues
//! ([`VirtioVsock`]) that carry its packets, so it can be tested on its own.
//!
//! A packet is a header (`Header`) and its payload, contiguous in one
//! buffer. Received data is copied out at once, and its buffer given back to
//! the device, so control packets never wait behind unread data; the host
//! may send at most `RX_CAPACITY` bytes the reader has not consumed (its
//! credit), else the connection is reset.
//!
//! The host is not trusted: a packet is copied out of DMA memory once, then
//! checked (lengths, addresses, type), and dropped if malformed, or, on the
//! connection, resets it. Nothing blocks; the device interrupts as it returns
//! buffers in any queue.

use super::Error;
use super::buffers::Buffers;
use super::pci::PciTransport;
use super::queue::VirtQueue;
use crate::dma::Hal;
use crate::interrupt::MsiMessage;
use alloc::collections::VecDeque;
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

/// The received data, not yet consumed, that the host may send: the
/// `buf_alloc` of every packet the driver sends.
const RX_CAPACITY: u32 = 64 * 1024;
/// `VMADDR_CID_HOST`: the only peer.
const HOST_CID: u64 = 2;
/// `VIRTIO_VSOCK_TYPE_STREAM`.
const TYPE_STREAM: u16 = 1;
/// `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET`.
const EVENT_TRANSPORT_RESET: u32 = 0;

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

/// `VIRTIO_VSOCK_SHUTDOWN_RCV`: the peer will receive no more.
const SHUTDOWN_RCV: u32 = 1;
/// `VIRTIO_VSOCK_SHUTDOWN_SEND`: the peer will send no more.
const SHUTDOWN_SEND: u32 = 2;
const SHUTDOWN_BOTH: u32 = SHUTDOWN_RCV | SHUTDOWN_SEND;

/// RSTs waiting for a transmit buffer; more for unknown connections are
/// dropped.
const MAX_RESETS: usize = 8;

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
}

/// A listener's state, as its user sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No connection: the next request from the host is accepted.
    Listening,
    /// A connection, which may still have data to read after the host shut
    /// down its sending side, or after the connection is gone (see
    /// [`Self::Closed`]), until its data is read.
    Connected,
    /// The connection is gone (reset, shut down both ways, or lost to a
    /// transport reset), and its data read; [`VirtioVsock::close`] it to
    /// listen again. Requests are refused meanwhile.
    Closed,
}

/// The host's end of the connection.
struct Peer {
    port: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
    /// `SHUTDOWN_*` flags it sent.
    shutdown: u32,
}

struct Connection {
    peer: Peer,
    /// Reset by either end, shut down both ways, or lost to a transport
    /// reset: nothing more is sent or received on it.
    gone: bool,
}

/// Control packets for the connection, waiting for a transmit buffer.
#[derive(Default)]
struct Pending {
    response: bool,
    credit_update: bool,
}

/// A listener's protocol: packets in, packets out. Its user reads and
/// writes stream data; the transport sends what [`Self::next_control`] and
/// [`Self::data_header`] give it.
struct Stream {
    guest_cid: u64,
    port: u32,
    connection: Option<Connection>,
    /// Received, not yet read; at most [`RX_CAPACITY`] bytes.
    rx: VecDeque<u8>,
    /// Bytes read, ever (wrapping).
    fwd_cnt: u32,
    /// The `fwd_cnt` the peer last got.
    reported_fwd_cnt: u32,
    /// Bytes sent, ever (wrapping).
    tx_cnt: u32,
    /// Control packets for the connection, waiting for a transmit buffer.
    pending: Pending,
    /// RSTs waiting for a transmit buffer, oldest first.
    resets: VecDeque<Header>,
}

impl Stream {
    fn new(guest_cid: u64, port: u32) -> Self {
        Self {
            guest_cid,
            port,
            connection: None,
            rx: VecDeque::new(),
            fwd_cnt: 0,
            reported_fwd_cnt: 0,
            tx_cnt: 0,
            pending: Pending::default(),
            resets: VecDeque::new(),
        }
    }

    fn peer_port(&self) -> Option<u32> {
        Some(self.connection.as_ref()?.peer.port)
    }

    fn state(&self) -> State {
        match &self.connection {
            None => State::Listening,
            Some(connection) if connection.gone && self.rx.is_empty() => State::Closed,
            Some(_) => State::Connected,
        }
    }

    /// The connection, unless it is gone.
    fn live(&mut self) -> Option<&mut Connection> {
        self.connection
            .as_mut()
            .filter(|connection| !connection.gone)
    }

    fn header(&self, op: u16, src_port: u32, dst_port: u32) -> Header {
        Header {
            src_cid: self.guest_cid,
            dst_cid: HOST_CID,
            src_port,
            dst_port,
            ty: TYPE_STREAM,
            op,
            buf_alloc: RX_CAPACITY,
            ..Header::default()
        }
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
        let port = self.port;
        let on_connection = self.live().is_some_and(|connection| {
            header.dst_port == port && header.src_port == connection.peer.port
        });
        let payload = usize::try_from(header.len)
            .ok()
            .and_then(|len| rest.get(..len));
        match payload {
            Some(payload) if on_connection => self.receive_on_connection(&header, payload),
            Some(_) => self.receive_other(&header),
            // Malformed.
            None if on_connection => self.reset(),
            None => {}
        }
    }

    fn receive_on_connection(&mut self, header: &Header, payload: &[u8]) {
        let Some(connection) = self.live() else {
            return;
        };
        let peer = &mut connection.peer;
        peer.buf_alloc = header.buf_alloc;
        peer.fwd_cnt = header.fwd_cnt;
        let peer_shutdown = peer.shutdown;
        match header.op {
            op::RW => {
                if peer_shutdown & SHUTDOWN_SEND != 0
                    || self.rx.len() + payload.len() > RX_CAPACITY as usize
                {
                    self.reset();
                } else {
                    self.rx.extend(payload);
                }
            }
            op::CREDIT_UPDATE => {}
            op::CREDIT_REQUEST => self.pending.credit_update = true,
            op::SHUTDOWN => {
                let shutdown = peer_shutdown | (header.flags & SHUTDOWN_BOTH);
                if let Some(connection) = self.live() {
                    connection.peer.shutdown = shutdown;
                }
                // As Linux does, so the host's close completes promptly.
                if shutdown == SHUTDOWN_BOTH {
                    self.reset();
                }
            }
            op::RST => self.lose(),
            // A repeated request, a response to a request never sent, or an
            // unknown operation.
            _ => self.reset(),
        }
    }

    /// A packet for no live connection.
    fn receive_other(&mut self, header: &Header) {
        match header.op {
            op::RST => {}
            op::REQUEST if self.connection.is_none() && header.dst_port == self.port => {
                self.connection = Some(Connection {
                    peer: Peer {
                        port: header.src_port,
                        buf_alloc: header.buf_alloc,
                        fwd_cnt: header.fwd_cnt,
                        shutdown: 0,
                    },
                    gone: false,
                });
                self.forget();
                self.pending.response = true;
            }
            _ => {
                let reset = self.header(op::RST, header.dst_port, header.src_port);
                if self.resets.len() < MAX_RESETS {
                    self.resets.push_back(reset);
                }
            }
        }
    }

    /// Clears what the stream knows of a connection.
    fn forget(&mut self) {
        self.rx.clear();
        self.fwd_cnt = 0;
        self.reported_fwd_cnt = 0;
        self.tx_cnt = 0;
        self.forget_pending();
    }

    fn forget_pending(&mut self) {
        self.pending = Pending::default();
    }

    /// The connection is gone without an RST from this end.
    fn lose(&mut self) {
        if let Some(connection) = self.live() {
            connection.gone = true;
            self.forget_pending();
        }
    }

    /// Resets the connection, unless it is gone: data already received can
    /// still be read.
    fn reset(&mut self) {
        let Some(peer_port) = self.live().map(|connection| connection.peer.port) else {
            return;
        };
        self.lose();
        if self.resets.len() >= MAX_RESETS {
            self.resets.pop_front();
        }
        self.resets
            .push_back(self.header(op::RST, self.port, peer_port));
    }

    /// The device reset its transport: every connection is gone, and the
    /// guest's CID may have changed.
    fn transport_reset(&mut self, guest_cid: u64) {
        self.guest_cid = guest_cid;
        self.lose();
        self.resets.clear();
    }

    /// A packet on the connection, carrying the reader's progress.
    fn connection_header(&mut self, op: u16, len: u32) -> Option<Header> {
        let peer_port = self.live()?.peer.port;
        self.reported_fwd_cnt = self.fwd_cnt;
        self.pending.credit_update = false;
        Some(Header {
            len,
            fwd_cnt: self.fwd_cnt,
            ..self.header(op, self.port, peer_port)
        })
    }

    /// The next control packet to send, if any.
    fn next_control(&mut self) -> Option<Header> {
        // RSTs first: they are for other connections than the one pending
        // packets are for.
        if let Some(reset) = self.resets.pop_front() {
            return Some(reset);
        }
        let op = if core::mem::take(&mut self.pending.response) {
            op::RESPONSE
        } else if self.pending.credit_update {
            op::CREDIT_UPDATE
        } else {
            return None;
        };
        self.connection_header(op, 0)
    }

    /// How much data the peer takes now; `None` if the stream takes no more
    /// (no live connection, or the peer receives no more).
    fn send_budget(&mut self) -> Option<usize> {
        let tx_cnt = self.tx_cnt;
        let response_pending = self.pending.response;
        let peer = &self.live()?.peer;
        if peer.shutdown & SHUTDOWN_RCV != 0 {
            return None;
        }
        if response_pending {
            // Data must follow the response.
            return Some(0);
        }
        // Zero if the peer's numbers are bogus.
        let in_flight = tx_cnt.wrapping_sub(peer.fwd_cnt);
        Some(peer.buf_alloc.saturating_sub(in_flight) as usize)
    }

    /// The header of `len` bytes of data, which [`Self::send_budget`]
    /// allowed.
    fn data_header(&mut self, len: usize) -> Option<Header> {
        if self.send_budget()? < len {
            return None;
        }
        let len = u32::try_from(len).ok()?;
        let header = self.connection_header(op::RW, len)?;
        self.tx_cnt = self.tx_cnt.wrapping_add(len);
        Some(header)
    }

    /// Copies received data into `output`: how much, or `None` at the end of
    /// the stream (there is no connection, or no more data will come).
    fn read(&mut self, output: &mut [u8]) -> Option<usize> {
        if self.rx.is_empty() {
            let ended = self.connection.as_ref().is_none_or(|connection| {
                connection.gone || connection.peer.shutdown & SHUTDOWN_SEND != 0
            });
            return if ended { None } else { Some(0) };
        }
        let len = output.len().min(self.rx.len());
        for (byte, received) in output.iter_mut().zip(self.rx.drain(..len)) {
            *byte = received;
        }
        #[expect(clippy::cast_possible_truncation, reason = "at most RX_CAPACITY")]
        let consumed = len as u32;
        self.fwd_cnt = self.fwd_cnt.wrapping_add(consumed);
        let unreported = self.fwd_cnt.wrapping_sub(self.reported_fwd_cnt);
        if self.live().is_some()
            && (unreported >= RX_CAPACITY / 2 || (self.rx.is_empty() && unreported != 0))
        {
            self.pending.credit_update = true;
        }
        Some(len)
    }

    /// Ends the connection, if any (resetting it unless it is gone), and
    /// listens again.
    fn close(&mut self) {
        self.reset();
        self.connection = None;
        self.forget();
    }
}

/// A live socket device: a stream listener on one port. Not internally
/// synchronized.
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
    /// How many transmit buffers there are.
    tx_count: usize,
    event: ManuallyDrop<VirtQueue>,
    event_buffers: ManuallyDrop<Buffers>,
    stream: Stream,
    /// A received packet, copied out of DMA memory.
    scratch: Vec<u8>,
}

impl VirtioVsock {
    /// The first virtio socket device on bus 0, brought up, interrupting
    /// with `interrupt` (if it can; see [`PciTransport::interrupts`]), and
    /// listening on `port`; `None` if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven, e.g., its guest CID is not valid.
    pub fn probe(
        hal: &'static dyn Hal,
        interrupt: Option<MsiMessage>,
        port: u32,
    ) -> Option<Result<Self, Error>> {
        let function = super::find_pci_devices(DEVICE_TYPE).next()?;
        Some(
            PciTransport::new(hal, function, interrupt)
                .and_then(|transport| Self::bring_up(hal, transport, port)),
        )
    }

    fn bring_up(hal: &'static dyn Hal, transport: PciTransport, port: u32) -> Result<Self, Error> {
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
            tx_count: tx_buffers.free.len(),
            tx_buffers: ManuallyDrop::new(tx_buffers),
            event: ManuallyDrop::new(event),
            event_buffers: ManuallyDrop::new(event_buffers),
            stream: Stream::new(guest_cid, port),
            scratch: vec![0; BUFFER_SIZE],
        })
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// The guest's CID, which the host connects to.
    pub fn guest_cid(&self) -> u64 {
        self.stream.guest_cid
    }

    /// The port it listens on.
    pub fn port(&self) -> u32 {
        self.stream.port
    }

    /// The host's port of the connection, if any.
    pub fn peer_port(&self) -> Option<u32> {
        self.stream.peer_port()
    }

    /// The listener's state, once what the device returned is taken.
    pub fn state(&mut self) -> State {
        self.poll();
        self.stream.state()
    }

    /// Copies received data into `output`: how much (zero if none has
    /// arrived), or `None` at the end of the stream: there is no connection,
    /// or it will receive no more.
    pub fn read(&mut self, output: &mut [u8]) -> Option<usize> {
        self.poll();
        let read = self.stream.read(output);
        self.send_control();
        read
    }

    /// Queues as much of `bytes` as the host's credit and free transmit
    /// buffers allow: how much (zero if either has none), or `None` if the
    /// stream takes no more: there is no live connection, or the host
    /// receives no more.
    pub fn write(&mut self, bytes: &[u8]) -> Option<usize> {
        self.poll();
        let mut budget = self.stream.send_budget()?;
        let mut written = 0;
        while written < bytes.len() && budget > 0 {
            let Some(&buffer) = self.tx_buffers.free.last() else {
                break;
            };
            let chunk = &bytes[written..];
            let chunk = &chunk[..chunk.len().min(MAX_PAYLOAD).min(budget)];
            let Some(header) = self.stream.data_header(chunk.len()) else {
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

    /// Ends the connection, if any, resetting it unless it is gone, and
    /// listens again.
    pub fn close(&mut self) {
        self.poll();
        self.stream.close();
        self.send_control();
    }

    /// Whether the device returned every transmit buffer: what was sent is
    /// in the host socket's queue.
    pub fn flushed(&mut self) -> bool {
        self.poll();
        self.tx_buffers.free.len() == self.tx_count
    }

    /// Takes what the device returned, and sends what is pending.
    fn poll(&mut self) {
        self.collect_events();
        self.collect_received();
        while let Some((buffer, _)) = self.tx_buffers.take_used(&mut self.tx) {
            self.tx_buffers.free.push(buffer);
        }
        self.send_control();
    }

    fn collect_events(&mut self) {
        let mut reposted = false;
        while let Some((buffer, len)) = self.event_buffers.take_used(&mut self.event) {
            let mut id = [0u8; EVENT_SIZE];
            if len >= EVENT_SIZE {
                let source = self.event_buffers.ptr(buffer, 0, EVENT_SIZE);
                // Safety: the device returned the buffer; `EVENT_SIZE` bytes
                // are in it, copied into a local.
                unsafe { core::ptr::copy_nonoverlapping(source, id.as_mut_ptr(), EVENT_SIZE) };
            }
            self.event_buffers
                .post(&mut self.event, buffer, EVENT_SIZE, true);
            reposted = true;
            if len >= EVENT_SIZE && u32::from_le_bytes(id) == EVENT_TRANSPORT_RESET {
                let guest_cid = guest_cid(&self.transport).unwrap_or_else(|_| {
                    litebox_util_log::warn!("vsock transport reset to an invalid guest CID");
                    self.stream.guest_cid
                });
                self.stream.transport_reset(guest_cid);
            }
        }
        if reposted {
            self.transport.notify(&self.event);
        }
    }

    fn collect_received(&mut self) {
        let mut reposted = false;
        while let Some((buffer, len)) = self.rx_buffers.take_used(&mut self.rx) {
            // `take_used` clamps `len` to the buffer.
            let source = self.rx_buffers.ptr(buffer, 0, len);
            // Safety: the device returned the buffer; `len` bytes are in it,
            // and in `scratch`, which is a buffer long.
            unsafe { core::ptr::copy_nonoverlapping(source, self.scratch.as_mut_ptr(), len) };
            self.rx_buffers
                .post(&mut self.rx, buffer, BUFFER_SIZE, true);
            reposted = true;
            self.stream.receive(&self.scratch[..len]);
        }
        if reposted {
            self.transport.notify(&self.rx);
        }
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

    fn stream() -> Stream {
        Stream::new(GUEST, PORT)
    }

    /// A packet from the host's port `PEER` to the guest's `PORT`.
    fn from_host(op: u16) -> Header {
        Header {
            src_cid: HOST_CID,
            dst_cid: GUEST,
            src_port: PEER,
            dst_port: PORT,
            ty: TYPE_STREAM,
            op,
            buf_alloc: 256 * 1024,
            ..Header::default()
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

    fn send_data(stream: &mut Stream, data: &[u8]) {
        let header = Header {
            len: u32::try_from(data.len()).unwrap(),
            ..from_host(op::RW)
        };
        stream.receive(&packet(header, data));
    }

    fn controls(stream: &mut Stream) -> Vec<Header> {
        core::iter::from_fn(|| stream.next_control()).collect()
    }

    fn ops(stream: &mut Stream) -> Vec<u16> {
        controls(stream).iter().map(|header| header.op).collect()
    }

    /// Accepted, with the response sent.
    fn connected() -> Stream {
        let mut s = stream();
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(ops(&mut s), [op::RESPONSE]);
        s
    }

    fn read_all(stream: &mut Stream) -> Vec<u8> {
        let mut output = vec![0; 2 * RX_CAPACITY as usize];
        let len = stream.read(&mut output).unwrap();
        output.truncate(len);
        output
    }

    #[test]
    fn headers_round_trip_little_endian() {
        let header = Header {
            src_cid: 0x0102_0304_0506_0708,
            dst_cid: 3,
            src_port: 0x1122_3344,
            dst_port: 5,
            len: 6,
            ty: 0x0a0b,
            op: 7,
            flags: 8,
            buf_alloc: 9,
            fwd_cnt: 0xdead_beef,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes[..8], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(bytes[28..30], [0x0b, 0x0a]);
        assert_eq!(bytes[40..], [0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(Header::parse(&bytes), header);
    }

    #[test]
    fn a_request_to_the_port_is_accepted() {
        let mut s = stream();
        assert_eq!(s.state(), State::Listening);
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(s.state(), State::Connected);
        // Data must wait for the response.
        assert_eq!(s.send_budget(), Some(0));
        let response = controls(&mut s);
        assert_eq!(
            response,
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
        assert_eq!(s.send_budget(), Some(256 * 1024));
    }

    #[test]
    fn other_requests_are_refused() {
        let mut s = stream();
        // Another port.
        send(
            &mut s,
            Header {
                dst_port: PORT + 1,
                ..from_host(op::REQUEST)
            },
        );
        let refused = controls(&mut s);
        assert_eq!(refused.len(), 1);
        assert_eq!(
            (refused[0].op, refused[0].src_port, refused[0].dst_port),
            (op::RST, PORT + 1, PEER)
        );
        assert_eq!(s.state(), State::Listening);
        // A second connection while connected.
        let mut s = connected();
        send(
            &mut s,
            Header {
                src_port: PEER + 1,
                ..from_host(op::REQUEST)
            },
        );
        let refused = controls(&mut s);
        assert_eq!((refused[0].op, refused[0].dst_port), (op::RST, PEER + 1));
        assert_eq!(s.state(), State::Connected);
        assert_eq!(s.peer_port(), Some(PEER));
    }

    #[test]
    fn foreign_and_short_packets_are_dropped() {
        let mut s = stream();
        for header in [
            Header {
                src_cid: 3,
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
        assert_eq!(s.state(), State::Listening);
        assert_eq!(ops(&mut s), []);
    }

    #[test]
    fn rsts_are_never_answered() {
        let mut s = stream();
        send(&mut s, from_host(op::RST));
        assert_eq!(ops(&mut s), []);
        // Others for unknown connections are.
        send(&mut s, from_host(op::RW));
        assert_eq!(ops(&mut s), [op::RST]);
    }

    #[test]
    fn data_is_read_and_credited() {
        let mut s = connected();
        send_data(&mut s, b"hello");
        send_data(&mut s, b" world");
        let mut output = [0; 8];
        assert_eq!(s.read(&mut output), Some(8));
        assert_eq!(&output, b"hello wo");
        // Not yet emptied, nor half the capacity.
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.read(&mut output), Some(3));
        let update = controls(&mut s);
        assert_eq!(update.len(), 1);
        assert_eq!((update[0].op, update[0].fwd_cnt), (op::CREDIT_UPDATE, 11));
        assert_eq!(s.read(&mut output), Some(0));
        assert_eq!(ops(&mut s), []);
    }

    #[test]
    fn half_the_capacity_read_is_credited_at_once() {
        let mut s = connected();
        for _ in 0..15 {
            send_data(&mut s, &[1; MAX_PAYLOAD]);
        }
        assert_eq!(s.rx.len(), RX_CAPACITY as usize - MAX_PAYLOAD);
        let mut output = vec![0; RX_CAPACITY as usize / 2];
        assert_eq!(s.read(&mut output), Some(output.len()));
        assert_eq!(ops(&mut s), [op::CREDIT_UPDATE]);
    }

    #[test]
    fn a_peer_beyond_its_credit_is_reset() {
        let mut s = connected();
        for _ in 0..16 {
            send_data(&mut s, &[1; MAX_PAYLOAD]);
        }
        assert_eq!(s.state(), State::Connected);
        send_data(&mut s, &[1]);
        assert_eq!(ops(&mut s), [op::RST]);
        // What arrived in its credit can still be read.
        assert_eq!(read_all(&mut s).len(), RX_CAPACITY as usize);
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.read(&mut [0]), None);
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
        assert_eq!(s.state(), State::Closed);
        // Off the connection, it is dropped.
        let mut s = stream();
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
        send(
            &mut s,
            Header {
                flags: SHUTDOWN_SEND,
                ..from_host(op::SHUTDOWN)
            },
        );
        assert_eq!(ops(&mut s), []);
        assert_eq!(read_all(&mut s), b"bye");
        assert_eq!(s.read(&mut [0]), None);
        // It still receives.
        assert_eq!(s.state(), State::Connected);
        assert!(s.send_budget().is_some());
        // More data is a violation.
        send_data(&mut s, b"more");
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn a_peer_shutting_down_both_ways_is_reset_and_closed_after_its_data() {
        let mut s = connected();
        send_data(&mut s, b"bye");
        send(
            &mut s,
            Header {
                flags: SHUTDOWN_BOTH,
                ..from_host(op::SHUTDOWN)
            },
        );
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.send_budget(), None);
        assert_eq!(s.state(), State::Connected);
        assert_eq!(read_all(&mut s), b"bye");
        assert_eq!(s.state(), State::Closed);
        // Already reset.
        s.close();
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.state(), State::Listening);
    }

    #[test]
    fn shutdown_flags_accumulate() {
        let mut s = connected();
        send(
            &mut s,
            Header {
                flags: SHUTDOWN_RCV,
                ..from_host(op::SHUTDOWN)
            },
        );
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.state(), State::Connected);
        send(
            &mut s,
            Header {
                flags: SHUTDOWN_SEND,
                ..from_host(op::SHUTDOWN)
            },
        );
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn shutting_down_receiving_stops_writes() {
        let mut s = connected();
        send(
            &mut s,
            Header {
                flags: SHUTDOWN_RCV,
                ..from_host(op::SHUTDOWN)
            },
        );
        assert_eq!(s.send_budget(), None);
        assert_eq!(s.read(&mut [0]), Some(0));
    }

    #[test]
    fn a_reset_connection_is_closed_and_listens_again() {
        let mut s = connected();
        send(&mut s, from_host(op::RST));
        assert_eq!(s.state(), State::Closed);
        assert_eq!(s.send_budget(), None);
        // Requests are refused until the user closes it.
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(ops(&mut s), [op::RST]);
        s.close();
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.state(), State::Listening);
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(ops(&mut s), [op::RESPONSE]);
        assert_eq!(s.state(), State::Connected);
    }

    #[test]
    fn packets_on_a_gone_connection_are_reset() {
        let mut s = connected();
        send_data(&mut s, b"unread");
        send(&mut s, from_host(op::RST));
        // Gone, not yet closed.
        assert_eq!(s.state(), State::Connected);
        send_data(&mut s, b"more");
        let reset = controls(&mut s);
        assert_eq!(reset.len(), 1);
        assert_eq!((reset[0].op, reset[0].dst_port), (op::RST, PEER));
        assert_eq!(read_all(&mut s), b"unread");
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn a_connection_reset_is_sent_before_the_next_response() {
        let mut s = connected();
        s.close();
        send(
            &mut s,
            Header {
                src_port: PEER + 1,
                ..from_host(op::REQUEST)
            },
        );
        let sent = controls(&mut s);
        assert_eq!(
            sent.iter()
                .map(|header| (header.op, header.dst_port))
                .collect::<Vec<_>>(),
            [(op::RST, PEER), (op::RESPONSE, PEER + 1)]
        );
    }

    #[test]
    fn closing_a_live_connection_resets_it() {
        let mut s = connected();
        send_data(&mut s, b"unread");
        s.close();
        let reset = controls(&mut s);
        assert_eq!(reset.len(), 1);
        assert_eq!((reset[0].op, reset[0].dst_port), (op::RST, PEER));
        assert_eq!(s.state(), State::Listening);
        assert_eq!(s.read(&mut [0]), None);
    }

    #[test]
    fn a_repeated_request_resets_the_connection() {
        let mut s = connected();
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(ops(&mut s), [op::RST]);
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn a_transport_reset_loses_the_connection_silently() {
        let mut s = connected();
        send(&mut s, from_host(op::CREDIT_REQUEST));
        s.transport_reset(GUEST + 1);
        assert_eq!(ops(&mut s), []);
        assert_eq!(s.state(), State::Closed);
        s.close();
        assert_eq!(ops(&mut s), []);
        // The new CID is used.
        send(&mut s, from_host(op::REQUEST));
        assert_eq!(s.state(), State::Listening);
        send(
            &mut s,
            Header {
                dst_cid: GUEST + 1,
                ..from_host(op::REQUEST)
            },
        );
        assert_eq!(s.state(), State::Connected);
        assert_eq!(controls(&mut s)[0].src_cid, GUEST + 1);
    }

    #[test]
    fn credit_follows_the_peer_with_wrapping_counters() {
        let mut s = connected();
        assert_eq!(s.data_header(1000).unwrap().len, 1000);
        assert_eq!(s.send_budget(), Some(256 * 1024 - 1000));
        send(
            &mut s,
            Header {
                fwd_cnt: 1000,
                ..from_host(op::CREDIT_UPDATE)
            },
        );
        assert_eq!(s.send_budget(), Some(256 * 1024));
        // Counters wrap.
        s.tx_cnt = u32::MAX - 9;
        send(
            &mut s,
            Header {
                buf_alloc: 100,
                fwd_cnt: u32::MAX - 9,
                ..from_host(op::CREDIT_UPDATE)
            },
        );
        assert_eq!(s.data_header(30).map(|header| header.len), Some(30));
        assert_eq!(s.tx_cnt, 20);
        assert_eq!(s.send_budget(), Some(70));
        assert_eq!(s.data_header(71), None);
        // Bogus numbers give no credit.
        send(
            &mut s,
            Header {
                buf_alloc: 100,
                fwd_cnt: 1000,
                ..from_host(op::CREDIT_UPDATE)
            },
        );
        assert_eq!(s.send_budget(), Some(0));
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
        let data = s.data_header(3).unwrap();
        assert_eq!((data.op, data.fwd_cnt, data.len), (op::RW, 7, 3));
        // So no separate update is needed.
        assert_eq!(ops(&mut s), []);
    }

    #[test]
    fn unknown_operations_reset_the_connection() {
        for unknown in [0, op::RESPONSE, 99] {
            let mut s = connected();
            send(&mut s, from_host(unknown));
            assert_eq!(ops(&mut s), [op::RST]);
            assert_eq!(s.state(), State::Closed);
        }
    }

    #[test]
    fn resets_for_unknown_connections_are_bounded() {
        let mut s = connected();
        for port in 0..2 * u32::try_from(MAX_RESETS).unwrap() {
            send(
                &mut s,
                Header {
                    src_port: port,
                    ..from_host(op::RW)
                },
            );
        }
        // The connection's own reset is kept.
        send(&mut s, from_host(op::RESPONSE));
        let resets = controls(&mut s);
        assert_eq!(resets.len(), MAX_RESETS);
        assert_eq!(resets.last().unwrap().dst_port, PEER);
    }
}
