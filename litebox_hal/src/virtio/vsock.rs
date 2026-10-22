// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Virtio socket device (device type 19): QEMU's `vhost-vsock-pci`, e.g.:
//!
//! ```text
//! -device vhost-vsock-pci,guest-cid=3,disable-legacy=on
//! ```
//!
//! A stream listener on one port, for the host (CID 2): one connection at a
//! time, other requests reset; it never connects out. No features are
//! negotiated, so streams are implied. `Stream` is the protocol and `Queues`
//! carries its packets, each tested on its own.
//!
//! A connection ([`VsockConnection`]) ends when the host resets it or shuts
//! down receiving, when the driver resets it (closed, or a protocol
//! violation), or on a transport reset; its unread data is dropped, even
//! what came with the end. If the host only shuts down sending, the
//! connection stays, and reads find nothing, as when nothing arrived yet.
//!
//! Every packet of a connection carries its credit. Packets for no
//! connection, or not of a stream, are refused with an RST, as Linux's
//! `virtio_transport_reset_no_sock` does; RSTs are never answered.
//!
//! Credit: the host may have up to `RX_CAPACITY` bytes unread, else the
//! connection is reset; the driver sends within the host's credit. A
//! CREDIT_UPDATE goes once half of `RX_CAPACITY` was read unreported, so a
//! host out of credit hears of freed space once at most half is unread. The
//! host (Linux) updates the driver's credit likewise as its reader drains.
//!
//! The host is trusted, but its input is still checked: a packet is copied
//! out of DMA memory once, then validated; a malformed one resets its
//! connection, and nothing panics. Nothing blocks, and each call does
//! bounded work ([`VirtioVsock::has_backlog`]). The device interrupts on
//! every buffer it returns; receive and event buffers are reposted at once
//! (QEMU drops a transport reset event that finds none).

use super::Error;
use super::buffers::Buffers;
use super::pci::PciTransport;
use super::queue::VirtQueue;
use crate::dma::Hal;
use crate::interrupt::MsiMessage;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
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

/// The `buf_alloc` the driver sends: how much unread data the host may send.
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

/// `VIRTIO_VSOCK_SHUTDOWN_RCV`: the sender will receive no more.
const SHUTDOWN_RCV: u32 = 1;
/// `VIRTIO_VSOCK_SHUTDOWN_SEND`: the sender will send no more.
const SHUTDOWN_SEND: u32 = 2;

/// The most RSTs waiting for a transmit buffer. Refusals leave one place,
/// and a connection is accepted only while one is free, so its RST always
/// fits; further refusals are dropped.
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
    fn parse(bytes: &[u8; HEADER_SIZE]) -> Self {
        fn le<const N: usize>(bytes: &[u8; HEADER_SIZE], offset: usize) -> [u8; N] {
            bytes[offset..][..N]
                .try_into()
                .expect("fields are within the header")
        }
        Self {
            src_cid: u64::from_le_bytes(le(bytes, 0)),
            dst_cid: u64::from_le_bytes(le(bytes, 8)),
            src_port: u32::from_le_bytes(le(bytes, 16)),
            dst_port: u32::from_le_bytes(le(bytes, 20)),
            len: u32::from_le_bytes(le(bytes, 24)),
            ty: u16::from_le_bytes(le(bytes, 28)),
            op: u16::from_le_bytes(le(bytes, 30)),
            flags: u32::from_le_bytes(le(bytes, 32)),
            buf_alloc: u32::from_le_bytes(le(bytes, 36)),
            fwd_cnt: u32::from_le_bytes(le(bytes, 40)),
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

/// A connection to a [`VirtioVsock`]'s listener; each is a new value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VsockConnection(u64);

impl fmt::Display for VsockConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The live connection.
struct Connection {
    id: VsockConnection,
    /// The host's port.
    peer_port: u32,
    /// The host's receive buffer, as of its latest packet.
    peer_buf_alloc: u32,
    /// Bytes the host's reader consumed (wrapping), as of its latest packet.
    peer_fwd_cnt: u32,
    /// The host sends no more data.
    peer_sent_all: bool,
    /// Received, not yet read; at most [`RX_CAPACITY`] bytes.
    rx: VecDeque<u8>,
    /// Bytes read, ever (wrapping).
    fwd_cnt: u32,
    /// The `fwd_cnt` the host last got.
    reported_fwd_cnt: u32,
    /// Bytes sent, ever (wrapping).
    tx_cnt: u32,
    /// The RESPONSE is still to be sent; data waits for it.
    response_pending: bool,
    /// A CREDIT_UPDATE is due, unless another packet carries the credit.
    credit_update_pending: bool,
}

/// A listener's protocol: packets in; headers out ([`Self::next_control`],
/// [`Self::data_header`]).
struct Stream {
    guest_cid: u64,
    port: u32,
    connection: Option<Connection>,
    /// Connections accepted, ever: the latest's id.
    accepted: u64,
    /// RSTs waiting for a transmit buffer, oldest first.
    resets: VecDeque<Header>,
}

impl Stream {
    fn new(guest_cid: u64, port: u32) -> Self {
        Self {
            guest_cid,
            port,
            connection: None,
            accepted: 0,
            resets: VecDeque::with_capacity(MAX_RESETS),
        }
    }

    /// The live connection, if `id` is it.
    fn live(&mut self, id: VsockConnection) -> Option<&mut Connection> {
        self.connection
            .as_mut()
            .filter(|connection| connection.id == id)
    }

    /// A header for `connection`, reporting its credit.
    fn connection_header(
        guest_cid: u64,
        port: u32,
        connection: &mut Connection,
        op: u16,
        len: u32,
    ) -> Header {
        connection.reported_fwd_cnt = connection.fwd_cnt;
        connection.credit_update_pending = false;
        Header {
            src_cid: guest_cid,
            dst_cid: HOST_CID,
            src_port: port,
            dst_port: connection.peer_port,
            len,
            ty: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: RX_CAPACITY,
            fwd_cnt: connection.fwd_cnt,
        }
    }

    /// A packet the device delivered: everything it wrote to the buffer.
    fn receive(&mut self, packet: &[u8]) {
        let Some((header, rest)) = packet.split_first_chunk::<HEADER_SIZE>() else {
            return;
        };
        let header = Header::parse(header);
        // Not addressed to the listener.
        if header.dst_cid != self.guest_cid || header.src_cid != HOST_CID {
            return;
        }
        if header.ty != TYPE_STREAM {
            self.refuse(&header);
            return;
        }
        let port = self.port;
        let on_connection = self.connection.as_ref().is_some_and(|connection| {
            header.dst_port == port && header.src_port == connection.peer_port
        });
        let payload = usize::try_from(header.len)
            .ok()
            .and_then(|len| rest.get(..len));
        match payload {
            Some(payload) if on_connection => self.receive_on_connection(&header, payload),
            Some(_) => self.receive_other(&header),
            // Malformed: it ends the connection, unanswered if an RST.
            None if on_connection && header.op == op::RST => self.connection = None,
            None if on_connection => self.reset(),
            None => {}
        }
    }

    fn receive_on_connection(&mut self, header: &Header, payload: &[u8]) {
        let Some(connection) = &mut self.connection else {
            return;
        };
        connection.peer_buf_alloc = header.buf_alloc;
        connection.peer_fwd_cnt = header.fwd_cnt;
        match header.op {
            op::RW => {
                if connection.peer_sent_all
                    || connection.rx.len() + payload.len() > RX_CAPACITY as usize
                {
                    self.reset();
                } else {
                    connection.rx.extend(payload);
                }
            }
            op::CREDIT_UPDATE => {}
            op::CREDIT_REQUEST => connection.credit_update_pending = true,
            op::SHUTDOWN if header.flags & SHUTDOWN_RCV != 0 => self.reset(),
            op::SHUTDOWN => connection.peer_sent_all |= header.flags & SHUTDOWN_SEND != 0,
            op::RST => self.connection = None,
            // A repeated REQUEST, an unsolicited RESPONSE, or an unknown op.
            _ => self.reset(),
        }
    }

    /// A stream packet for no live connection.
    fn receive_other(&mut self, header: &Header) {
        if header.op == op::REQUEST
            && self.connection.is_none()
            && header.dst_port == self.port
            && self.resets.len() < MAX_RESETS
        {
            self.accepted = self.accepted.wrapping_add(1);
            self.connection = Some(Connection {
                id: VsockConnection(self.accepted),
                peer_port: header.src_port,
                peer_buf_alloc: header.buf_alloc,
                peer_fwd_cnt: header.fwd_cnt,
                peer_sent_all: false,
                rx: VecDeque::new(),
                fwd_cnt: 0,
                reported_fwd_cnt: 0,
                tx_cnt: 0,
                response_pending: true,
                credit_update_pending: false,
            });
        } else {
            // Another port, a second connection, no place for its RST, or a
            // stale packet.
            self.refuse(header);
        }
    }

    /// Queues an RST refusing `header`'s packet, unless that is an RST or
    /// only the place kept for a connection's RST is left ([`MAX_RESETS`]).
    fn refuse(&mut self, header: &Header) {
        if header.op == op::RST || self.resets.len() >= MAX_RESETS - 1 {
            return;
        }
        self.resets.push_back(Header {
            src_cid: self.guest_cid,
            dst_cid: header.src_cid,
            src_port: header.dst_port,
            dst_port: header.src_port,
            ty: header.ty,
            op: op::RST,
            ..Header::default()
        });
    }

    /// Ends the live connection, if any, with an RST carrying its credit.
    fn reset(&mut self) {
        let Some(mut connection) = self.connection.take() else {
            return;
        };
        let reset = Self::connection_header(self.guest_cid, self.port, &mut connection, op::RST, 0);
        self.resets.push_back(reset);
    }

    /// The transport was reset: connections are gone; the CID may change.
    fn transport_reset(&mut self, guest_cid: u64) {
        self.guest_cid = guest_cid;
        self.connection = None;
        self.resets.clear();
    }

    /// The next control packet to send, if any.
    fn next_control(&mut self) -> Option<Header> {
        // RSTs first: one may end an earlier connection from the same port.
        if let Some(reset) = self.resets.pop_front() {
            return Some(reset);
        }
        let connection = self.connection.as_mut()?;
        let op = if core::mem::take(&mut connection.response_pending) {
            op::RESPONSE
        } else if connection.credit_update_pending {
            op::CREDIT_UPDATE
        } else {
            return None;
        };
        Some(Self::connection_header(
            self.guest_cid,
            self.port,
            connection,
            op,
            0,
        ))
    }

    /// How much data connection `id` takes now; `None` unless it is live.
    fn send_budget(&mut self, id: VsockConnection) -> Option<usize> {
        let connection = self.live(id)?;
        if connection.response_pending {
            return Some(0);
        }
        // Zero if the host's numbers are bogus.
        let in_flight = connection.tx_cnt.wrapping_sub(connection.peer_fwd_cnt);
        Some(connection.peer_buf_alloc.saturating_sub(in_flight) as usize)
    }

    /// The header of data on connection `id`: as much of `len` bytes as
    /// [`Self::send_budget`] allows, if any; `None` unless it is live.
    fn data_header(&mut self, id: VsockConnection, len: usize) -> Option<Header> {
        let budget = self.send_budget(id)?;
        let len = u32::try_from(len.min(budget))
            .ok()
            .filter(|&len| len != 0)?;
        let (guest_cid, port) = (self.guest_cid, self.port);
        let connection = self.live(id)?;
        connection.tx_cnt = connection.tx_cnt.wrapping_add(len);
        Some(Self::connection_header(
            guest_cid,
            port,
            connection,
            op::RW,
            len,
        ))
    }

    /// Copies data connection `id` received into `output`: how much (zero
    /// if none is waiting); `None` unless it is live.
    fn read(&mut self, id: VsockConnection, output: &mut [u8]) -> Option<usize> {
        let connection = self.live(id)?;
        let len = output.len().min(connection.rx.len());
        let (front, back) = connection.rx.as_slices();
        let split = len.min(front.len());
        output[..split].copy_from_slice(&front[..split]);
        output[split..len].copy_from_slice(&back[..len - split]);
        connection.rx.drain(..len);
        #[expect(clippy::cast_possible_truncation, reason = "at most RX_CAPACITY")]
        let consumed = len as u32;
        connection.fwd_cnt = connection.fwd_cnt.wrapping_add(consumed);
        // Half suffices: see the module docs.
        let unreported = connection.fwd_cnt.wrapping_sub(connection.reported_fwd_cnt);
        if unreported >= RX_CAPACITY / 2 {
            connection.credit_update_pending = true;
        }
        Some(len)
    }

    /// Resets connection `id` if it is live.
    fn close(&mut self, id: VsockConnection) {
        if self.live(id).is_some() {
            self.reset();
        }
    }
}

/// The device's registers: the [`PciTransport`], or a test's fake.
trait Registers {
    /// Tells the device that `queue` has new available buffers.
    fn notify(&self, queue: &VirtQueue);

    /// The guest's CID, from the device configuration.
    fn guest_cid(&self) -> Result<u64, Error>;
}

impl Registers for PciTransport {
    fn notify(&self, queue: &VirtQueue) {
        PciTransport::notify(self, queue);
    }

    /// `le64 guest_cid`: a guest's, 3 through `u32::MAX - 1`.
    fn guest_cid(&self) -> Result<u64, Error> {
        let config = self
            .device_config()
            .filter(|config| config.len() >= 8)
            .ok_or(Error::BadStructure("device configuration"))?;
        // No generation check: valid CIDs' high halves are zero.
        let cid = u64::from(config.read_u32(0)) | u64::from(config.read_u32(4)) << 32;
        if (3..u64::from(u32::MAX)).contains(&cid) {
            Ok(cid)
        } else {
            Err(Error::InvalidConfig("guest CID"))
        }
    }
}

/// The device's queues and buffers, and the stream they carry.
struct Queues {
    rx: VirtQueue,
    rx_buffers: Buffers,
    tx: VirtQueue,
    tx_buffers: Buffers,
    /// How many transmit buffers there are.
    tx_count: usize,
    event: VirtQueue,
    event_buffers: Buffers,
    stream: Stream,
    /// A received packet, copied out of DMA memory.
    scratch: Vec<u8>,
}

impl Queues {
    /// Buffers for the queues, with every receive and event buffer lent to
    /// the device (which must not have started).
    fn new(
        hal: &'static dyn Hal,
        mut rx: VirtQueue,
        tx: VirtQueue,
        mut event: VirtQueue,
        stream: Stream,
    ) -> Result<Self, Error> {
        let mut rx_buffers = Buffers::new(hal, &rx, RX_BUFFERS, BUFFER_SIZE)?;
        let tx_buffers = Buffers::new(hal, &tx, TX_BUFFERS, BUFFER_SIZE)?;
        let mut event_buffers = Buffers::new(hal, &event, EVENT_BUFFERS, EVENT_SIZE)?;
        while let Some(buffer) = rx_buffers.free.pop() {
            rx_buffers.post(&mut rx, buffer, BUFFER_SIZE, true);
        }
        while let Some(buffer) = event_buffers.free.pop() {
            event_buffers.post(&mut event, buffer, EVENT_SIZE, true);
        }
        Ok(Self {
            rx,
            rx_buffers,
            tx,
            tx_count: tx_buffers.free.len(),
            tx_buffers,
            event,
            event_buffers,
            stream,
            scratch: vec![0; BUFFER_SIZE],
        })
    }

    /// Takes a bounded amount of what the device returned; sends what waits.
    fn poll(&mut self, device: &impl Registers) {
        self.collect_events(device);
        self.collect_received(device);
        // At most once per buffer in flight.
        while let Some((buffer, _)) = self.tx_buffers.take_used(&mut self.tx) {
            self.tx_buffers.free.push(buffer);
        }
        self.send_control(device);
    }

    /// Whether returned receive or event buffers await a call.
    fn has_backlog(&self) -> bool {
        self.rx.has_used() || self.event.has_used()
    }

    fn collect_events(&mut self, device: &impl Registers) {
        let mut reposted = false;
        // A device may return buffers as fast as they are reposted.
        for _ in 0..EVENT_BUFFERS {
            let Some((buffer, len)) = self.event_buffers.take_used(&mut self.event) else {
                break;
            };
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
                let guest_cid = device.guest_cid().unwrap_or_else(|_| {
                    litebox_util_log::warn!("vsock transport reset to an invalid guest CID");
                    self.stream.guest_cid
                });
                self.stream.transport_reset(guest_cid);
            }
        }
        if reposted {
            device.notify(&self.event);
        }
    }

    fn collect_received(&mut self, device: &impl Registers) {
        let mut reposted = false;
        // A device may return buffers as fast as they are reposted.
        for _ in 0..RX_BUFFERS {
            let Some((buffer, len)) = self.rx_buffers.take_used(&mut self.rx) else {
                break;
            };
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
            device.notify(&self.rx);
        }
    }

    /// Sends pending control packets while transmit buffers are free.
    fn send_control(&mut self, device: &impl Registers) {
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
            device.notify(&self.tx);
        }
    }

    /// Sends `header` and `payload` in free transmit buffer `buffer`.
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

    fn connection(&mut self, device: &impl Registers) -> Option<VsockConnection> {
        self.poll(device);
        Some(self.stream.connection.as_ref()?.id)
    }

    fn read(
        &mut self,
        device: &impl Registers,
        connection: VsockConnection,
        output: &mut [u8],
    ) -> Option<usize> {
        self.poll(device);
        let read = self.stream.read(connection, output);
        self.send_control(device);
        read
    }

    fn write(
        &mut self,
        device: &impl Registers,
        connection: VsockConnection,
        bytes: &[u8],
    ) -> Option<usize> {
        self.poll(device);
        self.stream.live(connection)?;
        let mut written = 0;
        while let Some(&buffer) = self.tx_buffers.free.last() {
            let chunk = &bytes[written..];
            let chunk = &chunk[..chunk.len().min(MAX_PAYLOAD)];
            let Some(header) = self.stream.data_header(connection, chunk.len()) else {
                break;
            };
            self.tx_buffers.free.pop();
            let len = header.len as usize;
            self.post(buffer, header, &chunk[..len]);
            written += len;
        }
        if written != 0 {
            device.notify(&self.tx);
        }
        Some(written)
    }

    fn close(&mut self, device: &impl Registers, connection: VsockConnection) {
        self.poll(device);
        self.stream.close(connection);
        self.send_control(device);
    }

    fn flushed(&mut self, device: &impl Registers) -> bool {
        self.poll(device);
        self.tx_buffers.free.len() == self.tx_count
    }
}

/// A live socket device: a stream listener on one port, for the host. Not
/// internally synchronized. Dropping it resets the device, or leaks its
/// buffers if that fails (the device may still access them).
pub struct VirtioVsock {
    transport: PciTransport,
    queues: ManuallyDrop<Queues>,
}

impl VirtioVsock {
    /// The first virtio socket device on bus 0, brought up, interrupting
    /// with `interrupt` (if it can; see [`PciTransport::interrupts`]), and
    /// listening on `port`; `None` if there is none.
    ///
    /// # Errors
    ///
    /// The device cannot be driven (e.g., an invalid guest CID).
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
            let guest_cid = transport.guest_cid()?;
            let rx = transport.setup_queue(hal, RX_QUEUE, RX_BUFFERS)?;
            let tx = transport.setup_queue(hal, TX_QUEUE, TX_BUFFERS)?;
            let event = transport.setup_queue(hal, EVENT_QUEUE, EVENT_BUFFERS)?;
            Queues::new(hal, rx, tx, event, Stream::new(guest_cid, port))
        };
        let queues = setup().inspect_err(|_| transport.fail())?;
        transport.start();
        transport.notify(&queues.rx);
        transport.notify(&queues.event);
        Ok(Self {
            transport,
            queues: ManuallyDrop::new(queues),
        })
    }

    pub fn transport(&self) -> &PciTransport {
        &self.transport
    }

    /// The guest's CID, which the host connects to.
    pub fn guest_cid(&self) -> u64 {
        self.queues.stream.guest_cid
    }

    /// The port it listens on.
    pub fn port(&self) -> u32 {
        self.queues.stream.port
    }

    /// Whether returned buffers await another call (each takes a bounded
    /// number): make it before waiting for an interrupt.
    pub fn has_backlog(&self) -> bool {
        self.queues.has_backlog()
    }

    /// The live connection, if any, after taking what the device returned.
    pub fn connection(&mut self) -> Option<VsockConnection> {
        self.queues.connection(&self.transport)
    }

    /// Copies data `connection` received into `output`: how much (zero if
    /// none is waiting); `None` unless it is the live connection.
    pub fn read(&mut self, connection: VsockConnection, output: &mut [u8]) -> Option<usize> {
        self.queues.read(&self.transport, connection, output)
    }

    /// Queues as much of `bytes` as the host's credit and free transmit
    /// buffers allow: how much; `None` unless `connection` is live.
    pub fn write(&mut self, connection: VsockConnection, bytes: &[u8]) -> Option<usize> {
        self.queues.write(&self.transport, connection, bytes)
    }

    /// Resets `connection` if it is live; the listener then accepts the next.
    pub fn close(&mut self, connection: VsockConnection) {
        self.queues.close(&self.transport, connection);
    }

    /// Whether every transmit buffer is back: all sent data reached the host.
    pub fn flushed(&mut self) -> bool {
        self.queues.flushed(&self.transport)
    }
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        if self.transport.reset().is_err() {
            return;
        }
        // Safety: dropped once, here; after the reset, the device accesses
        // none of them.
        unsafe { ManuallyDrop::drop(&mut self.queues) };
    }
}

#[cfg(test)]
mod tests;
