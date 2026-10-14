// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! UDP sockets. Between guest sockets, the broker delivers a datagram to
//! the socket bound to its destination, directly, as the userland broker
//! does: one with no socket bound there fails (`ECONNREFUSED`); one the
//! socket would not take (from other than its peer, after its read
//! shutdown, or beyond its queue's bounds) is dropped. Beyond the guest, a
//! bound socket whose binding can reach it (not to a loopback address) has
//! a smoltcp socket on the Ethernet interface.
//!
//! ICMP errors about datagrams to the peer (e.g., port unreachable) become
//! the socket's pending error, as on Linux.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddrV4;
use core::time::Duration;
use litebox_broker_core::socket::{
    GUEST_IPV4_ADDRESS, GuestSocketBinding, PlatformConnectError, PlatformDatagramReceive,
    PlatformSocketStatus, is_internal_socket_address, normalize_socket_destination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, ShutdownMode, SocketConnectionStatus, SocketError,
    SocketOutcome,
};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata, UdpMetadata};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use super::{Kind, MAX_EXTERNAL_DATAGRAM, Sockets, Stack, is_broadcast, socket_address, zeroed};

pub(super) const PACKETS: usize = 32;

/// The smoltcp socket's payload buffers, per direction: unfragmented
/// datagrams.
const EXTERNAL_PAYLOAD: usize = 32 * 1024;

/// How long datagrams may wait in smoltcp's queue without one going out
/// (e.g., to a neighbor that does not answer ARP) before they are dropped,
/// as Linux drops what waits for a neighbor after its three solicitations,
/// a second apart (`mcast_solicit`, `retrans_time`). smoltcp would keep
/// them, and the socket, waiting for good.
const UNSENT_TIMEOUT: Duration = Duration::from_secs(3);

/// The socket's receive queue's bounds, as the userland broker's: in all,
/// and from any one guest process.
const MAX_RECEIVED: usize = 64;
const MAX_RECEIVED_BYTES: usize = 4 * MAX_UDP_DATAGRAM_SIZE as usize;
const MAX_RECEIVED_FROM_PROCESS: usize = 16;
const MAX_RECEIVED_BYTES_FROM_PROCESS: usize = 2 * MAX_UDP_DATAGRAM_SIZE as usize;

struct Datagram {
    data: Vec<u8>,
    source: SocketAddrV4,
    /// The guest process that sent it, if any.
    process: Option<ProcessId>,
}

pub(super) struct Udp {
    binding: Option<GuestSocketBinding>,
    external: Option<SocketHandle>,
    peer: Option<SocketAddrV4>,
    /// A send found no room in smoltcp's queue for a datagram of this size:
    /// not writable until there is (see [`fits`]).
    blocked: Option<usize>,
    /// Since when nothing in smoltcp's queue went out, and how much it held
    /// then (see [`UNSENT_TIMEOUT`]).
    unsent: Option<(Duration, usize)>,
    /// Datagrams to receive, oldest first, and their total size.
    received: VecDeque<Datagram>,
    received_bytes: usize,
    /// From an ICMP error about a datagram to the peer.
    pending_error: Option<SocketError>,
    read_shutdown: bool,
    write_shutdown: bool,
}

/// Whether `socket` surely takes a datagram of `size`: a free packet slot,
/// and payload room even if the datagram must wrap around the buffer's end
/// (which smoltcp pads, and cannot otherwise tell).
fn fits(socket: &udp::Socket, size: usize) -> bool {
    let queued = socket.send_queue();
    let free = socket.payload_send_capacity() - queued;
    socket.can_send() && (queued == 0 || free >= 2 * size)
}

/// Out of memory fails rather than panics.
fn new_socket(payload: usize) -> BrokerResult<udp::Socket<'static>> {
    let buffer = || -> BrokerResult<PacketBuffer<'static>> {
        Ok(PacketBuffer::new(
            vec![PacketMetadata::EMPTY; PACKETS],
            zeroed(payload)?,
        ))
    };
    Ok(udp::Socket::new(buffer()?, buffer()?))
}

impl Udp {
    pub(super) fn new() -> Self {
        Self {
            binding: None,
            external: None,
            peer: None,
            blocked: None,
            unsent: None,
            received: VecDeque::new(),
            received_bytes: 0,
            pending_error: None,
            read_shutdown: false,
            write_shutdown: false,
        }
    }

    /// Fails, leaving the socket unbound, if the stack's memory budget (see
    /// `MAX_BUFFER_BYTES`), or memory, has no room for its buffers.
    pub(super) fn bind(
        &mut self,
        sockets: &mut Sockets,
        has_network: bool,
        binding: GuestSocketBinding,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if self.binding.is_some() || binding.is_tcp() {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let address = binding.local_address();
        if has_network && (binding.is_wildcard() || *address.ip() == GUEST_IPV4_ADDRESS) {
            if sockets.room() < 2 * EXTERNAL_PAYLOAD {
                return Err(BrokerError::OutOfMemory);
            }
            let mut socket = new_socket(EXTERNAL_PAYLOAD)?;
            let endpoint = if binding.is_wildcard() {
                IpListenEndpoint::from(address.port())
            } else {
                IpListenEndpoint::from(address)
            };
            socket
                .bind(endpoint)
                .expect("a new socket with a nonzero port can bind");
            self.external = Some(sockets.set.add(socket));
        }
        self.binding = Some(binding);
        Ok(SocketOutcome::Completed(address))
    }

    /// Whether the guest datagrams sent to `destination` are this socket's.
    fn bound_to(&self, destination: SocketAddrV4) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|binding| binding.covers(destination))
    }

    /// Whether the socket has room for `len` more bytes from `process`.
    fn has_room(&self, len: usize, process: Option<ProcessId>) -> bool {
        let (from_process, bytes_from_process) = self
            .received
            .iter()
            .filter(|datagram| process.is_some() && datagram.process == process)
            .fold((0, 0), |(count, bytes), datagram| {
                (count + 1, bytes + datagram.data.len())
            });
        self.received.len() < MAX_RECEIVED
            && self.received_bytes + len <= MAX_RECEIVED_BYTES
            && (process.is_none()
                || from_process < MAX_RECEIVED_FROM_PROCESS
                    && bytes_from_process + len <= MAX_RECEIVED_BYTES_FROM_PROCESS)
    }

    /// Queues `data`, if the socket takes it (see the module's docs), and
    /// the stack's memory budget has room.
    fn deliver(
        &mut self,
        sockets: &mut Sockets,
        data: &[u8],
        source: SocketAddrV4,
        process: Option<ProcessId>,
    ) -> BrokerResult<()> {
        let wanted = !self.read_shutdown
            && self.peer.is_none_or(|peer| peer == source)
            && self.has_room(data.len(), process)
            && data.len() <= sockets.room();
        if !wanted {
            return Ok(());
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(data.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        copy.extend_from_slice(data);
        self.received
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        sockets.queued += copy.len();
        self.received_bytes += copy.len();
        self.received.push_back(Datagram {
            data: copy,
            source,
            process,
        });
        Ok(())
    }

    /// Queues what arrived from outside, as `room` in the memory budget
    /// allows; the rest waits in smoltcp's queue. What the socket would not
    /// receive is dropped, as from guest sockets.
    pub(super) fn sift(&mut self, sockets: &mut Sockets, room: &mut usize) {
        let Some(handle) = self.external else {
            return;
        };
        loop {
            let socket = sockets.udp(handle);
            let Ok((payload, meta)) = socket.peek() else {
                break;
            };
            let source = socket_address(meta.endpoint);
            let wanted = !self.read_shutdown
                && normalize_socket_destination(source) == Ok(source)
                && self.peer.is_none_or(|peer| peer == source);
            if wanted {
                if !self.has_room(payload.len(), None) || payload.len() > *room {
                    break;
                }
                let mut data = Vec::new();
                if data.try_reserve_exact(payload.len()).is_err() {
                    break;
                }
                data.extend_from_slice(payload);
                *room -= data.len();
                sockets.queued += data.len();
                self.received_bytes += data.len();
                self.received.push_back(Datagram {
                    data,
                    source,
                    process: None,
                });
            }
            let _ = sockets.udp(handle).recv();
        }
    }

    /// An ICMP error about a datagram from `source` to `destination`: the
    /// socket's error if it is the one connected so, as Linux matches it.
    pub(super) fn destination_error(
        &mut self,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        error: SocketError,
    ) {
        let sent = self
            .binding
            .as_ref()
            .and_then(|binding| binding.source_address_for_destination(destination))
            == Some(source);
        if self.external.is_some() && self.peer == Some(destination) && sent {
            self.pending_error = Some(error);
        }
    }

    /// Where a datagram to `destination` goes from: its source, or why it
    /// cannot be sent.
    fn source_for(&self, destination: SocketAddrV4) -> Result<SocketAddrV4, SocketError> {
        let source = self
            .binding
            .as_ref()
            .and_then(|binding| binding.source_address_for_destination(destination))
            .ok_or(SocketError::InvalidArgument)?;
        if !is_internal_socket_address(destination) {
            if self.external.is_none() {
                return Err(SocketError::NetworkUnreachable);
            }
            // As Linux without `SO_BROADCAST`: EACCES.
            if is_broadcast(*destination.ip()) {
                return Err(SocketError::PolicyDenied);
            }
        }
        Ok(source)
    }

    fn send_external(
        &mut self,
        sockets: &mut Sockets,
        data: &[u8],
        source: SocketAddrV4,
        destination: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let handle = self.external.ok_or(BrokerError::Internal)?;
        if data.len() > MAX_EXTERNAL_DATAGRAM {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let mut meta = UdpMetadata::from(IpEndpoint::from(destination));
        meta.local_address = Some((*source.ip()).into());
        match sockets.udp(handle).send_slice(data, meta) {
            Ok(()) => {
                self.blocked = None;
                Ok(SocketOutcome::Completed(data.len()))
            }
            Err(udp::SendError::BufferFull) => {
                // Writable again once it fits, which publishes the change.
                self.blocked = Some(data.len());
                Err(BrokerError::WouldBlock)
            }
            Err(udp::SendError::Unaddressable) => {
                Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
            }
        }
    }

    /// The oldest datagram received (which a peek leaves for the next
    /// receive), or the pending error, which this consumes.
    ///
    /// The stack sifted what arrived as it last ran, which it does after
    /// every operation.
    pub(super) fn receive_from(
        &mut self,
        sockets: &mut Sockets,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<SocketOutcome<PlatformDatagramReceive>> {
        if let Some(error) = self.pending_error.take() {
            return Ok(SocketOutcome::Failed(error));
        }
        let datagram = self.received.front().ok_or(BrokerError::WouldBlock)?;
        let received = PlatformDatagramReceive {
            data: datagram.data[..datagram.data.len().min(length)].to_vec(),
            datagram_length: datagram.data.len(),
            source_address: datagram.source,
        };
        if !flags.contains(ReceiveFromFlags::PEEK) {
            self.received_bytes -= datagram.data.len();
            sockets.queued -= datagram.data.len();
            self.received.pop_front();
        }
        Ok(SocketOutcome::Completed(received))
    }

    pub(super) fn shutdown(&mut self, mode: ShutdownMode) -> SocketOutcome<()> {
        match mode {
            ShutdownMode::Read => self.read_shutdown = true,
            ShutdownMode::Write => self.write_shutdown = true,
            ShutdownMode::Both => (self.read_shutdown, self.write_shutdown) = (true, true),
            _ => return SocketOutcome::Failed(SocketError::InvalidArgument),
        }
        SocketOutcome::Completed(())
    }

    pub(super) fn status(&mut self) -> PlatformSocketStatus {
        let local_address = self.binding.as_ref().map(|binding| {
            self.peer
                .and_then(|peer| binding.source_address_for_destination(peer))
                .unwrap_or_else(|| binding.local_address())
        });
        PlatformSocketStatus {
            status: if self.peer.is_some() {
                SocketConnectionStatus::Connected
            } else {
                SocketConnectionStatus::Unconnected
            },
            local_address,
            pending_error: self.pending_error.take(),
        }
    }

    /// Drops what waited in smoltcp's queue for [`UNSENT_TIMEOUT`] without
    /// any of it going out. (Received datagrams still in smoltcp's queue,
    /// which the socket's had no room for, go too.)
    fn drop_unsent(&mut self, sockets: &mut Sockets, now: Duration) {
        let Some(handle) = self.external else {
            return;
        };
        let socket = sockets.udp(handle);
        // Empty datagrams take a packet slot each, but no payload: smoltcp
        // shows them only once they fill the queue. Fewer wait unseen, but
        // a datagram behind them, with a payload, is seen.
        let queued = socket.send_queue();
        let waiting = queued != 0 || !socket.can_send();
        self.unsent = match self.unsent {
            _ if !waiting => None,
            Some((since, before)) if queued >= before => Some((since, queued)),
            _ => Some((now, queued)),
        };
        if self
            .unsent
            .is_some_and(|(since, _)| now >= since.saturating_add(UNSENT_TIMEOUT))
        {
            // Taken out of the set and put back, without reallocating: smoltcp
            // keeps a socket's wait for its neighbor until it next sends,
            // asking to be polled at once until then.
            let endpoint = socket.endpoint();
            let smoltcp::socket::Socket::Udp(mut socket) = sockets.set.remove(handle) else {
                unreachable!("a UDP socket");
            };
            socket.close();
            socket.bind(endpoint).expect("the endpoint it was bound to");
            self.external = Some(sockets.set.add(socket));
            self.unsent = None;
            self.blocked = None;
        }
    }

    pub(super) fn readiness(&mut self, sockets: &mut Sockets, now: Duration) -> ReadinessFlags {
        self.drop_unsent(sockets, now);
        let mut flags = ReadinessFlags::default();
        // The stack sifted what arrived. Anything still in smoltcp waits for
        // room: in the socket's queue (then not empty), or in the stack's
        // memory budget (sifted once there is).
        if self.read_shutdown || !self.received.is_empty() {
            flags = flags | ReadinessFlags::READ;
        }
        if self.pending_error.is_some() {
            flags = flags | ReadinessFlags::ERROR;
        }
        if let Some(size) = self.blocked
            && self
                .external
                .is_none_or(|handle| fits(sockets.udp(handle), size))
        {
            self.blocked = None;
        }
        // Guest datagrams are delivered, or dropped, at once: only smoltcp's
        // queue can be full.
        if !self.write_shutdown && self.blocked.is_none() {
            flags = flags | ReadinessFlags::WRITE;
        }
        flags
    }

    pub(super) fn retire(self, sockets: &mut Sockets) {
        sockets.queued -= self.received_bytes;
        if let Some(handle) = self.external {
            sockets.set.remove(handle);
        }
    }
}

impl Stack {
    fn udp_entry(&mut self, id: u64) -> BrokerResult<&mut Udp> {
        match &mut self.entries.get_mut(&id).ok_or(BrokerError::Internal)?.kind {
            Kind::Udp(udp) => Ok(udp),
            Kind::Tcp(_) => Err(BrokerError::Internal),
        }
    }

    /// The socket a guest datagram to `destination` goes to, if any.
    fn udp_bound_to(&self, destination: SocketAddrV4) -> Option<u64> {
        self.entries
            .iter()
            .find_map(|(&id, entry)| match &entry.kind {
                Kind::Udp(udp) if udp.bound_to(destination) => Some(id),
                _ => None,
            })
    }

    pub(super) fn bind_udp(
        &mut self,
        id: u64,
        binding: GuestSocketBinding,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let has_network = self.has_network();
        let Some(super::Entry {
            kind: Kind::Udp(udp),
            ..
        }) = self.entries.get_mut(&id)
        else {
            return Err(BrokerError::Internal);
        };
        udp.bind(&mut self.sockets, has_network, binding)
    }

    /// Sets the peer; the broker core keeps the previous one on failure. As
    /// on the userland broker, a guest peer must have a socket bound.
    pub(super) fn connect_udp(
        &mut self,
        id: u64,
        address: SocketAddrV4,
    ) -> Result<SocketConnectionStatus, PlatformConnectError> {
        let destination = match normalize_socket_destination(address) {
            Ok(destination) => destination,
            Err(error) => return Ok(SocketConnectionStatus::Failed(error)),
        };
        if is_internal_socket_address(destination) && self.udp_bound_to(destination).is_none() {
            return Ok(SocketConnectionStatus::Failed(
                SocketError::ConnectionRefused,
            ));
        }
        let udp = self
            .udp_entry(id)
            .map_err(PlatformConnectError::PeerUnchanged)?;
        if udp.binding.is_none() {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        if let Err(error) = udp.source_for(destination) {
            return Ok(SocketConnectionStatus::Failed(error));
        }
        udp.peer = Some(destination);
        Ok(SocketConnectionStatus::Connected)
    }

    pub(super) fn send_udp(
        &mut self,
        id: u64,
        data: &[u8],
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let process = self.entries.get(&id).ok_or(BrokerError::Internal)?.process;
        let udp = self.udp_entry(id)?;
        let Some(destination) = destination.or(udp.peer) else {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        };
        let destination = match normalize_socket_destination(destination) {
            Ok(destination) => destination,
            Err(error) => return Ok(SocketOutcome::Failed(error)),
        };
        if udp.write_shutdown {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let source = match udp.source_for(destination) {
            Ok(source) => source,
            Err(error) => return Ok(SocketOutcome::Failed(error)),
        };
        // As Linux, where allocating the datagram reports it.
        if let Some(error) = udp.pending_error.take() {
            return Ok(SocketOutcome::Failed(error));
        }
        if !is_internal_socket_address(destination) {
            let Some(super::Entry {
                kind: Kind::Udp(udp),
                ..
            }) = self.entries.get_mut(&id)
            else {
                return Err(BrokerError::Internal);
            };
            return udp.send_external(&mut self.sockets, data, source, destination);
        }
        let Some(receiver) = self.udp_bound_to(destination) else {
            return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
        };
        let Some(super::Entry {
            kind: Kind::Udp(receiver),
            ..
        }) = self.entries.get_mut(&receiver)
        else {
            return Err(BrokerError::Internal);
        };
        receiver.deliver(&mut self.sockets, data, source, Some(process))?;
        Ok(SocketOutcome::Completed(data.len()))
    }
}
