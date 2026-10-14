// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! UDP sockets: once bound, a smoltcp socket on the loopback interface,
//! and one on the Ethernet interface if the binding can reach it (it is not
//! to a loopback address). The broker core owns the peer; the socket only
//! keeps it to choose sources and filter what it receives.
//!
//! As the stack runs, [`Udp::sift`] moves what arrives into the socket's own
//! queue, in order, dropping what the socket would not receive (from other
//! than its peer, or from a source the guest cannot address): such datagrams
//! never take room the peer's need. ICMP errors about datagrams to the peer
//! (e.g., port unreachable) become the socket's pending error, as on Linux.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddrV4;
use litebox_broker_core::socket::{
    GUEST_IPV4_ADDRESS, GuestSocketBinding, PlatformConnectError, PlatformDatagramReceive,
    PlatformSocketStatus, is_internal_socket_address, normalize_socket_destination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, ShutdownMode, SocketConnectionStatus, SocketError,
    SocketOutcome,
};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata, UdpMetadata};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use super::{MAX_EXTERNAL_DATAGRAM, Side, Sockets, socket_address};

pub(super) const PACKETS: usize = 32;

/// Payload buffers, per direction: the loopback interface carries
/// datagrams of any size, the Ethernet interface only unfragmented ones.
const INTERNAL_PAYLOAD: usize = 2 * MAX_UDP_DATAGRAM_SIZE as usize;
const EXTERNAL_PAYLOAD: usize = 32 * 1024;

/// The socket's own receive queue's bounds; beyond, datagrams wait in
/// smoltcp's (which drops what does not fit).
const MAX_RECEIVED: usize = 2 * PACKETS;
const MAX_RECEIVED_BYTES: usize = INTERNAL_PAYLOAD;

struct Datagram {
    data: Vec<u8>,
    source: SocketAddrV4,
}

pub(super) struct Udp {
    binding: Option<GuestSocketBinding>,
    internal: Option<SocketHandle>,
    external: Option<SocketHandle>,
    peer: Option<SocketAddrV4>,
    /// A send found no room for a datagram of this size on this interface:
    /// not writable until there is (see [`fits`]).
    blocked: Option<(Side, usize)>,
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

fn new_socket(payload: usize) -> udp::Socket<'static> {
    let buffer = || PacketBuffer::new(vec![PacketMetadata::EMPTY; PACKETS], vec![0; payload]);
    udp::Socket::new(buffer(), buffer())
}

impl Udp {
    pub(super) fn new() -> Self {
        Self {
            binding: None,
            internal: None,
            external: None,
            peer: None,
            blocked: None,
            received: VecDeque::new(),
            received_bytes: 0,
            pending_error: None,
            read_shutdown: false,
            write_shutdown: false,
        }
    }

    pub(super) fn bind(
        &mut self,
        sockets: &mut Sockets,
        binding: GuestSocketBinding,
    ) -> SocketOutcome<SocketAddrV4> {
        if self.binding.is_some() || binding.is_tcp() {
            return SocketOutcome::Failed(SocketError::InvalidArgument);
        }
        let address = binding.local_address();
        let endpoint = if binding.is_wildcard() {
            IpListenEndpoint::from(address.port())
        } else {
            IpListenEndpoint::from(address)
        };
        let external = sockets.external.is_some()
            && (binding.is_wildcard() || *address.ip() == GUEST_IPV4_ADDRESS);
        let mut bound = |side: Side, payload: usize| {
            let mut socket = new_socket(payload);
            socket
                .bind(endpoint)
                .expect("a new socket with a nonzero port can bind");
            sockets.set(side).add(socket)
        };
        self.internal = Some(bound(Side::Internal, INTERNAL_PAYLOAD));
        if external {
            self.external = Some(bound(Side::External, EXTERNAL_PAYLOAD));
        }
        self.binding = Some(binding);
        SocketOutcome::Completed(address)
    }

    fn handle(&self, side: Side) -> Option<SocketHandle> {
        match side {
            Side::Internal => self.internal,
            Side::External => self.external,
        }
    }

    /// The bound port, if any.
    pub(super) fn port(&self) -> Option<u16> {
        self.binding
            .as_ref()
            .map(|binding| binding.local_address().port())
    }

    /// Moves what arrived on `side` into the socket's queue, as far as it
    /// has room, dropping what the socket would not receive.
    pub(super) fn sift(&mut self, side: Side, set: &mut SocketSet<'static>) {
        let Some(handle) = self.handle(side) else {
            return;
        };
        let socket = set.get_mut::<udp::Socket>(handle);
        while self.received.len() < MAX_RECEIVED && self.received_bytes < MAX_RECEIVED_BYTES {
            let Ok((payload, meta)) = socket.recv() else {
                break;
            };
            let source = socket_address(meta.endpoint);
            let wanted = normalize_socket_destination(source) == Ok(source)
                && self.peer.is_none_or(|peer| peer == source);
            if wanted {
                self.received_bytes += payload.len();
                self.received.push_back(Datagram {
                    data: payload.to_vec(),
                    source,
                });
            }
        }
    }

    /// An ICMP error on `side` about a datagram this socket sent to
    /// `destination`: the socket's error if that is its peer.
    pub(super) fn destination_error(
        &mut self,
        side: Side,
        destination: SocketAddrV4,
        error: SocketError,
    ) {
        if self.handle(side).is_some() && self.peer == Some(destination) {
            self.pending_error = Some(error);
        }
    }

    /// The interface and socket that reach `destination`.
    fn route(&self, destination: SocketAddrV4) -> Option<(Side, SocketHandle)> {
        if is_internal_socket_address(destination) {
            self.internal.map(|handle| (Side::Internal, handle))
        } else {
            self.external.map(|handle| (Side::External, handle))
        }
    }

    /// Sets the peer; the broker core keeps the previous one on failure.
    pub(super) fn connect(
        &mut self,
        address: SocketAddrV4,
    ) -> Result<SocketConnectionStatus, PlatformConnectError> {
        let binding = self
            .binding
            .as_ref()
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let destination = match normalize_socket_destination(address) {
            Ok(destination) => destination,
            Err(error) => return Ok(SocketConnectionStatus::Failed(error)),
        };
        if binding
            .source_address_for_destination(destination)
            .is_none()
        {
            return Ok(SocketConnectionStatus::Failed(SocketError::InvalidArgument));
        }
        if self.route(destination).is_none() {
            return Ok(SocketConnectionStatus::Failed(
                SocketError::NetworkUnreachable,
            ));
        }
        self.peer = Some(destination);
        Ok(SocketConnectionStatus::Connected)
    }

    pub(super) fn send_to(
        &mut self,
        sockets: &mut Sockets,
        data: &[u8],
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let Some(destination) = destination.or(self.peer) else {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        };
        let destination = match normalize_socket_destination(destination) {
            Ok(destination) => destination,
            Err(error) => return Ok(SocketOutcome::Failed(error)),
        };
        if self.write_shutdown {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let Some(source) = self
            .binding
            .as_ref()
            .and_then(|binding| binding.source_address_for_destination(destination))
        else {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        };
        let Some((side, handle)) = self.route(destination) else {
            return Ok(SocketOutcome::Failed(SocketError::NetworkUnreachable));
        };
        if side == Side::External && data.len() > MAX_EXTERNAL_DATAGRAM {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let mut meta = UdpMetadata::from(IpEndpoint::from(destination));
        meta.local_address = Some((*source.ip()).into());
        match sockets.udp(side, handle).send_slice(data, meta) {
            Ok(()) => {
                if self.blocked.is_some_and(|(blocked, _)| blocked == side) {
                    self.blocked = None;
                }
                Ok(SocketOutcome::Completed(data.len()))
            }
            Err(udp::SendError::BufferFull) => {
                // Writable again once it fits, which publishes the change.
                self.blocked = Some((side, data.len()));
                Err(BrokerError::WouldBlock)
            }
            Err(udp::SendError::Unaddressable) => {
                Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
            }
        }
    }

    /// The oldest datagram received (which a peek leaves for the next
    /// receive), or the pending error, which this consumes.
    pub(super) fn receive_from(
        &mut self,
        sockets: &mut Sockets,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<SocketOutcome<PlatformDatagramReceive>> {
        self.sift(Side::Internal, &mut sockets.internal);
        if let Some(external) = sockets.external.as_mut() {
            self.sift(Side::External, external);
        }
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

    pub(super) fn readiness(&mut self, sockets: &mut Sockets) -> ReadinessFlags {
        let mut flags = ReadinessFlags::default();
        // The stack sifted what arrived; anything still in smoltcp waits for
        // room in the queue, which is then not empty.
        if self.read_shutdown || !self.received.is_empty() {
            flags = flags | ReadinessFlags::READ;
        }
        if self.pending_error.is_some() {
            flags = flags | ReadinessFlags::ERROR;
        }
        if let Some((side, size)) = self.blocked
            && self
                .handle(side)
                .is_none_or(|handle| fits(sockets.udp(side, handle), size))
        {
            self.blocked = None;
        }
        // Either interface may be the next destination's: writable when both
        // have room, so a full one is waited out rather than spun on.
        let writable = !self.write_shutdown
            && self.blocked.is_none()
            && self
                .internal
                .is_none_or(|handle| sockets.udp(Side::Internal, handle).can_send())
            && self
                .external
                .is_none_or(|handle| sockets.udp(Side::External, handle).can_send());
        if writable {
            flags = flags | ReadinessFlags::WRITE;
        }
        flags
    }

    pub(super) fn retire(self, sockets: &mut Sockets) {
        if let Some(handle) = self.internal {
            sockets.set(Side::Internal).remove(handle);
        }
        if let Some(handle) = self.external {
            sockets.set(Side::External).remove(handle);
        }
    }
}
