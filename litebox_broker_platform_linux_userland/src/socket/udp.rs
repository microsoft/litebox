// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-wide UDP datagram routing for the Linux reactor.
//!
//! The reactor owns one broker-wide UDP namespace: guest bindings are resolved
//! against each other before any native endpoint is created, and native
//! endpoints are staged, rearmed, and retired here. Only the reactor seams that
//! guest sockets share with TCP stay in the parent module.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::OwnedFd;

use litebox_broker_core::socket::PlatformConnectError;
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, SocketError, SocketOutcome,
};
use rustix::event::epoll;
use rustix::io::Errno;
use rustix::net::{
    AddressFamily as LinuxAddressFamily, RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags,
    SocketFlags as LinuxSocketFlags, SocketType as LinuxSocketType, bind, connect, ipproto,
    recvfrom, sendto, socket_with, sockopt,
};

use super::{
    Reactor, ReactorReceiveFromOutcome, SocketKind, WAKE_TOKEN, broker_error_from_errno,
    local_socket_address, socket_operation_error_from_errno, update_snapshot, zeroed_vec,
};

pub(super) const MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND: usize = 64;
pub(super) const MAX_UDP_EXTERNAL_PEERS_PER_SOCKET: usize = 64;
const MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET: usize = 64;
const MAX_UDP_QUEUE_BYTES_PER_SOCKET: usize = 4 * 65_507;
pub(super) const MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE: usize = 16;
const MAX_UDP_QUEUE_BYTES_PER_SOURCE: usize = 2 * 65_507;
const MAX_UDP_NATIVE_PORT_RETRIES: usize = 16;
const MAX_UDP_NATIVE_CONNECT_DRAIN_DATAGRAMS: usize = 1024;
const UDP_NATIVE_RECEIVE_BUFFER_REQUEST: usize = 64 * 1024;
pub(super) const MAX_UDP_NATIVE_RECEIVE_BUFFER: usize = UDP_NATIVE_RECEIVE_BUFFER_REQUEST * 2;
pub(super) const UDP_EVENT_TOKEN_FLAG: u64 = 1 << 63;

/// Reactor-owned guest UDP bindings and live external endpoint identities.
#[derive(Default)]
pub(super) struct ReactorUdpState {
    pub(super) bindings: HashMap<u16, ReactorUdpBinding>,
    pub(super) native_endpoints: HashMap<u16, UdpNativeEndpointIdentity>,
}

#[derive(Clone, Copy)]
pub(super) struct ReactorUdpBinding {
    pub(super) socket_id: u64,
    pub(super) guest_address: SocketAddrV4,
    pub(super) internal_address: SocketAddrV4,
}

pub(super) struct UdpSocketState {
    pub(super) original_bind_was_wildcard: bool,
    pub(super) internal_address: Option<SocketAddrV4>,
    pub(super) peer: Option<ReactorUdpPeer>,
    guest_receive_queue: VecDeque<GuestDatagram>,
    guest_receive_bytes: usize,
    queued_by_source: HashMap<SessionId, UdpQueueAccounting>,
    pub(super) peeked_origin: Option<UdpReceiveOrigin>,
    pub(super) next_receive_origin: UdpReceiveOrigin,
    pub(super) external_endpoint: Option<ExternalUdpEndpoint>,
    pub(super) external_peers: HashSet<SocketAddrV4>,
    native_write_blocked: bool,
    pub(super) native_error: bool,
}

impl Default for UdpSocketState {
    fn default() -> Self {
        Self {
            original_bind_was_wildcard: false,
            internal_address: None,
            peer: None,
            guest_receive_queue: VecDeque::new(),
            guest_receive_bytes: 0,
            queued_by_source: HashMap::new(),
            peeked_origin: None,
            next_receive_origin: UdpReceiveOrigin::Guest,
            external_endpoint: None,
            external_peers: HashSet::new(),
            native_write_blocked: false,
            native_error: false,
        }
    }
}

struct GuestDatagram {
    payload: Vec<u8>,
    source_socket_generation: u64,
    source_guest_address: SocketAddrV4,
    source_session_id: SessionId,
}

pub(super) struct ExternalUdpEndpoint {
    pub(super) socket: OwnedFd,
    generation: u64,
    event_token: u64,
    pub(super) host_address: SocketAddrV4,
    pub(super) readable: bool,
}

#[derive(Clone, Copy)]
pub(super) struct UdpNativeEndpointIdentity {
    endpoint_generation: u64,
}

#[derive(Clone, Copy)]
pub(super) struct UdpEventTarget {
    socket_id: u64,
    endpoint_generation: u64,
}

#[derive(Clone, Copy, Default)]
pub(super) struct UdpQueueAccounting {
    datagrams: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UdpReceiveOrigin {
    Guest,
    Native,
}

#[derive(Clone, Copy)]
pub(super) enum ReactorUdpPeer {
    Guest {
        socket_generation: u64,
        guest_address: SocketAddrV4,
    },
    External(SocketAddrV4),
}

impl ReactorUdpState {
    pub(super) fn reserve_binding(&mut self, guest_port: u16) -> BrokerResult<()> {
        if guest_port == 0 || self.bindings.contains_key(&guest_port) {
            return Err(BrokerError::Internal);
        }
        self.bindings
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    pub(super) fn insert_binding(&mut self, binding: ReactorUdpBinding) -> BrokerResult<()> {
        let guest_port = binding.guest_address.port();
        if guest_port == 0 || self.bindings.contains_key(&guest_port) {
            return Err(BrokerError::Internal);
        }
        self.bindings.insert(guest_port, binding);
        Ok(())
    }

    pub(super) fn remove_binding(&mut self, guest_port: u16, socket_id: u64) {
        if self
            .bindings
            .get(&guest_port)
            .is_some_and(|binding| binding.socket_id == socket_id)
        {
            self.bindings.remove(&guest_port);
        }
    }

    fn guest_binding(&self, address: SocketAddrV4) -> Option<ReactorUdpBinding> {
        address
            .ip()
            .is_loopback()
            .then(|| self.bindings.get(&address.port()).copied())
            .flatten()
    }

    pub(super) fn binding_for_socket(&self, socket_id: u64) -> Option<ReactorUdpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .copied()
    }

    pub(super) fn update_guest_address(
        &mut self,
        socket_id: u64,
        guest_address: SocketAddrV4,
    ) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| binding.socket_id == socket_id)
            .ok_or(BrokerError::Internal)?;
        if binding.guest_address.port() != guest_address.port() {
            return Err(BrokerError::Internal);
        }
        binding.guest_address = guest_address;
        Ok(())
    }

    pub(super) fn is_private_host_port(&self, port: u16) -> bool {
        self.native_endpoints.contains_key(&port)
    }
}

impl Reactor {
    pub(super) fn resolve_udp_destination(
        &self,
        mut address: SocketAddrV4,
    ) -> SocketOutcome<ReactorUdpPeer> {
        if address.ip().is_unspecified() {
            address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port());
        }
        if let Some(binding) = self.udp.guest_binding(address) {
            return SocketOutcome::Completed(ReactorUdpPeer::Guest {
                socket_generation: binding.socket_id,
                guest_address: binding.internal_address,
            });
        }
        if self.is_private_udp_host_endpoint(address) {
            SocketOutcome::Failed(SocketError::ConnectionRefused)
        } else {
            SocketOutcome::Completed(ReactorUdpPeer::External(address))
        }
    }

    pub(super) fn reserve_udp_external_peer(
        &mut self,
        socket_id: u64,
        address: SocketAddrV4,
    ) -> BrokerResult<bool> {
        let session_id = {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let udp = socket.udp_state()?;
            if udp.external_peers.contains(&address) {
                return Ok(false);
            }
            if udp.external_peers.len() >= MAX_UDP_EXTERNAL_PEERS_PER_SOCKET {
                return Err(BrokerError::ResourceExhausted);
            }
            socket.session_id
        };
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(BrokerError::Internal)?;
        if self.udp_external_peer_count
            >= self
                .max_sockets
                .saturating_mul(MAX_UDP_EXTERNAL_PEERS_PER_SOCKET)
            || session.udp_external_peer_count
                >= self
                    .max_sockets_per_session
                    .saturating_mul(MAX_UDP_EXTERNAL_PEERS_PER_SOCKET)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        self.sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .external_peers
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        if !self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .external_peers
            .insert(address)
        {
            return Err(BrokerError::Internal);
        }
        self.udp_external_peer_count = self
            .udp_external_peer_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(BrokerError::Internal)?;
        session.udp_external_peer_count = session
            .udp_external_peer_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(true)
    }

    pub(super) fn remove_udp_external_peer(&mut self, socket_id: u64, address: SocketAddrV4) {
        let Some(socket) = self.sockets.get_mut(&socket_id) else {
            return;
        };
        let Ok(udp) = socket.udp_state_mut() else {
            return;
        };
        if !udp.external_peers.remove(&address) {
            return;
        }
        self.udp_external_peer_count = self
            .udp_external_peer_count
            .checked_sub(1)
            .expect("reactor UDP external peer count underflow");
        let session = self
            .sessions
            .get_mut(&socket.session_id)
            .expect("UDP external peer session state missing");
        session.udp_external_peer_count = session
            .udp_external_peer_count
            .checked_sub(1)
            .expect("session UDP external peer count underflow");
    }

    pub(super) fn clear_udp_external_peers(&mut self, socket_id: u64) -> BrokerResult<()> {
        let (session_id, count) = {
            let socket = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?;
            let session_id = socket.session_id;
            let udp = socket.udp_state_mut()?;
            let count = udp.external_peers.len();
            udp.external_peers.clear();
            (session_id, count)
        };
        self.udp_external_peer_count = self
            .udp_external_peer_count
            .checked_sub(count)
            .ok_or(BrokerError::Internal)?;
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(BrokerError::Internal)?;
        session.udp_external_peer_count = session
            .udp_external_peer_count
            .checked_sub(count)
            .ok_or(BrokerError::Internal)?;
        Ok(())
    }

    fn udp_queue_limits(&self) -> (usize, usize, usize, usize) {
        udp_queue_limits(self.max_sockets, self.max_sockets_per_session)
    }

    pub(super) fn udp_readiness(&self, socket_id: u64) -> BrokerResult<ReadinessFlags> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        let udp = socket.udp_state()?;
        let mut readiness = ReadinessFlags::default();
        if socket.read_shutdown
            || !udp.guest_receive_queue.is_empty()
            || udp
                .external_endpoint
                .as_ref()
                .is_some_and(|endpoint| endpoint.readable)
        {
            readiness = readiness | ReadinessFlags::READ;
        }
        if !socket.write_shutdown && !udp.native_write_blocked {
            readiness = readiness | ReadinessFlags::WRITE;
        }
        if udp.native_error {
            readiness = readiness | ReadinessFlags::ERROR;
        }
        Ok(readiness)
    }

    pub(super) fn publish_udp_readiness(&mut self, socket_id: u64) -> BrokerResult<()> {
        let readiness = self.udp_readiness(socket_id)?;
        let socket = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?;
        update_snapshot(socket, None, readiness)
    }

    fn udp_queue_would_drop(
        &self,
        receiver_id: u64,
        source_session_id: SessionId,
        length: usize,
    ) -> BrokerResult<bool> {
        let receiver = self
            .sockets
            .get(&receiver_id)
            .ok_or(BrokerError::UnknownObject)?;
        let udp = receiver.udp_state()?;
        let receiver_session = self
            .sessions
            .get(&receiver.session_id)
            .ok_or(BrokerError::Internal)?;
        let source = self
            .udp_source_queued
            .get(&source_session_id)
            .copied()
            .unwrap_or_default();
        let receiver_source = udp
            .queued_by_source
            .get(&source_session_id)
            .copied()
            .unwrap_or_default();
        let (global_datagrams, global_bytes, session_datagrams, session_bytes) =
            self.udp_queue_limits();

        Ok(
            udp.guest_receive_queue.len() >= MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET
                || udp.guest_receive_bytes.saturating_add(length) > MAX_UDP_QUEUE_BYTES_PER_SOCKET
                || receiver_source.datagrams >= MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE
                || receiver_source.bytes.saturating_add(length) > MAX_UDP_QUEUE_BYTES_PER_SOURCE
                || self.udp_queued_datagrams >= global_datagrams
                || self.udp_queued_bytes.saturating_add(length) > global_bytes
                || receiver_session.udp_queued_datagrams >= session_datagrams
                || receiver_session.udp_queued_bytes.saturating_add(length) > session_bytes
                || source.datagrams >= session_datagrams
                || source.bytes.saturating_add(length) > session_bytes,
        )
    }

    pub(super) fn enqueue_guest_datagram(
        &mut self,
        source_socket_id: u64,
        destination_generation: u64,
        payload: &[u8],
    ) -> BrokerResult<SocketOutcome<usize>> {
        let (source_session_id, source_guest_address) = {
            let source = self
                .sockets
                .get(&source_socket_id)
                .ok_or(BrokerError::Internal)?;
            (
                source.session_id,
                source
                    .udp_state()?
                    .internal_address
                    .ok_or(BrokerError::Internal)?,
            )
        };
        let destination_id = destination_generation;
        let accepts_source = {
            let Some(destination) = self.sockets.get(&destination_id) else {
                return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
            };
            if destination.kind != SocketKind::Udp || destination.read_shutdown {
                return Ok(SocketOutcome::Completed(payload.len()));
            }
            let udp = destination.udp_state()?;
            match udp.peer {
                None => true,
                Some(ReactorUdpPeer::Guest {
                    socket_generation,
                    guest_address,
                }) => {
                    socket_generation == source_socket_id && guest_address == source_guest_address
                }
                Some(ReactorUdpPeer::External(_)) => false,
            }
        };
        if !accepts_source
            || self.udp_queue_would_drop(destination_id, source_session_id, payload.len())?
        {
            return Ok(SocketOutcome::Completed(payload.len()));
        }

        let mut stored_payload = Vec::new();
        stored_payload
            .try_reserve_exact(payload.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        stored_payload.extend_from_slice(payload);
        if !self.udp_source_queued.contains_key(&source_session_id) {
            self.udp_source_queued
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
        }
        {
            let destination = self
                .sockets
                .get_mut(&destination_id)
                .ok_or(BrokerError::Internal)?;
            let udp = destination.udp_state_mut()?;
            udp.guest_receive_queue
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            if !udp.queued_by_source.contains_key(&source_session_id) {
                udp.queued_by_source
                    .try_reserve(1)
                    .map_err(|_| BrokerError::OutOfMemory)?;
            }
        }

        let was_empty = self
            .sockets
            .get(&destination_id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?
            .guest_receive_queue
            .is_empty();
        let datagram = GuestDatagram {
            payload: stored_payload,
            source_socket_generation: source_socket_id,
            source_guest_address,
            source_session_id,
        };
        let receiver_session_id = {
            let destination = self
                .sockets
                .get_mut(&destination_id)
                .ok_or(BrokerError::Internal)?;
            let receiver_session_id = destination.session_id;
            let udp = destination.udp_state_mut()?;
            udp.guest_receive_bytes += datagram.payload.len();
            let source = udp.queued_by_source.entry(source_session_id).or_default();
            source.datagrams += 1;
            source.bytes += datagram.payload.len();
            udp.guest_receive_queue.push_back(datagram);
            receiver_session_id
        };
        self.udp_queued_datagrams += 1;
        self.udp_queued_bytes += payload.len();
        let source = self.udp_source_queued.entry(source_session_id).or_default();
        source.datagrams += 1;
        source.bytes += payload.len();
        let receiver_session = self
            .sessions
            .get_mut(&receiver_session_id)
            .ok_or(BrokerError::Internal)?;
        receiver_session.udp_queued_datagrams += 1;
        receiver_session.udp_queued_bytes += payload.len();

        if was_empty && self.publish_udp_readiness(destination_id).is_err() {
            let datagram = self
                .sockets
                .get_mut(&destination_id)
                .expect("queued UDP destination disappeared")
                .udp_state_mut()
                .expect("queued UDP destination changed kind")
                .guest_receive_queue
                .pop_back()
                .expect("new UDP datagram disappeared before rollback");
            self.release_udp_datagram_accounting(destination_id, &datagram);
            let readiness = self
                .udp_readiness(destination_id)
                .expect("UDP destination disappeared during readiness rollback");
            self.sockets
                .get(&destination_id)
                .expect("UDP destination disappeared during readiness rollback")
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned")
                .readiness = readiness;
        }
        Ok(SocketOutcome::Completed(payload.len()))
    }

    fn release_udp_datagram_accounting(&mut self, receiver_id: u64, datagram: &GuestDatagram) {
        let receiver = self
            .sockets
            .get_mut(&receiver_id)
            .expect("UDP receiver disappeared before accounting release");
        let receiver_session_id = receiver.session_id;
        let udp = receiver
            .udp_state_mut()
            .expect("UDP receiver changed kind before accounting release");
        udp.guest_receive_bytes = udp
            .guest_receive_bytes
            .checked_sub(datagram.payload.len())
            .expect("UDP receiver byte count underflow");
        let remove_receiver_source = {
            let source = udp
                .queued_by_source
                .get_mut(&datagram.source_session_id)
                .expect("UDP receiver source accounting missing");
            source.datagrams = source
                .datagrams
                .checked_sub(1)
                .expect("UDP receiver source datagram count underflow");
            source.bytes = source
                .bytes
                .checked_sub(datagram.payload.len())
                .expect("UDP receiver source byte count underflow");
            source.datagrams == 0
        };
        if remove_receiver_source {
            udp.queued_by_source.remove(&datagram.source_session_id);
        }

        self.udp_queued_datagrams = self
            .udp_queued_datagrams
            .checked_sub(1)
            .expect("global UDP datagram count underflow");
        self.udp_queued_bytes = self
            .udp_queued_bytes
            .checked_sub(datagram.payload.len())
            .expect("global UDP byte count underflow");
        let remove_source = {
            let source = self
                .udp_source_queued
                .get_mut(&datagram.source_session_id)
                .expect("global UDP source accounting missing");
            source.datagrams = source
                .datagrams
                .checked_sub(1)
                .expect("global UDP source datagram count underflow");
            source.bytes = source
                .bytes
                .checked_sub(datagram.payload.len())
                .expect("global UDP source byte count underflow");
            source.datagrams == 0
        };
        if remove_source {
            self.udp_source_queued.remove(&datagram.source_session_id);
        }
        let receiver_session = self
            .sessions
            .get_mut(&receiver_session_id)
            .expect("UDP receiver session accounting missing");
        receiver_session.udp_queued_datagrams = receiver_session
            .udp_queued_datagrams
            .checked_sub(1)
            .expect("session UDP datagram count underflow");
        receiver_session.udp_queued_bytes = receiver_session
            .udp_queued_bytes
            .checked_sub(datagram.payload.len())
            .expect("session UDP byte count underflow");
    }

    pub(super) fn clear_udp_receive_queue(&mut self, socket_id: u64) -> BrokerResult<()> {
        loop {
            let datagram = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?
                .guest_receive_queue
                .pop_front();
            let Some(datagram) = datagram else {
                break;
            };
            self.release_udp_datagram_accounting(socket_id, &datagram);
        }
        let udp = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?;
        udp.peeked_origin = None;
        Ok(())
    }

    fn next_udp_endpoint_ids(&mut self) -> BrokerResult<(u64, u64)> {
        let generation = self.next_udp_endpoint_generation;
        self.next_udp_endpoint_generation = generation
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        let token_id = self.next_udp_event_token;
        self.next_udp_event_token = token_id
            .checked_add(1)
            .filter(|token| *token < UDP_EVENT_TOKEN_FLAG)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok((generation, UDP_EVENT_TOKEN_FLAG | token_id))
    }

    fn udp_port_conflicts(
        &self,
        socket_id: u64,
        port: u16,
        current_destination: SocketAddrV4,
    ) -> BrokerResult<bool> {
        if !self.sockets.contains_key(&socket_id) {
            return Err(BrokerError::Internal);
        }
        Ok(udp_address_matches_host_port(current_destination, port)
            || self.udp.native_endpoints.contains_key(&port)
            || self.sockets.values().any(|socket| {
                socket.udp_state().is_ok_and(|udp| {
                    udp.external_peers
                        .iter()
                        .any(|peer| udp_address_matches_host_port(*peer, port))
                        || matches!(
                            udp.peer,
                            Some(ReactorUdpPeer::External(peer))
                                if udp_address_matches_host_port(peer, port)
                        )
                })
            }))
    }

    pub(super) fn stage_udp_endpoint(
        &mut self,
        socket_id: u64,
        current_destination: SocketAddrV4,
        connected_peer: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<ExternalUdpEndpoint>> {
        let read_enabled = !self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .read_shutdown;
        self.udp
            .native_endpoints
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.udp_event_tokens
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;

        for _ in 0..MAX_UDP_NATIVE_PORT_RETRIES {
            let socket = socket_with(
                LinuxAddressFamily::INET,
                LinuxSocketType::DGRAM,
                LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
                Some(ipproto::UDP),
            )
            .map_err(broker_error_from_errno)?;
            configure_udp_native_receive_buffer(&socket)?;
            let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
            loop {
                match bind(&socket, &wildcard) {
                    Ok(()) => break,
                    Err(Errno::INTR) => {}
                    Err(error) => {
                        return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                            error,
                        )?));
                    }
                }
            }
            let host_address = local_socket_address(&socket)?;
            if self.udp_port_conflicts(socket_id, host_address.port(), current_destination)? {
                continue;
            }
            if let Some(peer) = connected_peer {
                loop {
                    match connect(&socket, &peer) {
                        Ok(()) => break,
                        Err(Errno::INTR) => {}
                        Err(error) => {
                            return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                                error,
                            )?));
                        }
                    }
                }
            }
            let host_address = if connected_peer.is_some() {
                local_socket_address(&socket)?
            } else {
                host_address
            };
            let (generation, event_token) = self.next_udp_endpoint_ids()?;
            if self
                .udp
                .native_endpoints
                .insert(
                    host_address.port(),
                    UdpNativeEndpointIdentity {
                        endpoint_generation: generation,
                    },
                )
                .is_some()
            {
                return Err(BrokerError::Internal);
            }
            if self
                .udp_event_tokens
                .insert(
                    event_token,
                    UdpEventTarget {
                        socket_id,
                        endpoint_generation: generation,
                    },
                )
                .is_some()
            {
                self.udp.native_endpoints.remove(&host_address.port());
                return Err(BrokerError::Internal);
            }
            if let Err(error) = epoll::add(
                &self.epoll,
                &socket,
                epoll::EventData::new_u64(event_token),
                udp_epoll_events(read_enabled, false),
            ) {
                self.udp_event_tokens.remove(&event_token);
                self.udp.native_endpoints.remove(&host_address.port());
                return Err(broker_error_from_errno(error));
            }
            return Ok(SocketOutcome::Completed(ExternalUdpEndpoint {
                socket,
                generation,
                event_token,
                host_address,
                readable: false,
            }));
        }
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    }

    pub(super) fn unregister_udp_endpoint(&mut self, endpoint: ExternalUdpEndpoint) {
        let _ = epoll::delete(&self.epoll, &endpoint.socket);
        self.udp_event_tokens.remove(&endpoint.event_token);
        if self
            .udp
            .native_endpoints
            .get(&endpoint.host_address.port())
            .is_some_and(|identity| identity.endpoint_generation == endpoint.generation)
        {
            self.udp
                .native_endpoints
                .remove(&endpoint.host_address.port());
        }
    }

    pub(super) fn connect_existing_udp_endpoint(
        &mut self,
        socket_id: u64,
        peer: SocketAddrV4,
    ) -> core::result::Result<SocketOutcome<SocketAddrV4>, PlatformConnectError> {
        {
            let socket =
                self.sockets
                    .get(&socket_id)
                    .ok_or(PlatformConnectError::PeerIndeterminate(
                        BrokerError::Internal,
                    ))?;
            let endpoint = socket
                .udp_state()
                .map_err(PlatformConnectError::PeerIndeterminate)?
                .external_endpoint
                .as_ref()
                .ok_or(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ))?;
            loop {
                match connect(&endpoint.socket, &peer) {
                    Ok(()) => break,
                    Err(Errno::INTR) => {}
                    Err(error) => {
                        return match socket_operation_error_from_errno(error) {
                            Ok(error) => Ok(SocketOutcome::Failed(error)),
                            Err(error) => Err(PlatformConnectError::PeerUnchanged(error)),
                        };
                    }
                }
            }
            let _ = sockopt::socket_error(&endpoint.socket).map_err(|error| {
                PlatformConnectError::PeerIndeterminate(broker_error_from_errno(error))
            })?;
        }

        for _ in 0..MAX_UDP_NATIVE_CONNECT_DRAIN_DATAGRAMS {
            let outcome =
                {
                    let socket = self.sockets.get(&socket_id).ok_or(
                        PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
                    )?;
                    let endpoint = socket
                        .udp_state()
                        .map_err(PlatformConnectError::PeerIndeterminate)?
                        .external_endpoint
                        .as_ref()
                        .ok_or(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ))?;
                    receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE)
                };
            match outcome {
                Ok(
                    ReactorReceiveFromOutcome::Received { .. }
                    | ReactorReceiveFromOutcome::Failed(_),
                ) => {}
                Err(BrokerError::WouldBlock) => {
                    let host_address = {
                        let socket = self.sockets.get_mut(&socket_id).ok_or(
                            PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
                        )?;
                        let udp = socket
                            .udp_state_mut()
                            .map_err(PlatformConnectError::PeerIndeterminate)?;
                        udp.native_write_blocked = false;
                        udp.native_error = false;
                        if udp.peeked_origin == Some(UdpReceiveOrigin::Native) {
                            udp.peeked_origin = None;
                        }
                        let endpoint = udp.external_endpoint.as_mut().ok_or(
                            PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
                        )?;
                        endpoint.readable = false;
                        let host_address = local_socket_address(&endpoint.socket)
                            .map_err(PlatformConnectError::PeerIndeterminate)?;
                        endpoint.host_address = host_address;
                        host_address
                    };
                    self.rearm_udp_endpoint(socket_id)
                        .map_err(PlatformConnectError::PeerIndeterminate)?;
                    return Ok(SocketOutcome::Completed(host_address));
                }
                Err(error) => return Err(PlatformConnectError::PeerIndeterminate(error)),
            }
        }
        Err(PlatformConnectError::PeerIndeterminate(
            BrokerError::ResourceExhausted,
        ))
    }

    pub(super) fn replace_udp_endpoint(
        &mut self,
        socket_id: u64,
        endpoint: Option<ExternalUdpEndpoint>,
    ) {
        let old = {
            let udp = self
                .sockets
                .get_mut(&socket_id)
                .expect("UDP socket disappeared during endpoint replacement")
                .udp_state_mut()
                .expect("socket changed kind during UDP endpoint replacement");
            udp.native_write_blocked = false;
            udp.native_error = false;
            if udp.peeked_origin == Some(UdpReceiveOrigin::Native) {
                udp.peeked_origin = None;
            }
            std::mem::replace(&mut udp.external_endpoint, endpoint)
        };
        if let Some(old) = old {
            self.unregister_udp_endpoint(old);
        }
    }

    pub(super) fn handle_udp_endpoint_event(
        &mut self,
        event_token: u64,
        events: epoll::EventFlags,
    ) -> BrokerResult<()> {
        let Some(target) = self.udp_event_tokens.get(&event_token).copied() else {
            return Ok(());
        };
        let readable_event = events.contains(epoll::EventFlags::IN);
        let error_event = events.intersects(epoll::EventFlags::ERR | epoll::EventFlags::HUP);
        {
            let Some(socket) = self.sockets.get_mut(&target.socket_id) else {
                return Ok(());
            };
            let udp = socket.udp_state_mut()?;
            let Some(endpoint) = udp.external_endpoint.as_mut() else {
                return Ok(());
            };
            if endpoint.generation != target.endpoint_generation {
                return Ok(());
            }
            if events.contains(epoll::EventFlags::OUT) {
                udp.native_write_blocked = false;
            }
            if error_event {
                endpoint.readable = true;
                udp.native_error = true;
            }
        }
        if readable_event && !error_event {
            self.drain_invalid_udp_ingress(target.socket_id)?;
        }
        self.rearm_udp_endpoint_if_needed(target.socket_id)?;
        // The cached snapshot remains authoritative if this association cannot
        // accept a notification. One session's sink must not fail the shared
        // reactor and every other session using it.
        let _ = self.publish_udp_readiness(target.socket_id);
        Ok(())
    }

    fn rearm_udp_endpoint(&mut self, socket_id: u64) -> BrokerResult<()> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        let udp = socket.udp_state()?;
        let Some(endpoint) = udp.external_endpoint.as_ref() else {
            return Ok(());
        };
        if udp.native_error {
            return Ok(());
        }
        epoll::modify(
            &self.epoll,
            &endpoint.socket,
            epoll::EventData::new_u64(endpoint.event_token),
            udp_rearm_events(
                socket.read_shutdown,
                endpoint.readable,
                udp.native_write_blocked,
            ),
        )
        .map_err(broker_error_from_errno)
    }

    pub(super) fn rearm_udp_endpoint_if_needed(&mut self, socket_id: u64) -> BrokerResult<()> {
        let should_rearm = {
            let udp = self
                .sockets
                .get(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state()?;
            udp.external_endpoint.as_ref().is_some_and(|endpoint| {
                udp_endpoint_needs_rearm(
                    endpoint.readable,
                    udp.native_write_blocked,
                    udp.native_error,
                )
            })
        };
        if should_rearm {
            self.rearm_udp_endpoint(socket_id)?;
        }
        Ok(())
    }

    fn udp_native_source_authorized(
        &self,
        socket_id: u64,
        source_address: SocketAddrV4,
    ) -> BrokerResult<bool> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        if socket.read_shutdown || self.is_private_udp_host_endpoint(source_address) {
            return Ok(false);
        }
        let udp = socket.udp_state()?;
        Ok(match udp.peer {
            Some(ReactorUdpPeer::Guest { .. }) => false,
            Some(ReactorUdpPeer::External(peer)) => peer == source_address,
            None => udp.external_peers.contains(&source_address),
        })
    }

    fn drain_invalid_udp_ingress(&mut self, socket_id: u64) -> BrokerResult<()> {
        if let Some(endpoint) = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .external_endpoint
            .as_mut()
        {
            endpoint.readable = false;
        }
        for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            let peek = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .external_endpoint
                    .as_ref()
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::PEEK)
            };
            let source_address = match peek {
                Ok(ReactorReceiveFromOutcome::Received { source_address, .. }) => source_address,
                Ok(ReactorReceiveFromOutcome::Failed(_)) => {
                    let udp = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?;
                    udp.native_error = true;
                    if let Some(endpoint) = udp.external_endpoint.as_mut() {
                        endpoint.readable = true;
                    }
                    return Ok(());
                }
                Err(BrokerError::WouldBlock) => {
                    if let Some(endpoint) = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .external_endpoint
                        .as_mut()
                    {
                        endpoint.readable = false;
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if self.udp_native_source_authorized(socket_id, source_address)? {
                self.sockets
                    .get_mut(&socket_id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state_mut()?
                    .external_endpoint
                    .as_mut()
                    .ok_or(BrokerError::Internal)?
                    .readable = true;
                return Ok(());
            }
            let consumed = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .external_endpoint
                    .as_ref()
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE)
            };
            match consumed {
                Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                Ok(ReactorReceiveFromOutcome::Failed(_)) => {
                    let udp = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?;
                    udp.native_error = true;
                    if let Some(endpoint) = udp.external_endpoint.as_mut() {
                        endpoint.readable = true;
                    }
                    return Ok(());
                }
                Err(BrokerError::WouldBlock) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        self.sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .external_endpoint
            .as_mut()
            .ok_or(BrokerError::Internal)?
            .readable = false;
        Ok(())
    }

    pub(super) fn send_external_udp(
        &mut self,
        socket_id: u64,
        data: &[u8],
        address: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let destination = address;
        let result = loop {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let endpoint = socket
                .udp_state()?
                .external_endpoint
                .as_ref()
                .ok_or(BrokerError::Internal)?;
            match sendto(
                &endpoint.socket,
                data,
                LinuxSendFlags::NOSIGNAL,
                &destination,
            ) {
                Ok(sent) if sent == data.len() => break Ok(SocketOutcome::Completed(sent)),
                Ok(_) => break Err(BrokerError::Internal),
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => break Err(BrokerError::WouldBlock),
                Err(error) => {
                    break socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
                }
            }
        };
        match result {
            Err(BrokerError::WouldBlock) => {
                let read_shutdown = self
                    .sockets
                    .get(&socket_id)
                    .ok_or(BrokerError::Internal)?
                    .read_shutdown;
                let socket = self
                    .sockets
                    .get_mut(&socket_id)
                    .ok_or(BrokerError::Internal)?;
                let udp = socket.udp_state_mut()?;
                let endpoint = udp
                    .external_endpoint
                    .as_mut()
                    .ok_or(BrokerError::Internal)?;
                udp.native_write_blocked = true;
                if !udp.native_error {
                    epoll::modify(
                        &self.epoll,
                        &endpoint.socket,
                        epoll::EventData::new_u64(endpoint.event_token),
                        udp_rearm_events(read_shutdown, endpoint.readable, true),
                    )
                    .map_err(broker_error_from_errno)?;
                }
                self.publish_udp_readiness(socket_id)?;
                Err(BrokerError::WouldBlock)
            }
            outcome => outcome,
        }
    }

    pub(super) fn receive_guest_udp(
        &mut self,
        socket_id: u64,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<Option<ReactorReceiveFromOutcome>> {
        let Some((data, datagram_length, source_address)) = ({
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let datagram = socket.udp_state()?.guest_receive_queue.front();
            datagram.map(|datagram| {
                let copied = length.min(datagram.payload.len());
                let mut data = Vec::new();
                data.try_reserve_exact(copied)
                    .map_err(|_| BrokerError::OutOfMemory)?;
                data.extend_from_slice(&datagram.payload[..copied]);
                debug_assert_ne!(datagram.source_socket_generation, WAKE_TOKEN);
                Ok::<_, BrokerError>((data, datagram.payload.len(), datagram.source_guest_address))
            })
        })
        .transpose()?
        else {
            return Ok(None);
        };

        if flags.contains(ReceiveFromFlags::PEEK) {
            self.sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?
                .peeked_origin = Some(UdpReceiveOrigin::Guest);
        } else {
            let datagram = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?
                .guest_receive_queue
                .pop_front()
                .ok_or(BrokerError::Internal)?;
            self.release_udp_datagram_accounting(socket_id, &datagram);
            let udp = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?;
            udp.peeked_origin = None;
            udp.next_receive_origin = UdpReceiveOrigin::Native;
            // The dequeue is committed and the cached snapshot is authoritative
            // even if this association cannot accept the notification.
            let _ = self.publish_udp_readiness(socket_id);
        }
        Ok(Some(ReactorReceiveFromOutcome::Received {
            data,
            datagram_length,
            source_address,
        }))
    }

    pub(super) fn receive_native_udp(
        &mut self,
        socket_id: u64,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<Option<ReactorReceiveFromOutcome>> {
        let can_receive = self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?
            .external_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.readable);
        if !can_receive {
            return Ok(None);
        }

        for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            let outcome = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .external_endpoint
                    .as_ref()
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, length, ReceiveFromFlags::PEEK)
            };
            let (data, datagram_length, source_address) = match outcome {
                Ok(ReactorReceiveFromOutcome::Received {
                    data,
                    datagram_length,
                    source_address,
                }) => (data, datagram_length, source_address),
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    return Ok(Some(ReactorReceiveFromOutcome::Failed(error)));
                }
                Err(BrokerError::WouldBlock) => {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .external_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?;
                    endpoint.readable = false;
                    self.rearm_udp_endpoint(socket_id)?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let authorized = self.udp_native_source_authorized(socket_id, source_address)?;
            if authorized {
                if flags.contains(ReceiveFromFlags::PEEK) {
                    self.sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .peeked_origin = Some(UdpReceiveOrigin::Native);
                    return Ok(Some(ReactorReceiveFromOutcome::Received {
                        data,
                        datagram_length,
                        source_address,
                    }));
                }

                let should_rearm = {
                    let udp = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?;
                    if udp.native_error {
                        false
                    } else {
                        udp.external_endpoint
                            .as_mut()
                            .ok_or(BrokerError::Internal)?
                            .readable = false;
                        true
                    }
                };
                if should_rearm && let Err(error) = self.rearm_udp_endpoint(socket_id) {
                    self.sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .external_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?
                        .readable = true;
                    return Err(error);
                }
                let consumed = {
                    let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                    let endpoint = socket
                        .udp_state()?
                        .external_endpoint
                        .as_ref()
                        .ok_or(BrokerError::Internal)?;
                    receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE)
                };
                match consumed {
                    Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                    Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                        self.sockets
                            .get_mut(&socket_id)
                            .ok_or(BrokerError::Internal)?
                            .udp_state_mut()?
                            .external_endpoint
                            .as_mut()
                            .ok_or(BrokerError::Internal)?
                            .readable = true;
                        return Ok(Some(ReactorReceiveFromOutcome::Failed(error)));
                    }
                    Err(BrokerError::WouldBlock) => {
                        let _ = self.publish_udp_readiness(socket_id);
                        return Ok(None);
                    }
                    Err(error) => {
                        self.sockets
                            .get_mut(&socket_id)
                            .ok_or(BrokerError::Internal)?
                            .udp_state_mut()?
                            .external_endpoint
                            .as_mut()
                            .ok_or(BrokerError::Internal)?
                            .readable = true;
                        return Err(error);
                    }
                }
                let udp = self
                    .sockets
                    .get_mut(&socket_id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state_mut()?;
                udp.peeked_origin = None;
                udp.next_receive_origin = UdpReceiveOrigin::Guest;
                // Consumption is committed. The endpoint was rearmed before
                // the dequeue. Refresh the cached head state so another
                // authorized datagram keeps READ asserted without requiring
                // an asynchronous low-to-high publication.
                let _ = self.drain_invalid_udp_ingress(socket_id);
                // The cached snapshot remains authoritative if notification
                // delivery fails after irreversible consumption.
                let _ = self.publish_udp_readiness(socket_id);
                return Ok(Some(ReactorReceiveFromOutcome::Received {
                    data,
                    datagram_length,
                    source_address,
                }));
            }
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let endpoint = socket
                .udp_state()?
                .external_endpoint
                .as_ref()
                .ok_or(BrokerError::Internal)?;
            match receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE) {
                Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    return Ok(Some(ReactorReceiveFromOutcome::Failed(error)));
                }
                Err(BrokerError::WouldBlock) => {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .external_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?;
                    endpoint.readable = false;
                    self.rearm_udp_endpoint(socket_id)?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        let readiness = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        let _ = socket.readiness.republish(readiness);
        Ok(None)
    }
}

fn receive_datagram_fd(
    socket: &OwnedFd,
    length: usize,
    flags: ReceiveFromFlags,
) -> BrokerResult<ReactorReceiveFromOutcome> {
    if length > MAX_UDP_DATAGRAM_SIZE as usize || flags.has_unsupported_bits() {
        return Ok(ReactorReceiveFromOutcome::Failed(
            SocketError::InvalidArgument,
        ));
    }
    let mut data = zeroed_vec(length)?;
    let mut linux_flags = LinuxRecvFlags::TRUNC;
    if flags.contains(ReceiveFromFlags::PEEK) {
        linux_flags |= LinuxRecvFlags::PEEK;
    }
    loop {
        match recvfrom(socket, data.as_mut_slice(), linux_flags) {
            Ok((received, datagram_length, address)) => {
                let source_address = SocketAddrV4::try_from(address.ok_or(BrokerError::Internal)?)
                    .map_err(|_| BrokerError::Internal)?;
                data.truncate(received);
                return Ok(ReactorReceiveFromOutcome::Received {
                    data,
                    datagram_length,
                    source_address,
                });
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => return Err(BrokerError::WouldBlock),
            Err(error) => {
                return Ok(ReactorReceiveFromOutcome::Failed(
                    socket_operation_error_from_errno(error)?,
                ));
            }
        }
    }
}

fn udp_epoll_events(read_enabled: bool, waiting_for_write: bool) -> epoll::EventFlags {
    let mut events = epoll::EventFlags::ONESHOT;
    if read_enabled {
        events |= epoll::EventFlags::IN;
    }
    if waiting_for_write {
        events |= epoll::EventFlags::OUT;
    }
    events
}

fn udp_endpoint_needs_rearm(readable: bool, waiting_for_write: bool, pending_error: bool) -> bool {
    !pending_error && (!readable || waiting_for_write)
}

fn udp_rearm_events(
    read_shutdown: bool,
    readable: bool,
    waiting_for_write: bool,
) -> epoll::EventFlags {
    udp_epoll_events(!read_shutdown && !readable, waiting_for_write)
}

fn udp_address_matches_host_port(address: SocketAddrV4, host_port: u16) -> bool {
    address.port() == host_port && is_local_ipv4_address(*address.ip())
}

pub(super) fn udp_queue_limits(
    max_sockets: usize,
    max_sockets_per_session: usize,
) -> (usize, usize, usize, usize) {
    let global_datagrams = max_sockets.saturating_mul(MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET);
    let global_bytes = max_sockets.saturating_mul(MAX_UDP_QUEUE_BYTES_PER_SOCKET);
    let session_datagrams = max_sockets_per_session
        .saturating_mul(MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET)
        .min(global_datagrams.saturating_sub(1));
    let session_bytes = max_sockets_per_session
        .saturating_mul(MAX_UDP_QUEUE_BYTES_PER_SOCKET)
        .min(global_bytes.saturating_sub(1));
    (
        global_datagrams,
        global_bytes,
        session_datagrams,
        session_bytes,
    )
}

fn configure_udp_native_receive_buffer(socket: &OwnedFd) -> BrokerResult<()> {
    sockopt::set_socket_recv_buffer_size(socket, UDP_NATIVE_RECEIVE_BUFFER_REQUEST)
        .map_err(broker_error_from_errno)?;
    if sockopt::socket_recv_buffer_size(socket).map_err(broker_error_from_errno)?
        > MAX_UDP_NATIVE_RECEIVE_BUFFER
    {
        return Err(BrokerError::ResourceExhausted);
    }
    Ok(())
}

pub(super) fn is_local_ipv4_address(address: Ipv4Addr) -> bool {
    let Ok(socket) = socket_with(
        LinuxAddressFamily::INET,
        LinuxSocketType::DGRAM,
        LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
        Some(ipproto::UDP),
    ) else {
        return true;
    };
    let address = SocketAddrV4::new(address, 0);
    loop {
        match bind(&socket, &address) {
            Err(Errno::INTR) => {}
            Err(Errno::ADDRNOTAVAIL) => return false,
            Ok(()) | Err(_) => return true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_write_wait_rearms_output_without_read_spin() {
        assert!(udp_endpoint_needs_rearm(true, true, false));
        let events = udp_rearm_events(false, true, true);
        assert!(events.contains(epoll::EventFlags::OUT));
        assert!(events.contains(epoll::EventFlags::ONESHOT));
        assert!(!events.contains(epoll::EventFlags::IN));
        assert!(!udp_endpoint_needs_rearm(true, true, true));
    }

    #[test]
    fn private_udp_host_ports_reject_only_local_addresses() {
        let port = 49152;
        assert!(udp_address_matches_host_port(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
            port
        ));
        assert!(!udp_address_matches_host_port(
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port),
            port
        ));
    }

    #[test]
    fn udp_session_queue_limits_remain_below_global_limits() {
        let (global_datagrams, global_bytes, session_datagrams, session_bytes) =
            udp_queue_limits(2, 2);
        assert!(session_datagrams < global_datagrams);
        assert!(session_bytes < global_bytes);
        let (_, _, single_session_datagrams, single_session_bytes) = udp_queue_limits(1, 1);
        assert_ne!(single_session_datagrams, 0);
        assert_ne!(single_session_bytes, 0);
    }
}
