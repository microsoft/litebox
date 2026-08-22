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

use litebox_broker_core::socket::{
    GUEST_IPV4_ADDRESS, GuestSocketBinding, PlatformConnectError, SocketDestination,
    classify_socket_destination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, SocketError, SocketOutcome,
};
use rustix::event::epoll;
use rustix::io::Errno;
#[cfg(test)]
use rustix::io::ioctl_fionread;
use rustix::net::{
    AddressFamily as LinuxAddressFamily, RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags,
    SocketFlags as LinuxSocketFlags, SocketType as LinuxSocketType, bind, connect, ipproto,
    recvfrom, sendto, socket_with, sockopt,
};

use super::{
    PlatformSocketStatus, Reactor, ReactorReceiveFromOutcome, SocketKind, WAKE_TOKEN,
    broker_error_from_errno, local_socket_address, socket_operation_error_from_errno,
    update_snapshot, zeroed_vec,
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

/// Reactor-wide UDP namespace, native endpoint, and queue-accounting state.
pub(super) struct ReactorUdpState {
    pub(super) bindings: ReactorUdpBindings,
    pub(super) native_endpoints: HashSet<u16>,
    pub(super) external_peer_count: usize,
    pub(super) queued_datagrams: usize,
    pub(super) queued_bytes: usize,
    pub(super) queued_by_source: HashMap<SessionId, UdpQueueAccounting>,
    pub(super) event_tokens: HashMap<u64, UdpEventTarget>,
    pub(super) next_event_token: u64,
}

#[derive(Default)]
pub(super) struct ReactorUdpBindings {
    wildcard: HashMap<u16, ReactorUdpBinding>,
    exact: HashMap<SocketAddrV4, ReactorUdpBinding>,
}

impl ReactorUdpBindings {
    fn clear(&mut self) {
        self.wildcard.clear();
        self.exact.clear();
    }

    fn values(&self) -> impl Iterator<Item = &ReactorUdpBinding> {
        self.wildcard.values().chain(self.exact.values())
    }

    #[cfg(test)]
    pub(super) fn get(&self, port: u16) -> Option<&ReactorUdpBinding> {
        self.wildcard.get(&port).or_else(|| {
            self.exact
                .iter()
                .find_map(|(address, binding)| (address.port() == port).then_some(binding))
        })
    }
}

impl Default for ReactorUdpState {
    fn default() -> Self {
        Self {
            bindings: ReactorUdpBindings::default(),
            native_endpoints: HashSet::new(),
            external_peer_count: 0,
            queued_datagrams: 0,
            queued_bytes: 0,
            queued_by_source: HashMap::new(),
            event_tokens: HashMap::new(),
            next_event_token: 1,
        }
    }
}

impl ReactorUdpState {
    /// Clears live registrations and accounting without reusing event tokens.
    pub(super) fn clear_live_state(&mut self) {
        self.bindings.clear();
        self.native_endpoints.clear();
        self.event_tokens.clear();
        self.queued_by_source.clear();
        self.external_peer_count = 0;
        self.queued_datagrams = 0;
        self.queued_bytes = 0;
    }
}

#[derive(Clone)]
pub(super) struct ReactorUdpBinding {
    pub(super) socket_id: u64,
    pub(super) guest_binding: GuestSocketBinding,
}

pub(super) struct UdpSocketState {
    pub(super) peer: Option<ReactorUdpPeer>,
    guest_receive_queue: VecDeque<GuestDatagram>,
    guest_receive_bytes: usize,
    queued_by_source: HashMap<SessionId, UdpQueueAccounting>,
    pub(super) peeked_origin: Option<UdpReceiveOrigin>,
    pub(super) next_receive_origin: UdpReceiveOrigin,
    pub(super) native_endpoint: Option<UdpNativeEndpoint>,
    pub(super) external_peers: HashMap<SocketAddrV4, SocketAddrV4>,
}

impl Default for UdpSocketState {
    fn default() -> Self {
        Self {
            peer: None,
            guest_receive_queue: VecDeque::new(),
            guest_receive_bytes: 0,
            queued_by_source: HashMap::new(),
            peeked_origin: None,
            next_receive_origin: UdpReceiveOrigin::Guest,
            native_endpoint: None,
            external_peers: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum UdpNativeErrorState {
    #[default]
    None,
    PendingKernel,
    Consumed(SocketError),
}

impl UdpNativeErrorState {
    const fn is_pending(self) -> bool {
        !matches!(self, Self::None)
    }

    fn record_kernel(&mut self) {
        if matches!(self, Self::None) {
            *self = Self::PendingKernel;
        }
    }

    fn record_consumed(&mut self, error: SocketError) {
        match *self {
            Self::None | Self::PendingKernel => *self = Self::Consumed(error),
            Self::Consumed(_) => {}
        }
    }
}

struct GuestDatagram {
    payload: Vec<u8>,
    source_socket_generation: u64,
    source_guest_address: SocketAddrV4,
    source_session_id: SessionId,
}

pub(super) struct UdpNativeEndpoint {
    pub(super) socket: OwnedFd,
    socket_id: u64,
    event_token: u64,
    pub(super) host_address: SocketAddrV4,
    pub(super) readable: bool,
    write_blocked: bool,
    error: UdpNativeErrorState,
}

#[derive(Clone, Copy)]
pub(super) struct UdpEventTarget {
    socket_id: u64,
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
    External(UdpNativePeer),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UdpNativePeer {
    guest_visible_address: SocketAddrV4,
    host_address: SocketAddrV4,
}

impl ReactorUdpState {
    pub(super) fn reserve_binding(&mut self, binding: &GuestSocketBinding) -> BrokerResult<()> {
        let requested = binding.requested();
        if !binding.is_valid()
            || if binding.is_wildcard() {
                self.bindings.wildcard.contains_key(&requested.port())
                    || self
                        .bindings
                        .exact
                        .keys()
                        .any(|address| address.port() == requested.port())
            } else {
                self.bindings.wildcard.contains_key(&requested.port())
                    || self.bindings.exact.contains_key(&requested)
            }
        {
            return Err(BrokerError::Internal);
        }
        if binding.is_wildcard() {
            self.bindings
                .wildcard
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)
        } else {
            self.bindings
                .exact
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)
        }
    }

    pub(super) fn insert_binding(&mut self, binding: ReactorUdpBinding) -> BrokerResult<()> {
        let requested = binding.guest_binding.requested();
        self.reserve_binding(&binding.guest_binding)?;
        if binding.guest_binding.is_wildcard() {
            self.bindings.wildcard.insert(requested.port(), binding);
        } else {
            self.bindings.exact.insert(requested, binding);
        }
        Ok(())
    }

    pub(super) fn remove_binding(&mut self, guest_port: u16, socket_id: u64) {
        if self
            .bindings
            .wildcard
            .get(&guest_port)
            .is_some_and(|binding| binding.socket_id == socket_id)
        {
            self.bindings.wildcard.remove(&guest_port);
            return;
        }
        if let Some(address) = self.bindings.exact.iter().find_map(|(address, binding)| {
            (address.port() == guest_port && binding.socket_id == socket_id).then_some(*address)
        }) {
            self.bindings.exact.remove(&address);
        }
    }

    fn guest_binding(&self, address: SocketAddrV4) -> Option<ReactorUdpBinding> {
        self.bindings
            .exact
            .get(&address)
            .or_else(|| self.bindings.wildcard.get(&address.port()))
            .filter(|binding| binding.guest_binding.covers(address))
            .cloned()
    }

    pub(super) fn binding_for_socket(&self, socket_id: u64) -> Option<ReactorUdpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .cloned()
    }

    pub(super) fn is_private_host_port(&self, port: u16) -> bool {
        self.native_endpoints.contains(&port)
    }
}

impl Reactor {
    /// Revalidates and resolves a normalized guest-visible UDP destination.
    pub(super) fn resolve_udp_destination(
        &self,
        address: SocketAddrV4,
    ) -> SocketOutcome<ReactorUdpPeer> {
        let destination = match classify_socket_destination(address) {
            Ok(destination) => destination,
            Err(error) => return SocketOutcome::Failed(error),
        };
        match destination {
            SocketDestination::Guest(guest_address) => {
                let Some(binding) = self.udp.guest_binding(guest_address) else {
                    return SocketOutcome::Failed(SocketError::ConnectionRefused);
                };
                SocketOutcome::Completed(ReactorUdpPeer::Guest {
                    socket_generation: binding.socket_id,
                    guest_address,
                })
            }
            SocketDestination::Native {
                guest_visible_address,
                host_address,
            } => {
                if self.is_private_udp_host_endpoint(host_address) {
                    SocketOutcome::Failed(SocketError::ConnectionRefused)
                } else {
                    SocketOutcome::Completed(ReactorUdpPeer::External(UdpNativePeer {
                        guest_visible_address,
                        host_address,
                    }))
                }
            }
        }
    }

    pub(super) fn reserve_udp_external_peer(
        &mut self,
        socket_id: u64,
        peer: UdpNativePeer,
    ) -> BrokerResult<bool> {
        let session_id = {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let udp = socket.udp_state()?;
            if let Some(guest_visible_address) = udp.external_peers.get(&peer.host_address) {
                if *guest_visible_address != peer.guest_visible_address {
                    return Err(BrokerError::Internal);
                }
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
        if self.udp.external_peer_count
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
        if self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .external_peers
            .insert(peer.host_address, peer.guest_visible_address)
            .is_some()
        {
            return Err(BrokerError::Internal);
        }
        self.udp.external_peer_count = self
            .udp
            .external_peer_count
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

    pub(super) fn remove_udp_external_peer(&mut self, socket_id: u64, peer: UdpNativePeer) {
        let Some(socket) = self.sockets.get_mut(&socket_id) else {
            return;
        };
        let Ok(udp) = socket.udp_state_mut() else {
            return;
        };
        if udp.external_peers.get(&peer.host_address) != Some(&peer.guest_visible_address) {
            return;
        }
        udp.external_peers.remove(&peer.host_address);
        self.udp.external_peer_count = self
            .udp
            .external_peer_count
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
        self.udp.external_peer_count = self
            .udp
            .external_peer_count
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
        let cached_error = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .pending_error
            .is_some();
        let mut readiness = ReadinessFlags::default();
        let native_readable = udp
            .native_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.readable);
        if socket.read_shutdown || !udp.guest_receive_queue.is_empty() || native_readable {
            readiness = readiness | ReadinessFlags::READ;
        }
        let native_write_blocked = udp
            .native_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.write_blocked);
        if !socket.write_shutdown && !native_write_blocked {
            readiness = readiness | ReadinessFlags::WRITE;
        }
        let native_error = udp
            .native_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.error.is_pending());
        if native_error || cached_error {
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

    fn take_udp_error(&mut self, socket_id: u64) -> BrokerResult<Option<SocketError>> {
        let (state, was_readable) = {
            let endpoint = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?
                .native_endpoint
                .as_mut()
                .ok_or(BrokerError::Internal)?;
            let was_readable = endpoint.readable;
            endpoint.readable = false;
            (std::mem::take(&mut endpoint.error), was_readable)
        };
        match state {
            UdpNativeErrorState::None => Err(BrokerError::Internal),
            UdpNativeErrorState::Consumed(error) => Ok(Some(error)),
            UdpNativeErrorState::PendingKernel => {
                let endpoint = self
                    .sockets
                    .get(&socket_id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state()?
                    .native_endpoint
                    .as_ref()
                    .ok_or(BrokerError::Internal)?;
                let socket_error = take_udp_socket_error(&endpoint.socket);
                if socket_error.is_err() {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?;
                    endpoint.error = state;
                    endpoint.readable = was_readable;
                }
                socket_error
            }
        }
    }

    pub(super) fn status_udp_socket(
        &mut self,
        socket_id: u64,
    ) -> BrokerResult<PlatformSocketStatus> {
        let (status, local_address, cached_error) = {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let mut snapshot = socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            (
                socket.connection_status,
                snapshot.local_address,
                snapshot.pending_error.take(),
            )
        };
        let mut pending_error = cached_error;
        let native_error_pending = self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?
            .native_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.error.is_pending());
        let republish_error = cached_error.is_some() && native_error_pending;
        if pending_error.is_none() && native_error_pending {
            pending_error = self.take_udp_error(socket_id)?;
        }
        let readiness = self.udp_readiness(socket_id)?;
        let socket = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?;
        let _ = update_snapshot(socket, None, readiness);
        if republish_error {
            // Returning the cached error leaves another error pending without
            // changing readiness, so wake a waiter for the remaining error.
            let _ = socket.readiness.republish(readiness);
        }
        if let Err(error) = self.rearm_udp_endpoint_if_needed(socket_id) {
            if let Some(pending_error) = pending_error {
                let socket = self
                    .sockets
                    .get_mut(&socket_id)
                    .expect("UDP status socket disappeared after rearm failure");
                let readiness = {
                    let mut snapshot = socket
                        .snapshot
                        .lock()
                        .expect("Linux socket snapshot mutex poisoned");
                    snapshot.pending_error = Some(pending_error);
                    snapshot.readiness = snapshot.readiness | ReadinessFlags::ERROR;
                    snapshot.readiness
                };
                let _ = socket.readiness.publish(readiness);
            }
            return Err(error);
        }
        Ok(PlatformSocketStatus {
            status,
            local_address,
            pending_error,
        })
    }

    #[cfg(test)]
    pub(super) fn inject_udp_status_errors(
        &mut self,
        guest_port: u16,
        cached_error: SocketError,
        native_error: SocketError,
    ) -> BrokerResult<()> {
        let socket_id = self
            .udp
            .bindings
            .get(guest_port)
            .ok_or(BrokerError::Internal)?
            .socket_id;
        let socket = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?;
        {
            let mut snapshot = socket
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            snapshot.pending_error = Some(cached_error);
            snapshot.readiness = snapshot.readiness | ReadinessFlags::ERROR;
        }
        socket
            .udp_state_mut()?
            .native_endpoint
            .as_mut()
            .ok_or(BrokerError::Internal)?
            .error
            .record_consumed(native_error);
        Ok(())
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
            .udp
            .queued_by_source
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
                || self.udp.queued_datagrams >= global_datagrams
                || self.udp.queued_bytes.saturating_add(length) > global_bytes
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
        source_guest_address: SocketAddrV4,
        payload: &[u8],
    ) -> BrokerResult<SocketOutcome<usize>> {
        let source_session_id = {
            let source = self
                .sockets
                .get(&source_socket_id)
                .ok_or(BrokerError::Internal)?;
            source.udp_state()?;
            source.session_id
        };
        let destination_id = destination_generation;
        let accepts_source = {
            let Some(destination) = self.sockets.get(&destination_id) else {
                return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
            };
            if destination.kind() != SocketKind::Udp || destination.read_shutdown {
                return Ok(SocketOutcome::Completed(payload.len()));
            }
            let udp = destination.udp_state()?;
            match udp.peer {
                None => true,
                Some(ReactorUdpPeer::Guest {
                    socket_generation, ..
                }) => socket_generation == source_socket_id,
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
        if !self.udp.queued_by_source.contains_key(&source_session_id) {
            self.udp
                .queued_by_source
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
        let receiver_session_id = self
            .sockets
            .get(&destination_id)
            .ok_or(BrokerError::Internal)?
            .session_id;
        let receiver_session = self
            .sessions
            .get_mut(&receiver_session_id)
            .ok_or(BrokerError::Internal)?;
        {
            let destination = self
                .sockets
                .get_mut(&destination_id)
                .ok_or(BrokerError::Internal)?;
            let udp = destination.udp_state_mut()?;
            udp.guest_receive_bytes += datagram.payload.len();
            let source = udp.queued_by_source.entry(source_session_id).or_default();
            source.datagrams += 1;
            source.bytes += datagram.payload.len();
            udp.guest_receive_queue.push_back(datagram);
            self.udp.queued_datagrams += 1;
            self.udp.queued_bytes += payload.len();
            let source = self
                .udp
                .queued_by_source
                .entry(source_session_id)
                .or_default();
            source.datagrams += 1;
            source.bytes += payload.len();
            receiver_session.udp_queued_datagrams += 1;
            receiver_session.udp_queued_bytes += payload.len();
        }

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

        self.udp.queued_datagrams = self
            .udp
            .queued_datagrams
            .checked_sub(1)
            .expect("global UDP datagram count underflow");
        self.udp.queued_bytes = self
            .udp
            .queued_bytes
            .checked_sub(datagram.payload.len())
            .expect("global UDP byte count underflow");
        let remove_source = {
            let source = self
                .udp
                .queued_by_source
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
            self.udp
                .queued_by_source
                .remove(&datagram.source_session_id);
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

    fn next_udp_event_token(&mut self) -> BrokerResult<u64> {
        let token_id = self.udp.next_event_token;
        self.udp.next_event_token = token_id
            .checked_add(1)
            .filter(|token| *token < UDP_EVENT_TOKEN_FLAG)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(UDP_EVENT_TOKEN_FLAG | token_id)
    }

    fn udp_port_conflicts(
        &self,
        socket_id: u64,
        port: u16,
        current_destination: UdpNativePeer,
    ) -> BrokerResult<bool> {
        if !self.sockets.contains_key(&socket_id) {
            return Err(BrokerError::Internal);
        }
        Ok(
            udp_address_matches_host_port(current_destination.host_address, port)
                || self.udp.native_endpoints.contains(&port)
                || self.sockets.values().any(|socket| {
                    socket.udp_state().is_ok_and(|udp| {
                        udp.external_peers
                            .keys()
                            .any(|peer| udp_address_matches_host_port(*peer, port))
                            || matches!(
                                udp.peer,
                                Some(ReactorUdpPeer::External(peer))
                                    if udp_address_matches_host_port(peer.host_address, port)
                            )
                    })
                }),
        )
    }

    pub(super) fn stage_udp_endpoint(
        &mut self,
        socket_id: u64,
        current_destination: UdpNativePeer,
        connected_peer: Option<UdpNativePeer>,
    ) -> BrokerResult<SocketOutcome<UdpNativeEndpoint>> {
        let read_enabled = !self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .read_shutdown;
        self.udp
            .native_endpoints
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.udp
            .event_tokens
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
                    match connect(&socket, &peer.host_address) {
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
            let native_address = if connected_peer.is_some() {
                local_socket_address(&socket)?
            } else {
                host_address
            };
            let event_token = self.next_udp_event_token()?;
            if !self.udp.native_endpoints.insert(native_address.port()) {
                return Err(BrokerError::Internal);
            }
            if self
                .udp
                .event_tokens
                .insert(event_token, UdpEventTarget { socket_id })
                .is_some()
            {
                self.udp.native_endpoints.remove(&native_address.port());
                return Err(BrokerError::Internal);
            }
            if let Err(error) = epoll::add(
                &self.epoll,
                &socket,
                epoll::EventData::new_u64(event_token),
                udp_epoll_events(read_enabled, false),
            ) {
                self.udp.event_tokens.remove(&event_token);
                self.udp.native_endpoints.remove(&native_address.port());
                return Err(broker_error_from_errno(error));
            }
            return Ok(SocketOutcome::Completed(UdpNativeEndpoint {
                socket,
                socket_id,
                event_token,
                host_address: SocketAddrV4::new(GUEST_IPV4_ADDRESS, native_address.port()),
                readable: false,
                write_blocked: false,
                error: UdpNativeErrorState::None,
            }));
        }
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    }

    pub(super) fn unregister_udp_endpoint(&mut self, endpoint: UdpNativeEndpoint) {
        let _ = epoll::delete(&self.epoll, &endpoint.socket);
        self.udp.event_tokens.remove(&endpoint.event_token);
        self.udp
            .native_endpoints
            .remove(&endpoint.host_address.port());
    }

    pub(super) fn connect_existing_udp_endpoint(
        &mut self,
        socket_id: u64,
        peer: UdpNativePeer,
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
                .native_endpoint
                .as_ref()
                .ok_or(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ))?;
            loop {
                match connect(&endpoint.socket, &peer.host_address) {
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
                        .native_endpoint
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
                    let guest_local_address = {
                        let socket = self.sockets.get_mut(&socket_id).ok_or(
                            PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
                        )?;
                        let udp = socket
                            .udp_state_mut()
                            .map_err(PlatformConnectError::PeerIndeterminate)?;
                        if udp.peeked_origin == Some(UdpReceiveOrigin::Native) {
                            udp.peeked_origin = None;
                        }
                        let endpoint = udp.native_endpoint.as_mut().ok_or(
                            PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
                        )?;
                        endpoint.write_blocked = false;
                        endpoint.error = UdpNativeErrorState::None;
                        endpoint.readable = false;
                        let native_address = local_socket_address(&endpoint.socket)
                            .map_err(PlatformConnectError::PeerIndeterminate)?;
                        let guest_local_address =
                            SocketAddrV4::new(GUEST_IPV4_ADDRESS, native_address.port());
                        endpoint.host_address = guest_local_address;
                        guest_local_address
                    };
                    self.rearm_udp_endpoint(socket_id)
                        .map_err(PlatformConnectError::PeerIndeterminate)?;
                    return Ok(SocketOutcome::Completed(guest_local_address));
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
        mut endpoint: Option<UdpNativeEndpoint>,
    ) -> BrokerResult<()> {
        let endpoint_matches = endpoint
            .as_ref()
            .is_none_or(|endpoint| endpoint.socket_id == socket_id);
        let socket_is_udp = self
            .sockets
            .get(&socket_id)
            .is_some_and(|socket| socket.kind() == SocketKind::Udp);
        if !endpoint_matches || !socket_is_udp {
            if let Some(endpoint) = endpoint.take() {
                self.unregister_udp_endpoint(endpoint);
            }
            return Err(BrokerError::Internal);
        }
        debug_assert!(
            endpoint
                .as_ref()
                .is_none_or(|endpoint| endpoint.socket_id == socket_id)
        );
        let old = {
            let udp = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?;
            if udp.peeked_origin == Some(UdpReceiveOrigin::Native) {
                udp.peeked_origin = None;
            }
            std::mem::replace(&mut udp.native_endpoint, endpoint)
        };
        if let Some(old) = old {
            self.unregister_udp_endpoint(old);
        }
        Ok(())
    }

    pub(super) fn handle_udp_endpoint_event(
        &mut self,
        event_token: u64,
        events: epoll::EventFlags,
    ) -> BrokerResult<()> {
        let Some(target) = self.udp.event_tokens.get(&event_token).copied() else {
            return Ok(());
        };
        let readable_event = events.contains(epoll::EventFlags::IN);
        let error_event = events.intersects(epoll::EventFlags::ERR | epoll::EventFlags::HUP);
        let endpoint_valid = self
            .sockets
            .get(&target.socket_id)
            .and_then(|socket| socket.udp_state().ok())
            .and_then(|udp| udp.native_endpoint.as_ref())
            .is_some_and(|endpoint| endpoint.event_token == event_token);
        if !endpoint_valid {
            return Ok(());
        }
        {
            let Some(socket) = self.sockets.get_mut(&target.socket_id) else {
                return Ok(());
            };
            let udp = socket.udp_state_mut()?;
            let Some(endpoint) = udp.native_endpoint.as_mut() else {
                return Ok(());
            };
            if events.contains(epoll::EventFlags::OUT) {
                endpoint.write_blocked = false;
            }
            if error_event {
                endpoint.readable = true;
                endpoint.error.record_kernel();
            }
        }
        if readable_event && !error_event {
            self.drain_invalid_udp_ingress(target.socket_id)?;
        }
        self.rearm_udp_endpoint(target.socket_id)?;
        // The cached snapshot remains authoritative if this association cannot
        // accept a notification. One session's sink must not fail the shared
        // reactor and every other session using it.
        let _ = self.publish_udp_readiness(target.socket_id);
        Ok(())
    }

    fn rearm_udp_endpoint(&mut self, socket_id: u64) -> BrokerResult<()> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        let udp = socket.udp_state()?;
        let Some(endpoint) = udp.native_endpoint.as_ref() else {
            return Ok(());
        };
        if endpoint.error.is_pending() {
            return Ok(());
        }
        epoll::modify(
            &self.epoll,
            &endpoint.socket,
            epoll::EventData::new_u64(endpoint.event_token),
            udp_rearm_events(
                socket.read_shutdown,
                endpoint.readable,
                endpoint.write_blocked,
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
            udp.native_endpoint.as_ref().is_some_and(|endpoint| {
                udp_endpoint_needs_rearm(
                    endpoint.readable,
                    endpoint.write_blocked,
                    endpoint.error.is_pending(),
                )
            })
        };
        if should_rearm {
            self.rearm_udp_endpoint(socket_id)?;
        }
        Ok(())
    }

    fn udp_native_source_guest_address(
        &self,
        socket_id: u64,
        source_address: SocketAddrV4,
    ) -> BrokerResult<Option<SocketAddrV4>> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        if socket.read_shutdown {
            return Ok(None);
        }
        let udp = socket.udp_state()?;
        Ok(if self.is_private_udp_host_endpoint(source_address) {
            None
        } else {
            match udp.peer {
                Some(ReactorUdpPeer::External(peer)) if peer.host_address == source_address => {
                    Some(peer.guest_visible_address)
                }
                Some(ReactorUdpPeer::Guest { .. } | ReactorUdpPeer::External(_)) => None,
                None => udp.external_peers.get(&source_address).copied(),
            }
        })
    }

    fn record_udp_endpoint_error(
        &mut self,
        socket_id: u64,
        error: SocketError,
    ) -> BrokerResult<()> {
        let endpoint = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .native_endpoint
            .as_mut()
            .ok_or(BrokerError::Internal)?;
        endpoint.error.record_consumed(error);
        Ok(())
    }

    fn finish_udp_receive_error(
        &mut self,
        socket_id: u64,
        error: SocketError,
    ) -> BrokerResult<Option<ReactorReceiveFromOutcome>> {
        {
            let endpoint = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?
                .native_endpoint
                .as_mut()
                .ok_or(BrokerError::Internal)?;
            endpoint.readable = false;
            endpoint.error = UdpNativeErrorState::None;
        }
        if let Err(rearm_error) = self.rearm_udp_endpoint(socket_id) {
            self.record_udp_endpoint_error(socket_id, error)?;
            return Err(rearm_error);
        }
        let _ = self.publish_udp_readiness(socket_id);
        Ok(Some(ReactorReceiveFromOutcome::Failed(error)))
    }

    fn drain_invalid_udp_ingress(&mut self, socket_id: u64) -> BrokerResult<()> {
        if let Some(endpoint) = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .native_endpoint
            .as_mut()
        {
            endpoint.readable = false;
        }
        for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            let peek = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .native_endpoint
                    .as_ref()
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::PEEK)
            };
            let source_address = match peek {
                Ok(ReactorReceiveFromOutcome::Received { source_address, .. }) => source_address,
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    self.record_udp_endpoint_error(socket_id, error)?;
                    self.sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?
                        .readable = true;
                    return Ok(());
                }
                Err(BrokerError::WouldBlock) => {
                    if let Some(endpoint) = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint
                        .as_mut()
                    {
                        endpoint.readable = false;
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if self
                .udp_native_source_guest_address(socket_id, source_address)?
                .is_some()
            {
                self.sockets
                    .get_mut(&socket_id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state_mut()?
                    .native_endpoint
                    .as_mut()
                    .ok_or(BrokerError::Internal)?
                    .readable = true;
                return Ok(());
            }
            let consumed = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .native_endpoint
                    .as_ref()
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE)
            };
            match consumed {
                Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    self.record_udp_endpoint_error(socket_id, error)?;
                    self.sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?
                        .readable = true;
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
            .native_endpoint
            .as_mut()
            .ok_or(BrokerError::Internal)?
            .readable = false;
        Ok(())
    }

    pub(super) fn send_external_udp(
        &mut self,
        socket_id: u64,
        data: &[u8],
        peer: UdpNativePeer,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let destination = peer.host_address;
        let result = loop {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let endpoint = socket
                .udp_state()?
                .native_endpoint
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
                let endpoint = udp.native_endpoint.as_mut().ok_or(BrokerError::Internal)?;
                endpoint.write_blocked = true;
                if !endpoint.error.is_pending() {
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
            .native_endpoint
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
                    .native_endpoint
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
                    return self.finish_udp_receive_error(socket_id, error);
                }
                Err(BrokerError::WouldBlock) => {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?;
                    endpoint.readable = false;
                    self.rearm_udp_endpoint(socket_id)?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let guest_visible_source_address =
                self.udp_native_source_guest_address(socket_id, source_address)?;
            if let Some(source_address) = guest_visible_source_address {
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
                    let endpoint = udp.native_endpoint.as_mut().ok_or(BrokerError::Internal)?;
                    if endpoint.error.is_pending() {
                        false
                    } else {
                        endpoint.readable = false;
                        true
                    }
                };
                if should_rearm && let Err(error) = self.rearm_udp_endpoint(socket_id) {
                    self.sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?
                        .readable = true;
                    return Err(error);
                }
                let consumed = {
                    let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                    let endpoint = socket
                        .udp_state()?
                        .native_endpoint
                        .as_ref()
                        .ok_or(BrokerError::Internal)?;
                    receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE)
                };
                match consumed {
                    Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                    Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                        return self.finish_udp_receive_error(socket_id, error);
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
                            .native_endpoint
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
                .native_endpoint
                .as_ref()
                .ok_or(BrokerError::Internal)?;
            match receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE) {
                Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    return self.finish_udp_receive_error(socket_id, error);
                }
                Err(BrokerError::WouldBlock) => {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint
                        .as_mut()
                        .ok_or(BrokerError::Internal)?;
                    endpoint.readable = false;
                    self.rearm_udp_endpoint(socket_id)?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        self.sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .native_endpoint
            .as_mut()
            .ok_or(BrokerError::Internal)?
            .readable = false;
        self.rearm_udp_endpoint(socket_id)?;
        Ok(None)
    }

    #[cfg(test)]
    pub(super) fn udp_native_head_datagram_bytes(&self, socket_id: u64) -> BrokerResult<usize> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        let endpoint = socket
            .udp_state()?
            .native_endpoint
            .as_ref()
            .ok_or(BrokerError::Internal)?;
        usize::try_from(ioctl_fionread(&endpoint.socket).map_err(broker_error_from_errno)?)
            .map_err(|_| BrokerError::Internal)
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

fn take_udp_socket_error(socket: &OwnedFd) -> BrokerResult<Option<SocketError>> {
    match sockopt::socket_error(socket) {
        Ok(Ok(())) => Ok(None),
        Ok(Err(error)) | Err(error) => socket_operation_error_from_errno(error).map(Some),
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
    fn consumed_udp_native_error_preserves_the_exact_error() {
        let mut state = UdpNativeErrorState::PendingKernel;
        state.record_consumed(SocketError::ConnectionRefused);
        assert_eq!(
            std::mem::take(&mut state),
            UdpNativeErrorState::Consumed(SocketError::ConnectionRefused)
        );
        assert_eq!(state, UdpNativeErrorState::None);
    }

    #[test]
    fn udp_native_error_coalescing_preserves_the_oldest_observation() {
        let mut state = UdpNativeErrorState::Consumed(SocketError::ConnectionRefused);
        state.record_consumed(SocketError::Other);
        assert_eq!(
            state,
            UdpNativeErrorState::Consumed(SocketError::ConnectionRefused)
        );
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
