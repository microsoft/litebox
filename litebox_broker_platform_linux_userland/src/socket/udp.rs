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

use litebox_broker_core::socket::{GuestSocketBinding, PlatformConnectError, SocketDestination};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, SocketError, SocketOutcome, SocketStatusResponse,
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
    PRIVATE_BACKEND_ADDRESS, Reactor, ReactorReceiveFromOutcome, SocketKind, WAKE_TOKEN,
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
    pub(super) native_endpoints: HashMap<u16, UdpNativeEndpointIdentity>,
    pub(super) external_peer_count: usize,
    pub(super) queued_datagrams: usize,
    pub(super) queued_bytes: usize,
    pub(super) queued_by_source: HashMap<SessionId, UdpQueueAccounting>,
    pub(super) event_tokens: HashMap<u64, UdpEventTarget>,
    pub(super) next_event_token: u64,
    pub(super) next_endpoint_generation: u64,
    next_error_sequence: u64,
}

impl Default for ReactorUdpState {
    fn default() -> Self {
        Self {
            bindings: ReactorUdpBindings::default(),
            native_endpoints: HashMap::new(),
            external_peer_count: 0,
            queued_datagrams: 0,
            queued_bytes: 0,
            queued_by_source: HashMap::new(),
            event_tokens: HashMap::new(),
            next_event_token: 1,
            next_endpoint_generation: 1,
            next_error_sequence: 1,
        }
    }
}

impl ReactorUdpState {
    /// Clears live registrations and accounting without reusing endpoint IDs.
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

#[derive(Clone)]
pub(super) struct ReactorUdpBinding {
    pub(super) socket_id: u64,
    pub(super) binding: GuestSocketBinding,
}

pub(super) struct UdpSocketState {
    pub(super) internal_address: Option<SocketAddrV4>,
    pub(super) peer: Option<ReactorUdpPeer>,
    guest_receive_queue: VecDeque<GuestDatagram>,
    guest_receive_bytes: usize,
    queued_by_source: HashMap<SessionId, UdpQueueAccounting>,
    pub(super) peeked_origin: Option<UdpReceiveOrigin>,
    pub(super) next_receive_origin: UdpReceiveOrigin,
    pub(super) external_endpoint: Option<ExternalUdpEndpoint>,
    pub(super) gateway_endpoint: Option<ExternalUdpEndpoint>,
    pub(super) override_endpoint: Option<UdpOverrideEndpoint>,
    pub(super) external_peers: HashSet<SocketDestination>,
    pub(super) override_error: UdpNativeErrorState,
}

impl Default for UdpSocketState {
    fn default() -> Self {
        Self {
            internal_address: None,
            peer: None,
            guest_receive_queue: VecDeque::new(),
            guest_receive_bytes: 0,
            queued_by_source: HashMap::new(),
            peeked_origin: None,
            next_receive_origin: UdpReceiveOrigin::Guest,
            external_endpoint: None,
            gateway_endpoint: None,
            override_endpoint: None,
            external_peers: HashSet::new(),
            override_error: UdpNativeErrorState::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum UdpNativeErrorState {
    #[default]
    None,
    PendingKernel {
        sequence: u64,
    },
    Consumed {
        sequence: u64,
        error: SocketError,
    },
}

impl UdpNativeErrorState {
    const fn is_pending(self) -> bool {
        !matches!(self, Self::None)
    }

    const fn sequence(self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::PendingKernel { sequence } | Self::Consumed { sequence, .. } => Some(sequence),
        }
    }

    fn record_kernel(&mut self, sequence: u64) {
        if matches!(self, Self::None) {
            *self = Self::PendingKernel { sequence };
        }
    }

    fn record_consumed(&mut self, sequence: u64, error: SocketError) {
        match *self {
            Self::None => *self = Self::Consumed { sequence, error },
            Self::PendingKernel {
                sequence: pending_sequence,
            } => {
                *self = Self::Consumed {
                    sequence: pending_sequence,
                    error,
                };
            }
            Self::Consumed { .. } => {}
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
    route: UdpNativeRoute,
    generation: u64,
    event_token: u64,
    pub(super) host_address: SocketAddrV4,
    pub(super) readable: bool,
    write_blocked: bool,
    error: UdpNativeErrorState,
}

pub(super) struct UdpOverrideEndpoint {
    endpoint: ExternalUdpEndpoint,
    route: SocketDestination,
    host_address: SocketAddrV4,
}

#[derive(Clone, Copy)]
pub(super) struct UdpNativeEndpointIdentity {
    endpoint_generation: u64,
}

#[derive(Clone, Copy)]
pub(super) struct UdpEventTarget {
    socket_id: u64,
    endpoint_generation: u64,
    slot: UdpEndpointSlot,
}

#[derive(Clone, Copy, Default)]
pub(super) struct UdpQueueAccounting {
    datagrams: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UdpReceiveOrigin {
    Guest,
    Gateway,
    External,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UdpNativeRoute {
    External,
    Gateway,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UdpEndpointSlot {
    Active(UdpNativeRoute),
    Override,
}

#[derive(Clone, Copy)]
enum UdpErrorSource {
    Endpoint(UdpEndpointSlot),
    Override,
}

impl UdpNativeRoute {
    pub(super) fn from_destination(destination: SocketDestination) -> Option<Self> {
        match destination {
            SocketDestination::Guest { .. } => None,
            SocketDestination::Gateway { .. } => Some(Self::Gateway),
            SocketDestination::External { .. } => Some(Self::External),
        }
    }

    const fn receive_origin(self) -> UdpReceiveOrigin {
        match self {
            Self::External => UdpReceiveOrigin::External,
            Self::Gateway => UdpReceiveOrigin::Gateway,
        }
    }
}

impl UdpSocketState {
    pub(super) fn native_endpoint(&self, route: UdpNativeRoute) -> Option<&ExternalUdpEndpoint> {
        match route {
            UdpNativeRoute::External => self.external_endpoint.as_ref(),
            UdpNativeRoute::Gateway => self.gateway_endpoint.as_ref(),
        }
    }

    pub(super) fn native_endpoint_mut(
        &mut self,
        route: UdpNativeRoute,
    ) -> Option<&mut ExternalUdpEndpoint> {
        match route {
            UdpNativeRoute::External => self.external_endpoint.as_mut(),
            UdpNativeRoute::Gateway => self.gateway_endpoint.as_mut(),
        }
    }

    fn endpoint(&self, slot: UdpEndpointSlot) -> Option<&ExternalUdpEndpoint> {
        match slot {
            UdpEndpointSlot::Active(route) => self.native_endpoint(route),
            UdpEndpointSlot::Override => self
                .override_endpoint
                .as_ref()
                .map(|override_endpoint| &override_endpoint.endpoint),
        }
    }

    fn endpoint_mut(&mut self, slot: UdpEndpointSlot) -> Option<&mut ExternalUdpEndpoint> {
        match slot {
            UdpEndpointSlot::Active(route) => self.native_endpoint_mut(route),
            UdpEndpointSlot::Override => self
                .override_endpoint
                .as_mut()
                .map(|override_endpoint| &mut override_endpoint.endpoint),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReactorUdpPeer {
    Guest {
        socket_generation: u64,
        guest_address: SocketAddrV4,
    },
    Native {
        route: SocketDestination,
        host_address: SocketAddrV4,
    },
}

impl ReactorUdpState {
    pub(super) fn reserve_binding(&mut self, binding: &GuestSocketBinding) -> BrokerResult<()> {
        let requested = binding.requested();
        if requested.port() == 0
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
        let requested = binding.binding.requested();
        self.reserve_binding(&binding.binding)?;
        if binding.binding.is_wildcard() {
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
            .cloned()
    }

    pub(super) fn binding_for_socket(&self, socket_id: u64) -> Option<ReactorUdpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .cloned()
    }
}

impl Reactor {
    fn udp_endpoint_covers_host_address(
        endpoint: &ExternalUdpEndpoint,
        address: SocketAddrV4,
    ) -> bool {
        endpoint.host_address.port() == address.port()
            && match endpoint.route {
                UdpNativeRoute::External => is_local_ipv4_address(*address.ip()),
                UdpNativeRoute::Gateway => *address.ip() == PRIVATE_BACKEND_ADDRESS,
            }
    }

    fn own_udp_endpoint_covers(&self, socket_id: u64, address: SocketAddrV4) -> BrokerResult<bool> {
        let udp = self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?;
        Ok([
            udp.external_endpoint.as_ref(),
            udp.gateway_endpoint.as_ref(),
            udp.override_endpoint
                .as_ref()
                .map(|override_endpoint| &override_endpoint.endpoint),
        ]
        .into_iter()
        .flatten()
        .any(|endpoint| Self::udp_endpoint_covers_host_address(endpoint, address)))
    }

    /// Resolves one core-classified UDP destination.
    pub(super) fn resolve_udp_destination(
        &self,
        socket_id: u64,
        destination: SocketDestination,
    ) -> BrokerResult<SocketOutcome<ReactorUdpPeer>> {
        Ok(match destination {
            SocketDestination::Guest { requested } => {
                let Some(binding) = self.udp.guest_binding(requested) else {
                    return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
                };
                SocketOutcome::Completed(ReactorUdpPeer::Guest {
                    socket_generation: binding.socket_id,
                    guest_address: requested,
                })
            }
            SocketDestination::Gateway { requested } => {
                let host_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, requested.port());
                if self.own_udp_endpoint_covers(socket_id, host_address)? {
                    SocketOutcome::Failed(SocketError::ConnectionRefused)
                } else {
                    SocketOutcome::Completed(ReactorUdpPeer::Native {
                        route: destination,
                        host_address,
                    })
                }
            }
            SocketDestination::External { requested } => {
                if self.own_udp_endpoint_covers(socket_id, requested)? {
                    SocketOutcome::Failed(SocketError::ConnectionRefused)
                } else {
                    SocketOutcome::Completed(ReactorUdpPeer::Native {
                        route: destination,
                        host_address: requested,
                    })
                }
            }
        })
    }

    pub(super) fn reserve_udp_external_peer(
        &mut self,
        socket_id: u64,
        route: SocketDestination,
    ) -> BrokerResult<bool> {
        let session_id = {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let udp = socket.udp_state()?;
            if udp.external_peers.contains(&route) {
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
        if !self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .external_peers
            .insert(route)
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

    pub(super) fn remove_udp_external_peer(&mut self, socket_id: u64, route: SocketDestination) {
        let Some(socket) = self.sockets.get_mut(&socket_id) else {
            return;
        };
        let Ok(udp) = socket.udp_state_mut() else {
            return;
        };
        if !udp.external_peers.remove(&route) {
            return;
        }
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

    fn clear_udp_external_peers_for_route(
        &mut self,
        socket_id: u64,
        route: UdpNativeRoute,
    ) -> BrokerResult<()> {
        loop {
            let peer = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                socket
                    .udp_state()?
                    .external_peers
                    .iter()
                    .copied()
                    .find(|peer| UdpNativeRoute::from_destination(*peer) == Some(route))
            };
            let Some(peer) = peer else {
                break;
            };
            self.remove_udp_external_peer(socket_id, peer);
        }
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
        let native_readable = match udp.peer {
            Some(ReactorUdpPeer::Guest { .. }) => false,
            Some(ReactorUdpPeer::Native { route, .. }) => UdpNativeRoute::from_destination(route)
                .and_then(|route| udp.native_endpoint(route))
                .is_some_and(|endpoint| endpoint.readable),
            None => {
                udp.external_endpoint
                    .as_ref()
                    .is_some_and(|endpoint| endpoint.readable)
                    || udp
                        .gateway_endpoint
                        .as_ref()
                        .is_some_and(|endpoint| endpoint.readable)
            }
        };
        if socket.read_shutdown || !udp.guest_receive_queue.is_empty() || native_readable {
            readiness = readiness | ReadinessFlags::READ;
        }
        let native_write_blocked = [
            udp.external_endpoint.as_ref(),
            udp.gateway_endpoint.as_ref(),
            udp.override_endpoint
                .as_ref()
                .map(|override_endpoint| &override_endpoint.endpoint),
        ]
        .into_iter()
        .flatten()
        .any(|endpoint| endpoint.write_blocked);
        if !socket.write_shutdown && !native_write_blocked {
            readiness = readiness | ReadinessFlags::WRITE;
        }
        let native_error = [
            udp.external_endpoint.as_ref(),
            udp.gateway_endpoint.as_ref(),
            udp.override_endpoint
                .as_ref()
                .map(|override_endpoint| &override_endpoint.endpoint),
        ]
        .into_iter()
        .flatten()
        .any(|endpoint| endpoint.error.is_pending())
            || udp.override_error.is_pending();
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

    fn oldest_udp_error_source(&self, socket_id: u64) -> BrokerResult<Option<UdpErrorSource>> {
        let udp = self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?;
        let mut oldest = None;
        for (source, error) in [
            (
                UdpErrorSource::Endpoint(UdpEndpointSlot::Active(UdpNativeRoute::External)),
                udp.external_endpoint
                    .as_ref()
                    .map_or(UdpNativeErrorState::None, |endpoint| endpoint.error),
            ),
            (
                UdpErrorSource::Endpoint(UdpEndpointSlot::Active(UdpNativeRoute::Gateway)),
                udp.gateway_endpoint
                    .as_ref()
                    .map_or(UdpNativeErrorState::None, |endpoint| endpoint.error),
            ),
            (
                UdpErrorSource::Endpoint(UdpEndpointSlot::Override),
                udp.override_endpoint
                    .as_ref()
                    .map_or(UdpNativeErrorState::None, |endpoint| {
                        endpoint.endpoint.error
                    }),
            ),
            (UdpErrorSource::Override, udp.override_error),
        ] {
            let Some(sequence) = error.sequence() else {
                continue;
            };
            if oldest.is_none_or(|(_, oldest_sequence)| sequence < oldest_sequence) {
                oldest = Some((source, sequence));
            }
        }
        Ok(oldest.map(|(source, _)| source))
    }

    fn take_udp_error(
        &mut self,
        socket_id: u64,
        source: UdpErrorSource,
    ) -> BrokerResult<Option<SocketError>> {
        match source {
            UdpErrorSource::Override => {
                let state = std::mem::take(
                    &mut self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .override_error,
                );
                match state {
                    UdpNativeErrorState::Consumed { error, .. } => Ok(Some(error)),
                    UdpNativeErrorState::None | UdpNativeErrorState::PendingKernel { .. } => {
                        Err(BrokerError::Internal)
                    }
                }
            }
            UdpErrorSource::Endpoint(slot) => {
                let state = {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .endpoint_mut(slot)
                        .ok_or(BrokerError::Internal)?;
                    std::mem::take(&mut endpoint.error)
                };
                match state {
                    UdpNativeErrorState::None => Err(BrokerError::Internal),
                    UdpNativeErrorState::Consumed { error, .. } => Ok(Some(error)),
                    UdpNativeErrorState::PendingKernel { .. } => {
                        let endpoint = self
                            .sockets
                            .get(&socket_id)
                            .ok_or(BrokerError::Internal)?
                            .udp_state()?
                            .endpoint(slot)
                            .ok_or(BrokerError::Internal)?;
                        take_udp_socket_error(&endpoint.socket)
                    }
                }
            }
        }
    }

    pub(super) fn status_udp_socket(
        &mut self,
        socket_id: u64,
    ) -> BrokerResult<SocketStatusResponse> {
        let cached_error = self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .pending_error
            .take();
        let mut pending_error = cached_error;
        while pending_error.is_none() {
            let Some(source) = self.oldest_udp_error_source(socket_id)? else {
                break;
            };
            pending_error = self.take_udp_error(socket_id, source)?;
        }
        let (status, local_address) = {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            (socket.connection_status, socket.guest_local_address)
        };
        let readiness = self.udp_readiness(socket_id)?;
        let socket = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?;
        let _ = update_snapshot(socket, None, readiness);
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
        Ok(SocketStatusResponse {
            status,
            local_address,
            pending_error,
        })
    }

    pub(super) fn clear_udp_errors(&mut self, socket_id: u64) -> BrokerResult<()> {
        {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let udp = socket.udp_state()?;
            for endpoint in [
                udp.external_endpoint.as_ref(),
                udp.gateway_endpoint.as_ref(),
                udp.override_endpoint
                    .as_ref()
                    .map(|override_endpoint| &override_endpoint.endpoint),
            ]
            .into_iter()
            .flatten()
            {
                let _ = take_udp_socket_error(&endpoint.socket)?;
            }
        }
        let socket = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?;
        let udp = socket.udp_state_mut()?;
        if let Some(endpoint) = udp.external_endpoint.as_mut() {
            endpoint.error = UdpNativeErrorState::None;
        }
        if let Some(endpoint) = udp.gateway_endpoint.as_mut() {
            endpoint.error = UdpNativeErrorState::None;
        }
        if let Some(endpoint) = udp.override_endpoint.as_mut() {
            endpoint.endpoint.error = UdpNativeErrorState::None;
        }
        udp.override_error = UdpNativeErrorState::None;
        socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .pending_error = None;
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
        source_guest_address: SocketAddrV4,
        destination_generation: u64,
        payload: &[u8],
    ) -> BrokerResult<SocketOutcome<usize>> {
        let source_session_id = {
            let source = self
                .sockets
                .get(&source_socket_id)
                .ok_or(BrokerError::Internal)?;
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
                    socket_generation,
                    guest_address,
                }) => {
                    socket_generation == source_socket_id && guest_address == source_guest_address
                }
                Some(ReactorUdpPeer::Native { .. }) => false,
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

    fn next_udp_endpoint_ids(&mut self) -> BrokerResult<(u64, u64)> {
        let generation = self.udp.next_endpoint_generation;
        self.udp.next_endpoint_generation = generation
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        let token_id = self.udp.next_event_token;
        self.udp.next_event_token = token_id
            .checked_add(1)
            .filter(|token| *token < UDP_EVENT_TOKEN_FLAG)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok((generation, UDP_EVENT_TOKEN_FLAG | token_id))
    }

    fn next_udp_error_sequence(&mut self) -> BrokerResult<u64> {
        let sequence = self.udp.next_error_sequence;
        self.udp.next_error_sequence = sequence
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(sequence)
    }

    fn udp_destination_host_address(destination: SocketDestination) -> SocketAddrV4 {
        match destination {
            SocketDestination::Guest { requested } | SocketDestination::External { requested } => {
                requested
            }
            SocketDestination::Gateway { requested } => {
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, requested.port())
            }
        }
    }

    fn udp_candidate_covers_peer(
        route: UdpNativeRoute,
        candidate: SocketAddrV4,
        peer: SocketAddrV4,
    ) -> bool {
        candidate.port() == peer.port()
            && match route {
                UdpNativeRoute::External => is_local_ipv4_address(*peer.ip()),
                UdpNativeRoute::Gateway => *peer.ip() == PRIVATE_BACKEND_ADDRESS,
            }
    }

    fn udp_port_conflicts(
        &self,
        socket_id: u64,
        route: UdpNativeRoute,
        candidate: SocketAddrV4,
        connected_peer: Option<SocketAddrV4>,
    ) -> BrokerResult<bool> {
        if !self.sockets.contains_key(&socket_id) {
            return Err(BrokerError::Internal);
        }
        if self.udp.native_endpoints.contains_key(&candidate.port())
            || connected_peer
                .is_some_and(|peer| Self::udp_candidate_covers_peer(route, candidate, peer))
        {
            return Ok(true);
        }
        for socket in self.sockets.values() {
            let Ok(udp) = socket.udp_state() else {
                continue;
            };
            if udp.external_peers.iter().copied().any(|peer| {
                Self::udp_candidate_covers_peer(
                    route,
                    candidate,
                    Self::udp_destination_host_address(peer),
                )
            }) {
                return Ok(true);
            }
            if let Some(ReactorUdpPeer::Native { host_address, .. }) = udp.peer
                && Self::udp_candidate_covers_peer(route, candidate, host_address)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn stage_udp_endpoint(
        &mut self,
        socket_id: u64,
        route: UdpNativeRoute,
        event_slot: UdpEndpointSlot,
        connected_peer: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<ExternalUdpEndpoint>> {
        if matches!(event_slot, UdpEndpointSlot::Active(active_route) if active_route != route) {
            return Err(BrokerError::Internal);
        }
        let owned_endpoint_count = {
            let udp = self
                .sockets
                .get(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state()?;
            usize::from(udp.external_endpoint.is_some())
                + usize::from(udp.gateway_endpoint.is_some())
                + usize::from(udp.override_endpoint.is_some())
        };
        if owned_endpoint_count >= 2
            || self.udp.native_endpoints.len() >= self.max_sockets.saturating_mul(2)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let read_enabled = event_slot != UdpEndpointSlot::Override
            && !self
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
            let wildcard = SocketAddrV4::new(
                match route {
                    UdpNativeRoute::External => Ipv4Addr::UNSPECIFIED,
                    UdpNativeRoute::Gateway => PRIVATE_BACKEND_ADDRESS,
                },
                0,
            );
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
            if self.udp_port_conflicts(socket_id, route, host_address, connected_peer)? {
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
                .udp
                .event_tokens
                .insert(
                    event_token,
                    UdpEventTarget {
                        socket_id,
                        endpoint_generation: generation,
                        slot: event_slot,
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
                self.udp.event_tokens.remove(&event_token);
                self.udp.native_endpoints.remove(&host_address.port());
                return Err(broker_error_from_errno(error));
            }
            return Ok(SocketOutcome::Completed(ExternalUdpEndpoint {
                socket,
                route,
                generation,
                event_token,
                host_address,
                readable: false,
                write_blocked: false,
                error: UdpNativeErrorState::None,
            }));
        }
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    }

    pub(super) fn unregister_udp_endpoint(&mut self, endpoint: ExternalUdpEndpoint) {
        let _ = epoll::delete(&self.epoll, &endpoint.socket);
        self.udp.event_tokens.remove(&endpoint.event_token);
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
        route: UdpNativeRoute,
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
                .native_endpoint(route)
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
                        .native_endpoint(route)
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
                        if udp.peeked_origin == Some(route.receive_origin()) {
                            udp.peeked_origin = None;
                        }
                        let endpoint = udp.native_endpoint_mut(route).ok_or(
                            PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
                        )?;
                        endpoint.write_blocked = false;
                        endpoint.error = UdpNativeErrorState::None;
                        endpoint.readable = false;
                        let host_address = local_socket_address(&endpoint.socket)
                            .map_err(PlatformConnectError::PeerIndeterminate)?;
                        endpoint.host_address = host_address;
                        host_address
                    };
                    self.rearm_udp_endpoint(socket_id, UdpEndpointSlot::Active(route))
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
        route: UdpNativeRoute,
        endpoint: Option<ExternalUdpEndpoint>,
    ) -> BrokerResult<()> {
        let old = {
            let udp = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?;
            if udp.peeked_origin == Some(route.receive_origin()) {
                udp.peeked_origin = None;
            }
            match route {
                UdpNativeRoute::External => std::mem::replace(&mut udp.external_endpoint, endpoint),
                UdpNativeRoute::Gateway => std::mem::replace(&mut udp.gateway_endpoint, endpoint),
            }
        };
        if let Some(old) = old {
            self.clear_udp_external_peers_for_route(socket_id, route)?;
            self.unregister_udp_endpoint(old);
        }
        Ok(())
    }

    pub(super) fn replace_all_udp_endpoints(
        &mut self,
        socket_id: u64,
        replacement: Option<ExternalUdpEndpoint>,
    ) -> BrokerResult<()> {
        if let Some(endpoint) = replacement {
            let route = endpoint.route;
            let other = match route {
                UdpNativeRoute::External => UdpNativeRoute::Gateway,
                UdpNativeRoute::Gateway => UdpNativeRoute::External,
            };
            self.replace_udp_endpoint(socket_id, other, None)?;
            self.replace_udp_endpoint(socket_id, route, Some(endpoint))?;
        } else {
            self.replace_udp_endpoint(socket_id, UdpNativeRoute::External, None)?;
            self.replace_udp_endpoint(socket_id, UdpNativeRoute::Gateway, None)?;
        }
        Ok(())
    }

    pub(super) fn replace_udp_override_endpoint(
        &mut self,
        socket_id: u64,
        replacement: Option<UdpOverrideEndpoint>,
    ) -> BrokerResult<()> {
        let old = {
            let udp = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?;
            std::mem::replace(&mut udp.override_endpoint, replacement)
        };
        if let Some(old) = old {
            self.unregister_udp_endpoint(old.endpoint);
            let _ = self.publish_udp_readiness(socket_id);
        }
        Ok(())
    }

    pub(super) fn prepare_udp_override_endpoint(
        &mut self,
        socket_id: u64,
        route: SocketDestination,
        host_address: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<()>> {
        let native_route = UdpNativeRoute::from_destination(route).ok_or(BrokerError::Internal)?;
        if self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?
            .override_endpoint
            .as_ref()
            .is_some_and(|endpoint| {
                endpoint.route == route && endpoint.host_address == host_address
            })
        {
            return Ok(SocketOutcome::Completed(()));
        }
        self.replace_udp_override_endpoint(socket_id, None)?;
        let endpoint = match self.stage_udp_endpoint(
            socket_id,
            native_route,
            UdpEndpointSlot::Override,
            None,
        )? {
            SocketOutcome::Completed(endpoint) => endpoint,
            SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
        };
        self.sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .override_endpoint = Some(UdpOverrideEndpoint {
            endpoint,
            route,
            host_address,
        });
        Ok(SocketOutcome::Completed(()))
    }

    #[cfg(test)]
    pub(super) fn install_blocked_udp_override(
        &mut self,
        socket_id: u64,
        route: SocketDestination,
        host_address: SocketAddrV4,
    ) -> BrokerResult<()> {
        match self.prepare_udp_override_endpoint(socket_id, route, host_address)? {
            SocketOutcome::Completed(()) => {}
            SocketOutcome::Failed(_) => return Err(BrokerError::Internal),
        }
        self.sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .override_endpoint
            .as_mut()
            .ok_or(BrokerError::Internal)?
            .endpoint
            .write_blocked = true;
        self.publish_udp_readiness(socket_id)
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
            .and_then(|udp| udp.endpoint(target.slot))
            .is_some_and(|endpoint| endpoint.generation == target.endpoint_generation);
        if !endpoint_valid {
            return Ok(());
        }
        if error_event && target.slot == UdpEndpointSlot::Override {
            let error = {
                let endpoint = self
                    .sockets
                    .get(&target.socket_id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state()?
                    .endpoint(target.slot)
                    .ok_or(BrokerError::Internal)?;
                take_udp_socket_error(&endpoint.socket)?.unwrap_or(SocketError::Other)
            };
            let sequence = self.next_udp_error_sequence()?;
            self.sockets
                .get_mut(&target.socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?
                .override_error
                .record_consumed(sequence, error);
            self.replace_udp_override_endpoint(target.socket_id, None)?;
            let _ = self.publish_udp_readiness(target.socket_id);
            return Ok(());
        }
        let error_sequence = error_event
            .then(|| self.next_udp_error_sequence())
            .transpose()?;
        {
            let Some(socket) = self.sockets.get_mut(&target.socket_id) else {
                return Ok(());
            };
            let udp = socket.udp_state_mut()?;
            let Some(endpoint) = udp.endpoint_mut(target.slot) else {
                return Ok(());
            };
            if events.contains(epoll::EventFlags::OUT) {
                endpoint.write_blocked = false;
            }
            if let Some(sequence) = error_sequence {
                endpoint.error.record_kernel(sequence);
            }
        }
        if readable_event
            && !error_event
            && let UdpEndpointSlot::Active(route) = target.slot
        {
            self.drain_invalid_udp_ingress(target.socket_id, route)?;
        }
        self.rearm_udp_endpoint(target.socket_id, target.slot)?;
        // The cached snapshot remains authoritative if this association cannot
        // accept a notification. One session's sink must not fail the shared
        // reactor and every other session using it.
        let _ = self.publish_udp_readiness(target.socket_id);
        Ok(())
    }

    fn rearm_udp_endpoint(&mut self, socket_id: u64, slot: UdpEndpointSlot) -> BrokerResult<()> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        let udp = socket.udp_state()?;
        let Some(endpoint) = udp.endpoint(slot) else {
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
                socket.read_shutdown || slot == UdpEndpointSlot::Override,
                endpoint.readable,
                endpoint.write_blocked,
            ),
        )
        .map_err(broker_error_from_errno)
    }

    pub(super) fn rearm_udp_endpoint_if_needed(&mut self, socket_id: u64) -> BrokerResult<()> {
        for slot in [
            UdpEndpointSlot::Active(UdpNativeRoute::External),
            UdpEndpointSlot::Active(UdpNativeRoute::Gateway),
            UdpEndpointSlot::Override,
        ] {
            let should_rearm = {
                let udp = self
                    .sockets
                    .get(&socket_id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state()?;
                udp.endpoint(slot).is_some_and(|endpoint| {
                    udp_endpoint_needs_rearm(
                        endpoint.readable,
                        endpoint.write_blocked,
                        endpoint.error.is_pending(),
                    )
                })
            };
            if should_rearm {
                self.rearm_udp_endpoint(socket_id, slot)?;
            }
        }
        Ok(())
    }

    fn udp_native_source_authorized(
        &self,
        socket_id: u64,
        route: UdpNativeRoute,
        source_address: SocketAddrV4,
    ) -> BrokerResult<Option<SocketDestination>> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        if socket.read_shutdown {
            return Ok(None);
        }
        let source = match route {
            UdpNativeRoute::External => SocketDestination::External {
                requested: source_address,
            },
            UdpNativeRoute::Gateway => {
                if *source_address.ip() != Ipv4Addr::LOCALHOST {
                    return Ok(None);
                }
                SocketDestination::Gateway {
                    requested: SocketAddrV4::new(
                        self.network_config.gateway_ipv4_address(),
                        source_address.port(),
                    ),
                }
            }
        };
        if !source.is_valid_for(&self.network_config) {
            return Ok(None);
        }
        let udp = socket.udp_state()?;
        let authorized = match udp.peer {
            Some(ReactorUdpPeer::Guest { .. }) => false,
            Some(ReactorUdpPeer::Native {
                route: peer_route, ..
            }) => peer_route == source,
            None => udp.external_peers.contains(&source),
        };
        Ok(authorized.then_some(source))
    }

    pub(super) fn record_udp_endpoint_error(
        &mut self,
        socket_id: u64,
        slot: UdpEndpointSlot,
        error: SocketError,
    ) -> BrokerResult<()> {
        let sequence = self.next_udp_error_sequence()?;
        let endpoint = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .endpoint_mut(slot)
            .ok_or(BrokerError::Internal)?;
        endpoint.readable = false;
        endpoint.error.record_consumed(sequence, error);
        Ok(())
    }

    fn finish_udp_receive_error(
        &mut self,
        socket_id: u64,
        route: UdpNativeRoute,
        error: SocketError,
    ) -> BrokerResult<Option<ReactorReceiveFromOutcome>> {
        let slot = UdpEndpointSlot::Active(route);
        {
            let endpoint = self
                .sockets
                .get_mut(&socket_id)
                .ok_or(BrokerError::Internal)?
                .udp_state_mut()?
                .native_endpoint_mut(route)
                .ok_or(BrokerError::Internal)?;
            endpoint.readable = false;
            endpoint.error = UdpNativeErrorState::None;
        }
        if let Err(rearm_error) = self.rearm_udp_endpoint(socket_id, slot) {
            self.record_udp_endpoint_error(socket_id, slot, error)?;
            return Err(rearm_error);
        }
        let _ = self.publish_udp_readiness(socket_id);
        Ok(Some(ReactorReceiveFromOutcome::Failed(error)))
    }

    fn drain_invalid_udp_ingress(
        &mut self,
        socket_id: u64,
        route: UdpNativeRoute,
    ) -> BrokerResult<()> {
        let slot = UdpEndpointSlot::Active(route);
        if let Some(endpoint) = self
            .sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .native_endpoint_mut(route)
        {
            endpoint.readable = false;
        }
        for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            let peek = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .native_endpoint(route)
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::PEEK)
            };
            let source_address = match peek {
                Ok(ReactorReceiveFromOutcome::Received { source, .. }) => source.requested(),
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    self.record_udp_endpoint_error(socket_id, slot, error)?;
                    return Ok(());
                }
                Err(BrokerError::WouldBlock) => {
                    if let Some(endpoint) = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint_mut(route)
                    {
                        endpoint.readable = false;
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if self
                .udp_native_source_authorized(socket_id, route, source_address)?
                .is_some()
            {
                self.sockets
                    .get_mut(&socket_id)
                    .ok_or(BrokerError::Internal)?
                    .udp_state_mut()?
                    .native_endpoint_mut(route)
                    .ok_or(BrokerError::Internal)?
                    .readable = true;
                return Ok(());
            }
            let consumed = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .native_endpoint(route)
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE)
            };
            match consumed {
                Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    self.record_udp_endpoint_error(socket_id, slot, error)?;
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
            .native_endpoint_mut(route)
            .ok_or(BrokerError::Internal)?
            .readable = false;
        Ok(())
    }

    pub(super) fn send_external_udp(
        &mut self,
        socket_id: u64,
        slot: UdpEndpointSlot,
        data: &[u8],
        address: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let destination = address;
        let result = loop {
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let endpoint = socket
                .udp_state()?
                .endpoint(slot)
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
                let endpoint = udp.endpoint_mut(slot).ok_or(BrokerError::Internal)?;
                endpoint.write_blocked = true;
                if !endpoint.error.is_pending() {
                    epoll::modify(
                        &self.epoll,
                        &endpoint.socket,
                        epoll::EventData::new_u64(endpoint.event_token),
                        udp_rearm_events(
                            read_shutdown || slot == UdpEndpointSlot::Override,
                            endpoint.readable,
                            true,
                        ),
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
            udp.next_receive_origin = UdpReceiveOrigin::Gateway;
            // The dequeue is committed and the cached snapshot is authoritative
            // even if this association cannot accept the notification.
            let _ = self.publish_udp_readiness(socket_id);
        }
        Ok(Some(ReactorReceiveFromOutcome::Received {
            data,
            datagram_length,
            source: SocketDestination::Guest {
                requested: source_address,
            },
        }))
    }

    pub(super) fn receive_native_udp(
        &mut self,
        socket_id: u64,
        route: UdpNativeRoute,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<Option<ReactorReceiveFromOutcome>> {
        let slot = UdpEndpointSlot::Active(route);
        let can_receive = self
            .sockets
            .get(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state()?
            .native_endpoint(route)
            .is_some_and(|endpoint| endpoint.readable);
        if !can_receive {
            return Ok(None);
        }

        for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            let outcome = {
                let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                let endpoint = socket
                    .udp_state()?
                    .native_endpoint(route)
                    .ok_or(BrokerError::Internal)?;
                receive_datagram_fd(&endpoint.socket, length, ReceiveFromFlags::PEEK)
            };
            let (data, datagram_length, source) = match outcome {
                Ok(ReactorReceiveFromOutcome::Received {
                    data,
                    datagram_length,
                    source,
                }) => (data, datagram_length, source),
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    return self.finish_udp_receive_error(socket_id, route, error);
                }
                Err(BrokerError::WouldBlock) => {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint_mut(route)
                        .ok_or(BrokerError::Internal)?;
                    endpoint.readable = false;
                    self.rearm_udp_endpoint(socket_id, slot)?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let source_address = source.requested();
            if let Some(source) =
                self.udp_native_source_authorized(socket_id, route, source_address)?
            {
                if flags.contains(ReceiveFromFlags::PEEK) {
                    self.sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .peeked_origin = Some(route.receive_origin());
                    return Ok(Some(ReactorReceiveFromOutcome::Received {
                        data,
                        datagram_length,
                        source,
                    }));
                }

                let should_rearm = {
                    let udp = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?;
                    let endpoint = udp
                        .native_endpoint_mut(route)
                        .ok_or(BrokerError::Internal)?;
                    if endpoint.error.is_pending() {
                        false
                    } else {
                        endpoint.readable = false;
                        true
                    }
                };
                if should_rearm && let Err(error) = self.rearm_udp_endpoint(socket_id, slot) {
                    self.sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint_mut(route)
                        .ok_or(BrokerError::Internal)?
                        .readable = true;
                    return Err(error);
                }
                let consumed = {
                    let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
                    let endpoint = socket
                        .udp_state()?
                        .native_endpoint(route)
                        .ok_or(BrokerError::Internal)?;
                    receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE)
                };
                match consumed {
                    Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                    Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                        return self.finish_udp_receive_error(socket_id, route, error);
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
                            .native_endpoint_mut(route)
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
                udp.next_receive_origin = match route {
                    UdpNativeRoute::Gateway => UdpReceiveOrigin::External,
                    UdpNativeRoute::External => UdpReceiveOrigin::Guest,
                };
                // Consumption is committed. The endpoint was rearmed before
                // the dequeue. Refresh the cached head state so another
                // authorized datagram keeps READ asserted without requiring
                // an asynchronous low-to-high publication.
                let _ = self.drain_invalid_udp_ingress(socket_id, route);
                // The cached snapshot remains authoritative if notification
                // delivery fails after irreversible consumption.
                let _ = self.publish_udp_readiness(socket_id);
                return Ok(Some(ReactorReceiveFromOutcome::Received {
                    data,
                    datagram_length,
                    source,
                }));
            }
            let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
            let endpoint = socket
                .udp_state()?
                .native_endpoint(route)
                .ok_or(BrokerError::Internal)?;
            match receive_datagram_fd(&endpoint.socket, 0, ReceiveFromFlags::NONE) {
                Ok(ReactorReceiveFromOutcome::Received { .. }) => {}
                Ok(ReactorReceiveFromOutcome::Failed(error)) => {
                    return self.finish_udp_receive_error(socket_id, route, error);
                }
                Err(BrokerError::WouldBlock) => {
                    let endpoint = self
                        .sockets
                        .get_mut(&socket_id)
                        .ok_or(BrokerError::Internal)?
                        .udp_state_mut()?
                        .native_endpoint_mut(route)
                        .ok_or(BrokerError::Internal)?;
                    endpoint.readable = false;
                    self.rearm_udp_endpoint(socket_id, slot)?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        self.sockets
            .get_mut(&socket_id)
            .ok_or(BrokerError::Internal)?
            .udp_state_mut()?
            .native_endpoint_mut(route)
            .ok_or(BrokerError::Internal)?
            .readable = false;
        self.rearm_udp_endpoint(socket_id, slot)?;
        Ok(None)
    }

    #[cfg(test)]
    pub(super) fn udp_native_head_datagram_bytes(&self, socket_id: u64) -> BrokerResult<usize> {
        let socket = self.sockets.get(&socket_id).ok_or(BrokerError::Internal)?;
        let endpoint = socket
            .udp_state()?
            .external_endpoint
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
                    source: SocketDestination::External {
                        requested: source_address,
                    },
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

#[cfg(test)]
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
    fn consumed_udp_native_error_coalesces_to_the_oldest_error() {
        let mut state = UdpNativeErrorState::None;
        state.record_consumed(1, SocketError::ConnectionRefused);
        state.record_consumed(2, SocketError::HostUnreachable);
        assert_eq!(
            std::mem::take(&mut state),
            UdpNativeErrorState::Consumed {
                sequence: 1,
                error: SocketError::ConnectionRefused,
            }
        );
        assert_eq!(state, UdpNativeErrorState::None);
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
        assert!(Reactor::udp_candidate_covers_peer(
            UdpNativeRoute::External,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        ));
        assert!(!Reactor::udp_candidate_covers_peer(
            UdpNativeRoute::External,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port + 1),
        ));
        assert!(Reactor::udp_candidate_covers_peer(
            UdpNativeRoute::Gateway,
            SocketAddrV4::new(PRIVATE_BACKEND_ADDRESS, port),
            SocketAddrV4::new(PRIVATE_BACKEND_ADDRESS, port),
        ));
        assert!(!Reactor::udp_candidate_covers_peer(
            UdpNativeRoute::Gateway,
            SocketAddrV4::new(PRIVATE_BACKEND_ADDRESS, port),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
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
