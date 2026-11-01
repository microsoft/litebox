// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest UDP routing and broker-owned native UDP endpoints.
//!
//! Guest bindings live in the provider's `topology`, so a datagram between
//! guest sockets is routed by address and queued directly in the receiver's
//! inbox. A socket stages a native endpoint only for external destinations;
//! [`UdpPorts`] keeps those endpoints distinct from external hosts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use litebox_broker_core::socket::{
    GUEST_IPV4_ADDRESS, GuestSocketBinding, PlatformConnectError, host_socket_destination,
    is_internal_socket_address, normalize_socket_destination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_UDP_DATAGRAM_SIZE, ReceiveFromFlags, SocketConnectionStatus, SocketError, SocketOutcome,
};
#[cfg(test)]
use litebox_platform::buffer::RawBytes;

#[cfg(test)]
use super::UserlandSocket;
use super::direct::RawParts;
use super::host::{self, Errno, HostEvents, HostSocket, Interest};
use super::{
    PlatformSocketStatus, ProviderCore, ReceiveFromOutcome, SocketEntry, SocketInbox, Topology,
    broker_error_from_errno, local_socket_address, lock, read_lock, republish_own_readiness,
    set_own_readiness, socket_error_from_errno, socket_operation_error_from_errno, write_lock,
    zeroed_vec,
};

pub(super) const MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND: usize = 64;
pub(super) const MAX_UDP_EXTERNAL_PEERS_PER_SOCKET: usize = 64;
const MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET: usize = 64;
const MAX_UDP_QUEUE_BYTES_PER_SOCKET: usize = 4 * MAX_UDP_DATAGRAM_SIZE as usize;
pub(super) const MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE: usize = 16;
const MAX_UDP_QUEUE_BYTES_PER_SOURCE: usize = 2 * MAX_UDP_DATAGRAM_SIZE as usize;
const MAX_UDP_NATIVE_PORT_RETRIES: usize = 16;
const MAX_UDP_NATIVE_CONNECT_DRAIN_DATAGRAMS: usize = 1024;
const UDP_NATIVE_RECEIVE_BUFFER_REQUEST: usize = 64 * 1024;
pub(super) const MAX_UDP_NATIVE_RECEIVE_BUFFER: usize = UDP_NATIVE_RECEIVE_BUFFER_REQUEST * 2;
pub(super) const UDP_EVENT_TOKEN_FLAG: u64 = 1 << 63;

/// Guest UDP bindings and external peer accounting shared between sockets.
#[derive(Default)]
pub(super) struct UdpTopology {
    wildcard: HashMap<u16, UdpBinding>,
    exact: HashMap<SocketAddrV4, UdpBinding>,
    external_peer_count: usize,
    /// External reply peers on host-local addresses, also counted in
    /// `external_peer_count`.
    local_peer_count: usize,
}

/// A bound guest UDP socket, as other sockets reach it.
#[derive(Clone)]
pub(super) struct UdpBinding {
    socket_id: u64,
    guest_binding: GuestSocketBinding,
    inbox: Arc<SocketInbox>,
    /// UDP queue accounting of the socket's process.
    counters: Arc<ProcessCounters>,
}

impl UdpTopology {
    fn insert_binding(&mut self, binding: UdpBinding) -> BrokerResult<()> {
        let guest_binding = &binding.guest_binding;
        let local_address = guest_binding.local_address();
        let port = local_address.port();
        let taken = self.wildcard.contains_key(&port)
            || if guest_binding.is_wildcard() {
                self.exact.keys().any(|address| address.port() == port)
            } else {
                self.exact.contains_key(&local_address)
            };
        if !guest_binding.is_valid() || taken {
            return Err(BrokerError::Internal);
        }
        if guest_binding.is_wildcard() {
            self.wildcard
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.wildcard.insert(port, binding);
        } else {
            self.exact
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.exact.insert(local_address, binding);
        }
        Ok(())
    }

    fn remove_binding(&mut self, local_address: SocketAddrV4, socket_id: u64) {
        if self
            .wildcard
            .get(&local_address.port())
            .is_some_and(|binding| binding.socket_id == socket_id)
        {
            self.wildcard.remove(&local_address.port());
        } else if self
            .exact
            .get(&local_address)
            .is_some_and(|binding| binding.socket_id == socket_id)
        {
            self.exact.remove(&local_address);
        }
    }

    /// The guest socket bound to receive datagrams sent to `address`.
    fn guest_binding(&self, address: SocketAddrV4) -> Option<&UdpBinding> {
        self.exact
            .get(&address)
            .or_else(|| self.wildcard.get(&address.port()))
            .filter(|binding| binding.guest_binding.covers(address))
    }

    #[cfg(test)]
    fn get(&self, port: u16) -> Option<&UdpBinding> {
        self.wildcard.get(&port).or_else(|| {
            self.exact
                .iter()
                .find_map(|(address, binding)| (address.port() == port).then_some(binding))
        })
    }
}

impl Topology {
    /// Charges one external reply peer to `process_authority` if the global
    /// and per-process limits allow it.
    ///
    /// A peer on a host-local address also keeps native endpoints off its
    /// port (see [`UdpPorts::port_conflicts`]). Such peers are limited to one
    /// per allowed socket, globally and per process, so they block about as
    /// many host ports as the sockets' own native endpoints use, and one
    /// process cannot cover the host's ephemeral port range and make other
    /// processes' native endpoint staging fail.
    fn charge_udp_external_peer(
        &mut self,
        process_authority: ProcessId,
        host_local: bool,
        max_sockets: usize,
        max_sockets_per_process: usize,
    ) -> BrokerResult<()> {
        let local = usize::from(host_local);
        let global = self
            .udp
            .external_peer_count
            .checked_add(1)
            .filter(|count| *count <= max_sockets.saturating_mul(MAX_UDP_EXTERNAL_PEERS_PER_SOCKET))
            .ok_or(BrokerError::ResourceExhausted)?;
        let global_local = self
            .udp
            .local_peer_count
            .checked_add(local)
            .filter(|count| *count <= max_sockets)
            .ok_or(BrokerError::ResourceExhausted)?;
        let process = self
            .processes
            .get_mut(&process_authority)
            .ok_or(BrokerError::Internal)?;
        let process_count = process
            .udp_external_peer_count
            .checked_add(1)
            .filter(|count| {
                *count <= max_sockets_per_process.saturating_mul(MAX_UDP_EXTERNAL_PEERS_PER_SOCKET)
            })
            .ok_or(BrokerError::ResourceExhausted)?;
        let process_local = process
            .udp_local_peer_count
            .checked_add(local)
            .filter(|count| *count <= max_sockets_per_process)
            .ok_or(BrokerError::ResourceExhausted)?;
        process.udp_external_peer_count = process_count;
        process.udp_local_peer_count = process_local;
        self.udp.external_peer_count = global;
        self.udp.local_peer_count = global_local;
        Ok(())
    }

    /// Releases `count` external reply peers, `local_count` of them
    /// host-local.
    fn release_udp_external_peers(
        &mut self,
        process_authority: ProcessId,
        count: usize,
        local_count: usize,
    ) {
        self.udp.external_peer_count = self
            .udp
            .external_peer_count
            .checked_sub(count)
            .expect("UDP external peer count underflow");
        self.udp.local_peer_count = self
            .udp
            .local_peer_count
            .checked_sub(local_count)
            .expect("UDP host-local peer count underflow");
        let process = self.process_mut(process_authority);
        process.udp_external_peer_count = process
            .udp_external_peer_count
            .checked_sub(count)
            .expect("process UDP external peer count underflow");
        process.udp_local_peer_count = process
            .udp_local_peer_count
            .checked_sub(local_count)
            .expect("process UDP host-local peer count underflow");
    }
}

/// Host UDP ports that broker endpoints own or guest sockets send to.
///
/// Native endpoints never take a local port that a guest peer refers to, and
/// a guest never peers with a broker endpoint, so a datagram from a broker
/// endpoint never passes as one from an external host. Only connected peers
/// and reply peers charged as host-local keep native endpoints off their
/// ports, so a remote reply peer whose address the host later takes blocks
/// none; sends and receives check for broker endpoints anyway.
#[derive(Default)]
pub(super) struct UdpPorts {
    /// Host ports bound by native endpoints.
    native: HashSet<u16>,
    /// Host addresses of external peers that keep native endpoints off their
    /// ports, with the number of sockets that refer to each.
    peers: HashMap<SocketAddrV4, usize>,
}

impl UdpPorts {
    fn targets_broker_endpoint(&self, host_destination: SocketAddrV4) -> bool {
        self.native.contains(&host_destination.port())
            && is_local_ipv4_address(*host_destination.ip())
    }

    /// Reports whether a native endpoint on `port` would receive datagrams
    /// meant for a guest peer, including `host_destination`.
    fn port_conflicts(&self, port: u16, host_destination: SocketAddrV4) -> bool {
        udp_destination_uses_local_port(host_destination, port)
            || self.native.contains(&port)
            || self
                .peers
                .keys()
                .any(|peer| udp_destination_uses_local_port(*peer, port))
    }

    /// Adds a reference to an external peer unless it is a broker endpoint;
    /// with `reserve_port`, the peer keeps native endpoints off its port.
    fn add_peer(
        &mut self,
        host_destination: SocketAddrV4,
        reserve_port: bool,
    ) -> BrokerResult<SocketOutcome<()>> {
        if self.targets_broker_endpoint(host_destination) {
            return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
        }
        if reserve_port {
            self.peers
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            *self.peers.entry(host_destination).or_default() += 1;
        }
        Ok(SocketOutcome::Completed(()))
    }

    fn remove_peer(&mut self, host_destination: SocketAddrV4, reserve_port: bool) {
        if !reserve_port {
            return;
        }
        let count = self
            .peers
            .get_mut(&host_destination)
            .expect("UDP external peer reference missing");
        *count -= 1;
        if *count == 0 {
            self.peers.remove(&host_destination);
        }
    }
}

/// Datagrams and bytes queued between guest UDP sockets at one level.
#[derive(Default)]
pub(super) struct QueueCounter {
    datagrams: AtomicUsize,
    bytes: AtomicUsize,
}

impl QueueCounter {
    /// Charges one datagram of `length` bytes if both counts stay in limits.
    fn reserve(&self, length: usize, max_datagrams: usize, max_bytes: usize) -> bool {
        if self
            .datagrams
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |datagrams| {
                (datagrams < max_datagrams).then_some(datagrams + 1)
            })
            .is_err()
        {
            return false;
        }
        if self
            .bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |bytes| {
                bytes
                    .checked_add(length)
                    .filter(|bytes| *bytes <= max_bytes)
            })
            .is_err()
        {
            self.datagrams.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn release(&self, length: usize) {
        self.datagrams.fetch_sub(1, Ordering::Relaxed);
        self.bytes.fetch_sub(length, Ordering::Relaxed);
    }
}

/// UDP queue accounting for one process instance.
#[derive(Default)]
pub(super) struct ProcessCounters {
    /// Datagrams queued to the process's sockets.
    received: QueueCounter,
    /// Datagrams the process's sockets queued to any socket.
    sent: QueueCounter,
}

/// The queue accounting one queued datagram holds until it is dropped.
struct UdpCharge {
    length: usize,
    global: Arc<QueueCounter>,
    receiver: Arc<ProcessCounters>,
    source: Arc<ProcessCounters>,
}

impl UdpCharge {
    /// Charges a datagram to the broker, its receiving process, and its
    /// sending process if each stays within its limits.
    fn reserve(
        length: usize,
        core: &ProviderCore,
        receiver: Arc<ProcessCounters>,
        source: Arc<ProcessCounters>,
    ) -> Option<Self> {
        let (global_datagrams, global_bytes, process_datagrams, process_bytes) =
            udp_queue_limits(core.max_sockets, core.max_sockets_per_process);
        if !core
            .udp_queued
            .reserve(length, global_datagrams, global_bytes)
        {
            return None;
        }
        if !receiver
            .received
            .reserve(length, process_datagrams, process_bytes)
        {
            core.udp_queued.release(length);
            return None;
        }
        if !source
            .sent
            .reserve(length, process_datagrams, process_bytes)
        {
            receiver.received.release(length);
            core.udp_queued.release(length);
            return None;
        }
        Some(Self {
            length,
            global: Arc::clone(&core.udp_queued),
            receiver,
            source,
        })
    }
}

impl Drop for UdpCharge {
    fn drop(&mut self) {
        self.source.sent.release(self.length);
        self.receiver.received.release(self.length);
        self.global.release(self.length);
    }
}

struct InternalDatagram {
    payload: Vec<u8>,
    source_address: SocketAddrV4,
    charge: UdpCharge,
}

/// Identifies the source process instance that `counters` belong to.
///
/// Each datagram's charge keeps its source's counters alive, so the address
/// is unique while any of the instance's datagrams is queued.
fn source_instance(counters: &Arc<ProcessCounters>) -> usize {
    Arc::as_ptr(counters).addr()
}

/// Datagrams other guest sockets queued for a socket, guarded by its inbox.
#[derive(Default)]
pub(super) struct UdpInbox {
    /// Drop deliveries: the socket shut down reading.
    read_shutdown: bool,
    /// Accept deliveries only from this peer.
    peer: Option<UdpPeer>,
    queue: VecDeque<InternalDatagram>,
    bytes: usize,
    /// Queued datagrams by source process instance; a reused process ID has
    /// its own entry.
    by_source: HashMap<usize, UdpQueueAccounting>,
}

#[derive(Clone, Copy, Default)]
struct UdpQueueAccounting {
    datagrams: usize,
    bytes: usize,
}

impl UdpInbox {
    pub(super) fn has_queued_datagrams(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Drops every queued datagram.
    pub(super) fn clear(&mut self) {
        drop(self.take_queue());
    }

    fn take_queue(&mut self) -> VecDeque<InternalDatagram> {
        self.bytes = 0;
        self.by_source.clear();
        core::mem::take(&mut self.queue)
    }

    fn accepts_from(&self, source_address: SocketAddrV4) -> bool {
        self.peer
            .is_none_or(|peer| peer == UdpPeer::Internal(source_address))
    }

    /// Reports whether the socket's queue has room for a datagram of `length`
    /// bytes from the process instance `source` counts for.
    fn has_room(&self, source: &Arc<ProcessCounters>, length: usize) -> bool {
        let source = self
            .by_source
            .get(&source_instance(source))
            .copied()
            .unwrap_or_default();
        self.queue.len() < MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET
            && self.bytes.saturating_add(length) <= MAX_UDP_QUEUE_BYTES_PER_SOCKET
            && source.datagrams < MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE
            && source.bytes.saturating_add(length) <= MAX_UDP_QUEUE_BYTES_PER_SOURCE
    }

    fn reserve(&mut self, source: &Arc<ProcessCounters>) -> BrokerResult<()> {
        self.queue
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        if !self.by_source.contains_key(&source_instance(source)) {
            self.by_source
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
        }
        Ok(())
    }

    fn push(&mut self, datagram: InternalDatagram) {
        let length = datagram.payload.len();
        let source = self
            .by_source
            .entry(source_instance(&datagram.charge.source))
            .or_default();
        source.datagrams += 1;
        source.bytes += length;
        self.bytes += length;
        self.queue.push_back(datagram);
    }

    fn pop(&mut self) -> Option<InternalDatagram> {
        let datagram = self.queue.pop_front()?;
        let length = datagram.payload.len();
        self.bytes -= length;
        let instance = source_instance(&datagram.charge.source);
        let source = self
            .by_source
            .get_mut(&instance)
            .expect("UDP source accounting missing");
        source.datagrams -= 1;
        source.bytes -= length;
        if source.datagrams == 0 {
            self.by_source.remove(&instance);
        }
        Some(datagram)
    }
}

pub(super) struct UdpSocketState {
    /// The socket's guest binding, once bound.
    binding: Option<GuestSocketBinding>,
    /// A connected peer; an external one holds a reference in `udp_ports`.
    pub(super) peer: Option<UdpPeer>,
    pub(super) peeked_origin: Option<UdpReceiveOrigin>,
    pub(super) next_receive_origin: UdpReceiveOrigin,
    pub(super) native_endpoint: Option<UdpNativeEndpoint>,
    /// The external peers an unconnected socket accepts replies from, by
    /// host address. Each holds a reference in `udp_ports`.
    external_peers: HashMap<SocketAddrV4, UdpReplyPeer>,
}

/// An external peer that an unconnected socket accepts replies from.
#[derive(Clone, Copy)]
struct UdpReplyPeer {
    /// The peer's guest-visible address.
    address: SocketAddrV4,
    /// Whether the peer was host-local when added, so that it is charged as
    /// host-local and keeps native endpoints off its port.
    host_local: bool,
}

/// How many of `peers` are charged as host-local.
fn udp_local_peer_count(peers: &HashMap<SocketAddrV4, UdpReplyPeer>) -> usize {
    peers.values().filter(|peer| peer.host_local).count()
}

impl Default for UdpSocketState {
    fn default() -> Self {
        Self {
            binding: None,
            peer: None,
            peeked_origin: None,
            next_receive_origin: UdpReceiveOrigin::Internal,
            native_endpoint: None,
            external_peers: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum UdpNativeErrorState {
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

    fn take_receive_error(&mut self, error: SocketError) -> SocketError {
        match std::mem::take(self) {
            Self::Consumed(oldest) => oldest,
            Self::None | Self::PendingKernel => error,
        }
    }

    /// The error taken from the host socket, which no longer reports it.
    const fn consumed(self) -> Option<SocketError> {
        match self {
            Self::Consumed(error) => Some(error),
            Self::None | Self::PendingKernel => None,
        }
    }
}

pub(super) struct UdpNativeEndpoint {
    pub(super) socket: HostSocket,
    pub(super) event_token: u64,
    guest_local_address: SocketAddrV4,
    pub(super) readable: bool,
    write_blocked: bool,
    error: UdpNativeErrorState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UdpReceiveOrigin {
    Internal,
    External,
}

/// A UDP peer address. Like an IP network, routing and peer filtering use
/// only the address, never the identity of the socket bound to it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UdpPeer {
    Internal(SocketAddrV4),
    External(SocketAddrV4),
}

impl SocketEntry<'_> {
    pub(super) fn bind_udp_socket(
        &mut self,
        binding: GuestSocketBinding,
        already_bound: bool,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if already_bound {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let local_address = binding.local_address();
        let socket_id = self.id();
        let inbox = Arc::clone(&self.socket.inbox);
        let mut topology = self.topology();
        let counters = Arc::clone(
            &topology
                .processes
                .get(&self.process_authority())
                .ok_or(BrokerError::Internal)?
                .udp_counters,
        );
        let udp = self.udp_state_mut()?;
        topology.udp.insert_binding(UdpBinding {
            socket_id,
            guest_binding: binding.clone(),
            inbox,
            counters,
        })?;
        drop(topology);
        udp.binding = Some(binding);
        self.guest_local_address = Some(local_address);
        Ok(SocketOutcome::Completed(local_address))
    }

    /// Revalidates and resolves a normalized guest-visible UDP destination.
    pub(super) fn resolve_udp_destination(
        &self,
        requested_destination: SocketAddrV4,
    ) -> SocketOutcome<UdpPeer> {
        let destination = match normalize_socket_destination(requested_destination) {
            Ok(destination) => destination,
            Err(error) => return SocketOutcome::Failed(error),
        };
        if is_internal_socket_address(destination) {
            return SocketOutcome::Completed(UdpPeer::Internal(destination));
        }
        if read_lock(&self.core().udp_ports)
            .targets_broker_endpoint(host_socket_destination(destination))
        {
            SocketOutcome::Failed(SocketError::ConnectionRefused)
        } else {
            SocketOutcome::Completed(UdpPeer::External(destination))
        }
    }

    /// The guest address the socket sends from to reach `destination`.
    pub(super) fn udp_source_address(
        &self,
        destination: SocketAddrV4,
    ) -> BrokerResult<SocketAddrV4> {
        self.udp_state()?
            .binding
            .as_ref()
            .and_then(|binding| binding.source_address_for_destination(destination))
            .ok_or(BrokerError::Internal)
    }

    /// Consumes a cached socket error, which takes precedence over data
    /// transfer.
    pub(super) fn take_udp_cached_error(&mut self) -> Option<SocketError> {
        let error = self.pending_error.take();
        if error.is_some() {
            // The error is already consumed; ignore a failure to recompute
            // readiness.
            let _ = self.publish_udp_readiness();
        }
        error
    }

    fn udp_readiness(&self) -> BrokerResult<ReadinessFlags> {
        let endpoint = self.udp_state()?.native_endpoint.as_ref();
        let mut readiness = ReadinessFlags::default();
        if self.read_shutdown || endpoint.is_some_and(|endpoint| endpoint.readable) {
            readiness = readiness | ReadinessFlags::READ;
        }
        if !self.write_shutdown && !endpoint.is_some_and(|endpoint| endpoint.write_blocked) {
            readiness = readiness | ReadinessFlags::WRITE;
        }
        if self.pending_error.is_some()
            || endpoint.is_some_and(|endpoint| endpoint.error.is_pending())
        {
            readiness = readiness | ReadinessFlags::ERROR;
        }
        Ok(readiness)
    }

    /// Publishes the readiness derived from the socket's own state; queued
    /// internal datagrams add READ in the inbox.
    pub(super) fn publish_udp_readiness(&self) -> BrokerResult<()> {
        let readiness = self.udp_readiness()?;
        set_own_readiness(self, readiness);
        Ok(())
    }

    /// Sends a datagram to the guest socket bound to `destination`.
    ///
    /// Like UDP on a lossy network, a datagram the receiver has no room for is
    /// dropped and the send still succeeds.
    pub(super) fn send_internal_udp(
        &mut self,
        destination: SocketAddrV4,
        data: RawParts<'_>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let source_address = self.udp_source_address(destination)?;
        let receiver = {
            let topology = self.topology();
            let source = Arc::clone(
                &topology
                    .processes
                    .get(&self.process_authority())
                    .ok_or(BrokerError::Internal)?
                    .udp_counters,
            );
            topology.udp.guest_binding(destination).map(|binding| {
                (
                    Arc::clone(&binding.inbox),
                    Arc::clone(&binding.counters),
                    source,
                )
            })
        };
        let reachable = match receiver {
            Some((inbox, counters, source)) => {
                self.deliver_internal_udp(&inbox, counters, source, source_address, data)?
            }
            None => false,
        };
        if !reachable && self.udp_state()?.peer == Some(UdpPeer::Internal(destination)) {
            // Report the undeliverable datagram to a sender connected to its
            // destination, as an ICMP port-unreachable error would.
            self.pending_error = Some(SocketError::ConnectionRefused);
            // The error is already committed; ignore a failure to recompute
            // readiness.
            let _ = self.publish_udp_readiness();
        }
        Ok(SocketOutcome::Completed(data.len()))
    }

    /// Queues a datagram in a receiver's inbox; returns whether the receiver
    /// is still bound and accepts datagrams from `source_address`.
    fn deliver_internal_udp(
        &self,
        receiver: &SocketInbox,
        receiver_counters: Arc<ProcessCounters>,
        source_counters: Arc<ProcessCounters>,
        source_address: SocketAddrV4,
        data: RawParts<'_>,
    ) -> BrokerResult<bool> {
        let mut payload = zeroed_vec(data.len())?;
        data.copy_to_slice(&mut payload);
        let mut inbox = receiver.lock();
        if inbox.closed || !inbox.udp.accepts_from(source_address) {
            return Ok(false);
        }
        if inbox.udp.read_shutdown || !inbox.udp.has_room(&source_counters, data.len()) {
            return Ok(true);
        }
        inbox.udp.reserve(&source_counters)?;
        let Some(charge) =
            UdpCharge::reserve(data.len(), self.core(), receiver_counters, source_counters)
        else {
            return Ok(true);
        };
        inbox.udp.push(InternalDatagram {
            payload,
            source_address,
            charge,
        });
        inbox.publish();
        Ok(true)
    }

    pub(super) fn receive_internal_udp(
        &mut self,
        output: RawParts<'_>,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<Option<ReceiveFromOutcome>> {
        let peek = flags.contains(ReceiveFromFlags::PEEK);
        let (outcome, consumed) = {
            let mut inbox = self.inbox();
            let Some(datagram) = inbox.udp.queue.front() else {
                return Ok(None);
            };
            let received = output.len().min(datagram.payload.len());
            output.copy_from_slice(&datagram.payload[..received]);
            let outcome = ReceiveFromOutcome::Received {
                received,
                datagram_length: datagram.payload.len(),
                source_address: datagram.source_address,
            };
            let consumed = if peek {
                None
            } else {
                let consumed = inbox.udp.pop();
                inbox.publish();
                consumed
            };
            (outcome, consumed)
        };
        drop(consumed);
        let udp = self.udp_state_mut()?;
        if peek {
            udp.peeked_origin = Some(UdpReceiveOrigin::Internal);
        } else {
            udp.peeked_origin = None;
            udp.next_receive_origin = UdpReceiveOrigin::External;
        }
        Ok(Some(outcome))
    }

    /// Drops every queued internal datagram and makes the inbox accept later
    /// ones only from `peer`, if set, or none after a read shutdown.
    pub(super) fn filter_udp_receive_queue(&mut self, peer: Option<UdpPeer>, read_shutdown: bool) {
        let dropped = {
            let mut inbox = self.inbox();
            inbox.udp.peer = peer;
            inbox.udp.read_shutdown = read_shutdown;
            let dropped = inbox.udp.take_queue();
            inbox.publish();
            dropped
        };
        drop(dropped);
        if let Ok(udp) = self.udp_state_mut() {
            udp.peeked_origin = None;
        }
    }

    /// Lets an unconnected socket accept replies from `external_destination`,
    /// and returns whether the peer is new.
    fn reserve_udp_external_peer(
        &mut self,
        external_destination: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<bool>> {
        let core = self.core();
        let process_authority = self.process_authority();
        let host_destination = host_socket_destination(external_destination);
        let udp = self.udp_state_mut()?;
        if let Some(existing) = udp.external_peers.get(&host_destination) {
            if existing.address != external_destination {
                return Err(BrokerError::Internal);
            }
            return Ok(SocketOutcome::Completed(false));
        }
        if udp.external_peers.len() >= MAX_UDP_EXTERNAL_PEERS_PER_SOCKET {
            return Err(BrokerError::ResourceExhausted);
        }
        udp.external_peers
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let host_local = is_local_ipv4_address(*host_destination.ip());
        let local = usize::from(host_local);
        lock(&core.topology).charge_udp_external_peer(
            process_authority,
            host_local,
            core.max_sockets,
            core.max_sockets_per_process,
        )?;
        let added = write_lock(&core.udp_ports).add_peer(host_destination, host_local);
        if !matches!(added, Ok(SocketOutcome::Completed(()))) {
            lock(&core.topology).release_udp_external_peers(process_authority, 1, local);
        }
        if let SocketOutcome::Failed(error) = added? {
            return Ok(SocketOutcome::Failed(error));
        }
        udp.external_peers.insert(
            host_destination,
            UdpReplyPeer {
                address: external_destination,
                host_local,
            },
        );
        Ok(SocketOutcome::Completed(true))
    }

    /// Undoes [`Self::reserve_udp_external_peer`] of a new peer.
    fn remove_udp_external_peer(&mut self, external_destination: SocketAddrV4) {
        let core = self.core();
        let process_authority = self.process_authority();
        let host_destination = host_socket_destination(external_destination);
        let Ok(udp) = self.udp_state_mut() else {
            return;
        };
        let Some(peer) = udp.external_peers.get(&host_destination).copied() else {
            return;
        };
        if peer.address != external_destination {
            return;
        }
        udp.external_peers.remove(&host_destination);
        let local = usize::from(peer.host_local);
        lock(&core.topology).release_udp_external_peers(process_authority, 1, local);
        write_lock(&core.udp_ports).remove_peer(host_destination, peer.host_local);
    }

    fn clear_udp_external_peers(&mut self) -> BrokerResult<()> {
        let peers = core::mem::take(&mut self.udp_state_mut()?.external_peers);
        if !peers.is_empty() {
            self.topology().release_udp_external_peers(
                self.process_authority(),
                peers.len(),
                udp_local_peer_count(&peers),
            );
        }
        self.release_udp_port_refs(&peers, None);
        Ok(())
    }

    /// Drops the `udp_ports` references of the given external reply peers
    /// and connected peer.
    fn release_udp_port_refs(
        &self,
        external_peers: &HashMap<SocketAddrV4, UdpReplyPeer>,
        connected_peer: Option<UdpPeer>,
    ) {
        let mut ports = write_lock(&self.core().udp_ports);
        for (host_destination, peer) in external_peers {
            ports.remove_peer(*host_destination, peer.host_local);
        }
        if let Some(UdpPeer::External(destination)) = connected_peer {
            ports.remove_peer(host_socket_destination(destination), true);
        }
    }

    pub(super) fn connect_udp_socket(
        &mut self,
        requested_destination: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let peer = match self.resolve_udp_destination(requested_destination) {
            SocketOutcome::Completed(peer) => peer,
            SocketOutcome::Failed(error) => {
                return Ok(SocketConnectionStatus::Failed(error));
            }
        };
        let (UdpPeer::Internal(destination) | UdpPeer::External(destination)) = peer;
        let guest_local_address = self
            .udp_source_address(destination)
            .map_err(PlatformConnectError::PeerUnchanged)?;
        let previous_peer = self
            .udp_state()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .peer;
        if let UdpPeer::External(destination) = peer {
            match write_lock(&self.core().udp_ports)
                .add_peer(host_socket_destination(destination), true)
                .map_err(PlatformConnectError::PeerUnchanged)?
            {
                SocketOutcome::Completed(()) => {}
                SocketOutcome::Failed(error) => {
                    return Ok(SocketConnectionStatus::Failed(error));
                }
            }
        }
        let result = self.connect_udp_peer(peer, guest_local_address);
        // Whichever of the previous and the requested peer the socket is not
        // connected to now gives up its reference.
        let connected = self.udp_state().is_ok_and(|udp| udp.peer == Some(peer));
        let released = if connected { previous_peer } else { Some(peer) };
        self.release_udp_port_refs(&HashMap::new(), released);
        result
    }

    fn connect_udp_peer(
        &mut self,
        peer: UdpPeer,
        guest_local_address: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let mut reused_native_endpoint = false;
        let staged_endpoint = match peer {
            UdpPeer::Internal(_) => None,
            UdpPeer::External(destination) => {
                let udp = self
                    .udp_state()
                    .map_err(PlatformConnectError::PeerUnchanged)?;
                let reuse = udp.native_endpoint.as_ref().is_some_and(|endpoint| {
                    !udp_reconnect_changes_source(
                        &endpoint.socket,
                        host_socket_destination(destination),
                    )
                });
                if reuse {
                    match self.connect_existing_udp_endpoint(destination)? {
                        SocketOutcome::Completed(()) => {
                            reused_native_endpoint = true;
                            None
                        }
                        SocketOutcome::Failed(error) => {
                            return Ok(SocketConnectionStatus::Failed(error));
                        }
                    }
                } else {
                    match self
                        .stage_udp_endpoint(destination, Some(destination))
                        .map_err(PlatformConnectError::PeerUnchanged)?
                    {
                        SocketOutcome::Completed(endpoint) => Some(endpoint),
                        SocketOutcome::Failed(error) => {
                            return Ok(SocketConnectionStatus::Failed(error));
                        }
                    }
                }
            }
        };
        let read_shutdown = self.read_shutdown;
        self.filter_udp_receive_queue(Some(peer), read_shutdown);
        if !reused_native_endpoint {
            self.replace_udp_endpoint(staged_endpoint)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
        }
        self.clear_udp_external_peers()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        self.guest_local_address = Some(guest_local_address);
        self.connection_status = SocketConnectionStatus::Connected;
        self.udp_state_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?
            .peer = Some(peer);
        self.publish_udp_readiness()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        Ok(SocketConnectionStatus::Connected)
    }

    /// Sends a datagram to an external host, staging the socket's native
    /// endpoint first if needed. With `authorize_reply`, the socket also
    /// accepts replies from the destination.
    pub(super) fn send_to_external_udp(
        &mut self,
        data: RawParts<'_>,
        external_destination: SocketAddrV4,
        authorize_reply: bool,
    ) -> BrokerResult<SocketOutcome<usize>> {
        let added_peer = authorize_reply
            && match self.reserve_udp_external_peer(external_destination)? {
                SocketOutcome::Completed(added) => added,
                SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            };
        let outcome = self.stage_and_send_external_udp(data, external_destination);
        if added_peer && !matches!(outcome, Ok(SocketOutcome::Completed(_))) {
            self.remove_udp_external_peer(external_destination);
        }
        outcome
    }

    fn stage_and_send_external_udp(
        &mut self,
        data: RawParts<'_>,
        external_destination: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<usize>> {
        if self.udp_state()?.native_endpoint.is_none() {
            let endpoint = match self.stage_udp_endpoint(external_destination, None)? {
                SocketOutcome::Completed(endpoint) => endpoint,
                SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            };
            self.replace_udp_endpoint(Some(endpoint))?;
        }
        self.send_external_udp(data, external_destination)
    }

    /// Creates a native endpoint on a host port that no guest peer refers to.
    fn stage_udp_endpoint(
        &self,
        current_external_destination: SocketAddrV4,
        connected_external_destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<UdpNativeEndpoint>> {
        let core = self.core();
        let event_token = core.allocate_udp_event_token()?;
        let current_host_destination = host_socket_destination(current_external_destination);
        for _ in 0..MAX_UDP_NATIVE_PORT_RETRIES {
            let mut socket = HostSocket::udp().map_err(broker_error_from_errno)?;
            configure_udp_native_receive_buffer(&socket)?;
            let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
            let port = {
                // Bind, and close a rejected candidate, under the lock, so
                // every port a broker endpoint is bound to is in `udp_ports`
                // before any send checks it.
                let mut ports = write_lock(&core.udp_ports);
                loop {
                    match socket.bind(wildcard) {
                        Ok(()) => break,
                        Err(Errno::INTR) => {}
                        Err(error) => {
                            return socket_operation_error_from_errno(error)
                                .map(SocketOutcome::Failed);
                        }
                    }
                }
                let port = match local_socket_address(&socket) {
                    Ok(address) => address.port(),
                    Err(error) => {
                        drop(socket);
                        return Err(error);
                    }
                };
                if ports.port_conflicts(port, current_host_destination) {
                    drop(socket);
                    continue;
                }
                if ports.native.try_reserve(1).is_err() {
                    drop(socket);
                    return Err(BrokerError::OutOfMemory);
                }
                ports.native.insert(port);
                port
            };
            let failure = match self.register_udp_endpoint(
                &mut socket,
                event_token,
                connected_external_destination,
            ) {
                Ok(SocketOutcome::Completed(())) => None,
                Ok(SocketOutcome::Failed(error)) => Some(Ok(SocketOutcome::Failed(error))),
                Err(error) => Some(Err(error)),
            };
            if let Some(failure) = failure {
                drop(socket);
                write_lock(&core.udp_ports).native.remove(&port);
                return failure;
            }
            return Ok(SocketOutcome::Completed(UdpNativeEndpoint {
                socket,
                event_token,
                guest_local_address: SocketAddrV4::new(GUEST_IPV4_ADDRESS, port),
                readable: false,
                write_blocked: false,
                error: UdpNativeErrorState::None,
            }));
        }
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    }

    /// Connects a staged endpoint if requested and watches it.
    fn register_udp_endpoint(
        &self,
        socket: &mut HostSocket,
        event_token: u64,
        connected_external_destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<()>> {
        if let Some(external_destination) = connected_external_destination {
            loop {
                match socket.connect(host_socket_destination(external_destination)) {
                    Ok(()) => break,
                    Err(Errno::INTR) => {}
                    Err(error) => {
                        return socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
                    }
                }
            }
        }
        let core = self.core();
        {
            let mut registry = write_lock(&core.registry);
            registry
                .udp_tokens
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            registry.udp_tokens.insert(event_token, self.id());
        }
        if let Err(error) = core.watch_host_socket(
            socket,
            event_token,
            Interest::Oneshot {
                read: udp_watches_reads(self.read_shutdown),
                write: false,
            },
        ) {
            write_lock(&core.registry).udp_tokens.remove(&event_token);
            return Err(error);
        }
        Ok(SocketOutcome::Completed(()))
    }

    /// Stops watching a native endpoint, closes it, and frees its port.
    fn retire_udp_endpoint(&self, mut endpoint: UdpNativeEndpoint) {
        let core = self.core();
        write_lock(&core.registry)
            .udp_tokens
            .remove(&endpoint.event_token);
        core.unwatch_host_socket(&mut endpoint.socket);
        let port = endpoint.guest_local_address.port();
        drop(endpoint);
        write_lock(&core.udp_ports).native.remove(&port);
    }

    fn replace_udp_endpoint(&mut self, endpoint: Option<UdpNativeEndpoint>) -> BrokerResult<()> {
        let old = match self.udp_state_mut() {
            Ok(udp) => {
                if udp.peeked_origin == Some(UdpReceiveOrigin::External) {
                    udp.peeked_origin = None;
                }
                std::mem::replace(&mut udp.native_endpoint, endpoint)
            }
            Err(error) => {
                if let Some(endpoint) = endpoint {
                    self.retire_udp_endpoint(endpoint);
                }
                return Err(error);
            }
        };
        if let Some(old) = old {
            self.retire_udp_endpoint(old);
        }
        Ok(())
    }

    pub(super) fn retire_udp(&mut self) {
        let id = self.id();
        let core = self.core();
        let process_authority = self.process_authority();
        let (binding, external_peers, connected_peer, endpoint) = match self.udp_state_mut() {
            Ok(udp) => (
                udp.binding.take(),
                core::mem::take(&mut udp.external_peers),
                udp.peer.take(),
                udp.native_endpoint.take(),
            ),
            Err(_) => (None, HashMap::new(), None, None),
        };
        {
            let mut topology = self.topology();
            if let Some(binding) = &binding {
                topology.udp.remove_binding(binding.local_address(), id);
            }
            if !external_peers.is_empty() {
                topology.release_udp_external_peers(
                    process_authority,
                    external_peers.len(),
                    udp_local_peer_count(&external_peers),
                );
            }
            topology.release_socket(process_authority);
        }
        core.unregister(id);
        if let Some(endpoint) = endpoint {
            self.retire_udp_endpoint(endpoint);
        }
        self.release_udp_port_refs(&external_peers, connected_peer);
    }

    fn udp_endpoint(&self) -> BrokerResult<&UdpNativeEndpoint> {
        self.udp_state()?
            .native_endpoint
            .as_ref()
            .ok_or(BrokerError::Internal)
    }

    fn udp_endpoint_mut(&mut self) -> BrokerResult<&mut UdpNativeEndpoint> {
        self.udp_state_mut()?
            .native_endpoint
            .as_mut()
            .ok_or(BrokerError::Internal)
    }

    pub(super) fn status_udp_socket(&mut self) -> BrokerResult<PlatformSocketStatus> {
        let status = self.connection_status;
        let local_address = self.guest_local_address;
        let cached_error = self.pending_error.take();
        let native_error_pending = self
            .udp_state()?
            .native_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.error.is_pending());
        let mut pending_error = cached_error;
        if pending_error.is_none() && native_error_pending {
            pending_error = self.take_udp_error()?;
        }
        let readiness = self.udp_readiness()?;
        if cached_error.is_some() && native_error_pending {
            // Returning the cached error leaves another error pending without
            // changing readiness, so wake a waiter for the remaining error.
            republish_own_readiness(self, readiness);
        } else {
            set_own_readiness(self, readiness);
        }
        if let Err(error) = self.rearm_udp_endpoint_if_needed() {
            if let Some(pending_error) = pending_error {
                self.pending_error = Some(pending_error);
                let readiness = self.own() | ReadinessFlags::ERROR;
                set_own_readiness(self, readiness);
            }
            return Err(error);
        }
        Ok(PlatformSocketStatus {
            status,
            local_address,
            pending_error,
        })
    }

    fn take_udp_error(&mut self) -> BrokerResult<Option<SocketError>> {
        let udp = self.udp_state_mut()?;
        let peeked_origin = udp.peeked_origin;
        let endpoint = udp.native_endpoint.as_mut().ok_or(BrokerError::Internal)?;
        let was_readable = endpoint.readable;
        endpoint.readable = udp_readable_after_error(peeked_origin);
        match std::mem::take(&mut endpoint.error) {
            UdpNativeErrorState::None => Err(BrokerError::Internal),
            UdpNativeErrorState::Consumed(error) => Ok(Some(error)),
            UdpNativeErrorState::PendingKernel => {
                let socket_error = take_udp_socket_error(&endpoint.socket);
                if socket_error.is_err() {
                    endpoint.error = UdpNativeErrorState::PendingKernel;
                    endpoint.readable = was_readable;
                }
                socket_error
            }
        }
    }

    /// Reconnects the socket's native endpoint and discards what the host
    /// queued before the reconnect: datagrams, from any source, and errors.
    fn connect_existing_udp_endpoint(
        &mut self,
        external_destination: SocketAddrV4,
    ) -> core::result::Result<SocketOutcome<()>, PlatformConnectError> {
        let indeterminate = PlatformConnectError::PeerIndeterminate;
        let endpoint = self.udp_endpoint().map_err(indeterminate)?;
        loop {
            match endpoint
                .socket
                .connect(host_socket_destination(external_destination))
            {
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
        let _ = endpoint
            .socket
            .take_error()
            .map_err(|error| indeterminate(broker_error_from_errno(error)))?;
        for _ in 0..MAX_UDP_NATIVE_CONNECT_DRAIN_DATAGRAMS {
            match endpoint.socket.discard_datagram() {
                Ok(()) | Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    let udp = self.udp_state_mut().map_err(indeterminate)?;
                    if udp.peeked_origin == Some(UdpReceiveOrigin::External) {
                        udp.peeked_origin = None;
                    }
                    let endpoint = udp
                        .native_endpoint
                        .as_mut()
                        .ok_or(indeterminate(BrokerError::Internal))?;
                    endpoint.error = UdpNativeErrorState::None;
                    endpoint.readable = false;
                    self.rearm_udp_endpoint().map_err(indeterminate)?;
                    return Ok(SocketOutcome::Completed(()));
                }
                Err(error) => {
                    socket_operation_error_from_errno(error).map_err(indeterminate)?;
                }
            }
        }
        Err(indeterminate(BrokerError::ResourceExhausted))
    }

    pub(super) fn handle_udp_endpoint_event(
        &mut self,
        event_token: u64,
        events: HostEvents,
    ) -> BrokerResult<()> {
        let readable_event = events.contains(HostEvents::READABLE);
        let error_event = events.intersects(HostEvents::ERROR | HostEvents::HANGUP);
        let Some(endpoint) = self
            .udp_state_mut()
            .ok()
            .and_then(|udp| udp.native_endpoint.as_mut())
            .filter(|endpoint| endpoint.event_token == event_token)
        else {
            return Ok(());
        };
        if events.contains(HostEvents::WRITABLE) {
            endpoint.write_blocked = false;
        }
        if error_event {
            endpoint.readable = true;
            endpoint.error.record_kernel();
        }
        if readable_event && !error_event {
            self.drain_rejected_external_datagrams()?;
        }
        self.rearm_udp_endpoint()?;
        // The event is already applied; ignore a failure to recompute
        // readiness.
        let _ = self.publish_udp_readiness();
        Ok(())
    }

    fn rearm_udp_endpoint(&mut self) -> BrokerResult<()> {
        let core = self.core();
        let read_shutdown = self.read_shutdown;
        let Some(endpoint) = self.udp_state_mut()?.native_endpoint.as_mut() else {
            return Ok(());
        };
        if endpoint.error.is_pending() {
            return Ok(());
        }
        let interest = udp_rearm_interest(read_shutdown, endpoint.readable, endpoint.write_blocked);
        core.poller
            .modify(&mut endpoint.socket, endpoint.event_token, interest)
            .map_err(broker_error_from_errno)
    }

    pub(super) fn rearm_udp_endpoint_if_needed(&mut self) -> BrokerResult<()> {
        let should_rearm = self
            .udp_state()?
            .native_endpoint
            .as_ref()
            .is_some_and(|endpoint| {
                udp_endpoint_needs_rearm(
                    endpoint.readable,
                    endpoint.write_blocked,
                    endpoint.error.is_pending(),
                )
            });
        if should_rearm {
            self.rearm_udp_endpoint()?;
        }
        Ok(())
    }

    fn rearm_udp_endpoint_and_publish(&mut self) -> BrokerResult<()> {
        let rearm_result = self.rearm_udp_endpoint();
        let publish_result = self.publish_udp_readiness();
        rearm_result?;
        publish_result
    }

    fn clear_udp_readable_and_rearm(&mut self) -> BrokerResult<()> {
        self.udp_endpoint_mut()?.readable = false;
        self.rearm_udp_endpoint_and_publish()
    }

    /// The guest-visible source of a datagram from `host_source`, or `None`
    /// if the socket does not accept it.
    fn resolve_external_udp_source(
        &self,
        host_source: SocketAddrV4,
    ) -> BrokerResult<Option<SocketAddrV4>> {
        if self.read_shutdown {
            return Ok(None);
        }
        let udp = self.udp_state()?;
        if read_lock(&self.core().udp_ports).targets_broker_endpoint(host_source) {
            return Ok(None);
        }
        Ok(match udp.peer {
            Some(UdpPeer::External(peer)) if host_socket_destination(peer) == host_source => {
                Some(peer)
            }
            Some(UdpPeer::Internal(_) | UdpPeer::External(_)) => None,
            None => udp
                .external_peers
                .get(&host_source)
                .map(|peer| peer.address),
        })
    }

    fn record_udp_endpoint_error(&mut self, error: SocketError) -> BrokerResult<()> {
        self.udp_endpoint_mut()?.error.record_consumed(error);
        Ok(())
    }

    fn finish_udp_receive_error(
        &mut self,
        error: SocketError,
    ) -> BrokerResult<Option<ReceiveFromOutcome>> {
        self.finish_udp_endpoint_error(error)
            .map(|error| Some(ReceiveFromOutcome::Failed(error)))
    }

    /// Takes the error a transfer reports, the endpoint's consumed error if
    /// any or else `error`, and rearms the endpoint.
    fn finish_udp_endpoint_error(&mut self, error: SocketError) -> BrokerResult<SocketError> {
        let error = {
            let udp = self.udp_state_mut()?;
            let peeked_origin = udp.peeked_origin;
            let endpoint = udp.native_endpoint.as_mut().ok_or(BrokerError::Internal)?;
            endpoint.readable = udp_readable_after_error(peeked_origin);
            endpoint.error.take_receive_error(error)
        };
        if let Err(rearm_error) = self.rearm_udp_endpoint() {
            self.record_udp_endpoint_error(error)?;
            let _ = self.publish_udp_readiness();
            return Err(rearm_error);
        }
        let _ = self.publish_udp_readiness();
        Ok(error)
    }

    /// Takes an error that the host socket no longer reports, because a
    /// receive took it, so that the next transfer reports it.
    fn take_consumed_udp_endpoint_error(&mut self) -> BrokerResult<Option<SocketError>> {
        match self.udp_endpoint()?.error.consumed() {
            Some(error) => self.finish_udp_endpoint_error(error).map(Some),
            None => Ok(None),
        }
    }

    /// Discards queued native datagrams the socket does not accept, leaving
    /// the endpoint readable only if an accepted datagram or an error is at
    /// the head.
    fn drain_rejected_external_datagrams(&mut self) -> BrokerResult<()> {
        self.udp_endpoint_mut()?.readable = false;
        for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            let host_source = match receive_datagram(
                &self.udp_endpoint()?.socket,
                RawParts::EMPTY,
                ReceiveFromFlags::PEEK,
            ) {
                Ok(ReceiveFromOutcome::Received { source_address, .. }) => source_address,
                Ok(ReceiveFromOutcome::Failed(error)) => {
                    self.record_udp_endpoint_error(error)?;
                    self.udp_endpoint_mut()?.readable = true;
                    return Ok(());
                }
                Err(BrokerError::WouldBlock) => return Ok(()),
                Err(error) => return Err(error),
            };
            if self.resolve_external_udp_source(host_source)?.is_some() {
                self.udp_endpoint_mut()?.readable = true;
                return Ok(());
            }
            match receive_datagram(
                &self.udp_endpoint()?.socket,
                RawParts::EMPTY,
                ReceiveFromFlags::NONE,
            ) {
                Ok(ReceiveFromOutcome::Received { .. }) => {}
                Ok(ReceiveFromOutcome::Failed(error)) => {
                    self.record_udp_endpoint_error(error)?;
                    self.udp_endpoint_mut()?.readable = true;
                    return Ok(());
                }
                Err(BrokerError::WouldBlock) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(super) fn send_external_udp(
        &mut self,
        data: RawParts<'_>,
        external_destination: SocketAddrV4,
    ) -> BrokerResult<SocketOutcome<usize>> {
        if let Some(error) = self.take_consumed_udp_endpoint_error()? {
            return Ok(SocketOutcome::Failed(error));
        }
        let destination = host_socket_destination(external_destination);
        let past_peer = matches!(
            self.udp_state()?.peer,
            Some(UdpPeer::External(peer)) if host_socket_destination(peer) != destination
        );
        let result = {
            // Hold the port set so no broker endpoint appears on the
            // destination port between the check and the send.
            let ports = read_lock(&self.core().udp_ports);
            if ports.targets_broker_endpoint(destination) {
                return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
            }
            let socket = &self.udp_endpoint()?.socket;
            loop {
                let sent = if past_peer {
                    socket.send_as_unconnected(data, destination)
                } else {
                    socket.send(data, Some(destination))
                };
                match sent {
                    Ok(sent) if sent == data.len() => break Ok(SocketOutcome::Completed(sent)),
                    Ok(_) => break Err(BrokerError::Internal),
                    Err(Errno::INTR) => {}
                    Err(Errno::AGAIN) => break Err(BrokerError::WouldBlock),
                    Err(error) => {
                        break socket_operation_error_from_errno(error).map(SocketOutcome::Failed);
                    }
                }
            }
        };
        if matches!(result, Err(BrokerError::WouldBlock)) {
            self.udp_endpoint_mut()?.write_blocked = true;
            self.rearm_udp_endpoint_and_publish()?;
        }
        result
    }

    pub(super) fn receive_external_udp(
        &mut self,
        output: RawParts<'_>,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<Option<ReceiveFromOutcome>> {
        let Some(endpoint) = self.udp_state()?.native_endpoint.as_ref() else {
            return Ok(None);
        };
        if let Some(error) = endpoint.error.consumed() {
            return self.finish_udp_receive_error(error);
        }
        if !endpoint.readable {
            return Ok(None);
        }
        for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
            // Peek at no bytes, so a rejected sender's bytes never reach the
            // output.
            let host_source = match receive_datagram(
                &self.udp_endpoint()?.socket,
                RawParts::EMPTY,
                ReceiveFromFlags::PEEK,
            ) {
                Ok(ReceiveFromOutcome::Received { source_address, .. }) => source_address,
                Ok(ReceiveFromOutcome::Failed(error)) => {
                    return self.finish_udp_receive_error(error);
                }
                Err(BrokerError::WouldBlock) => {
                    self.clear_udp_readable_and_rearm()?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            if let Some(source_address) = self.resolve_external_udp_source(host_source)? {
                return self.consume_external_udp(output, source_address, flags);
            }
            match receive_datagram(
                &self.udp_endpoint()?.socket,
                RawParts::EMPTY,
                ReceiveFromFlags::NONE,
            ) {
                Ok(ReceiveFromOutcome::Received { .. }) => {}
                Ok(ReceiveFromOutcome::Failed(error)) => {
                    return self.finish_udp_receive_error(error);
                }
                Err(BrokerError::WouldBlock) => {
                    self.clear_udp_readable_and_rearm()?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        self.clear_udp_readable_and_rearm()?;
        Ok(None)
    }

    /// Receives the accepted native datagram at the head of the endpoint,
    /// sent from `source_address`, into `output`, dequeuing it unless the
    /// caller only peeks.
    ///
    /// The socket is its endpoint's only reader, so the head stays the
    /// datagram the caller peeked.
    fn consume_external_udp(
        &mut self,
        output: RawParts<'_>,
        source_address: SocketAddrV4,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<Option<ReceiveFromOutcome>> {
        if flags.contains(ReceiveFromFlags::PEEK) {
            let (received, datagram_length) = match receive_datagram(
                &self.udp_endpoint()?.socket,
                output,
                ReceiveFromFlags::PEEK,
            ) {
                Ok(ReceiveFromOutcome::Received {
                    received,
                    datagram_length,
                    ..
                }) => (received, datagram_length),
                Ok(ReceiveFromOutcome::Failed(error)) => {
                    return self.finish_udp_receive_error(error);
                }
                Err(BrokerError::WouldBlock) => {
                    self.clear_udp_readable_and_rearm()?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            self.udp_state_mut()?.peeked_origin = Some(UdpReceiveOrigin::External);
            return Ok(Some(ReceiveFromOutcome::Received {
                received,
                datagram_length,
                source_address,
            }));
        }
        let endpoint = self.udp_endpoint_mut()?;
        let should_rearm = !endpoint.error.is_pending();
        if should_rearm {
            endpoint.readable = false;
            if let Err(error) = self.rearm_udp_endpoint() {
                self.udp_endpoint_mut()?.readable = true;
                return Err(error);
            }
        }
        let (received, datagram_length) =
            match receive_datagram(&self.udp_endpoint()?.socket, output, ReceiveFromFlags::NONE) {
                Ok(ReceiveFromOutcome::Received {
                    received,
                    datagram_length,
                    ..
                }) => (received, datagram_length),
                Ok(ReceiveFromOutcome::Failed(error)) => {
                    return self.finish_udp_receive_error(error);
                }
                Err(BrokerError::WouldBlock) => {
                    let _ = self.publish_udp_readiness();
                    return Ok(None);
                }
                Err(error) => {
                    self.udp_endpoint_mut()?.readable = true;
                    return Err(error);
                }
            };
        let udp = self.udp_state_mut()?;
        udp.peeked_origin = None;
        udp.next_receive_origin = UdpReceiveOrigin::Internal;
        // Consumption is committed. The endpoint was rearmed before the
        // dequeue. Refresh the cached head state so another accepted datagram
        // keeps READ asserted without an asynchronous low-to-high publication.
        let _ = self.drain_rejected_external_datagrams();
        // Consumption is irreversible; ignore a failure to recompute
        // readiness.
        let _ = self.publish_udp_readiness();
        Ok(Some(ReceiveFromOutcome::Received {
            received,
            datagram_length,
            source_address,
        }))
    }
}

impl ProviderCore {
    fn allocate_udp_event_token(&self) -> BrokerResult<u64> {
        self.next_udp_event_token
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
                token
                    .checked_add(1)
                    .filter(|next| *next < UDP_EVENT_TOKEN_FLAG)
            })
            .map(|token| UDP_EVENT_TOKEN_FLAG | token)
            .map_err(|_| BrokerError::ResourceExhausted)
    }
}

#[cfg(test)]
impl ProviderCore {
    pub(super) fn udp_native_endpoint_count(&self) -> usize {
        read_lock(&self.udp_ports).native.len()
    }

    pub(super) fn udp_native_event_token_count(&self) -> usize {
        read_lock(&self.registry).udp_tokens.len()
    }

    pub(super) fn udp_queued_datagram_count(&self) -> usize {
        self.udp_queued.datagrams.load(Ordering::Relaxed)
    }

    pub(super) fn udp_external_peer_count(&self) -> usize {
        lock(&self.topology).udp.external_peer_count
    }

    /// Whether datagrams `process_authority` sent are charged to it.
    pub(super) fn has_udp_source_accounting(&self, process_authority: ProcessId) -> bool {
        lock(&self.topology)
            .processes
            .get(&process_authority)
            .is_some_and(|process| process.udp_counters.sent.datagrams.load(Ordering::Relaxed) != 0)
    }

    pub(super) fn exhaust_udp_event_tokens(&self) {
        self.next_udp_event_token
            .store(UDP_EVENT_TOKEN_FLAG - 1, Ordering::Relaxed);
    }

    /// Runs `operation` on the UDP socket bound to `guest_port`.
    fn with_udp_socket<T>(
        &self,
        guest_port: u16,
        operation: impl FnOnce(&mut SocketEntry<'_>) -> BrokerResult<T>,
    ) -> BrokerResult<T> {
        let socket_id = lock(&self.topology)
            .udp
            .get(guest_port)
            .ok_or(BrokerError::Internal)?
            .socket_id;
        let socket: Arc<UserlandSocket> = read_lock(&self.registry)
            .sockets
            .get(&socket_id)
            .and_then(std::sync::Weak::upgrade)
            .ok_or(BrokerError::Internal)?;
        let result = socket.call(operation);
        // Dropping the last reference retires the socket, so drop it only
        // after the call released the socket's lock.
        drop(socket);
        result
    }

    pub(super) fn inject_udp_status_errors(
        &self,
        guest_port: u16,
        cached_error: SocketError,
        native_error: SocketError,
    ) {
        self.with_udp_socket(guest_port, |socket| {
            socket.pending_error = Some(cached_error);
            let readiness = socket.own() | ReadinessFlags::ERROR;
            set_own_readiness(socket, readiness);
            socket
                .udp_endpoint_mut()?
                .error
                .record_consumed(native_error);
            Ok(())
        })
        .unwrap();
    }

    pub(super) fn udp_native_receive_buffer_size(&self, guest_port: u16) -> Option<usize> {
        self.with_udp_socket(guest_port, |socket| {
            socket
                .udp_state()?
                .native_endpoint
                .as_ref()
                .map(|endpoint| {
                    endpoint
                        .socket
                        .receive_buffer_size()
                        .map_err(broker_error_from_errno)
                })
                .transpose()
        })
        .unwrap()
    }

    pub(super) fn udp_guest_local_address(&self, guest_port: u16) -> Option<SocketAddrV4> {
        self.with_udp_socket(guest_port, |socket| {
            Ok(socket
                .udp_state()?
                .native_endpoint
                .as_ref()
                .map(|endpoint| endpoint.guest_local_address))
        })
        .ok()
        .flatten()
    }

    pub(super) fn udp_native_head_datagram_bytes(&self, guest_port: u16) -> usize {
        self.with_udp_socket(guest_port, |socket| {
            socket
                .udp_endpoint()?
                .socket
                .head_datagram_length()
                .map_err(broker_error_from_errno)
        })
        .unwrap()
    }

    /// Runs `before` while holding the socket bound to `guest_port`, then
    /// receives from a readable native endpoint whose head datagrams are all
    /// rejected; returns whether the endpoint stays readable, the size of the
    /// datagram left at its head, and the receive's 1-byte output, which
    /// starts as 0.
    pub(super) fn exercise_udp_receive_rejection_cap(
        &self,
        guest_port: u16,
        before: impl FnOnce(),
    ) -> BrokerResult<(bool, usize, u8)> {
        self.with_udp_socket(guest_port, |socket| {
            before();
            socket.udp_endpoint_mut()?.readable = true;
            let mut byte = [0];
            let part = [RawBytes::from(&mut byte[..])];
            if socket
                .receive_external_udp(RawParts::from(&part), ReceiveFromFlags::NONE)?
                .is_some()
            {
                return Err(BrokerError::Internal);
            }
            let endpoint = socket.udp_endpoint()?;
            let head_datagram_bytes = endpoint
                .socket
                .head_datagram_length()
                .map_err(broker_error_from_errno)?;
            Ok((endpoint.readable, head_datagram_bytes, byte[0]))
        })
    }
}

/// Receives the datagram at the head of `socket` into `output`, reporting
/// its full length even if `output` is shorter.
fn receive_datagram(
    socket: &HostSocket,
    output: RawParts<'_>,
    flags: ReceiveFromFlags,
) -> BrokerResult<ReceiveFromOutcome> {
    if output.len() > MAX_UDP_DATAGRAM_SIZE as usize || flags.has_unsupported_bits() {
        return Ok(ReceiveFromOutcome::Failed(SocketError::InvalidArgument));
    }
    let peek = flags.contains(ReceiveFromFlags::PEEK);
    loop {
        match socket.receive_datagram(output, peek) {
            Ok((datagram_length, address)) => {
                return Ok(ReceiveFromOutcome::Received {
                    received: datagram_length.min(output.len()),
                    datagram_length,
                    source_address: address.ok_or(BrokerError::Internal)?,
                });
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => return Err(BrokerError::WouldBlock),
            Err(error) => {
                return Ok(ReceiveFromOutcome::Failed(
                    socket_operation_error_from_errno(error)?,
                ));
            }
        }
    }
}

fn take_udp_socket_error(socket: &HostSocket) -> BrokerResult<Option<SocketError>> {
    match socket.take_error() {
        Ok(error) => Ok(error.map(socket_error_from_errno)),
        Err(error) => Err(broker_error_from_errno(error)),
    }
}

fn udp_endpoint_needs_rearm(readable: bool, waiting_for_write: bool, pending_error: bool) -> bool {
    !pending_error && (!readable || waiting_for_write)
}

fn udp_rearm_interest(read_shutdown: bool, readable: bool, waiting_for_write: bool) -> Interest {
    Interest::Oneshot {
        read: udp_watches_reads(read_shutdown) && !readable,
        write: waiting_for_write,
    }
}

/// Whether a native endpoint is watched for reads. One shut for reading
/// discards what arrives, but is still watched on a host that reports errors
/// only to sockets watched for reads.
fn udp_watches_reads(read_shutdown: bool) -> bool {
    !read_shutdown || !host::REPORTS_UNWATCHED_ERRORS
}

fn udp_destination_uses_local_port(destination: SocketAddrV4, local_port: u16) -> bool {
    destination.port() == local_port && is_local_ipv4_address(*destination.ip())
}

/// Reports whether reconnecting the native endpoint `socket` to
/// `host_destination` would keep a source address other than the one the
/// route there selects. Linux fixes a UDP socket's source address at its
/// first connect. Leaving loopback then fails with `EINVAL`; elsewhere,
/// replies to the old source may not return, and a host service bound to the
/// wildcard address sends them from an address other than the connected
/// peer. The socket stages a new endpoint instead. A source that cannot be
/// checked counts as changed.
fn udp_reconnect_changes_source(socket: &HostSocket, host_destination: SocketAddrV4) -> bool {
    let Ok(source) = socket.local_address() else {
        return true;
    };
    !source.ip().is_unspecified() && udp_route_source(host_destination) != Some(*source.ip())
}

/// Returns the source address that the host's route to `host_destination`
/// selects.
fn udp_route_source(host_destination: SocketAddrV4) -> Option<Ipv4Addr> {
    let socket = HostSocket::udp().ok()?;
    loop {
        match socket.connect(host_destination) {
            Ok(()) => break,
            Err(Errno::INTR) => {}
            Err(_) => return None,
        }
    }
    Some(*socket.local_address().ok()?.ip())
}

fn udp_readable_after_error(peeked_origin: Option<UdpReceiveOrigin>) -> bool {
    peeked_origin == Some(UdpReceiveOrigin::External)
}

pub(super) fn udp_queue_limits(
    max_sockets: usize,
    max_sockets_per_process: usize,
) -> (usize, usize, usize, usize) {
    let global_datagrams = max_sockets.saturating_mul(MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET);
    let global_bytes = max_sockets.saturating_mul(MAX_UDP_QUEUE_BYTES_PER_SOCKET);
    let process_datagrams = max_sockets_per_process
        .saturating_mul(MAX_UDP_QUEUE_DATAGRAMS_PER_SOCKET)
        .min(global_datagrams.saturating_sub(1));
    let process_bytes = max_sockets_per_process
        .saturating_mul(MAX_UDP_QUEUE_BYTES_PER_SOCKET)
        .min(global_bytes.saturating_sub(MAX_UDP_DATAGRAM_SIZE as usize));
    (
        global_datagrams,
        global_bytes,
        process_datagrams,
        process_bytes,
    )
}

fn configure_udp_native_receive_buffer(socket: &HostSocket) -> BrokerResult<()> {
    socket
        .set_receive_buffer_size(UDP_NATIVE_RECEIVE_BUFFER_REQUEST)
        .map_err(broker_error_from_errno)?;
    if socket
        .receive_buffer_size()
        .map_err(broker_error_from_errno)?
        > MAX_UDP_NATIVE_RECEIVE_BUFFER
    {
        return Err(BrokerError::ResourceExhausted);
    }
    Ok(())
}

/// Reports whether `address` is one of the host's own, so that the host
/// delivers datagrams sent to it locally.
///
/// A socket binds only a host address, unless Linux's `ip_nonlocal_bind` is
/// set; even then, a socket bound to another address cannot connect, since
/// no route sends from it. The route to a host address may select another
/// address as the source, as Linux's does for a secondary address. An
/// address that cannot be checked counts as local.
pub(super) fn is_local_ipv4_address(address: Ipv4Addr) -> bool {
    if address.is_loopback() || address.is_unspecified() {
        return true;
    }
    let Ok(socket) = HostSocket::udp() else {
        return true;
    };
    match socket.bind(SocketAddrV4::new(address, 0)) {
        Ok(()) => {}
        Err(Errno::ADDRNOTAVAIL) => return false,
        Err(_) => return true,
    }
    // Any nonzero port; connecting a UDP socket sends nothing.
    let probe = SocketAddrV4::new(address, 9);
    loop {
        match socket.connect(probe) {
            Err(Errno::INTR) => {}
            result => return !matches!(result, Err(Errno::NETUNREACH | Errno::HOSTUNREACH)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_write_wait_rearms_output_without_read_spin() {
        assert!(udp_endpoint_needs_rearm(true, true, false));
        assert_eq!(
            udp_rearm_interest(false, true, true),
            Interest::Oneshot {
                read: false,
                write: true
            }
        );
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
    fn only_reserving_udp_peers_keep_native_endpoints_off_their_ports() {
        let mut ports = UdpPorts::default();
        let peer = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7);
        let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
        // A reply peer charged as remote, whose address the host took since.
        assert!(matches!(
            ports.add_peer(peer, false),
            Ok(SocketOutcome::Completed(()))
        ));
        assert!(!ports.port_conflicts(peer.port(), destination));
        assert!(matches!(
            ports.add_peer(peer, true),
            Ok(SocketOutcome::Completed(()))
        ));
        assert!(ports.port_conflicts(peer.port(), destination));
        ports.remove_peer(peer, true);
        assert!(!ports.port_conflicts(peer.port(), destination));
        ports.remove_peer(peer, false);
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
    fn udp_receive_error_preserves_the_oldest_observation() {
        let mut state = UdpNativeErrorState::Consumed(SocketError::ConnectionRefused);
        assert_eq!(
            state.take_receive_error(SocketError::Other),
            SocketError::ConnectionRefused
        );
        assert_eq!(state, UdpNativeErrorState::None);

        state = UdpNativeErrorState::PendingKernel;
        assert_eq!(
            state.take_receive_error(SocketError::Other),
            SocketError::Other
        );
        assert_eq!(state, UdpNativeErrorState::None);
    }

    #[test]
    fn udp_error_preserves_readability_for_an_external_peek() {
        assert!(udp_readable_after_error(Some(UdpReceiveOrigin::External)));
        assert!(!udp_readable_after_error(Some(UdpReceiveOrigin::Internal)));
        assert!(!udp_readable_after_error(None));
    }

    #[test]
    fn broker_udp_endpoint_ports_reject_only_local_destinations() {
        let port = 49152;
        assert!(udp_destination_uses_local_port(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
            port
        ));
        assert!(!udp_destination_uses_local_port(
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port),
            port
        ));
    }

    #[test]
    fn udp_process_queue_limits_remain_below_global_limits() {
        let (global_datagrams, global_bytes, process_datagrams, process_bytes) =
            udp_queue_limits(2, 2);
        assert_eq!(global_datagrams - process_datagrams, 1);
        assert_eq!(global_bytes - process_bytes, MAX_UDP_DATAGRAM_SIZE as usize);
        let (_, _, single_process_datagrams, single_process_bytes) = udp_queue_limits(1, 1);
        assert_ne!(single_process_datagrams, 0);
        assert_ne!(single_process_bytes, 0);
    }

    #[test]
    fn udp_source_limits_count_per_process_instance() {
        let provider = super::super::UserlandSocketProvider::new(4, 4).unwrap();
        let receiver = Arc::new(ProcessCounters::default());
        let exited = Arc::new(ProcessCounters::default());
        let source_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
        let mut inbox = UdpInbox::default();
        for _ in 0..MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE {
            assert!(inbox.has_room(&exited, 1));
            inbox.reserve(&exited).unwrap();
            let charge =
                UdpCharge::reserve(1, &provider.core, receiver.clone(), exited.clone()).unwrap();
            inbox.push(InternalDatagram {
                payload: vec![0],
                source_address,
                charge,
            });
        }
        assert!(!inbox.has_room(&exited, 1));
        // A process that reuses the exited one's ID has its own counters, so
        // the exited instance's queued datagrams do not count against it.
        assert!(inbox.has_room(&Arc::new(ProcessCounters::default()), 1));
        inbox.clear();
        assert!(inbox.has_room(&exited, 1));
        assert_eq!(provider.core.udp_queued_datagram_count(), 0);
    }
}
