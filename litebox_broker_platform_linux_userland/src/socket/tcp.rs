// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux TCP reactor state and transport-specific helpers.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{
    GuestSocketBinding, GuestSourceLease, GuestTcpListenerTarget, PlatformConnectError,
    SocketDestination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE, ReceiveFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOutcome, TcpOptionName, TcpOptionValue,
};
use rustix::event::epoll;
use rustix::io::{Errno, ioctl_fionread};
use rustix::net::ipproto;
use rustix::net::{
    AddressFamily as LinuxAddressFamily, RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags,
    Shutdown as LinuxShutdown, SocketFlags as LinuxSocketFlags, SocketType as LinuxSocketType,
    connect, recv, send, shutdown, socket_with, socketpair, sockopt,
};

use super::{
    Reactor, SocketEntry, SocketKind, SocketLifecycle, SocketSnapshot, SocketTransportState,
    broker_error_from_errno, can_consume_synchronous_error, retain_session_state,
    socket_error_from_errno, socket_operation_error_from_errno, take_socket_error, update_snapshot,
    zeroed_vec,
};

/// Upper bound on connections one logical listener may hold before accept.
///
/// Guest listeners are realized entirely inside the reactor, so the backlog
/// bounds broker-owned descriptors rather than a kernel accept queue.
const MAX_TCP_LISTEN_BACKLOG: usize = 128;

pub(super) struct AcceptedEndpoints {
    pub(super) local_address: SocketAddrV4,
    pub(super) remote: SocketDestination,
    pub(super) guest_source: GuestSourceLease,
}

pub(super) enum ReactorReceiveOutcome {
    Received(Vec<u8>),
    EndOfStream,
    Failed(SocketError),
}

pub(super) struct PeekCache {
    pub(super) socket_id: u64,
    pub(super) requested_length: usize,
    pub(super) data: Vec<u8>,
}

/// Reactor-owned TCP descriptor and its route-specific realization.
pub(super) enum TcpDescriptor {
    /// Broker-local `AF_UNIX` stream realizing one guest-to-guest connection.
    ///
    /// Both ends stay inside the reactor, so guest streams never consume a host
    /// port and are unreachable from anything outside the broker.
    Virtual(OwnedFd),
    /// Host `AF_INET` stream used only by gateway and external routes.
    Native(OwnedFd),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TcpTransportKind {
    NoDescriptor,
    Virtual,
    Native,
}

impl TcpDescriptor {
    pub(super) const fn socket(&self) -> &OwnedFd {
        match self {
            Self::Virtual(socket) | Self::Native(socket) => socket,
        }
    }

    pub(super) const fn is_virtual(&self) -> bool {
        matches!(self, Self::Virtual(_))
    }
}

/// Broker-local peer of one virtual guest stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum VirtualPeer {
    /// No broker-local peer exists, or the peer is already gone.
    #[default]
    None,
    /// The connect is waiting for backlog space on this listener socket.
    Blocked(u64),
    /// The peer descriptor is queued for accept on this listener socket.
    Queued(u64),
    /// The peer is this live reactor socket.
    Live(u64),
}

/// One accepted-but-unclaimed virtual stream held by a logical listener.
pub(super) struct QueuedGuestConnection {
    socket: OwnedFd,
    guest_source: GuestSourceLease,
    /// Connector socket while it stays live; `None` once it has closed.
    connector_id: Option<u64>,
    /// Session charged for this queued accept slot.
    session_id: SessionId,
}

/// Reactor-owned TCP descriptor and transport-specific lifecycle state.
#[expect(
    clippy::struct_excessive_bools,
    reason = "TCP lifecycle and option flags are independent"
)]
#[derive(Default)]
pub(super) struct TcpSocketState {
    /// Descriptor for a connected socket; logical listeners own none.
    pub(super) socket: Option<TcpDescriptor>,
    pub(super) peek_waitall_threshold: Option<usize>,
    pub(super) listening: bool,
    pub(super) backlog: usize,
    pub(super) pending_accepts: VecDeque<QueuedGuestConnection>,
    pub(super) blocked_connectors: VecDeque<u64>,
    /// Source lease held while a guest connect waits for backlog space.
    pub(super) blocked_guest_source: Option<GuestSourceLease>,
    pub(super) peer: VirtualPeer,
    pub(super) peer_reset: bool,
    pub(super) abortive_close: bool,
    pub(super) no_delay: bool,
    pub(super) keep_alive: bool,
}

impl TcpSocketState {
    const fn is_virtual(&self) -> bool {
        match &self.socket {
            Some(descriptor) => descriptor.is_virtual(),
            None => false,
        }
    }

    /// Returns the host descriptor, if this socket owns one.
    pub(super) const fn host_socket(&self) -> Option<&OwnedFd> {
        match &self.socket {
            Some(TcpDescriptor::Native(socket)) => Some(socket),
            Some(TcpDescriptor::Virtual(_)) | None => None,
        }
    }

    #[cfg(test)]
    pub(super) const fn transport_kind(&self) -> TcpTransportKind {
        match &self.socket {
            Some(TcpDescriptor::Virtual(_)) => TcpTransportKind::Virtual,
            Some(TcpDescriptor::Native(_)) => TcpTransportKind::Native,
            None => TcpTransportKind::NoDescriptor,
        }
    }
}

impl SocketEntry {
    pub(super) fn tcp_state(&self) -> BrokerResult<&TcpSocketState> {
        match &self.transport {
            SocketTransportState::Tcp(tcp) => Ok(tcp),
            SocketTransportState::Udp(_) => Err(BrokerError::Internal),
        }
    }

    pub(super) fn tcp_state_mut(&mut self) -> BrokerResult<&mut TcpSocketState> {
        match &mut self.transport {
            SocketTransportState::Tcp(tcp) => Ok(tcp),
            SocketTransportState::Udp(_) => Err(BrokerError::Internal),
        }
    }

    /// Returns the TCP descriptor, or `None` for a socket that owns none.
    fn tcp_socket(&self) -> BrokerResult<Option<&OwnedFd>> {
        Ok(self.tcp_state()?.socket.as_ref().map(TcpDescriptor::socket))
    }
}

pub(super) fn create_tcp_transport() -> SocketTransportState {
    // Guest routes never need a host descriptor, so one is created lazily and
    // only for the gateway and external routes that must leave the broker.
    SocketTransportState::Tcp(TcpSocketState::default())
}

/// Creates one anonymous nonblocking `AF_UNIX` stream pair.
fn create_virtual_stream_pair() -> BrokerResult<(OwnedFd, OwnedFd)> {
    socketpair(
        LinuxAddressFamily::UNIX,
        LinuxSocketType::STREAM,
        LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
        None,
    )
    .map_err(broker_error_from_errno)
}

fn register_socket_events(epoll_fd: &OwnedFd, socket: &OwnedFd, id: u64) -> BrokerResult<()> {
    epoll::add(
        epoll_fd,
        socket,
        epoll::EventData::new_u64(id),
        active_epoll_events(),
    )
    .map_err(broker_error_from_errno)
}

/// Reactor-owned realization of guest TCP bindings and queued accepts.
#[derive(Default)]
pub(super) struct ReactorTcpState {
    pub(super) bindings: ReactorTcpBindings,
    /// Broker-wide count of queued and reserved accept slots.
    pub(super) queued_accepts: usize,
    pub(super) peek_cache: Option<PeekCache>,
}

#[derive(Default)]
pub(super) struct ReactorTcpBindings {
    wildcard: HashMap<u16, ReactorTcpBinding>,
    exact: HashMap<SocketAddrV4, ReactorTcpBinding>,
}

impl ReactorTcpBindings {
    pub(super) fn clear(&mut self) {
        self.wildcard.clear();
        self.exact.clear();
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &ReactorTcpBinding> {
        self.wildcard.values().chain(self.exact.values())
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut ReactorTcpBinding> {
        self.wildcard.values_mut().chain(self.exact.values_mut())
    }

    #[cfg(test)]
    pub(super) fn get(&self, port: u16) -> Option<&ReactorTcpBinding> {
        self.wildcard.get(&port).or_else(|| {
            self.exact
                .iter()
                .find_map(|(address, binding)| (address.port() == port).then_some(binding))
        })
    }
}

fn readiness_from_epoll(socket: &SocketEntry, events: epoll::EventFlags) -> ReadinessFlags {
    let mut readiness = ReadinessFlags::default();
    if events.contains(epoll::EventFlags::IN) {
        readiness = readiness | ReadinessFlags::READ;
    }
    if events.contains(epoll::EventFlags::OUT) && !socket.write_shutdown {
        readiness = readiness | ReadinessFlags::WRITE;
    }
    if socket.kind() == SocketKind::Tcp
        && !socket.read_shutdown
        && events.intersects(epoll::EventFlags::RDHUP | epoll::EventFlags::HUP)
    {
        readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
    }
    if events.contains(epoll::EventFlags::ERR) {
        readiness = readiness | ReadinessFlags::ERROR;
    }
    let previous = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    ReadinessFlags(readiness.0 | previous.0)
}

fn active_epoll_events() -> epoll::EventFlags {
    // Cached readiness turns these edge-triggered kernel events into the
    // level-triggered snapshots consumed by the broker protocol.
    epoll::EventFlags::IN
        | epoll::EventFlags::OUT
        | epoll::EventFlags::RDHUP
        | epoll::EventFlags::ET
}

fn add_readiness(socket: &SocketEntry, readiness: ReadinessFlags) -> BrokerResult<()> {
    let current = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    update_snapshot(socket, None, ReadinessFlags(current.0 | readiness.0))
}

fn clear_readiness(socket: &SocketEntry, readiness: ReadinessFlags) -> BrokerResult<()> {
    let current = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    update_snapshot(socket, None, ReadinessFlags(current.0 & !readiness.0))
}

fn consume_synchronous_error(socket: &SocketEntry) -> BrokerResult<()> {
    let query_socket_error = {
        let snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        if !can_consume_synchronous_error(socket.kind(), socket.connection_status) {
            return Ok(());
        }
        snapshot.pending_error.is_none()
    };
    let socket_error = if query_socket_error {
        take_socket_error(socket)?
    } else {
        None
    };
    let (readiness, changed) = {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        if snapshot.pending_error.is_none() {
            snapshot.pending_error = socket_error;
        }
        let readiness = if snapshot.pending_error.is_some() {
            snapshot.readiness | ReadinessFlags::ERROR
        } else {
            ReadinessFlags(snapshot.readiness.0 & !ReadinessFlags::ERROR.0)
        };
        let changed = readiness != snapshot.readiness;
        snapshot.readiness = readiness;
        (readiness, changed)
    };
    if changed {
        socket.readiness.publish(readiness)?;
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct ReactorTcpBinding {
    pub(super) socket_id: u64,
    pub(super) binding: GuestSocketBinding,
    pub(super) listening: bool,
}

impl ReactorTcpState {
    pub(super) fn clear_live_state(&mut self) {
        self.bindings.clear();
        self.queued_accepts = 0;
        self.peek_cache = None;
    }

    pub(super) fn insert_binding(&mut self, binding: ReactorTcpBinding) -> BrokerResult<()> {
        let requested = binding.binding.requested();
        if requested.port() == 0 {
            return Err(BrokerError::Internal);
        }
        if binding.binding.is_wildcard() {
            if self.bindings.wildcard.contains_key(&requested.port())
                || self
                    .bindings
                    .exact
                    .keys()
                    .any(|address| address.port() == requested.port())
            {
                return Err(BrokerError::Internal);
            }
            self.bindings
                .wildcard
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.bindings.wildcard.insert(requested.port(), binding);
        } else {
            if self.bindings.wildcard.contains_key(&requested.port())
                || self.bindings.exact.contains_key(&requested)
            {
                return Err(BrokerError::Internal);
            }
            self.bindings
                .exact
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.bindings.exact.insert(requested, binding);
        }
        Ok(())
    }

    pub(super) fn remove_binding(&mut self, port: u16, socket_id: u64) {
        if self
            .bindings
            .wildcard
            .get(&port)
            .is_some_and(|binding| binding.socket_id == socket_id)
        {
            self.bindings.wildcard.remove(&port);
            return;
        }
        if let Some(address) = self.bindings.exact.iter().find_map(|(address, binding)| {
            (address.port() == port && binding.socket_id == socket_id).then_some(*address)
        }) {
            self.bindings.exact.remove(&address);
        }
    }

    pub(super) fn binding_for_socket(&self, socket_id: u64) -> Option<ReactorTcpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .cloned()
    }

    /// Resolves the listener socket that owns one core-selected listener target.
    ///
    /// Broker core issues the target when it authorizes a guest connect, so the
    /// reactor never has to re-derive a listener from a guest address.
    pub(super) fn listener_for_target(&self, target: GuestTcpListenerTarget) -> Option<u64> {
        self.bindings.values().find_map(|binding| {
            (binding.listening && binding.binding.tcp_listener_target() == Some(target))
                .then_some(binding.socket_id)
        })
    }

    pub(super) fn mark_listening(&mut self, port: u16, socket_id: u64) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| binding.socket_id == socket_id)
            .ok_or(BrokerError::Internal)?;
        if binding.binding.requested().port() != port {
            return Err(BrokerError::Internal);
        }
        binding.listening = true;
        Ok(())
    }

    pub(super) fn stop_listening(&mut self, port: u16, socket_id: u64) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| binding.socket_id == socket_id)
            .ok_or(BrokerError::Internal)?;
        if binding.binding.requested().port() != port {
            return Err(BrokerError::Internal);
        }
        binding.listening = false;
        Ok(())
    }
}

fn confirm_tcp_connected(socket: &mut SocketEntry) {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Connected;
    let readiness = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness;
    let _ = update_snapshot(socket, Some(SocketConnectionStatus::Connected), readiness);
}

/// Records a terminal native operation while a connect is pending.
///
/// A reactor command that can call this helper must subsequently invoke
/// `Reactor::discard_failed_connect_after_command` after releasing its socket
/// table borrow.
fn fail_connect(socket: &mut SocketEntry, error: SocketError) {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Failed(error);
    let readiness = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .readiness
        | ReadinessFlags::ERROR;
    let _ = update_snapshot(
        socket,
        Some(SocketConnectionStatus::Failed(error)),
        readiness,
    );
}

/// Creates the lazily allocated host descriptor for a gateway or external route.
fn create_native_tcp_socket() -> BrokerResult<OwnedFd> {
    socket_with(
        LinuxAddressFamily::INET,
        LinuxSocketType::STREAM,
        LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
        Some(ipproto::TCP),
    )
    .map_err(broker_error_from_errno)
}

/// Connects a gateway or external route over a freshly created host socket.
///
/// Guest-to-guest routes never reach this path; they are realized by
/// [`Reactor::connect_guest_listener`] without any host descriptor.
pub(super) fn connect_native_tcp_socket(
    epoll_fd: &OwnedFd,
    id: u64,
    socket: &mut SocketEntry,
    local_guest_address: SocketAddrV4,
    address: SocketAddrV4,
) -> core::result::Result<(SocketConnectionStatus, ReadinessFlags), PlatformConnectError> {
    if socket.connection_status != SocketConnectionStatus::Unconnected {
        return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
    }
    let tcp = socket
        .tcp_state()
        .map_err(PlatformConnectError::PeerUnchanged)?;
    if tcp.socket.is_some() || tcp.listening {
        return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
    }
    let (no_delay, keep_alive) = (tcp.no_delay, tcp.keep_alive);
    let native = create_native_tcp_socket().map_err(PlatformConnectError::PeerUnchanged)?;
    // Options accepted while the socket had no descriptor are cached, so they
    // must reach the host socket before it carries any traffic.
    apply_cached_tcp_options(&native, no_delay, keep_alive)
        .map_err(PlatformConnectError::PeerUnchanged)?;
    register_socket_events(epoll_fd, &native, id).map_err(PlatformConnectError::PeerUnchanged)?;
    socket
        .tcp_state_mut()
        .map_err(PlatformConnectError::PeerUnchanged)?
        .socket = Some(TcpDescriptor::Native(native));
    socket.guest_local_address = Some(local_guest_address);
    socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned")
        .local_address = Some(local_guest_address);
    // Record the first half of the native transition before connect(2). Any
    // later failure can then be settled or conservatively retired without
    // reconstructing whether a SYN may have reached the destination.
    socket.connection_status = SocketConnectionStatus::Connecting;
    let status = loop {
        match connect(
            socket
                .tcp_socket()
                .map_err(PlatformConnectError::PeerIndeterminate)?
                .ok_or(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ))?,
            &address,
        ) {
            Ok(()) | Err(Errno::ISCONN) => break SocketConnectionStatus::Connected,
            Err(Errno::INTR) => {}
            Err(Errno::INPROGRESS | Errno::ALREADY) => {
                break SocketConnectionStatus::Connecting;
            }
            Err(error) => {
                let error = match socket_operation_error_from_errno(error) {
                    Ok(error) => error,
                    Err(error) => {
                        socket.connection_status =
                            SocketConnectionStatus::Failed(SocketError::Other);
                        update_snapshot(
                            socket,
                            Some(SocketConnectionStatus::Failed(SocketError::Other)),
                            ReadinessFlags::ERROR,
                        )
                        .map_err(PlatformConnectError::PeerIndeterminate)?;
                        return Err(PlatformConnectError::PeerIndeterminate(error));
                    }
                };
                break SocketConnectionStatus::Failed(error);
            }
        }
    };
    socket.connection_status = status;
    let readiness = match status {
        SocketConnectionStatus::Connected | SocketConnectionStatus::Connecting => {
            if status == SocketConnectionStatus::Connected {
                ReadinessFlags::WRITE
            } else {
                ReadinessFlags::default()
            }
        }
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        SocketConnectionStatus::Unconnected => ReadinessFlags::default(),
        _ => {
            return Err(PlatformConnectError::PeerIndeterminate(
                BrokerError::Internal,
            ));
        }
    };
    Ok((status, readiness))
}

/// Marks a guest socket as a logical listener.
///
/// Guest listeners have no host descriptor: connections are queued directly on
/// this socket by [`Reactor::connect_guest_listener`], so `listen(2)` reduces
/// to recording the requested backlog.
pub(super) fn listen_tcp_socket(
    socket: &mut SocketEntry,
    backlog: u32,
) -> BrokerResult<SocketOutcome<()>> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let tcp = socket.tcp_state()?;
    if tcp.socket.is_some() {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let backlog = usize::try_from(backlog)
        .map_err(|_| BrokerError::UnsupportedOperation)?
        .clamp(1, MAX_TCP_LISTEN_BACKLOG);
    let was_listening = tcp.listening;
    let tcp = socket.tcp_state_mut()?;
    tcp.listening = true;
    tcp.backlog = backlog;
    if !was_listening {
        let mut snapshot = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        snapshot.readiness = ReadinessFlags::default();
    }
    Ok(SocketOutcome::Completed(()))
}

/// Resolves the descriptor a data-path operation must use.
fn tcp_descriptor(socket: &SocketEntry) -> BrokerResult<&OwnedFd> {
    socket.tcp_socket()?.ok_or(BrokerError::Internal)
}

/// Reports the terminal condition, if any, that blocks data-path use.
///
/// A peer reset is sticky and outranks the descriptor state. A socket without
/// a descriptor is either a guest connect still waiting for backlog space,
/// which must block, or a socket that was never connected.
fn tcp_data_path_error(socket: &SocketEntry) -> BrokerResult<Option<SocketError>> {
    let tcp = socket.tcp_state()?;
    if tcp.peer_reset {
        return Ok(Some(SocketError::ConnectionReset));
    }
    if tcp.socket.is_none() {
        if socket.connection_status == SocketConnectionStatus::Connecting {
            return Err(BrokerError::WouldBlock);
        }
        return Ok(Some(SocketError::NotConnected));
    }
    Ok(None)
}

pub(super) fn send_socket(
    socket: &mut SocketEntry,
    data: &[u8],
) -> BrokerResult<SocketOutcome<usize>> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if socket.write_shutdown {
        return Ok(SocketOutcome::Failed(SocketError::Other));
    }
    if let Some(error) = tcp_data_path_error(socket)? {
        return Ok(SocketOutcome::Failed(error));
    }
    loop {
        let result = send(tcp_descriptor(socket)?, data, LinuxSendFlags::NOSIGNAL);
        match result {
            Ok(sent) => {
                if sent != 0 {
                    confirm_tcp_connected(socket);
                }
                return Ok(SocketOutcome::Completed(sent));
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                clear_readiness(socket, ReadinessFlags::WRITE)?;
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                fail_connect(socket, error);
                let _ = consume_synchronous_error(socket);
                return Ok(SocketOutcome::Failed(error));
            }
        }
    }
}

pub(super) fn receive_socket(
    socket: &mut SocketEntry,
    peek_cache: &mut Option<PeekCache>,
    socket_id: u64,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<ReactorReceiveOutcome> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(ReactorReceiveOutcome::Failed(SocketError::InvalidArgument));
    }
    if let Some(error) = tcp_data_path_error(socket)? {
        return Ok(ReactorReceiveOutcome::Failed(error));
    }
    let peek = flags.contains(ReceiveFlags::PEEK);
    if !peek {
        if peek_offset != 0 || peek_length != 0 {
            return Err(BrokerError::UnsupportedOperation);
        }
        if peek_cache
            .as_ref()
            .is_some_and(|cache| cache.socket_id == socket_id)
        {
            *peek_cache = None;
        }
        return receive_socket_once(socket, zeroed_vec(length)?, LinuxRecvFlags::empty());
    }

    let peek_end = peek_offset
        .checked_add(length)
        .ok_or(BrokerError::UnsupportedOperation)?;
    let canonical_length = peek_length
        .checked_sub(peek_offset)
        .map(|remaining| remaining.min(MAX_SOCKET_TRANSFER_SIZE as usize));
    if !peek_offset.is_multiple_of(MAX_SOCKET_TRANSFER_SIZE as usize)
        || canonical_length != Some(length)
        || peek_length < peek_end
        || peek_length > MAX_SOCKET_PEEK_SIZE as usize
    {
        return Err(BrokerError::UnsupportedOperation);
    }
    if flags.contains(ReceiveFlags::WAITALL) {
        let snapshot = *socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned");
        let terminal = socket.read_shutdown
            || snapshot.readiness.contains(ReadinessFlags::HANGUP)
            || snapshot.readiness.contains(ReadinessFlags::ERROR);
        if socket.connection_status == SocketConnectionStatus::Connected
            && !terminal
            && ioctl_fionread(tcp_descriptor(socket)?).map_err(broker_error_from_errno)?
                < peek_length.try_into().map_err(|_| BrokerError::Internal)?
        {
            let tcp = socket.tcp_state_mut()?;
            tcp.peek_waitall_threshold = Some(
                tcp.peek_waitall_threshold
                    .map_or(peek_length, |threshold| threshold.min(peek_length)),
            );
            return Err(BrokerError::WouldBlock);
        }
    }

    let refresh_exhausted_cache = match peek_cache.as_ref() {
        Some(cache)
            if cache.socket_id == socket_id
                && cache.requested_length == peek_length
                && cache.data.len() <= peek_offset =>
        {
            usize::try_from(
                ioctl_fionread(tcp_descriptor(socket)?).map_err(broker_error_from_errno)?,
            )
            .map_err(|_| BrokerError::Internal)?
                > cache.data.len()
        }
        _ => false,
    };
    let refresh = peek_offset == 0
        || !peek_cache.as_ref().is_some_and(|cache| {
            cache.socket_id == socket_id && cache.requested_length == peek_length
        })
        || refresh_exhausted_cache;
    if refresh {
        *peek_cache = None;
        let flags = if flags.contains(ReceiveFlags::WAITALL) {
            LinuxRecvFlags::PEEK | LinuxRecvFlags::WAITALL
        } else {
            LinuxRecvFlags::PEEK
        };
        match receive_socket_once(socket, zeroed_vec(peek_length)?, flags)? {
            ReactorReceiveOutcome::Received(data) => {
                *peek_cache = Some(PeekCache {
                    socket_id,
                    requested_length: peek_length,
                    data,
                });
            }
            outcome => return Ok(outcome),
        }
    }

    let cache = peek_cache.as_ref().ok_or(BrokerError::Internal)?;
    if cache.data.len() <= peek_offset {
        let readiness = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        let terminal = socket.read_shutdown
            || readiness.contains(ReadinessFlags::HANGUP)
            || readiness.contains(ReadinessFlags::ERROR);
        *peek_cache = None;
        return if terminal {
            Ok(ReactorReceiveOutcome::EndOfStream)
        } else {
            Err(BrokerError::WouldBlock)
        };
    }
    let end = peek_end.min(cache.data.len());
    let mut data = Vec::new();
    data.try_reserve_exact(end - peek_offset)
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.extend_from_slice(&cache.data[peek_offset..end]);
    if end < peek_end || end == peek_length {
        *peek_cache = None;
    }
    Ok(ReactorReceiveOutcome::Received(data))
}

fn receive_socket_once(
    socket: &mut SocketEntry,
    mut data: Vec<u8>,
    flags: LinuxRecvFlags,
) -> BrokerResult<ReactorReceiveOutcome> {
    loop {
        let result = recv(tcp_descriptor(socket)?, data.as_mut_slice(), flags);
        match result {
            Ok((_buffer, 0)) => {
                confirm_tcp_connected(socket);
                let readiness = if socket.read_shutdown {
                    ReadinessFlags::READ
                } else {
                    ReadinessFlags::READ | ReadinessFlags::HANGUP
                };
                let _ = add_readiness(socket, readiness);
                return Ok(ReactorReceiveOutcome::EndOfStream);
            }
            Ok((_buffer, received)) => {
                confirm_tcp_connected(socket);
                data.truncate(received);
                let terminal_readable = socket.read_shutdown
                    || socket
                        .snapshot
                        .lock()
                        .expect("Linux socket snapshot mutex poisoned")
                        .readiness
                        .contains(ReadinessFlags::HANGUP);
                if !flags.contains(LinuxRecvFlags::PEEK) && !terminal_readable {
                    let no_queued_data = ioctl_fionread(tcp_descriptor(socket)?)
                        .is_ok_and(|available| available == 0);
                    if no_queued_data {
                        let _ = clear_readiness(socket, ReadinessFlags::READ);
                    }
                }
                return Ok(ReactorReceiveOutcome::Received(data));
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                // A virtual stream cannot shut down its own read half without
                // signalling the peer, so a local read shutdown is emulated by
                // reporting the end of stream the kernel would deliver.
                let tcp = socket.tcp_state()?;
                if socket.read_shutdown && tcp.is_virtual() {
                    return Ok(ReactorReceiveOutcome::EndOfStream);
                }
                clear_readiness(socket, ReadinessFlags::READ)?;
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                let error = socket_operation_error_from_errno(error)?;
                fail_connect(socket, error);
                let _ = consume_synchronous_error(socket);
                return Ok(ReactorReceiveOutcome::Failed(error));
            }
        }
    }
}

pub(super) fn set_tcp_option(socket: &mut SocketEntry, value: TcpOptionValue) -> BrokerResult<()> {
    if socket.kind() != SocketKind::Tcp {
        return Err(BrokerError::UnsupportedOperation);
    }
    // Options are cached on the reactor entry because virtual guest streams
    // reject the TCP level and a native descriptor may not exist yet. The
    // cache is replayed when a gateway or external route creates one.
    match value {
        TcpOptionValue::NoDelay(value) => {
            if let Some(TcpDescriptor::Native(native)) = socket.tcp_state()?.socket.as_ref() {
                sockopt::set_tcp_nodelay(native, value).map_err(broker_error_from_errno)?;
            }
            socket.tcp_state_mut()?.no_delay = value;
        }
        TcpOptionValue::KeepAlive(value) => {
            if let Some(TcpDescriptor::Native(native)) = socket.tcp_state()?.socket.as_ref() {
                sockopt::set_socket_keepalive(native, value).map_err(broker_error_from_errno)?;
            }
            socket.tcp_state_mut()?.keep_alive = value;
        }
        _ => return Err(BrokerError::UnsupportedOperation),
    }
    Ok(())
}

/// Replays cached TCP options onto a freshly created host descriptor.
fn apply_cached_tcp_options(
    socket: &OwnedFd,
    no_delay: bool,
    keep_alive: bool,
) -> BrokerResult<()> {
    sockopt::set_tcp_nodelay(socket, no_delay).map_err(broker_error_from_errno)?;
    sockopt::set_socket_keepalive(socket, keep_alive).map_err(broker_error_from_errno)
}

pub(super) fn get_tcp_option(
    socket: &SocketEntry,
    name: TcpOptionName,
) -> BrokerResult<TcpOptionValue> {
    if socket.kind() != SocketKind::Tcp {
        return Err(BrokerError::UnsupportedOperation);
    }
    let tcp = socket.tcp_state()?;
    match name {
        TcpOptionName::NoDelay => Ok(TcpOptionValue::NoDelay(tcp.no_delay)),
        TcpOptionName::KeepAlive => Ok(TcpOptionValue::KeepAlive(tcp.keep_alive)),
        _ => Err(BrokerError::UnsupportedOperation),
    }
}

pub(super) fn shutdown_tcp_socket(
    socket: &mut SocketEntry,
    mode: ShutdownMode,
) -> BrokerResult<SocketOutcome<()>> {
    if socket.kind() != SocketKind::Tcp {
        return Err(BrokerError::Internal);
    }
    if mode == ShutdownMode::Abort {
        // A virtual stream carries no linger state; its reset is emulated when
        // the descriptor is removed.
        if let Some(TcpDescriptor::Native(native)) = socket.tcp_state()?.socket.as_ref() {
            sockopt::set_socket_linger(native, Some(Duration::ZERO))
                .map_err(broker_error_from_errno)?;
        }
        socket.tcp_state_mut()?.abortive_close = true;
        return Ok(SocketOutcome::Completed(()));
    }
    let stop_listening = mode == ShutdownMode::StopListening;
    let listening = socket.tcp_state()?.listening;
    if stop_listening {
        if !listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let tcp = socket.tcp_state_mut()?;
        tcp.listening = false;
        tcp.peek_waitall_threshold = None;
        socket.read_shutdown = true;
        socket.connection_status = SocketConnectionStatus::Failed(SocketError::NotConnected);
        // The listener transition is complete and the cached terminal snapshot
        // is authoritative even if its notification cannot be published.
        // Acknowledge completion so core listener state cannot diverge from
        // the platform.
        let _ = update_snapshot(
            socket,
            Some(SocketConnectionStatus::Failed(SocketError::NotConnected)),
            ReadinessFlags::WRITE | ReadinessFlags::HANGUP,
        );
        return Ok(SocketOutcome::Completed(()));
    }
    if listening || socket.tcp_state()?.socket.is_none() {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let (add, clear, shuts_down_read, shuts_down_write) = match mode {
        ShutdownMode::Read => (ReadinessFlags::READ, ReadinessFlags::default(), true, false),
        ShutdownMode::Write => (
            ReadinessFlags::default(),
            ReadinessFlags::WRITE,
            false,
            true,
        ),
        ShutdownMode::Both => (ReadinessFlags::READ, ReadinessFlags::WRITE, true, true),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    // Shutting down the read half of a virtual stream would hang up its peer,
    // so only the write half is ever signalled and the local read shutdown is
    // enforced by the reactor instead.
    let linux_mode = if socket.tcp_state()?.is_virtual() {
        shuts_down_write.then_some(LinuxShutdown::Write)
    } else {
        Some(match (shuts_down_read, shuts_down_write) {
            (true, true) => LinuxShutdown::Both,
            (true, false) => LinuxShutdown::Read,
            _ => LinuxShutdown::Write,
        })
    };
    loop {
        if let Some(linux_mode) = linux_mode {
            let result = shutdown(tcp_descriptor(socket)?, linux_mode);
            match result {
                Ok(()) => {}
                Err(Errno::INTR) => continue,
                Err(Errno::NOTCONN) => {
                    fail_connect(socket, SocketError::NotConnected);
                    return Ok(SocketOutcome::Failed(SocketError::NotConnected));
                }
                Err(error) => {
                    let error = socket_operation_error_from_errno(error)?;
                    fail_connect(socket, error);
                    return Ok(SocketOutcome::Failed(error));
                }
            }
        }
        if stop_listening {
            let tcp = socket.tcp_state_mut()?;
            tcp.listening = false;
            tcp.peek_waitall_threshold = None;
            socket.read_shutdown = true;
            socket.connection_status = SocketConnectionStatus::Failed(SocketError::NotConnected);
            // The native transition is complete and the cached terminal
            // snapshot is authoritative even if its notification cannot be
            // published. Acknowledge completion so core listener state cannot
            // diverge from the platform.
            let _ = update_snapshot(
                socket,
                Some(SocketConnectionStatus::Failed(SocketError::NotConnected)),
                ReadinessFlags::WRITE | ReadinessFlags::HANGUP,
            );
            return Ok(SocketOutcome::Completed(()));
        }
        socket.read_shutdown |= shuts_down_read;
        socket.write_shutdown |= shuts_down_write;
        let republish_readiness = shuts_down_read
            && socket
                .tcp_state_mut()?
                .peek_waitall_threshold
                .take()
                .is_some();
        let current = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        let readiness = ReadinessFlags((current.0 & !clear.0) | add.0);
        // Native shutdown and the cached directional state are committed.
        let _ = update_snapshot(socket, None, readiness);
        if republish_readiness {
            let _ = socket.readiness.republish(readiness);
        }
        return Ok(SocketOutcome::Completed(()));
    }
}

pub(super) fn handle_socket_event(
    socket: &mut SocketEntry,
    events: epoll::EventFlags,
) -> BrokerResult<()> {
    if socket.kind() == SocketKind::Udp {
        update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
        return Ok(());
    }
    let republish_readiness = if events.contains(epoll::EventFlags::IN)
        && let Some(threshold) = socket
            .tcp_state()
            .ok()
            .and_then(|tcp| tcp.peek_waitall_threshold)
    {
        let threshold_reached = tcp_descriptor(socket)
            .and_then(|descriptor| ioctl_fionread(descriptor).map_err(broker_error_from_errno))
            .ok()
            .and_then(|available| usize::try_from(available).ok())
            .is_none_or(|available| available >= threshold);
        if threshold_reached {
            socket.tcp_state_mut()?.peek_waitall_threshold = None;
        }
        threshold_reached
    } else {
        false
    };
    match socket.connection_status {
        SocketConnectionStatus::Unconnected => {}
        SocketConnectionStatus::Connecting => {
            complete_connect(socket, events)?;
        }
        SocketConnectionStatus::Connected => {
            update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
        }
        SocketConnectionStatus::Failed(SocketError::NotConnected) if socket.read_shutdown => {
            update_snapshot(socket, None, ReadinessFlags::WRITE | ReadinessFlags::HANGUP)?;
        }
        SocketConnectionStatus::Failed(_) => {
            update_snapshot(socket, None, ReadinessFlags::ERROR)?;
        }
        _ => return Err(BrokerError::Internal),
    }
    if republish_readiness {
        let readiness = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        socket.readiness.republish(readiness)?;
    }
    Ok(())
}

fn complete_connect(
    socket: &mut SocketEntry,
    events: epoll::EventFlags,
) -> BrokerResult<SocketConnectionStatus> {
    // Epoll re-polls the descriptor when waiting, so OUT here reflects the
    // current post-connect state rather than readiness cached before connect.
    let status = match sockopt::socket_error(tcp_descriptor(socket)?) {
        Ok(Ok(())) if events.contains(epoll::EventFlags::OUT) => SocketConnectionStatus::Connected,
        Ok(Ok(())) => SocketConnectionStatus::Connecting,
        Ok(Err(error)) | Err(error) => {
            SocketConnectionStatus::Failed(socket_error_from_errno(error))
        }
    };
    let readiness = match status {
        SocketConnectionStatus::Connected => {
            readiness_from_epoll(socket, events) | ReadinessFlags::WRITE
        }
        SocketConnectionStatus::Connecting => ReadinessFlags::default(),
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        _ => return Err(BrokerError::Internal),
    };
    socket.connection_status = status;
    update_snapshot(socket, Some(status), readiness)?;
    Ok(status)
}

impl Reactor {
    pub(super) fn send_tcp_socket(
        &mut self,
        id: u64,
        data: &[u8],
    ) -> BrokerResult<SocketOutcome<usize>> {
        self.sockets
            .get_mut(&id)
            .ok_or(BrokerError::Internal)
            .and_then(|socket| send_socket(socket, data))
    }

    pub(super) fn receive_tcp_socket(
        &mut self,
        id: u64,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: usize,
        peek_length: usize,
    ) -> BrokerResult<ReactorReceiveOutcome> {
        match self.sockets.get_mut(&id) {
            Some(socket) => receive_socket(
                socket,
                &mut self.tcp.peek_cache,
                id,
                length,
                flags,
                peek_offset,
                peek_length,
            ),
            None => Err(BrokerError::Internal),
        }
    }

    pub(super) fn set_tcp_socket_option(
        &mut self,
        id: u64,
        value: TcpOptionValue,
    ) -> BrokerResult<()> {
        self.sockets
            .get_mut(&id)
            .ok_or(BrokerError::Internal)
            .and_then(|socket| set_tcp_option(socket, value))
    }

    pub(super) fn get_tcp_socket_option(
        &self,
        id: u64,
        name: TcpOptionName,
    ) -> BrokerResult<TcpOptionValue> {
        self.sockets
            .get(&id)
            .ok_or(BrokerError::Internal)
            .and_then(|socket| get_tcp_option(socket, name))
    }

    pub(super) fn shutdown_tcp_socket(
        &mut self,
        id: u64,
        mode: ShutdownMode,
    ) -> BrokerResult<SocketOutcome<()>> {
        if self
            .tcp
            .peek_cache
            .as_ref()
            .is_some_and(|cache| cache.socket_id == id)
        {
            self.tcp.peek_cache = None;
        }
        let was_listening = mode == ShutdownMode::StopListening
            && self
                .sockets
                .get(&id)
                .is_some_and(|socket| socket.tcp_state().is_ok_and(|tcp| tcp.listening));
        let mut outcome = shutdown_tcp_socket(
            self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?,
            mode,
        );
        let stopped_listening = was_listening
            && self
                .sockets
                .get(&id)
                .is_some_and(|socket| socket.tcp_state().is_ok_and(|tcp| !tcp.listening));
        if stopped_listening {
            self.abandon_listener_queue(id);
            let update = self
                .sockets
                .get(&id)
                .and_then(|socket| socket.guest_local_address)
                .ok_or(BrokerError::Internal)
                .and_then(|address| self.tcp.stop_listening(address.port(), id));
            if let Err(error) = update {
                outcome = Err(error);
            }
        }
        outcome
    }

    pub(super) fn bind_tcp_socket(
        &mut self,
        id: u64,
        binding: GuestSocketBinding,
        already_bound: bool,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if already_bound {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = binding.requested();
        self.tcp.insert_binding(ReactorTcpBinding {
            socket_id: id,
            binding,
            listening: false,
        })?;
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        socket.guest_local_address = Some(guest_address);
        socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .local_address = Some(guest_address);
        Ok(SocketOutcome::Completed(guest_address))
    }

    /// Connects a guest socket to its authorized destination.
    ///
    /// Guest destinations are realized entirely inside the reactor: broker core
    /// resolves the logical listener, and the connection is a broker-local
    /// stream pair queued on that listener. Only gateway and external routes
    /// allocate a host descriptor.
    pub(super) fn connect_tcp_destination(
        &mut self,
        id: u64,
        destination: SocketDestination,
        guest_source: Option<GuestSourceLease>,
        listener_target: Option<GuestTcpListenerTarget>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let session_id = self
            .sockets
            .get(&id)
            .map(|socket| socket.session_id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let binding = self
            .tcp
            .binding_for_socket(id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let local_guest_address = match guest_source.as_ref() {
            Some(source)
                if matches!(destination, SocketDestination::Guest { .. })
                    && source.destination() == destination.requested()
                    && binding
                        .binding
                        .covers(&self.network_config, source.source()) =>
            {
                source.source()
            }
            Some(_) => {
                return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
            }
            None => binding
                .binding
                .concrete_address_for(&self.network_config, destination)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?,
        };
        let (status, readiness) = match destination {
            SocketDestination::Guest { .. } => {
                let guest_source = guest_source
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                let listener_target = listener_target
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                if guest_source.listener_target() != listener_target {
                    return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
                }
                self.connect_guest_listener(
                    id,
                    session_id,
                    guest_source,
                    listener_target,
                    local_guest_address,
                )?
            }
            SocketDestination::Gateway { requested } => connect_native_tcp_socket(
                &self.epoll,
                id,
                self.sockets
                    .get_mut(&id)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?,
                local_guest_address,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, requested.port()),
            )?,
            SocketDestination::External { requested } => connect_native_tcp_socket(
                &self.epoll,
                id,
                self.sockets
                    .get_mut(&id)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?,
                local_guest_address,
                requested,
            )?,
        };
        let socket = self
            .sockets
            .get_mut(&id)
            .ok_or(PlatformConnectError::PeerIndeterminate(
                BrokerError::Internal,
            ))?;
        socket.connection_status = status;
        update_snapshot(socket, Some(status), readiness)
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        Ok(status)
    }

    /// Realizes one guest-to-guest connection on its logical listener.
    ///
    /// The connection is either queued for accept together with its source
    /// lease or parked until the listener drains its backlog. Both outcomes
    /// reserve one accept slot, so a listener that never accepts cannot grow
    /// unbounded reactor state.
    fn connect_guest_listener(
        &mut self,
        id: u64,
        session_id: SessionId,
        guest_source: GuestSourceLease,
        listener_target: GuestTcpListenerTarget,
        local_guest_address: SocketAddrV4,
    ) -> core::result::Result<(SocketConnectionStatus, ReadinessFlags), PlatformConnectError> {
        let Some(listener_id) = self.tcp.listener_for_target(listener_target) else {
            return Ok(refused_connect());
        };
        let (queued, blocked, backlog) = {
            let listener = self
                .sockets
                .get(&listener_id)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
            let tcp = listener
                .tcp_state()
                .map_err(PlatformConnectError::PeerUnchanged)?;
            (
                tcp.pending_accepts.len(),
                tcp.blocked_connectors.len(),
                tcp.backlog,
            )
        };
        if queued >= backlog && blocked >= backlog {
            return Ok(refused_connect());
        }
        self.reserve_queued_accept(session_id)
            .map_err(PlatformConnectError::PeerUnchanged)?;
        let outcome = if queued < backlog {
            self.queue_guest_connection(id, listener_id, session_id, guest_source)
        } else {
            self.park_guest_connection(id, listener_id, guest_source)
        };
        match outcome {
            Ok(outcome) => {
                // Queueing is the commit point. Before it succeeds, errors are
                // retryable and must not leave a platform-local address.
                self.record_guest_source_address(id, local_guest_address)
                    .map_err(PlatformConnectError::PeerIndeterminate)?;
                Ok(outcome)
            }
            Err(error) => {
                self.release_queued_accept(session_id);
                Err(PlatformConnectError::PeerUnchanged(error))
            }
        }
    }

    /// Records the guest address a connecting socket sources traffic from.
    fn record_guest_source_address(
        &mut self,
        id: u64,
        local_guest_address: SocketAddrV4,
    ) -> BrokerResult<()> {
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        socket.guest_local_address = Some(local_guest_address);
        socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .local_address = Some(local_guest_address);
        Ok(())
    }

    /// Queues a new stream pair for accept and hands the connector its end.
    fn queue_guest_connection(
        &mut self,
        id: u64,
        listener_id: u64,
        session_id: SessionId,
        guest_source: GuestSourceLease,
    ) -> BrokerResult<(SocketConnectionStatus, ReadinessFlags)> {
        let (connector_socket, listener_socket) = create_virtual_stream_pair()?;
        self.sockets
            .get_mut(&listener_id)
            .ok_or(BrokerError::Internal)?
            .tcp_state_mut()?
            .pending_accepts
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        register_socket_events(&self.epoll, &connector_socket, id)?;
        {
            let connector = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
            connector.connection_status = SocketConnectionStatus::Connected;
            let tcp = connector.tcp_state_mut()?;
            tcp.socket = Some(TcpDescriptor::Virtual(connector_socket));
            tcp.peer = VirtualPeer::Queued(listener_id);
        }
        let listener = self
            .sockets
            .get_mut(&listener_id)
            .ok_or(BrokerError::Internal)?;
        listener
            .tcp_state_mut()?
            .pending_accepts
            .push_back(QueuedGuestConnection {
                socket: listener_socket,
                guest_source,
                connector_id: Some(id),
                session_id,
            });
        // The listener snapshot is authoritative for a queued connection, so a
        // failed notification must not undo an established connection.
        let _ = add_readiness(listener, ReadinessFlags::READ);
        Ok((SocketConnectionStatus::Connected, ReadinessFlags::WRITE))
    }

    /// Parks a connector until the listener frees one backlog slot.
    fn park_guest_connection(
        &mut self,
        id: u64,
        listener_id: u64,
        guest_source: GuestSourceLease,
    ) -> BrokerResult<(SocketConnectionStatus, ReadinessFlags)> {
        self.sockets
            .get_mut(&listener_id)
            .ok_or(BrokerError::Internal)?
            .tcp_state_mut()?
            .blocked_connectors
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        {
            let connector = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
            connector.connection_status = SocketConnectionStatus::Connecting;
            let tcp = connector.tcp_state_mut()?;
            tcp.peer = VirtualPeer::Blocked(listener_id);
            tcp.blocked_guest_source = Some(guest_source);
        }
        self.sockets
            .get_mut(&listener_id)
            .ok_or(BrokerError::Internal)?
            .tcp_state_mut()?
            .blocked_connectors
            .push_back(id);
        Ok((
            SocketConnectionStatus::Connecting,
            ReadinessFlags::default(),
        ))
    }

    /// Reserves one accept slot for a queued or parked guest connection.
    fn reserve_queued_accept(&mut self, session_id: SessionId) -> BrokerResult<()> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(BrokerError::Internal)?;
        // A queued connection owns a reactor descriptor before any socket is
        // created for it, so live and queued resources share the configured
        // provider and connector-session budgets.
        if session
            .live_socket_count
            .checked_add(session.queued_accept_count)
            .is_none_or(|count| count >= self.max_sockets_per_session)
            || self
                .sockets
                .len()
                .checked_add(self.tcp.queued_accepts)
                .is_none_or(|count| count >= self.max_sockets)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        self.sessions
            .get_mut(&session_id)
            .ok_or(BrokerError::Internal)?
            .queued_accept_count += 1;
        self.tcp.queued_accepts = self
            .tcp
            .queued_accepts
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(())
    }

    /// Releases one accept slot reserved by [`Self::reserve_queued_accept`].
    fn release_queued_accept(&mut self, session_id: SessionId) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.queued_accept_count = session
                .queued_accept_count
                .checked_sub(1)
                .expect("session queued accept count underflow");
        }
        self.tcp.queued_accepts = self
            .tcp
            .queued_accepts
            .checked_sub(1)
            .expect("reactor queued accept count underflow");
        self.sessions
            .retain(|_, session| retain_session_state(session));
    }

    /// Marks a live virtual peer as reset by its counterpart.
    ///
    /// A broker-local stream reports a peer close as an ordinary end of
    /// stream, so an abortive close is emulated with a cached error and the
    /// terminal readiness a reset would produce.
    fn reset_virtual_peer(&mut self, peer_id: u64) {
        let Some(peer) = self.sockets.get_mut(&peer_id) else {
            return;
        };
        let Ok(tcp) = peer.tcp_state_mut() else {
            return;
        };
        tcp.peer = VirtualPeer::None;
        tcp.peer_reset = true;
        let readiness = {
            let mut snapshot = peer
                .snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            snapshot.pending_error = Some(SocketError::ConnectionReset);
            snapshot.readiness
                | ReadinessFlags::READ
                | ReadinessFlags::ERROR
                | ReadinessFlags::HANGUP
        };
        // The cached snapshot is authoritative; a failed notification cannot
        // undo the peer reset.
        let _ = update_snapshot(peer, None, readiness);
    }

    /// Clears the virtual peer link a live socket holds, without resetting it.
    fn clear_virtual_peer(&mut self, peer_id: u64) {
        if let Some(peer) = self.sockets.get_mut(&peer_id)
            && let Ok(tcp) = peer.tcp_state_mut()
        {
            tcp.peer = VirtualPeer::None;
        }
    }

    /// Detaches a closing connector from the accept queue of its listener.
    fn detach_queued_connector(&mut self, listener_id: u64, connector_id: u64, reset: bool) {
        let Some(listener) = self.sockets.get_mut(&listener_id) else {
            return;
        };
        let Ok(tcp) = listener.tcp_state_mut() else {
            return;
        };
        let Some(position) = tcp
            .pending_accepts
            .iter()
            .position(|queued| queued.connector_id == Some(connector_id))
        else {
            return;
        };
        if !reset {
            // A graceful close keeps the queued connection acceptable; the
            // late accept observes the end of stream the connector left.
            tcp.pending_accepts[position].connector_id = None;
            return;
        }
        let queued = tcp
            .pending_accepts
            .remove(position)
            .expect("queued guest connection missing");
        let queue_empty = tcp.pending_accepts.is_empty();
        if queue_empty {
            let _ = clear_readiness(listener, ReadinessFlags::READ);
        }
        self.release_queued_accept(queued.session_id);
        self.promote_blocked_connector(listener_id);
    }

    /// Detaches a closing connector that was waiting for backlog space.
    fn detach_blocked_connector(
        &mut self,
        listener_id: u64,
        connector_id: u64,
        session_id: SessionId,
    ) {
        let Some(listener) = self.sockets.get_mut(&listener_id) else {
            return;
        };
        let Ok(tcp) = listener.tcp_state_mut() else {
            return;
        };
        let Some(position) = tcp
            .blocked_connectors
            .iter()
            .position(|blocked| *blocked == connector_id)
        else {
            return;
        };
        tcp.blocked_connectors.remove(position);
        self.release_queued_accept(session_id);
    }

    /// Promotes the first parked connector into the accept queue.
    fn promote_blocked_connector(&mut self, listener_id: u64) {
        loop {
            let Some(listener) = self.sockets.get_mut(&listener_id) else {
                return;
            };
            let Ok(tcp) = listener.tcp_state_mut() else {
                return;
            };
            if !tcp.listening || tcp.pending_accepts.len() >= tcp.backlog {
                return;
            }
            let Some(connector_id) = tcp.blocked_connectors.pop_front() else {
                return;
            };
            let Some(connector) = self.sockets.get_mut(&connector_id) else {
                continue;
            };
            let session_id = connector.session_id;
            let Ok(tcp) = connector.tcp_state_mut() else {
                continue;
            };
            let Some(guest_source) = tcp.blocked_guest_source.take() else {
                continue;
            };
            tcp.peer = VirtualPeer::None;
            if let Ok((status, readiness)) =
                self.queue_guest_connection(connector_id, listener_id, session_id, guest_source)
            {
                if let Some(connector) = self.sockets.get(&connector_id) {
                    // The promoted connector is established even if its status
                    // notification cannot be delivered.
                    let _ = update_snapshot(connector, Some(status), readiness);
                }
            } else {
                self.fail_blocked_connector(connector_id, SocketError::ConnectionReset);
                self.release_queued_accept(session_id);
            }
        }
    }

    /// Fails a parked connector that can never be accepted.
    fn fail_blocked_connector(&mut self, connector_id: u64, error: SocketError) {
        let Some(connector) = self.sockets.get_mut(&connector_id) else {
            return;
        };
        let Ok(tcp) = connector.tcp_state_mut() else {
            return;
        };
        tcp.peer = VirtualPeer::None;
        tcp.blocked_guest_source = None;
        if connector.connection_status != SocketConnectionStatus::Connecting {
            return;
        }
        connector.connection_status = SocketConnectionStatus::Failed(error);
        // The connect outcome is decided; a failed notification cannot revive
        // the parked connection.
        let _ = update_snapshot(
            connector,
            Some(SocketConnectionStatus::Failed(error)),
            ReadinessFlags::ERROR,
        );
    }

    /// Discards every connection a listener still owns.
    ///
    /// Queued peers observe a reset because their connection was never
    /// accepted, and parked connectors are refused.
    fn release_listener_queue(
        &mut self,
        pending_accepts: VecDeque<QueuedGuestConnection>,
        blocked_connectors: VecDeque<u64>,
    ) {
        for queued in pending_accepts {
            drop(queued.socket);
            if let Some(connector_id) = queued.connector_id {
                self.reset_virtual_peer(connector_id);
            }
            self.release_queued_accept(queued.session_id);
        }
        for connector_id in blocked_connectors {
            let session_id = self
                .sockets
                .get(&connector_id)
                .map(|connector| connector.session_id);
            self.fail_blocked_connector(connector_id, SocketError::ConnectionRefused);
            if let Some(session_id) = session_id {
                self.release_queued_accept(session_id);
            }
        }
    }

    /// Releases the accept queue of a listener that stopped listening.
    fn abandon_listener_queue(&mut self, listener_id: u64) {
        let Some(listener) = self.sockets.get_mut(&listener_id) else {
            return;
        };
        let Ok(tcp) = listener.tcp_state_mut() else {
            return;
        };
        let pending_accepts = core::mem::take(&mut tcp.pending_accepts);
        let blocked_connectors = core::mem::take(&mut tcp.blocked_connectors);
        self.release_listener_queue(pending_accepts, blocked_connectors);
    }

    /// Drops unaccepted connections charged to a session being torn down.
    pub(super) fn release_session_queued_accepts(&mut self, session_id: SessionId) {
        loop {
            let Some((listener_id, position)) =
                self.sockets.iter().find_map(|(listener_id, listener)| {
                    listener
                        .tcp_state()
                        .ok()?
                        .pending_accepts
                        .iter()
                        .position(|queued| queued.session_id == session_id)
                        .map(|position| (*listener_id, position))
                })
            else {
                return;
            };
            let (queued, queue_empty) = {
                let listener = self
                    .sockets
                    .get_mut(&listener_id)
                    .expect("queued accept listener missing");
                let tcp = listener
                    .tcp_state_mut()
                    .expect("queued accept listener changed transport");
                let queued = tcp
                    .pending_accepts
                    .remove(position)
                    .expect("queued session connection missing");
                (queued, tcp.pending_accepts.is_empty())
            };
            drop(queued.socket);
            if let Some(connector_id) = queued.connector_id {
                self.reset_virtual_peer(connector_id);
            }
            if queue_empty && let Some(listener) = self.sockets.get_mut(&listener_id) {
                let _ = clear_readiness(listener, ReadinessFlags::READ);
            }
            self.release_queued_accept(queued.session_id);
            self.promote_blocked_connector(listener_id);
        }
    }

    pub(super) fn remove_tcp_socket(&mut self, id: u64, session_id: SessionId) {
        if self
            .tcp
            .peek_cache
            .as_ref()
            .is_some_and(|cache| cache.socket_id == id)
        {
            self.tcp.peek_cache = None;
        }
        let socket = self
            .sockets
            .remove(&id)
            .expect("checked TCP socket missing");
        let SocketEntry {
            transport,
            guest_local_address,
            ..
        } = socket;
        let SocketTransportState::Tcp(TcpSocketState {
            socket,
            pending_accepts,
            blocked_connectors,
            peer,
            abortive_close,
            ..
        }) = transport
        else {
            unreachable!("checked TCP socket changed transport");
        };
        if let Some(address) = guest_local_address {
            self.tcp.remove_binding(address.port(), id);
        }
        // Unread data at close is what turns a peer close into a reset on a
        // real connection, so it is sampled before the descriptor is dropped.
        let reset = abortive_close
            || socket.as_ref().is_some_and(|descriptor| {
                descriptor.is_virtual()
                    && ioctl_fionread(descriptor.socket()).is_ok_and(|available| available > 0)
            });
        drop(socket);
        match peer {
            VirtualPeer::None => {}
            VirtualPeer::Live(peer_id) => {
                if reset {
                    self.reset_virtual_peer(peer_id);
                } else {
                    self.clear_virtual_peer(peer_id);
                }
            }
            VirtualPeer::Queued(listener_id) => {
                self.detach_queued_connector(listener_id, id, reset);
            }
            VirtualPeer::Blocked(listener_id) => {
                self.detach_blocked_connector(listener_id, id, session_id);
            }
        }
        self.release_listener_queue(pending_accepts, blocked_connectors);
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.live_socket_count = session
                .live_socket_count
                .checked_sub(1)
                .expect("session socket count underflow");
        }
        self.sessions
            .retain(|_, session| retain_session_state(session));
    }

    pub(super) fn listen_socket(
        &mut self,
        id: u64,
        backlog: u32,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let (kind, guest_address) = self
            .sockets
            .get(&id)
            .map(|socket| (socket.kind(), socket.guest_local_address))
            .ok_or(BrokerError::Internal)?;
        if kind != SocketKind::Tcp {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = guest_address.ok_or(BrokerError::Internal)?;
        match listen_tcp_socket(
            self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?,
            backlog,
        )? {
            SocketOutcome::Completed(()) => {
                self.tcp.mark_listening(guest_address.port(), id)?;
                // A larger backlog can admit connections that were parked
                // while the previous one was saturated.
                self.promote_blocked_connector(id);
                Ok(SocketOutcome::Completed(guest_address))
            }
            SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    pub(super) fn accept_socket(
        &mut self,
        listener_id: u64,
        accepted_id: u64,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
        lifecycle: &SocketLifecycle,
    ) -> BrokerResult<SocketOutcome<AcceptedEndpoints>> {
        if self.sockets.contains_key(&accepted_id) {
            return Err(BrokerError::Internal);
        }
        let (listener_session_id, listener_tcp_no_delay, listener_tcp_keep_alive) = {
            let listener = self
                .sockets
                .get(&listener_id)
                .ok_or(BrokerError::Internal)?;
            if listener.kind() != SocketKind::Tcp || !listener.tcp_state()?.listening {
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            (
                listener.session_id,
                listener.tcp_state()?.no_delay,
                listener.tcp_state()?.keep_alive,
            )
        };
        let Some(queued_session_id) = self
            .sockets
            .get(&listener_id)
            .ok_or(BrokerError::Internal)?
            .tcp_state()?
            .pending_accepts
            .front()
            .map(|queued| queued.session_id)
        else {
            let listener = self
                .sockets
                .get_mut(&listener_id)
                .ok_or(BrokerError::Internal)?;
            clear_readiness(listener, ReadinessFlags::READ)?;
            return Err(BrokerError::WouldBlock);
        };
        // Accepting converts one reserved accept slot into one live socket, so
        // only the session that owns the listener can exceed its budget.
        let listener_session = self
            .sessions
            .get(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        let released = usize::from(queued_session_id == listener_session_id);
        if listener_session
            .live_socket_count
            .checked_add(listener_session.queued_accept_count)
            .and_then(|count| count.checked_sub(released))
            .is_none_or(|count| count >= self.max_sockets_per_session)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let queued = self
            .sockets
            .get_mut(&listener_id)
            .ok_or(BrokerError::Internal)?
            .tcp_state_mut()?
            .pending_accepts
            .pop_front()
            .ok_or(BrokerError::Internal)?;
        match self.install_accepted_socket(
            listener_id,
            accepted_id,
            queued,
            listener_session_id,
            listener_tcp_no_delay,
            listener_tcp_keep_alive,
            readiness,
            snapshot,
            lifecycle,
        ) {
            Ok(accepted) => Ok(SocketOutcome::Completed(accepted)),
            Err((queued, error)) => {
                self.sockets
                    .get_mut(&listener_id)
                    .ok_or(BrokerError::Internal)?
                    .tcp_state_mut()?
                    .pending_accepts
                    .push_front(queued);
                Err(error)
            }
        }
    }

    /// Turns one queued connection into a live accepted socket.
    #[expect(
        clippy::too_many_arguments,
        reason = "accept installs one socket from independent listener and core state"
    )]
    fn install_accepted_socket(
        &mut self,
        listener_id: u64,
        accepted_id: u64,
        queued: QueuedGuestConnection,
        listener_session_id: SessionId,
        no_delay: bool,
        keep_alive: bool,
        readiness: ReadinessRegistration,
        snapshot: Arc<Mutex<SocketSnapshot>>,
        lifecycle: &SocketLifecycle,
    ) -> core::result::Result<AcceptedEndpoints, (QueuedGuestConnection, BrokerError)> {
        if self.sockets.try_reserve(1).is_err() {
            return Err((queued, BrokerError::OutOfMemory));
        }
        if let Err(error) = register_socket_events(&self.epoll, &queued.socket, accepted_id) {
            return Err((queued, error));
        }
        let listener_guest_address = queued.guest_source.destination();
        let remote_address = queued.guest_source.source();
        {
            let mut snapshot = snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            snapshot.status = SocketConnectionStatus::Connected;
            snapshot.local_address = Some(listener_guest_address);
            snapshot.readiness = ReadinessFlags::WRITE;
        }
        if let Err(error) = readiness.publish(ReadinessFlags::WRITE) {
            let _ = epoll::delete(&self.epoll, &queued.socket);
            return Err((queued, error));
        }
        if !lifecycle.activate() {
            let _ = epoll::delete(&self.epoll, &queued.socket);
            return Err((queued, BrokerError::Internal));
        }
        let QueuedGuestConnection {
            socket,
            guest_source,
            connector_id,
            session_id,
        } = queued;
        self.sockets.insert(
            accepted_id,
            SocketEntry {
                session_id: listener_session_id,
                transport: SocketTransportState::Tcp(TcpSocketState {
                    socket: Some(TcpDescriptor::Virtual(socket)),
                    peer: connector_id.map_or(VirtualPeer::None, VirtualPeer::Live),
                    no_delay,
                    keep_alive,
                    ..TcpSocketState::default()
                }),
                readiness,
                snapshot,
                connection_status: SocketConnectionStatus::Connected,
                read_shutdown: false,
                write_shutdown: false,
                guest_local_address: Some(listener_guest_address),
            },
        );
        if let Some(connector_id) = connector_id
            && let Some(connector) = self.sockets.get_mut(&connector_id)
            && let Ok(tcp) = connector.tcp_state_mut()
        {
            tcp.peer = VirtualPeer::Live(accepted_id);
        }
        self.release_queued_accept(session_id);
        let session = self
            .sessions
            .get_mut(&listener_session_id)
            .expect("listener session state missing");
        session.live_socket_count = session
            .live_socket_count
            .checked_add(1)
            .expect("session socket count overflow");
        let queue_empty = self
            .sockets
            .get(&listener_id)
            .and_then(|listener| listener.tcp_state().ok())
            .is_none_or(|tcp| tcp.pending_accepts.is_empty());
        if queue_empty && let Some(listener) = self.sockets.get_mut(&listener_id) {
            let _ = clear_readiness(listener, ReadinessFlags::READ);
        }
        self.promote_blocked_connector(listener_id);
        Ok(AcceptedEndpoints {
            local_address: listener_guest_address,
            remote: SocketDestination::Guest {
                requested: remote_address,
            },
            guest_source,
        })
    }
}

/// Reports the connect outcome for a destination with no live listener.
const fn refused_connect() -> (SocketConnectionStatus, ReadinessFlags) {
    (
        SocketConnectionStatus::Failed(SocketError::ConnectionRefused),
        ReadinessFlags::ERROR,
    )
}
