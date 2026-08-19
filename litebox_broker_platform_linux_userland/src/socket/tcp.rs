// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux TCP reactor state and transport-specific helpers.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{
    BrokerNetworkConfig, GuestSocketBinding, PlatformConnectError, SocketDestination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult, SessionId};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE, ReceiveFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOutcome, TcpOptionName, TcpOptionValue,
};
use rustix::event::{PollFd, PollFlags, Timespec, epoll, poll};
use rustix::io::{Errno, ioctl_fionread};
use rustix::net::ipproto;
use rustix::net::{
    RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags, Shutdown as LinuxShutdown,
    SocketFlags as LinuxSocketFlags, acceptfrom_with, bind, connect, listen, recv, send, shutdown,
    socket_with, sockopt,
};

use super::{
    Reactor, SocketEntry, SocketKind, SocketLifecycle, SocketSnapshot, SocketTransportState,
    broker_error_from_errno, can_consume_synchronous_error, local_socket_address,
    native_host_address, retain_session_state, socket_error_from_errno,
    socket_operation_error_from_errno, take_socket_error, update_snapshot, zeroed_vec,
};

pub(super) const MAX_UNMATCHED_ACCEPTS_PER_COMMAND: usize = 64;
pub(super) const PENDING_CONNECT_DISCARD_LIFETIME: Duration = Duration::from_mins(5);

pub(super) struct AcceptedEndpoints {
    pub(super) local_address: SocketAddrV4,
    pub(super) remote: SocketDestination,
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

/// Reactor-owned TCP descriptor and transport-specific lifecycle state.
#[expect(
    clippy::struct_excessive_bools,
    reason = "TCP lifecycle and option flags are independent"
)]
pub(super) struct TcpSocketState {
    pub(super) socket: OwnedFd,
    pub(super) untracked_guest_listener_id: Option<u64>,
    pub(super) peek_waitall_threshold: Option<usize>,
    pub(super) listening: bool,
    pub(super) was_listener: bool,
    pub(super) abortive_close: bool,
    pub(super) host_connection: Option<(SocketAddrV4, SocketAddrV4)>,
    pub(super) no_delay: bool,
    pub(super) keep_alive: bool,
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
}

pub(super) fn create_tcp_transport(
    epoll_fd: &OwnedFd,
    id: u64,
) -> BrokerResult<SocketTransportState> {
    let socket = socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
        Some(ipproto::TCP),
    )
    .map_err(broker_error_from_errno)?;
    epoll::add(
        epoll_fd,
        &socket,
        epoll::EventData::new_u64(id),
        idle_epoll_events(),
    )
    .map_err(broker_error_from_errno)?;
    Ok(SocketTransportState::Tcp(TcpSocketState {
        socket,
        untracked_guest_listener_id: None,
        peek_waitall_threshold: None,
        listening: false,
        was_listener: false,
        abortive_close: false,
        host_connection: None,
        no_delay: false,
        keep_alive: false,
    }))
}

/// Reactor-owned realization of guest TCP bindings and pending connections.
#[derive(Default)]
pub(super) struct ReactorTcpState {
    pub(super) bindings: ReactorTcpBindings,
    pub(super) pending_guest_connections:
        HashMap<(SocketAddrV4, SocketAddrV4), PendingGuestTcpConnection>,
    pub(super) retained_connector_count: usize,
    pub(super) peek_cache: Option<PeekCache>,
}

#[derive(Default)]
pub(super) struct ReactorTcpBindings {
    wildcard: HashMap<u16, ReactorTcpBinding>,
    exact: HashMap<SocketAddrV4, ReactorTcpBinding>,
}

impl ReactorTcpBindings {
    fn clear(&mut self) {
        self.wildcard.clear();
        self.exact.clear();
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &ReactorTcpBinding> {
        self.wildcard.values().chain(self.exact.values())
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut ReactorTcpBinding> {
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

fn idle_epoll_events() -> epoll::EventFlags {
    epoll::EventFlags::RDHUP | epoll::EventFlags::ET
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

pub(super) struct PendingGuestTcpConnection {
    pub(super) session_id: super::SessionId,
    pub(super) guest_address: SocketAddrV4,
    pub(super) local_address: SocketAddrV4,
    pub(super) listener_id: u64,
    pub(super) discard_on_accept: bool,
    pub(super) discard_until_deadline: bool,
    pub(super) discard_deadline: Option<Instant>,
    pub(super) retained_connector: Option<OwnedFd>,
}

pub(super) enum PendingGuestConnectionMatch {
    PersistentDiscard,
    Take(PendingGuestTcpConnection),
}

#[derive(Clone)]
pub(super) struct ReactorTcpBinding {
    pub(super) socket_id: u64,
    pub(super) guest_binding: GuestSocketBinding,
    pub(super) host_address: Option<SocketAddrV4>,
    pub(super) listening: bool,
    pub(super) requires_backlog_drain: bool,
    pub(super) untracked_connection_deadline: Option<Instant>,
}

impl ReactorTcpState {
    pub(super) fn clear_live_state(&mut self) {
        self.bindings.clear();
        self.pending_guest_connections.clear();
        self.retained_connector_count = 0;
        self.peek_cache = None;
    }

    pub(super) fn insert_binding(
        &mut self,
        config: &BrokerNetworkConfig,
        binding: ReactorTcpBinding,
    ) -> BrokerResult<()> {
        let requested = binding.guest_binding.requested();
        if !binding.guest_binding.is_valid_for(config)
            || if binding.guest_binding.is_wildcard() {
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
        if binding.guest_binding.is_wildcard() {
            self.bindings
                .wildcard
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.bindings.wildcard.insert(requested.port(), binding);
        } else {
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

    /// Finds the binding that owns one concrete guest-namespace address.
    ///
    /// An exact binding answers only its own address; a wildcard binding
    /// answers every guest-local address on its port, including the
    /// configured private guest address.
    pub(super) fn guest_binding(
        &self,
        config: &BrokerNetworkConfig,
        requested: SocketAddrV4,
    ) -> Option<ReactorTcpBinding> {
        let binding = self
            .bindings
            .exact
            .get(&requested)
            .or_else(|| self.bindings.wildcard.get(&requested.port()))?;
        binding
            .guest_binding
            .covers(config, requested)
            .then(|| binding.clone())
    }

    pub(super) fn binding_for_socket(&self, socket_id: u64) -> Option<ReactorTcpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .cloned()
    }

    pub(super) fn set_host_address(
        &mut self,
        port: u16,
        socket_id: u64,
        host_address: SocketAddrV4,
    ) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| {
                binding.socket_id == socket_id && binding.guest_binding.requested().port() == port
            })
            .ok_or(BrokerError::Internal)?;
        binding.host_address = Some(host_address);
        Ok(())
    }

    pub(super) fn mark_listening(&mut self, port: u16, socket_id: u64) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| {
                binding.socket_id == socket_id && binding.guest_binding.requested().port() == port
            })
            .ok_or(BrokerError::Internal)?;
        if binding.host_address.is_none() {
            return Err(BrokerError::Internal);
        }
        binding.listening = true;
        Ok(())
    }

    pub(super) fn stop_listening(&mut self, port: u16, socket_id: u64) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| {
                binding.socket_id == socket_id && binding.guest_binding.requested().port() == port
            })
            .ok_or(BrokerError::Internal)?;
        binding.listening = false;
        binding.requires_backlog_drain = false;
        binding.untracked_connection_deadline = None;
        Ok(())
    }

    pub(super) fn defer_untracked_connection(&mut self, listener_id: u64, deadline: Instant) {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| binding.socket_id == listener_id)
            .expect("untracked guest connection listener binding missing");
        binding.untracked_connection_deadline = Some(
            binding
                .untracked_connection_deadline
                .map_or(deadline, |current| current.max(deadline)),
        );
    }

    pub(super) fn persist_discard_marker_for_collision(
        &mut self,
        connection: (SocketAddrV4, SocketAddrV4),
        listener_id: u64,
        deadline: Instant,
    ) -> bool {
        let Some(pending) = self.pending_guest_connections.get_mut(&connection) else {
            return false;
        };
        if !pending.discard_on_accept || pending.listener_id != listener_id {
            return false;
        }
        // A collision can represent both the old ambiguous child and the new
        // one. Keep dropping this tuple until the refreshed deadline instead
        // of blocking unrelated connections to the listener. The marker stays
        // charged to its original session even when another session refreshes
        // it; identity protection is broker-wide and adds no new record.
        pending.discard_until_deadline = true;
        pending.discard_deadline = Some(deadline);
        true
    }

    pub(super) fn finish_listener_backlog_drain(&mut self, listener_id: u64) -> BrokerResult<()> {
        let binding = self
            .bindings
            .values_mut()
            .find(|binding| binding.socket_id == listener_id)
            .ok_or(BrokerError::Internal)?;
        // A tuple-unknown connect can still complete after an empty drain
        // observation, so only its maturation deadline may release that block.
        binding.requires_backlog_drain = false;
        Ok(())
    }

    pub(super) fn take_pending_guest_connection(
        &mut self,
        remote_address: SocketAddrV4,
        local_address: SocketAddrV4,
    ) -> Option<PendingGuestConnectionMatch> {
        if self
            .pending_guest_connections
            .get(&(remote_address, local_address))
            .is_some_and(|connection| {
                connection.discard_on_accept && connection.discard_until_deadline
            })
        {
            return Some(PendingGuestConnectionMatch::PersistentDiscard);
        }
        self.pending_guest_connections
            .remove(&(remote_address, local_address))
            .map(PendingGuestConnectionMatch::Take)
    }

    pub(super) fn insert_pending_guest_connection(
        &mut self,
        connection: (SocketAddrV4, SocketAddrV4),
        pending: PendingGuestTcpConnection,
    ) -> BrokerResult<()> {
        if self.pending_guest_connections.contains_key(&connection) {
            return Err(BrokerError::ResourceExhausted);
        }
        self.pending_guest_connections.insert(connection, pending);
        Ok(())
    }
}

pub(super) fn listener_backlog_is_nonempty(
    sockets: &HashMap<u64, SocketEntry>,
    listener_id: u64,
) -> bool {
    let Some(listener) = sockets.get(&listener_id) else {
        return false;
    };
    let Ok(tcp) = listener.tcp_state() else {
        return false;
    };
    if !tcp.listening {
        return false;
    }
    socket_backlog_is_nonempty(&tcp.socket)
}

fn socket_backlog_is_nonempty(socket: &OwnedFd) -> bool {
    let no_wait = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let mut poll_fd = [PollFd::new(socket, PollFlags::IN)];
        match poll(&mut poll_fd, Some(&no_wait)) {
            Ok(_) => return !poll_fd[0].revents().is_empty(),
            Err(Errno::INTR) => {}
            Err(_) => return true,
        }
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

pub(super) fn connect_tcp_socket(
    epoll_fd: &OwnedFd,
    id: u64,
    socket: &mut SocketEntry,
    address: SocketAddrV4,
    guest_listener_id: Option<u64>,
) -> core::result::Result<(SocketConnectionStatus, ReadinessFlags), PlatformConnectError> {
    if let Err(error) = epoll::modify(
        epoll_fd,
        &socket
            .tcp_state()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .socket,
        epoll::EventData::new_u64(id),
        active_epoll_events(),
    ) {
        return Err(PlatformConnectError::PeerUnchanged(
            broker_error_from_errno(error),
        ));
    }
    if socket.connection_status != SocketConnectionStatus::Unconnected {
        return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
    }
    // Record the first half of the native transition before connect(2). Any
    // later failure can then be settled or conservatively retired without
    // reconstructing whether a SYN may have reached a guest listener.
    socket.connection_status = SocketConnectionStatus::Connecting;
    socket
        .tcp_state_mut()
        .map_err(PlatformConnectError::PeerUnchanged)?
        .untracked_guest_listener_id = guest_listener_id;
    let status = loop {
        match connect(
            &socket
                .tcp_state()
                .map_err(PlatformConnectError::PeerIndeterminate)?
                .socket,
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
    if matches!(status, SocketConnectionStatus::Failed(_)) {
        socket
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?
            .untracked_guest_listener_id = None;
    }
    let readiness = match status {
        SocketConnectionStatus::Connected | SocketConnectionStatus::Connecting => {
            if socket.guest_local_address.is_none() {
                return Err(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ));
            }
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

pub(super) fn bind_host_socket(
    socket: &mut SocketEntry,
    address: SocketAddrV4,
) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
    loop {
        match bind(&socket.tcp_state()?.socket, &address) {
            Ok(()) => {
                let local_address = local_socket_address(&socket.tcp_state()?.socket)?;
                return Ok(SocketOutcome::Completed(local_address));
            }
            Err(Errno::INTR) => {}
            Err(error) => {
                return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                    error,
                )?));
            }
        }
    }
}

pub(super) fn listen_tcp_socket(
    epoll_fd: &OwnedFd,
    id: u64,
    socket: &mut SocketEntry,
    backlog: u32,
) -> BrokerResult<SocketOutcome<()>> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let backlog = i32::try_from(backlog).map_err(|_| BrokerError::UnsupportedOperation)?;
    let was_listening = socket.tcp_state()?.listening;
    if !was_listening {
        epoll::modify(
            epoll_fd,
            &socket.tcp_state()?.socket,
            epoll::EventData::new_u64(id),
            active_epoll_events(),
        )
        .map_err(broker_error_from_errno)?;
    }
    loop {
        match listen(&socket.tcp_state()?.socket, backlog) {
            Ok(()) => break,
            Err(Errno::INTR) => {}
            Err(error) => {
                if !was_listening {
                    epoll::modify(
                        epoll_fd,
                        &socket.tcp_state()?.socket,
                        epoll::EventData::new_u64(id),
                        idle_epoll_events(),
                    )
                    .map_err(broker_error_from_errno)?;
                }
                return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                    error,
                )?));
            }
        }
    }
    let tcp = socket.tcp_state_mut()?;
    tcp.listening = true;
    tcp.was_listener = true;
    let mut snapshot = socket
        .snapshot
        .lock()
        .expect("Linux socket snapshot mutex poisoned");
    if !was_listening {
        snapshot.readiness = ReadinessFlags::default();
    }
    Ok(SocketOutcome::Completed(()))
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
    loop {
        match send(&socket.tcp_state()?.socket, data, LinuxSendFlags::NOSIGNAL) {
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
            && ioctl_fionread(&socket.tcp_state()?.socket).map_err(broker_error_from_errno)?
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
                ioctl_fionread(&socket.tcp_state()?.socket).map_err(broker_error_from_errno)?,
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
        match recv(&socket.tcp_state()?.socket, data.as_mut_slice(), flags) {
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
                    let no_queued_data = ioctl_fionread(&socket.tcp_state()?.socket)
                        .is_ok_and(|available| available == 0);
                    if no_queued_data {
                        let _ = clear_readiness(socket, ReadinessFlags::READ);
                    }
                }
                return Ok(ReactorReceiveOutcome::Received(data));
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
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
    match value {
        TcpOptionValue::NoDelay(value) => {
            sockopt::set_tcp_nodelay(&socket.tcp_state()?.socket, value)
                .map_err(broker_error_from_errno)?;
            socket.tcp_state_mut()?.no_delay = value;
        }
        TcpOptionValue::KeepAlive(value) => {
            sockopt::set_socket_keepalive(&socket.tcp_state()?.socket, value)
                .map_err(broker_error_from_errno)?;
            socket.tcp_state_mut()?.keep_alive = value;
        }
        _ => return Err(BrokerError::UnsupportedOperation),
    }
    Ok(())
}

pub(super) fn apply_tcp_options(
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
    match name {
        TcpOptionName::NoDelay => sockopt::tcp_nodelay(&socket.tcp_state()?.socket)
            .map(TcpOptionValue::NoDelay)
            .map_err(broker_error_from_errno),
        TcpOptionName::KeepAlive => sockopt::socket_keepalive(&socket.tcp_state()?.socket)
            .map(TcpOptionValue::KeepAlive)
            .map_err(broker_error_from_errno),
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
        sockopt::set_socket_linger(&socket.tcp_state()?.socket, Some(Duration::ZERO))
            .map_err(broker_error_from_errno)?;
        socket.tcp_state_mut()?.abortive_close = true;
        return Ok(SocketOutcome::Completed(()));
    }
    let stop_listening = mode == ShutdownMode::StopListening;
    let listening = socket.tcp_state()?.listening;
    if stop_listening {
        if !listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
    } else if listening {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let (mode, add, clear, shuts_down_read, shuts_down_write) = match mode {
        ShutdownMode::Read => (
            LinuxShutdown::Read,
            ReadinessFlags::READ,
            ReadinessFlags::default(),
            true,
            false,
        ),
        ShutdownMode::Write => (
            LinuxShutdown::Write,
            ReadinessFlags::default(),
            ReadinessFlags::WRITE,
            false,
            true,
        ),
        ShutdownMode::Both => (
            LinuxShutdown::Both,
            ReadinessFlags::READ,
            ReadinessFlags::WRITE,
            true,
            true,
        ),
        ShutdownMode::StopListening => (
            LinuxShutdown::Read,
            ReadinessFlags::default(),
            ReadinessFlags::default(),
            true,
            false,
        ),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    loop {
        match shutdown(&socket.tcp_state()?.socket, mode) {
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
) -> BrokerResult<bool> {
    if socket.tcp_state().is_ok_and(|tcp| tcp.listening) {
        update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
        return Ok(false);
    }
    if socket.kind() == SocketKind::Udp {
        update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
        return Ok(false);
    }
    let republish_readiness = if events.contains(epoll::EventFlags::IN)
        && let Some(threshold) = socket
            .tcp_state()
            .ok()
            .and_then(|tcp| tcp.peek_waitall_threshold)
    {
        let threshold_reached = socket
            .tcp_state()
            .and_then(|tcp| ioctl_fionread(&tcp.socket).map_err(broker_error_from_errno))
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
    let failed_connector = match socket.connection_status {
        SocketConnectionStatus::Unconnected => false,
        SocketConnectionStatus::Connecting => {
            matches!(
                complete_connect(socket, events)?,
                SocketConnectionStatus::Failed(_)
            )
        }
        SocketConnectionStatus::Connected => {
            update_snapshot(socket, None, readiness_from_epoll(socket, events))?;
            false
        }
        SocketConnectionStatus::Failed(SocketError::NotConnected) if socket.read_shutdown => {
            update_snapshot(socket, None, ReadinessFlags::WRITE | ReadinessFlags::HANGUP)?;
            false
        }
        SocketConnectionStatus::Failed(_) => {
            update_snapshot(socket, None, ReadinessFlags::ERROR)?;
            false
        }
        _ => return Err(BrokerError::Internal),
    };
    if republish_readiness {
        let readiness = socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .readiness;
        socket.readiness.republish(readiness)?;
    }
    Ok(failed_connector)
}

fn complete_connect(
    socket: &mut SocketEntry,
    events: epoll::EventFlags,
) -> BrokerResult<SocketConnectionStatus> {
    // Epoll re-polls the descriptor when waiting, so OUT here reflects the
    // current post-connect state rather than readiness cached before connect.
    let status = match sockopt::socket_error(&socket.tcp_state()?.socket) {
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
        let was_connecting = self
            .sockets
            .get(&id)
            .is_some_and(|socket| socket.connection_status == SocketConnectionStatus::Connecting);
        let outcome = self
            .sockets
            .get_mut(&id)
            .ok_or(BrokerError::Internal)
            .and_then(|socket| send_socket(socket, data));
        self.discard_failed_connect_after_command(id, was_connecting);
        outcome
    }

    pub(super) fn receive_tcp_socket(
        &mut self,
        id: u64,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: usize,
        peek_length: usize,
    ) -> BrokerResult<ReactorReceiveOutcome> {
        let was_connecting = self
            .sockets
            .get(&id)
            .is_some_and(|socket| socket.connection_status == SocketConnectionStatus::Connecting);
        let outcome = match self.sockets.get_mut(&id) {
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
        };
        self.discard_failed_connect_after_command(id, was_connecting);
        outcome
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
        let was_connecting = self
            .sockets
            .get(&id)
            .is_some_and(|socket| socket.connection_status == SocketConnectionStatus::Connecting);
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
            self.remove_pending_guest_connections_for_listener(id);
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
        self.discard_failed_connect_after_command(id, was_connecting);
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
        self.tcp.insert_binding(
            &self.network_config,
            ReactorTcpBinding {
                socket_id: id,
                guest_binding: binding,
                host_address: None,
                listening: false,
                requires_backlog_drain: false,
                untracked_connection_deadline: None,
            },
        )?;
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        socket.guest_local_address = Some(guest_address);
        socket
            .snapshot
            .lock()
            .expect("Linux socket snapshot mutex poisoned")
            .local_address = Some(guest_address);
        Ok(SocketOutcome::Completed(guest_address))
    }

    pub(super) fn connect_tcp_guest(
        &mut self,
        id: u64,
        destination: SocketDestination,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let session_id = self
            .sockets
            .get(&id)
            .filter(|socket| socket.guest_local_address.is_some())
            .map(|socket| socket.session_id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        // The broker-issued binding and the route decide the visible source
        // before any native state changes; disagreement fails closed.
        let local_guest_address = self
            .tcp
            .binding_for_socket(id)
            .and_then(|binding| {
                binding
                    .guest_binding
                    .concrete_address_for(&self.network_config, destination)
            })
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let concrete_guest_destination = destination.requested();
        let route = self
            .resolve_tcp_destination(destination)
            .map_err(PlatformConnectError::PeerUnchanged)?;
        let (network_address, guest_listener_id) = match route {
            SocketOutcome::Completed(route) => route,
            SocketOutcome::Failed(error) => {
                let status = SocketConnectionStatus::Failed(error);
                let socket = self
                    .sockets
                    .get_mut(&id)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                socket.connection_status = status;
                update_snapshot(socket, Some(status), ReadinessFlags::ERROR)
                    .map_err(PlatformConnectError::PeerIndeterminate)?;
                return Ok(status);
            }
        };
        if guest_listener_id.is_some() {
            self.expire_deadlined_state(Instant::now());
            self.reserve_pending_guest_connection(session_id)
                .map_err(PlatformConnectError::PeerUnchanged)?;
        }
        let (status, readiness) = connect_tcp_socket(
            &self.epoll,
            id,
            self.sockets
                .get_mut(&id)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?,
            network_address,
            guest_listener_id,
        )?;
        if matches!(
            status,
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ) {
            let host_address = local_socket_address(
                &self
                    .sockets
                    .get(&id)
                    .ok_or(PlatformConnectError::PeerIndeterminate(
                        BrokerError::Internal,
                    ))?
                    .tcp_state()
                    .map_err(PlatformConnectError::PeerIndeterminate)?
                    .socket,
            )
            .map_err(PlatformConnectError::PeerIndeterminate)?;
            self.tcp
                .set_host_address(local_guest_address.port(), id, host_address)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            {
                let socket =
                    self.sockets
                        .get_mut(&id)
                        .ok_or(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ))?;
                socket.guest_local_address = Some(local_guest_address);
                socket
                    .snapshot
                    .lock()
                    .expect("Linux socket snapshot mutex poisoned")
                    .local_address = Some(local_guest_address);
            }
            if let Some(listener_id) = guest_listener_id {
                let connection = (host_address, network_address);
                if self.tcp.persist_discard_marker_for_collision(
                    connection,
                    listener_id,
                    Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME,
                ) {
                    self.sockets
                        .get_mut(&id)
                        .ok_or(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ))?
                        .tcp_state_mut()
                        .map_err(PlatformConnectError::PeerIndeterminate)?
                        .untracked_guest_listener_id = None;
                    return Err(PlatformConnectError::PeerIndeterminate(
                        BrokerError::ResourceExhausted,
                    ));
                }
                self.insert_pending_guest_connection(
                    session_id,
                    connection,
                    local_guest_address,
                    concrete_guest_destination,
                    listener_id,
                )
                .map_err(PlatformConnectError::PeerIndeterminate)?;
                let socket =
                    self.sockets
                        .get_mut(&id)
                        .ok_or(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ))?;
                let tcp = socket
                    .tcp_state_mut()
                    .map_err(PlatformConnectError::PeerIndeterminate)?;
                tcp.host_connection = Some(connection);
                tcp.untracked_guest_listener_id = None;
            }
        }
        if let Err(error) = update_snapshot(
            self.sockets
                .get(&id)
                .ok_or(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ))?,
            Some(status),
            readiness,
        ) {
            if let Some(connection) = self
                .sockets
                .get(&id)
                .and_then(|socket| socket.tcp_state().ok().and_then(|tcp| tcp.host_connection))
            {
                self.discard_pending_guest_connection(connection, session_id);
            }
            return Err(PlatformConnectError::PeerIndeterminate(error));
        }
        Ok(status)
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
            connection_status,
            guest_local_address,
            ..
        } = socket;
        let SocketTransportState::Tcp(TcpSocketState {
            socket,
            untracked_guest_listener_id,
            was_listener,
            abortive_close,
            host_connection,
            ..
        }) = transport
        else {
            unreachable!("checked TCP socket changed transport");
        };
        let guest_connector = untracked_guest_listener_id.is_some()
            || host_connection.is_some_and(|connection| {
                self.tcp
                    .pending_guest_connections
                    .get(&connection)
                    .is_some_and(|pending| pending.session_id == session_id)
            });
        if was_listener {
            self.remove_pending_guest_connections_for_listener(id);
        }
        if let Some(address) = guest_local_address {
            self.tcp.remove_binding(address.port(), id);
        }

        let mut socket = Some(socket);
        if !abortive_close
            && guest_connector
            && matches!(
                connection_status,
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        {
            let _ = shutdown(
                socket.as_ref().expect("connector descriptor missing"),
                LinuxShutdown::Both,
            );
        }
        if let Some(connection) = host_connection
            && let Some(pending) = self.tcp.pending_guest_connections.get_mut(&connection)
            && pending.session_id == session_id
        {
            let retain = !abortive_close
                && connection_status == SocketConnectionStatus::Connected
                && !pending.discard_on_accept;
            // A close that wins before native completion is observed is
            // deliberately non-deliverable; teardown never re-infers it.
            pending.discard_on_accept = !retain;
            pending.discard_deadline =
                (!retain).then(|| Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME);
            if retain {
                pending.retained_connector = socket.take();
                self.tcp.retained_connector_count = self
                    .tcp
                    .retained_connector_count
                    .checked_add(1)
                    .expect("reactor retained connector count overflow");
                let session = self
                    .sessions
                    .get_mut(&session_id)
                    .expect("socket session state missing");
                session.retained_connector_count = session
                    .retained_connector_count
                    .checked_add(1)
                    .expect("session retained connector count overflow");
            }
        }
        if let Some(listener_id) = untracked_guest_listener_id
            && self
                .tcp
                .bindings
                .values()
                .any(|binding| binding.socket_id == listener_id)
        {
            // No tuple exists to key a discard marker. Block later routes for
            // the same bounded maturation period, then probe the listener just
            // like an expiring keyed marker.
            self.tcp.defer_untracked_connection(
                listener_id,
                Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME,
            );
        }
        drop(socket);
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.live_socket_count = session
                .live_socket_count
                .checked_sub(1)
                .expect("session socket count underflow");
        }
        if self
            .sessions
            .get(&session_id)
            .is_some_and(|session| session.closing)
        {
            self.retire_session_connectors(session_id);
        }
        self.sessions
            .retain(|_, session| retain_session_state(session));
    }

    pub(super) fn discard_failed_connect_after_command(&mut self, id: u64, was_connecting: bool) {
        if !was_connecting {
            return;
        }
        let failed_connection = self.sockets.get(&id).and_then(|socket| {
            matches!(socket.connection_status, SocketConnectionStatus::Failed(_))
                .then(|| {
                    socket
                        .tcp_state()
                        .ok()
                        .and_then(|tcp| tcp.host_connection)
                        .map(|connection| (connection, socket.session_id))
                })
                .flatten()
        });
        if let Some((connection, session_id)) = failed_connection {
            self.discard_pending_guest_connection(connection, session_id);
        }
    }

    pub(super) fn reserve_pending_guest_connection(
        &mut self,
        session_id: SessionId,
    ) -> BrokerResult<()> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(BrokerError::Internal)?;
        // Pending records can outlive connector descriptors, so bound this
        // metadata independently using the configured socket budgets.
        if session.pending_guest_connection_count >= self.max_sockets_per_session
            || self.tcp.pending_guest_connections.len() >= self.max_sockets
        {
            return Err(BrokerError::ResourceExhausted);
        }
        self.tcp
            .pending_guest_connections
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    fn finish_removed_pending_guest_connection(&mut self, connection: &PendingGuestTcpConnection) {
        let session = self
            .sessions
            .get_mut(&connection.session_id)
            .expect("pending guest connection session state missing");
        session.pending_guest_connection_count = session
            .pending_guest_connection_count
            .checked_sub(1)
            .expect("session pending guest connection count underflow");
        if connection.retained_connector.is_some() {
            self.tcp.retained_connector_count = self
                .tcp
                .retained_connector_count
                .checked_sub(1)
                .expect("reactor retained connector count underflow");
            session.retained_connector_count = session
                .retained_connector_count
                .checked_sub(1)
                .expect("session retained connector count underflow");
        }
    }

    pub(super) fn insert_pending_guest_connection(
        &mut self,
        session_id: SessionId,
        connection: (SocketAddrV4, SocketAddrV4),
        guest_address: SocketAddrV4,
        local_address: SocketAddrV4,
        listener_id: u64,
    ) -> BrokerResult<()> {
        let pending_count = self
            .sessions
            .get(&session_id)
            .ok_or(BrokerError::Internal)?
            .pending_guest_connection_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        self.tcp.insert_pending_guest_connection(
            connection,
            PendingGuestTcpConnection {
                session_id,
                guest_address,
                local_address,
                listener_id,
                discard_on_accept: false,
                discard_until_deadline: false,
                discard_deadline: None,
                retained_connector: None,
            },
        )?;
        self.sessions
            .get_mut(&session_id)
            .expect("pending guest connection session state missing")
            .pending_guest_connection_count = pending_count;
        Ok(())
    }

    pub(super) fn discard_pending_guest_connection(
        &mut self,
        connection: (SocketAddrV4, SocketAddrV4),
        session_id: SessionId,
    ) {
        if let Some(pending) = self.tcp.pending_guest_connections.get_mut(&connection)
            && pending.session_id == session_id
        {
            // The descriptor remains open and pins the native tuple. Final
            // close starts the bounded discard deadline.
            pending.discard_on_accept = true;
            pending.discard_deadline = None;
        }
    }

    pub(super) fn remove_pending_guest_connections_for_listener(&mut self, listener_id: u64) {
        let Reactor { tcp, sessions, .. } = self;
        let ReactorTcpState {
            pending_guest_connections,
            retained_connector_count,
            ..
        } = tcp;
        pending_guest_connections.retain(|_, connection| {
            let retain = connection.listener_id != listener_id;
            if !retain {
                let session = sessions
                    .get_mut(&connection.session_id)
                    .expect("pending guest connection session state missing");
                session.pending_guest_connection_count = session
                    .pending_guest_connection_count
                    .checked_sub(1)
                    .expect("session pending guest connection count underflow");
                if connection.retained_connector.is_some() {
                    session.retained_connector_count = session
                        .retained_connector_count
                        .checked_sub(1)
                        .expect("session retained connector count underflow");
                    *retained_connector_count = retained_connector_count
                        .checked_sub(1)
                        .expect("reactor retained connector count underflow");
                }
            }
            retain
        });
        sessions.retain(|_, session| retain_session_state(session));
    }

    pub(super) fn retire_session_connectors(&mut self, session_id: SessionId) {
        let discard_deadline = Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME;
        let mut released = 0;
        for connection in self
            .tcp
            .pending_guest_connections
            .values_mut()
            .filter(|connection| connection.session_id == session_id)
        {
            if let Some(connector) = connection.retained_connector.take() {
                let _ = sockopt::set_socket_linger(&connector, None);
                drop(connector);
                connection.discard_on_accept = true;
                connection.discard_deadline = Some(discard_deadline);
                released += 1;
            }
        }
        self.tcp.retained_connector_count = self
            .tcp
            .retained_connector_count
            .checked_sub(released)
            .expect("reactor retained connector count underflow");
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.retained_connector_count = session
                .retained_connector_count
                .checked_sub(released)
                .expect("session retained connector count underflow");
        }
    }

    pub(super) fn next_cleanup_deadline(&self) -> Option<Instant> {
        self.tcp
            .pending_guest_connections
            .values()
            .filter_map(|connection| connection.discard_deadline)
            .chain(
                self.tcp
                    .bindings
                    .values()
                    .filter_map(|binding| binding.untracked_connection_deadline),
            )
            .min()
    }

    pub(super) fn expire_deadlined_state(&mut self, now: Instant) {
        let Reactor {
            tcp,
            sockets,
            sessions,
            ..
        } = self;
        let ReactorTcpState {
            bindings,
            pending_guest_connections,
            retained_connector_count,
            ..
        } = tcp;
        for binding in bindings.values_mut() {
            if binding
                .untracked_connection_deadline
                .is_some_and(|deadline| deadline <= now)
            {
                if listener_backlog_is_nonempty(sockets, binding.socket_id) {
                    binding.requires_backlog_drain = true;
                }
                binding.untracked_connection_deadline = None;
            }
        }
        for connection in pending_guest_connections.values().filter(|connection| {
            connection.discard_on_accept
                && connection
                    .discard_deadline
                    .is_some_and(|deadline| deadline <= now)
        }) {
            if listener_backlog_is_nonempty(sockets, connection.listener_id) {
                bindings
                    .values_mut()
                    .find(|binding| binding.socket_id == connection.listener_id)
                    .expect("pending guest connection listener binding missing")
                    .requires_backlog_drain = true;
            }
        }
        pending_guest_connections.retain(|_, connection| {
            let retain = !connection.discard_on_accept
                || connection
                    .discard_deadline
                    .is_none_or(|deadline| deadline > now);
            if !retain {
                let session = sessions
                    .get_mut(&connection.session_id)
                    .expect("pending guest connection session state missing");
                session.pending_guest_connection_count = session
                    .pending_guest_connection_count
                    .checked_sub(1)
                    .expect("session pending guest connection count underflow");
                if connection.retained_connector.is_some() {
                    session.retained_connector_count = session
                        .retained_connector_count
                        .checked_sub(1)
                        .expect("session retained connector count underflow");
                    *retained_connector_count = retained_connector_count
                        .checked_sub(1)
                        .expect("reactor retained connector count underflow");
                }
            }
            retain
        });
        sessions.retain(|_, session| retain_session_state(session));
    }

    fn take_pending_guest_connection_for_accept(
        &mut self,
        listener_id: u64,
        remote_address: SocketAddrV4,
        local_address: SocketAddrV4,
    ) -> Option<(SocketAddrV4, SocketAddrV4)> {
        let PendingGuestConnectionMatch::Take(mut connection) = self
            .tcp
            .take_pending_guest_connection(remote_address, local_address)?
        else {
            return None;
        };
        self.finish_removed_pending_guest_connection(&connection);
        drop(connection.retained_connector.take());
        let addresses = (!connection.discard_on_accept && connection.listener_id == listener_id)
            .then_some((connection.guest_address, connection.local_address));
        self.sessions
            .retain(|_, session| retain_session_state(session));
        addresses
    }

    fn has_accept_capacity(
        &self,
        listener_id: u64,
        listener_session_id: SessionId,
    ) -> BrokerResult<bool> {
        let global_at_limit = self
            .sockets
            .len()
            .checked_add(self.tcp.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets);
        let listener_session = self
            .sessions
            .get(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        let session_at_limit = listener_session
            .live_socket_count
            .checked_add(listener_session.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets_per_session);
        if !global_at_limit && !session_at_limit {
            return Ok(true);
        }

        for connection in self
            .tcp
            .pending_guest_connections
            .values()
            .filter(|connection| connection.listener_id == listener_id)
            .filter(|connection| !connection.discard_on_accept)
        {
            if global_at_limit && connection.retained_connector.is_none() {
                return Ok(false);
            }
            if session_at_limit
                && (connection.session_id != listener_session_id
                    || connection.retained_connector.is_none())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn is_private_tcp_host_endpoint(&self, address: SocketAddrV4) -> bool {
        self.tcp
            .bindings
            .values()
            .filter_map(|binding| binding.host_address)
            .any(|host_address| host_address == address)
    }

    /// Resolves one broker-classified TCP destination to a native target.
    ///
    /// A guest route resolves only inside the broker's guest namespace and
    /// never falls back to a native connection, while gateway and external
    /// routes translate to a host address that must not name a broker-private
    /// guest listener endpoint. Guest routing owns its namespace first because
    /// guest and native ports may numerically collide.
    pub(super) fn resolve_tcp_destination(
        &self,
        destination: SocketDestination,
    ) -> BrokerResult<SocketOutcome<(SocketAddrV4, Option<u64>)>> {
        if !destination.is_valid_for(&self.network_config) {
            return Err(BrokerError::Internal);
        }
        let SocketDestination::Guest { requested } = destination else {
            let host_address = native_host_address(destination).ok_or(BrokerError::Internal)?;
            return Ok(if self.is_private_tcp_host_endpoint(host_address) {
                SocketOutcome::Failed(SocketError::ConnectionRefused)
            } else {
                SocketOutcome::Completed((host_address, None))
            });
        };
        let Some(binding) = self.tcp.guest_binding(&self.network_config, requested) else {
            return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
        };
        // A live guest binding owns this destination port broker-wide; only a
        // listener with a fully classified backlog may receive new guest
        // connections through it.
        if !binding.listening
            || binding.requires_backlog_drain
            // Defence in depth for failures after connect(2) but before a
            // complete host tuple can be recorded.
            || binding.untracked_connection_deadline.is_some()
        {
            return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
        }
        Ok(match binding.host_address {
            Some(host_address) => SocketOutcome::Completed((host_address, Some(binding.socket_id))),
            None => SocketOutcome::Failed(SocketError::ConnectionRefused),
        })
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
        let needs_host_bind = local_socket_address(
            &self
                .sockets
                .get(&id)
                .ok_or(BrokerError::Internal)?
                .tcp_state()?
                .socket,
        )?
        .port()
            == 0;
        if needs_host_bind {
            let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
            let host_address =
                match bind_host_socket(socket, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))? {
                    SocketOutcome::Completed(address) => address,
                    SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
                };
            self.tcp
                .set_host_address(guest_address.port(), id, host_address)?;
        }
        match listen_tcp_socket(
            &self.epoll,
            id,
            self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?,
            backlog,
        )? {
            SocketOutcome::Completed(()) => {
                self.tcp.mark_listening(guest_address.port(), id)?;
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
        self.expire_deadlined_state(Instant::now());
        if !self.has_accept_capacity(listener_id, listener_session_id)? {
            return Err(BrokerError::ResourceExhausted);
        }
        let mut unmatched_accept_count = 0;
        let (socket, guest_remote_address, accepted_local_address) = loop {
            let (socket, remote_address) = loop {
                let listener = self
                    .sockets
                    .get_mut(&listener_id)
                    .ok_or(BrokerError::Internal)?;
                match acceptfrom_with(
                    &listener.tcp_state()?.socket,
                    LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
                ) {
                    Ok((socket, address)) => break (socket, address),
                    Err(Errno::INTR) => {}
                    Err(Errno::AGAIN) => {
                        clear_readiness(listener, ReadinessFlags::READ)?;
                        self.tcp.finish_listener_backlog_drain(listener_id)?;
                        return Err(BrokerError::WouldBlock);
                    }
                    Err(error) => {
                        return Ok(SocketOutcome::Failed(socket_operation_error_from_errno(
                            error,
                        )?));
                    }
                }
            };
            let remote_address =
                SocketAddrV4::try_from(remote_address.ok_or(BrokerError::Internal)?)
                    .map_err(|_| BrokerError::Internal)?;
            let host_local_address = local_socket_address(&socket)?;
            if let Some((guest_address, guest_local_address)) = self
                .take_pending_guest_connection_for_accept(
                    listener_id,
                    remote_address,
                    host_local_address,
                )
            {
                break (socket, guest_address, guest_local_address);
            }
            drop(socket);
            unmatched_accept_count += 1;
            if unmatched_accept_count >= MAX_UNMATCHED_ACCEPTS_PER_COMMAND {
                let listener = self
                    .sockets
                    .get(&listener_id)
                    .ok_or(BrokerError::Internal)?;
                let readiness = listener
                    .snapshot
                    .lock()
                    .expect("Linux socket snapshot mutex poisoned")
                    .readiness;
                // Edge-triggered epoll will not report connections that remain
                // queued, so wake a blocking accept waiter to continue draining.
                listener.readiness.republish(readiness)?;
                return Err(BrokerError::WouldBlock);
            }
        };
        // Only a guest-namespace peer may be accepted, and both accepted
        // identities must agree with the shared configuration.
        let remote = SocketDestination::Guest {
            requested: guest_remote_address,
        };
        if !remote.is_valid_for(&self.network_config)
            || !self
                .tcp
                .binding_for_socket(listener_id)
                .is_some_and(|binding| {
                    binding
                        .guest_binding
                        .covers(&self.network_config, accepted_local_address)
                })
        {
            return Err(BrokerError::Internal);
        }
        let listener_session = self
            .sessions
            .get(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        if self
            .sockets
            .len()
            .checked_add(self.tcp.retained_connector_count)
            .is_none_or(|count| count >= self.max_sockets)
            || listener_session
                .live_socket_count
                .checked_add(listener_session.retained_connector_count)
                .is_none_or(|count| count >= self.max_sockets_per_session)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        apply_tcp_options(&socket, listener_tcp_no_delay, listener_tcp_keep_alive)?;
        let backlog_empty = {
            let listener = self
                .sockets
                .get_mut(&listener_id)
                .ok_or(BrokerError::Internal)?;
            let no_wait = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            loop {
                let mut poll_fd = [PollFd::new(&listener.tcp_state()?.socket, PollFlags::IN)];
                match poll(&mut poll_fd, Some(&no_wait)) {
                    Ok(_) if poll_fd[0].revents().contains(PollFlags::IN) => break false,
                    Ok(_) => {
                        clear_readiness(listener, ReadinessFlags::READ)?;
                        break true;
                    }
                    Err(Errno::INTR) => {}
                    Err(error) => return Err(broker_error_from_errno(error)),
                }
            }
        };
        if backlog_empty {
            self.tcp.finish_listener_backlog_drain(listener_id)?;
        }
        epoll::add(
            &self.epoll,
            &socket,
            epoll::EventData::new_u64(accepted_id),
            active_epoll_events(),
        )
        .map_err(broker_error_from_errno)?;
        {
            let mut snapshot = snapshot
                .lock()
                .expect("Linux socket snapshot mutex poisoned");
            snapshot.status = SocketConnectionStatus::Connected;
            snapshot.local_address = Some(accepted_local_address);
            snapshot.readiness = ReadinessFlags::WRITE;
        }
        readiness.publish(ReadinessFlags::WRITE)?;
        if !lifecycle.activate() {
            return Err(BrokerError::Internal);
        }
        self.sockets.insert(
            accepted_id,
            SocketEntry {
                session_id: listener_session_id,
                transport: SocketTransportState::Tcp(TcpSocketState {
                    socket,
                    untracked_guest_listener_id: None,
                    peek_waitall_threshold: None,
                    listening: false,
                    was_listener: false,
                    abortive_close: false,
                    host_connection: None,
                    no_delay: listener_tcp_no_delay,
                    keep_alive: listener_tcp_keep_alive,
                }),
                readiness,
                snapshot,
                connection_status: SocketConnectionStatus::Connected,
                read_shutdown: false,
                write_shutdown: false,
                guest_local_address: Some(accepted_local_address),
            },
        );
        let session = self
            .sessions
            .get_mut(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        session.live_socket_count = session
            .live_socket_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(SocketOutcome::Completed(AcceptedEndpoints {
            local_address: accepted_local_address,
            remote,
        }))
    }
}
