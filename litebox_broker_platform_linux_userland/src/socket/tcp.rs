// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux TCP reactor state and transport-specific helpers.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::{
    GuestSocketBinding, GuestSourceLease, PlatformConnectError, host_socket_destination,
    is_internal_socket_address, normalize_socket_destination,
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
    RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags, Shutdown as LinuxShutdown,
    SocketFlags as LinuxSocketFlags, connect, recv, send, shutdown, socket_with, socketpair,
    sockopt,
};

use super::{
    Reactor, SocketEntry, SocketKind, SocketLifecycle, SocketSnapshot, SocketTransportState,
    broker_error_from_errno, can_consume_synchronous_error, retain_session_state,
    socket_error_from_errno, socket_operation_error_from_errno, take_socket_error, update_snapshot,
    zeroed_vec,
};

pub(super) struct AcceptedEndpoints {
    pub(super) local_address: SocketAddrV4,
    pub(super) guest_source_lease: GuestSourceLease,
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
pub(super) struct TcpSocketState {
    pub(super) descriptor: TcpDescriptor,
    pub(super) listener: Option<GuestTcpListenerState>,
    pub(super) guest_endpoint: Option<GuestTcpEndpoint>,
    pub(super) peek_waitall_threshold: Option<usize>,
    guest_read_shutdown: Option<GuestTcpReadShutdown>,
    pub(super) abortive_close: bool,
    pub(super) no_delay: bool,
    pub(super) keep_alive: bool,
}

/// Pre-shutdown bytes preserved while later guest data is discarded.
struct GuestTcpReadShutdown {
    queued: Vec<u8>,
    consumed: usize,
    discarded_data: bool,
}

impl GuestTcpReadShutdown {
    fn has_unread_data(&self) -> bool {
        self.consumed < self.queued.len() || self.discarded_data
    }
}

fn guest_tcp_has_unread_data(tcp: &TcpSocketState) -> bool {
    tcp.guest_read_shutdown
        .as_ref()
        .is_some_and(GuestTcpReadShutdown::has_unread_data)
        || match ioctl_fionread(
            tcp.descriptor
                .socket()
                .expect("guest endpoint descriptor missing"),
        ) {
            Ok(0) => false,
            Ok(_) | Err(_) => true,
        }
}

#[cfg(test)]
impl TcpSocketState {
    pub(super) fn install_empty_guest_read_shutdown_for_test(&mut self) {
        self.guest_read_shutdown = Some(GuestTcpReadShutdown {
            queued: Vec::new(),
            consumed: 0,
            discarded_data: false,
        });
    }

    pub(super) fn has_guest_unread_data_for_test(&self) -> bool {
        guest_tcp_has_unread_data(self)
    }
}

pub(super) enum TcpDescriptor {
    Unrealized,
    NativeInet(OwnedFd),
    GuestUnix(OwnedFd),
}

impl TcpDescriptor {
    pub(super) fn socket(&self) -> BrokerResult<&OwnedFd> {
        match self {
            Self::NativeInet(socket) | Self::GuestUnix(socket) => Ok(socket),
            Self::Unrealized => Err(BrokerError::Internal),
        }
    }

    pub(super) fn is_native(&self) -> bool {
        matches!(self, Self::NativeInet(_))
    }

    fn is_guest(&self) -> bool {
        matches!(self, Self::GuestUnix(_))
    }
}

pub(super) struct GuestTcpListenerState {
    pub(super) backlog: usize,
    pub(super) queue: VecDeque<QueuedGuestTcpConnection>,
}

pub(super) struct QueuedGuestTcpConnection {
    pub(super) socket: OwnedFd,
    pub(super) connector_socket_id: u64,
    pub(super) connector_session_id: SessionId,
    pub(super) local_address: SocketAddrV4,
    pub(super) guest_source_lease: GuestSourceLease,
}

pub(super) struct GuestTcpEndpoint {
    pub(super) connector_socket_id: u64,
    pub(super) queued_listener_id: Option<u64>,
    reset_state: GuestTcpResetState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestTcpResetState {
    None,
    Pending,
    Reported,
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

pub(super) fn create_tcp_transport() -> SocketTransportState {
    SocketTransportState::Tcp(TcpSocketState {
        descriptor: TcpDescriptor::Unrealized,
        listener: None,
        guest_endpoint: None,
        peek_waitall_threshold: None,
        guest_read_shutdown: None,
        abortive_close: false,
        no_delay: false,
        keep_alive: false,
    })
}

/// Reactor-owned realization of guest TCP bindings and queued connections.
#[derive(Default)]
pub(super) struct ReactorTcpState {
    pub(super) bindings: ReactorTcpBindings,
    pub(super) queued_guest_connection_count: usize,
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
    let previous = socket.snapshot.load();
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
    let current = socket.snapshot.load();
    update_snapshot(socket, ReadinessFlags(current.0 | readiness.0))
}

fn clear_readiness(socket: &SocketEntry, readiness: ReadinessFlags) -> BrokerResult<()> {
    let current = socket.snapshot.load();
    update_snapshot(socket, ReadinessFlags(current.0 & !readiness.0))
}

fn consume_synchronous_error(socket: &mut SocketEntry) -> BrokerResult<()> {
    if !can_consume_synchronous_error(socket.connection_status) {
        return Ok(());
    }
    if socket.pending_error.is_none() {
        socket.pending_error = take_socket_error(socket)?;
    }
    let current = socket.snapshot.load();
    let readiness = if socket.pending_error.is_some() {
        current | ReadinessFlags::ERROR
    } else {
        ReadinessFlags(current.0 & !ReadinessFlags::ERROR.0)
    };
    update_snapshot(socket, readiness)
}

#[derive(Clone)]
pub(super) struct ReactorTcpBinding {
    pub(super) socket_id: u64,
    pub(super) guest_binding: GuestSocketBinding,
}

enum ResolvedTcpDestination {
    Internal {
        listener_id: u64,
        concrete_address: SocketAddrV4,
    },
    External(SocketAddrV4),
}

impl ReactorTcpState {
    pub(super) fn clear_live_state(&mut self) {
        self.bindings.clear();
        self.queued_guest_connection_count = 0;
        self.peek_cache = None;
    }

    pub(super) fn insert_binding(&mut self, binding: ReactorTcpBinding) -> BrokerResult<()> {
        let requested = binding.guest_binding.requested();
        if !binding.guest_binding.is_valid()
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

    pub(super) fn guest_binding(&self, address: SocketAddrV4) -> Option<ReactorTcpBinding> {
        self.bindings
            .exact
            .get(&address)
            .or_else(|| self.bindings.wildcard.get(&address.port()))
            .filter(|binding| binding.guest_binding.covers(address))
            .cloned()
    }

    pub(super) fn binding_for_socket(&self, socket_id: u64) -> Option<ReactorTcpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .cloned()
    }
}

fn confirm_tcp_connected(socket: &mut SocketEntry) {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Connected;
    let readiness = socket.snapshot.load();
    let _ = update_snapshot(socket, readiness);
}

/// Records a terminal native operation while a connect is pending.
fn fail_connect(socket: &mut SocketEntry, error: SocketError) {
    if socket.kind() != SocketKind::Tcp
        || socket.connection_status != SocketConnectionStatus::Connecting
    {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Failed(error);
    let readiness = socket.snapshot.load() | ReadinessFlags::ERROR;
    let _ = update_snapshot(socket, readiness);
}

pub(super) fn connect_tcp_socket(
    epoll_fd: &OwnedFd,
    id: u64,
    socket: &mut SocketEntry,
    address: SocketAddrV4,
) -> core::result::Result<(SocketConnectionStatus, ReadinessFlags), PlatformConnectError> {
    if socket.connection_status != SocketConnectionStatus::Unconnected {
        return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
    }
    let (no_delay, keep_alive, unrealized) = {
        let tcp = socket
            .tcp_state()
            .map_err(PlatformConnectError::PeerUnchanged)?;
        (
            tcp.no_delay,
            tcp.keep_alive,
            matches!(tcp.descriptor, TcpDescriptor::Unrealized),
        )
    };
    if !unrealized {
        return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
    }
    let native_socket = socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
        Some(ipproto::TCP),
    )
    .map_err(|error| PlatformConnectError::PeerUnchanged(broker_error_from_errno(error)))?;
    apply_tcp_options(&native_socket, no_delay, keep_alive)
        .map_err(PlatformConnectError::PeerUnchanged)?;
    epoll::add(
        epoll_fd,
        &native_socket,
        epoll::EventData::new_u64(id),
        active_epoll_events(),
    )
    .map_err(|error| PlatformConnectError::PeerUnchanged(broker_error_from_errno(error)))?;
    socket
        .tcp_state_mut()
        .map_err(PlatformConnectError::PeerUnchanged)?
        .descriptor = TcpDescriptor::NativeInet(native_socket);
    socket.connection_status = SocketConnectionStatus::Connecting;
    let status = loop {
        match connect(
            socket
                .tcp_state()
                .map_err(PlatformConnectError::PeerIndeterminate)?
                .descriptor
                .socket()
                .map_err(PlatformConnectError::PeerIndeterminate)?,
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
                        update_snapshot(socket, ReadinessFlags::ERROR)
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
    if guest_reset_pending(socket)? {
        if !consume_pending_guest_reset(socket)? {
            return Err(BrokerError::Internal);
        }
        return Ok(SocketOutcome::Failed(SocketError::ConnectionReset));
    }
    match socket.connection_status {
        SocketConnectionStatus::Unconnected => {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        SocketConnectionStatus::Failed(error) => return Ok(SocketOutcome::Failed(error)),
        _ => {}
    }
    loop {
        match send(
            socket.tcp_state()?.descriptor.socket()?,
            data,
            LinuxSendFlags::NOSIGNAL,
        ) {
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
    if socket.tcp_state()?.guest_read_shutdown.is_some() {
        if !flags.contains(ReceiveFlags::PEEK)
            && peek_cache
                .as_ref()
                .is_some_and(|cache| cache.socket_id == socket_id)
        {
            *peek_cache = None;
        }
        if let Some(outcome) =
            receive_guest_read_shutdown(socket, length, flags, peek_offset, peek_length)?
        {
            return Ok(outcome);
        }
        if guest_reset_pending(socket)? {
            if !consume_pending_guest_reset(socket)? {
                return Err(BrokerError::Internal);
            }
            return Ok(ReactorReceiveOutcome::Failed(SocketError::ConnectionReset));
        }
        return Ok(ReactorReceiveOutcome::EndOfStream);
    }
    if guest_reset_pending(socket)? {
        let available = ioctl_fionread(socket.tcp_state()?.descriptor.socket()?)
            .map_err(broker_error_from_errno)?;
        if available == 0 {
            if !consume_pending_guest_reset(socket)? {
                return Err(BrokerError::Internal);
            }
            return Ok(ReactorReceiveOutcome::Failed(SocketError::ConnectionReset));
        }
    }
    match socket.connection_status {
        SocketConnectionStatus::Unconnected => {
            return Ok(ReactorReceiveOutcome::Failed(SocketError::NotConnected));
        }
        SocketConnectionStatus::Failed(error) => {
            return Ok(ReactorReceiveOutcome::Failed(error));
        }
        _ => {}
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
        let readiness = socket.snapshot.load();
        let terminal = socket.read_shutdown
            || readiness.contains(ReadinessFlags::HANGUP)
            || readiness.contains(ReadinessFlags::ERROR);
        if socket.connection_status == SocketConnectionStatus::Connected
            && !terminal
            && ioctl_fionread(socket.tcp_state()?.descriptor.socket()?)
                .map_err(broker_error_from_errno)?
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
                ioctl_fionread(socket.tcp_state()?.descriptor.socket()?)
                    .map_err(broker_error_from_errno)?,
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
        let readiness = socket.snapshot.load();
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
        match recv(
            socket.tcp_state()?.descriptor.socket()?,
            data.as_mut_slice(),
            flags,
        ) {
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
                let terminal_readable =
                    socket.read_shutdown || socket.snapshot.load().contains(ReadinessFlags::HANGUP);
                if !flags.contains(LinuxRecvFlags::PEEK) && !terminal_readable {
                    let no_queued_data = ioctl_fionread(socket.tcp_state()?.descriptor.socket()?)
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

fn receive_guest_read_shutdown(
    socket: &mut SocketEntry,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<Option<ReactorReceiveOutcome>> {
    let peek = flags.contains(ReceiveFlags::PEEK);
    let (relative_start, relative_end) = if peek {
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
        (peek_offset, peek_end)
    } else {
        if peek_offset != 0 || peek_length != 0 {
            return Err(BrokerError::UnsupportedOperation);
        }
        (0, length)
    };

    let shutdown = socket
        .tcp_state_mut()?
        .guest_read_shutdown
        .as_mut()
        .ok_or(BrokerError::Internal)?;
    if shutdown.queued.is_empty() {
        return Ok(None);
    }
    let start = shutdown
        .consumed
        .checked_add(relative_start)
        .ok_or(BrokerError::Internal)?;
    if start >= shutdown.queued.len() {
        return Ok(Some(ReactorReceiveOutcome::EndOfStream));
    }
    let end = shutdown
        .consumed
        .checked_add(relative_end)
        .ok_or(BrokerError::Internal)?
        .min(shutdown.queued.len());
    let mut data = Vec::new();
    data.try_reserve_exact(end - start)
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.extend_from_slice(&shutdown.queued[start..end]);
    if !peek {
        shutdown.consumed = end;
        if shutdown.consumed == shutdown.queued.len() {
            shutdown.queued = Vec::new();
            shutdown.consumed = 0;
        }
    }
    Ok(Some(ReactorReceiveOutcome::Received(data)))
}

fn capture_guest_read_shutdown(
    socket: &SocketEntry,
    mut queued: Vec<u8>,
) -> BrokerResult<GuestTcpReadShutdown> {
    let mut received = 0;
    while received < queued.len() {
        match recv(
            socket.tcp_state()?.descriptor.socket()?,
            &mut queued[received..],
            LinuxRecvFlags::WAITALL,
        ) {
            Ok((_buffer, 0)) => return Err(BrokerError::Internal),
            Ok((_buffer, count)) => {
                received = received.checked_add(count).ok_or(BrokerError::Internal)?;
            }
            Err(Errno::INTR) => {}
            Err(_) => return Err(BrokerError::Internal),
        }
    }
    Ok(GuestTcpReadShutdown {
        queued,
        consumed: 0,
        discarded_data: false,
    })
}

fn discard_guest_read_shutdown_data(socket: &mut SocketEntry) -> BrokerResult<()> {
    if socket.tcp_state()?.guest_read_shutdown.is_none() {
        return Ok(());
    }
    let mut data = [0_u8; 8192];
    let mut discarded_data = false;
    loop {
        match recv(
            socket.tcp_state()?.descriptor.socket()?,
            &mut data,
            LinuxRecvFlags::empty(),
        ) {
            Ok((_, 0)) | Err(Errno::AGAIN) => break,
            Ok((_buffer, _)) => discarded_data = true,
            Err(Errno::INTR) => {}
            Err(error) => {
                socket_operation_error_from_errno(error)?;
                break;
            }
        }
    }
    if discarded_data {
        socket
            .tcp_state_mut()?
            .guest_read_shutdown
            .as_mut()
            .ok_or(BrokerError::Internal)?
            .discarded_data = true;
    }
    Ok(())
}

pub(super) fn set_tcp_option(socket: &mut SocketEntry, value: TcpOptionValue) -> BrokerResult<()> {
    if socket.kind() != SocketKind::Tcp {
        return Err(BrokerError::UnsupportedOperation);
    }
    match value {
        TcpOptionValue::NoDelay(value) => {
            if socket.tcp_state()?.descriptor.is_native() {
                sockopt::set_tcp_nodelay(socket.tcp_state()?.descriptor.socket()?, value)
                    .map_err(broker_error_from_errno)?;
            }
            socket.tcp_state_mut()?.no_delay = value;
        }
        TcpOptionValue::KeepAlive(value) => {
            if socket.tcp_state()?.descriptor.is_native() {
                sockopt::set_socket_keepalive(socket.tcp_state()?.descriptor.socket()?, value)
                    .map_err(broker_error_from_errno)?;
            }
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
        TcpOptionName::NoDelay if socket.tcp_state()?.descriptor.is_native() => {
            sockopt::tcp_nodelay(socket.tcp_state()?.descriptor.socket()?)
                .map(TcpOptionValue::NoDelay)
                .map_err(broker_error_from_errno)
        }
        TcpOptionName::NoDelay => Ok(TcpOptionValue::NoDelay(socket.tcp_state()?.no_delay)),
        TcpOptionName::KeepAlive if socket.tcp_state()?.descriptor.is_native() => {
            sockopt::socket_keepalive(socket.tcp_state()?.descriptor.socket()?)
                .map(TcpOptionValue::KeepAlive)
                .map_err(broker_error_from_errno)
        }
        TcpOptionName::KeepAlive => Ok(TcpOptionValue::KeepAlive(socket.tcp_state()?.keep_alive)),
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
        if socket.tcp_state()?.descriptor.is_native() {
            sockopt::set_socket_linger(
                socket.tcp_state()?.descriptor.socket()?,
                Some(Duration::ZERO),
            )
            .map_err(broker_error_from_errno)?;
        }
        socket.tcp_state_mut()?.abortive_close = true;
        return Ok(SocketOutcome::Completed(()));
    }
    if mode == ShutdownMode::StopListening {
        return Err(BrokerError::Internal);
    }
    if socket.tcp_state()?.listener.is_some() {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    if matches!(socket.tcp_state()?.descriptor, TcpDescriptor::Unrealized) {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let guest_endpoint = socket.tcp_state()?.descriptor.is_guest();
    // AF_UNIX read shutdown changes peer write behavior, so guest read
    // shutdown remains logical while write shutdown reaches the kernel.
    let (kernel_shutdown, add, clear, shuts_down_read, shuts_down_write) = match mode {
        ShutdownMode::Read => (
            (!guest_endpoint).then_some(LinuxShutdown::Read),
            ReadinessFlags::READ,
            ReadinessFlags::default(),
            true,
            false,
        ),
        ShutdownMode::Write => (
            Some(LinuxShutdown::Write),
            ReadinessFlags::default(),
            ReadinessFlags::WRITE,
            false,
            true,
        ),
        ShutdownMode::Both => (
            Some(if guest_endpoint {
                LinuxShutdown::Write
            } else {
                LinuxShutdown::Both
            }),
            ReadinessFlags::READ,
            ReadinessFlags::WRITE,
            true,
            true,
        ),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    let guest_read_shutdown_buffer = if guest_endpoint && shuts_down_read && !socket.read_shutdown {
        let available: usize = ioctl_fionread(socket.tcp_state()?.descriptor.socket()?)
            .map_err(broker_error_from_errno)?
            .try_into()
            .map_err(|_| BrokerError::Internal)?;
        Some(zeroed_vec(available)?)
    } else {
        None
    };
    if let Some(kernel_shutdown) = kernel_shutdown {
        loop {
            match shutdown(socket.tcp_state()?.descriptor.socket()?, kernel_shutdown) {
                Ok(()) => break,
                Err(Errno::INTR) => {}
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
    }
    if let Some(queued) = guest_read_shutdown_buffer {
        let shutdown = capture_guest_read_shutdown(socket, queued)?;
        socket.tcp_state_mut()?.guest_read_shutdown = Some(shutdown);
    }
    socket.read_shutdown |= shuts_down_read;
    socket.write_shutdown |= shuts_down_write;
    let republish_readiness = shuts_down_read
        && socket
            .tcp_state_mut()?
            .peek_waitall_threshold
            .take()
            .is_some();
    let current = socket.snapshot.load();
    let readiness = ReadinessFlags((current.0 & !clear.0) | add.0);
    // Native shutdown and the cached directional state are committed.
    let _ = update_snapshot(socket, readiness);
    if republish_readiness {
        let _ = socket.readiness.republish(readiness);
    }
    Ok(SocketOutcome::Completed(()))
}

pub(super) fn handle_socket_event(
    socket: &mut SocketEntry,
    events: epoll::EventFlags,
) -> BrokerResult<()> {
    // Readiness publication is best-effort on the shared reactor path: a single
    // association's publication failure must not fail the reactor for every
    // other session using it (this mirrors the UDP endpoint handler).
    // `update_snapshot` commits the cached snapshot before publishing, so a
    // dropped notification leaves the cached readiness authoritative. In
    // production an admitted socket's publication does not fail: the broker
    // bounds live readiness registrations to the sink's capacity at association
    // setup, so this only absorbs a synthetic sink fault. Genuine host-syscall
    // or internal-consistency errors still propagate and remain fatal.
    if socket.kind() == SocketKind::Udp {
        let _ = update_snapshot(socket, readiness_from_epoll(socket, events));
        return Ok(());
    }
    if events.contains(epoll::EventFlags::IN) {
        discard_guest_read_shutdown_data(socket)?;
    }
    let republish_readiness = if events.contains(epoll::EventFlags::IN)
        && let Some(threshold) = socket
            .tcp_state()
            .ok()
            .and_then(|tcp| tcp.peek_waitall_threshold)
    {
        let threshold_reached = socket
            .tcp_state()
            .and_then(|tcp| {
                ioctl_fionread(tcp.descriptor.socket()?).map_err(broker_error_from_errno)
            })
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
        SocketConnectionStatus::Connecting => {
            complete_connect(socket, events)?;
        }
        SocketConnectionStatus::Connected => {
            let _ = update_snapshot(socket, readiness_from_epoll(socket, events));
        }
        SocketConnectionStatus::Failed(SocketError::NotConnected) if socket.read_shutdown => {
            let _ = update_snapshot(socket, ReadinessFlags::WRITE | ReadinessFlags::HANGUP);
        }
        SocketConnectionStatus::Failed(_) => {
            let _ = update_snapshot(socket, ReadinessFlags::ERROR);
        }
        _ => return Err(BrokerError::Internal),
    }
    if republish_readiness {
        let readiness = socket.snapshot.load();
        let _ = socket.readiness.republish(readiness);
    }
    Ok(())
}

fn complete_connect(
    socket: &mut SocketEntry,
    events: epoll::EventFlags,
) -> BrokerResult<SocketConnectionStatus> {
    // Epoll re-polls the descriptor when waiting, so OUT here reflects the
    // current post-connect state rather than readiness cached before connect.
    if !socket.tcp_state()?.descriptor.is_native() {
        return Err(BrokerError::Internal);
    }
    let status = match sockopt::socket_error(socket.tcp_state()?.descriptor.socket()?) {
        Ok(Ok(())) if events.contains(epoll::EventFlags::OUT) => SocketConnectionStatus::Connected,
        Ok(Ok(())) => SocketConnectionStatus::Connecting,
        Ok(Err(error)) => SocketConnectionStatus::Failed(socket_error_from_errno(error)),
        Err(error) => return Err(broker_error_from_errno(error)),
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
    let _ = update_snapshot(socket, readiness);
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
        if mode == ShutdownMode::StopListening {
            let queued = {
                let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
                if socket.kind() != SocketKind::Tcp {
                    return Err(BrokerError::Internal);
                }
                let Some(listener) = socket.tcp_state_mut()?.listener.take() else {
                    return Ok(SocketOutcome::Failed(SocketError::NotConnected));
                };
                socket.tcp_state_mut()?.peek_waitall_threshold = None;
                socket.read_shutdown = true;
                socket.connection_status =
                    SocketConnectionStatus::Failed(SocketError::NotConnected);
                let _ = update_snapshot(socket, ReadinessFlags::WRITE | ReadinessFlags::HANGUP);
                listener.queue
            };
            self.discard_queued_guest_connections(queued, true);
            return Ok(SocketOutcome::Completed(()));
        }
        shutdown_tcp_socket(
            self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?,
            mode,
        )
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
            guest_binding: binding,
        })?;
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        socket.guest_local_address = Some(guest_address);
        Ok(SocketOutcome::Completed(guest_address))
    }

    pub(super) fn connect_tcp_destination(
        &mut self,
        id: u64,
        requested_destination: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let session_id = self
            .sockets
            .get(&id)
            .and_then(|socket| socket.guest_local_address.map(|_| socket.session_id))
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let binding = self
            .tcp
            .binding_for_socket(id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let destination = match self.resolve_tcp_destination(requested_destination) {
            SocketOutcome::Completed(destination) => destination,
            SocketOutcome::Failed(error) => {
                drop(guest_source_lease);
                let status = SocketConnectionStatus::Failed(error);
                let socket = self
                    .sockets
                    .get_mut(&id)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                socket.connection_status = status;
                update_snapshot(socket, ReadinessFlags::ERROR)
                    .map_err(PlatformConnectError::PeerIndeterminate)?;
                return Ok(status);
            }
        };
        if let ResolvedTcpDestination::Internal {
            listener_id,
            concrete_address,
        } = destination
        {
            let source_address = binding
                .guest_binding
                .source_address_for_destination(concrete_address)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
            let guest_source_lease = guest_source_lease
                .filter(|lease| lease.source_address() == source_address)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
            return self.connect_guest_tcp_socketpair(
                id,
                session_id,
                listener_id,
                concrete_address,
                guest_source_lease,
            );
        }
        drop(guest_source_lease);
        let ResolvedTcpDestination::External(external_destination) = destination else {
            unreachable!("internal destination handled above");
        };
        let native_destination = host_socket_destination(external_destination);
        let guest_local_address = binding
            .guest_binding
            .source_address_for_destination(external_destination)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let (status, readiness) = connect_tcp_socket(
            &self.epoll,
            id,
            self.sockets
                .get_mut(&id)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?,
            native_destination,
        )?;
        if matches!(
            status,
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ) {
            let socket =
                self.sockets
                    .get_mut(&id)
                    .ok_or(PlatformConnectError::PeerIndeterminate(
                        BrokerError::Internal,
                    ))?;
            socket.guest_local_address = Some(guest_local_address);
        }
        update_snapshot(
            self.sockets
                .get(&id)
                .ok_or(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ))?,
            readiness,
        )
        .map_err(PlatformConnectError::PeerIndeterminate)?;
        Ok(status)
    }

    fn connect_guest_tcp_socketpair(
        &mut self,
        connector_socket_id: u64,
        connector_session_id: SessionId,
        listener_id: u64,
        local_address: SocketAddrV4,
        guest_source_lease: GuestSourceLease,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let source_address = guest_source_lease.source_address();
        let combined_count = self
            .sockets
            .len()
            .checked_add(self.tcp.queued_guest_connection_count)
            .and_then(|count| count.checked_add(1))
            .ok_or(PlatformConnectError::PeerUnchanged(
                BrokerError::ResourceExhausted,
            ))?;
        let session = self
            .sessions
            .get(&connector_session_id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let next_pending_count = session
            .pending_guest_connection_count
            .checked_add(1)
            .ok_or(PlatformConnectError::PeerUnchanged(
                BrokerError::ResourceExhausted,
            ))?;
        let connector_session_count = session
            .live_socket_count
            .checked_add(next_pending_count)
            .ok_or(PlatformConnectError::PeerUnchanged(
                BrokerError::ResourceExhausted,
            ))?;
        if combined_count > self.max_sockets
            || connector_session_count > self.max_sockets_per_session
        {
            return Err(PlatformConnectError::PeerUnchanged(
                BrokerError::ResourceExhausted,
            ));
        }
        {
            let connector = self
                .sockets
                .get(&connector_socket_id)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
            if connector.connection_status != SocketConnectionStatus::Unconnected
                || !matches!(
                    connector
                        .tcp_state()
                        .map_err(PlatformConnectError::PeerUnchanged)?
                        .descriptor,
                    TcpDescriptor::Unrealized
                )
            {
                return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
            }
            let listener = self
                .sockets
                .get(&listener_id)
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
            let listener = listener
                .tcp_state()
                .map_err(PlatformConnectError::PeerUnchanged)?
                .listener
                .as_ref()
                .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
            if listener.queue.len() >= listener.backlog {
                drop(guest_source_lease);
                let status = SocketConnectionStatus::Failed(SocketError::ConnectionRefused);
                let connector = self
                    .sockets
                    .get_mut(&connector_socket_id)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                connector.connection_status = status;
                update_snapshot(connector, ReadinessFlags::ERROR)
                    .map_err(PlatformConnectError::PeerIndeterminate)?;
                return Ok(status);
            }
        }
        self.sockets
            .get_mut(&listener_id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .listener
            .as_mut()
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?
            .queue
            .try_reserve(1)
            .map_err(|_| PlatformConnectError::PeerUnchanged(BrokerError::OutOfMemory))?;
        let (connector_socket, accepted_socket) = socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
            None,
        )
        .map_err(|error| PlatformConnectError::PeerUnchanged(broker_error_from_errno(error)))?;
        epoll::add(
            &self.epoll,
            &connector_socket,
            epoll::EventData::new_u64(connector_socket_id),
            active_epoll_events(),
        )
        .map_err(|error| PlatformConnectError::PeerUnchanged(broker_error_from_errno(error)))?;

        {
            let connector = self.sockets.get_mut(&connector_socket_id).ok_or(
                PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
            )?;
            let tcp = connector
                .tcp_state_mut()
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            tcp.descriptor = TcpDescriptor::GuestUnix(connector_socket);
            tcp.guest_endpoint = Some(GuestTcpEndpoint {
                connector_socket_id,
                queued_listener_id: Some(listener_id),
                reset_state: GuestTcpResetState::None,
            });
            connector.guest_local_address = Some(source_address);
            connector.connection_status = SocketConnectionStatus::Connected;
        }
        self.sockets
            .get_mut(&listener_id)
            .expect("validated guest listener missing")
            .tcp_state_mut()
            .expect("validated guest listener changed transport")
            .listener
            .as_mut()
            .expect("validated guest listener stopped")
            .queue
            .push_back(QueuedGuestTcpConnection {
                socket: accepted_socket,
                connector_socket_id,
                connector_session_id,
                local_address,
                guest_source_lease,
            });
        self.tcp.queued_guest_connection_count = combined_count - self.sockets.len();
        self.sessions
            .get_mut(&connector_session_id)
            .expect("validated connector session missing")
            .pending_guest_connection_count = next_pending_count;

        if let Err(error) = update_snapshot(
            self.sockets.get(&connector_socket_id).ok_or(
                PlatformConnectError::PeerIndeterminate(BrokerError::Internal),
            )?,
            ReadinessFlags::WRITE,
        ) {
            self.remove_queued_guest_connection(listener_id, connector_socket_id, false);
            return Err(PlatformConnectError::PeerIndeterminate(error));
        }
        if let Err(error) = self.publish_listener_queue_readiness(listener_id) {
            self.remove_queued_guest_connection(listener_id, connector_socket_id, false);
            return Err(PlatformConnectError::PeerIndeterminate(error));
        }
        Ok(SocketConnectionStatus::Connected)
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
        let session_closing = self
            .sessions
            .get(&session_id)
            .is_some_and(|session| session.closing);
        let queued_connection = self
            .sockets
            .get(&id)
            .and_then(|socket| socket.tcp_state().ok())
            .and_then(|tcp| {
                tcp.guest_endpoint.as_ref().and_then(|endpoint| {
                    endpoint
                        .queued_listener_id
                        .map(|listener_id| (listener_id, endpoint.connector_socket_id))
                })
            });
        let abortive_close = self
            .sockets
            .get(&id)
            .and_then(|socket| socket.tcp_state().ok())
            .is_some_and(|tcp| tcp.abortive_close);
        if (session_closing || abortive_close)
            && let Some((listener_id, connector_socket_id)) = queued_connection
        {
            self.remove_queued_guest_connection(listener_id, connector_socket_id, false);
        }
        let guest_connector_socket_id = self
            .sockets
            .get(&id)
            .and_then(|socket| socket.tcp_state().ok())
            .and_then(|tcp| {
                tcp.guest_endpoint
                    .as_ref()
                    .map(|endpoint| endpoint.connector_socket_id)
            });
        let reset_peer = guest_connector_socket_id.is_some()
            && self
                .sockets
                .get(&id)
                .and_then(|socket| socket.tcp_state().ok())
                .is_some_and(|tcp| {
                    tcp.abortive_close
                        || tcp.descriptor.is_guest() && guest_tcp_has_unread_data(tcp)
                });
        let socket = self
            .sockets
            .remove(&id)
            .expect("checked TCP socket missing");
        let SocketEntry {
            transport,
            guest_local_address,
            ..
        } = socket;
        let SocketTransportState::Tcp(mut tcp) = transport else {
            unreachable!("checked TCP socket changed transport");
        };
        if tcp.abortive_close
            && let TcpDescriptor::NativeInet(socket) = &tcp.descriptor
        {
            // Abort may be requested before lazy native realization or after
            // the response receiver disappears, so enforce it again at close.
            let _ = sockopt::set_socket_linger(socket, Some(Duration::ZERO));
        }
        if let Some(address) = guest_local_address {
            self.tcp.remove_binding(address.port(), id);
        }
        if let Some(listener) = tcp.listener.take() {
            self.discard_queued_guest_connections(listener.queue, true);
        }
        if reset_peer && let Some(connector_socket_id) = guest_connector_socket_id {
            self.mark_guest_peer_reset(connector_socket_id, id);
        }
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.live_socket_count = session
                .live_socket_count
                .checked_sub(1)
                .expect("session socket count underflow");
        }
        self.sessions
            .retain(|_, session| retain_session_state(session));
    }

    fn release_queued_guest_connection(&mut self, connector_session_id: SessionId) {
        self.tcp.queued_guest_connection_count = self
            .tcp
            .queued_guest_connection_count
            .checked_sub(1)
            .expect("reactor queued guest connection count underflow");
        let session = self
            .sessions
            .get_mut(&connector_session_id)
            .expect("queued guest connection session state missing");
        session.pending_guest_connection_count = session
            .pending_guest_connection_count
            .checked_sub(1)
            .expect("session queued guest connection count underflow");
    }

    fn discard_queued_guest_connections(
        &mut self,
        queued: VecDeque<QueuedGuestTcpConnection>,
        reset_connectors: bool,
    ) {
        for connection in queued {
            self.release_queued_guest_connection(connection.connector_session_id);
            if let Some(connector) = self.sockets.get_mut(&connection.connector_socket_id)
                && let Ok(tcp) = connector.tcp_state_mut()
                && let Some(endpoint) = tcp.guest_endpoint.as_mut()
                && endpoint.connector_socket_id == connection.connector_socket_id
            {
                endpoint.queued_listener_id = None;
            }
            if reset_connectors {
                self.mark_guest_socket_reset(connection.connector_socket_id);
            }
        }
        self.sessions
            .retain(|_, session| retain_session_state(session));
    }

    pub(super) fn purge_connector_session_queues(&mut self, session_id: SessionId) {
        loop {
            let queued = self.sockets.iter().find_map(|(listener_id, socket)| {
                socket
                    .tcp_state()
                    .ok()
                    .and_then(|tcp| tcp.listener.as_ref())
                    .and_then(|listener| {
                        listener
                            .queue
                            .iter()
                            .find(|connection| connection.connector_session_id == session_id)
                    })
                    .map(|connection| (*listener_id, connection.connector_socket_id))
            });
            let Some((listener_id, connector_socket_id)) = queued else {
                break;
            };
            if !self.remove_queued_guest_connection(listener_id, connector_socket_id, false) {
                break;
            }
        }
    }

    fn remove_queued_guest_connection(
        &mut self,
        listener_id: u64,
        connector_socket_id: u64,
        reset_connector: bool,
    ) -> bool {
        let connection = self
            .sockets
            .get_mut(&listener_id)
            .and_then(|listener| listener.tcp_state_mut().ok())
            .and_then(|tcp| tcp.listener.as_mut())
            .and_then(|listener| {
                listener
                    .queue
                    .iter()
                    .position(|connection| connection.connector_socket_id == connector_socket_id)
                    .and_then(|index| listener.queue.remove(index))
            });
        let Some(connection) = connection else {
            return false;
        };
        self.release_queued_guest_connection(connection.connector_session_id);
        if let Some(connector) = self.sockets.get_mut(&connection.connector_socket_id)
            && let Ok(tcp) = connector.tcp_state_mut()
            && let Some(endpoint) = tcp.guest_endpoint.as_mut()
            && endpoint.connector_socket_id == connector_socket_id
        {
            endpoint.queued_listener_id = None;
        }
        if reset_connector {
            self.mark_guest_socket_reset(connection.connector_socket_id);
        }
        let _ = self.publish_listener_queue_readiness(listener_id);
        self.sessions
            .retain(|_, session| retain_session_state(session));
        true
    }

    fn mark_guest_peer_reset(&mut self, connector_socket_id: u64, excluded_id: u64) {
        let peer_id = self.sockets.iter().find_map(|(id, socket)| {
            (*id != excluded_id
                && socket
                    .tcp_state()
                    .ok()
                    .and_then(|tcp| tcp.guest_endpoint.as_ref())
                    .is_some_and(|endpoint| endpoint.connector_socket_id == connector_socket_id))
            .then_some(*id)
        });
        if let Some(peer_id) = peer_id {
            self.mark_guest_socket_reset(peer_id);
        }
    }

    fn mark_guest_socket_reset(&mut self, id: u64) {
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        let Ok(tcp) = socket.tcp_state_mut() else {
            return;
        };
        let Some(endpoint) = tcp.guest_endpoint.as_mut() else {
            return;
        };
        match endpoint.reset_state {
            GuestTcpResetState::None => endpoint.reset_state = GuestTcpResetState::Pending,
            GuestTcpResetState::Pending => {}
            GuestTcpResetState::Reported => return,
        }
        if socket.pending_error.is_none() {
            socket.pending_error = Some(SocketError::ConnectionReset);
        }
        let current = socket.snapshot.load();
        let readiness =
            current | ReadinessFlags::READ | ReadinessFlags::ERROR | ReadinessFlags::HANGUP;
        let _ = if readiness == current {
            socket.readiness.republish(readiness)
        } else {
            update_snapshot(socket, readiness)
        };
    }

    fn publish_listener_queue_readiness(&self, listener_id: u64) -> BrokerResult<()> {
        let listener = self
            .sockets
            .get(&listener_id)
            .ok_or(BrokerError::Internal)?;
        let queue_nonempty = listener
            .tcp_state()?
            .listener
            .as_ref()
            .is_some_and(|state| !state.queue.is_empty());
        let current = listener.snapshot.load();
        if queue_nonempty {
            if current.contains(ReadinessFlags::READ) {
                listener.readiness.republish(current)
            } else {
                update_snapshot(listener, current | ReadinessFlags::READ)
            }
        } else if current.contains(ReadinessFlags::READ) {
            update_snapshot(
                listener,
                ReadinessFlags(current.0 & !ReadinessFlags::READ.0),
            )
        } else {
            Ok(())
        }
    }

    fn purge_failed_accept_setup(&mut self, listener_id: u64, connector_socket_id: u64) {
        if let Some(socket) = self
            .sockets
            .get(&listener_id)
            .and_then(|listener| listener.tcp_state().ok())
            .and_then(|tcp| tcp.listener.as_ref())
            .and_then(|listener| {
                listener
                    .queue
                    .iter()
                    .find(|connection| connection.connector_socket_id == connector_socket_id)
            })
            .map(|connection| &connection.socket)
        {
            let _ = epoll::delete(&self.epoll, socket);
        }
        self.remove_queued_guest_connection(listener_id, connector_socket_id, true);
    }

    fn resolve_tcp_destination(
        &self,
        requested_destination: SocketAddrV4,
    ) -> SocketOutcome<ResolvedTcpDestination> {
        let destination = match normalize_socket_destination(requested_destination) {
            Ok(destination) => destination,
            Err(error) => return SocketOutcome::Failed(error),
        };
        if !is_internal_socket_address(destination) {
            return SocketOutcome::Completed(ResolvedTcpDestination::External(destination));
        }
        let Some(binding) = self.tcp.guest_binding(destination) else {
            return SocketOutcome::Failed(SocketError::ConnectionRefused);
        };
        let listener_live = self
            .sockets
            .get(&binding.socket_id)
            .and_then(|listener| listener.tcp_state().ok())
            .and_then(|tcp| tcp.listener.as_ref())
            .is_some();
        if !listener_live {
            return SocketOutcome::Failed(SocketError::ConnectionRefused);
        }
        SocketOutcome::Completed(ResolvedTcpDestination::Internal {
            listener_id: binding.socket_id,
            concrete_address: destination,
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
        self.tcp
            .binding_for_socket(id)
            .filter(|binding| binding.guest_binding.requested() == guest_address)
            .ok_or(BrokerError::Internal)?;
        let backlog = usize::try_from(backlog)
            .map_err(|_| BrokerError::UnsupportedOperation)?
            .max(1);
        let socket = self.sockets.get_mut(&id).ok_or(BrokerError::Internal)?;
        if socket.connection_status != SocketConnectionStatus::Unconnected
            || !matches!(socket.tcp_state()?.descriptor, TcpDescriptor::Unrealized)
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        match socket.tcp_state_mut()?.listener.as_mut() {
            Some(listener) => {
                listener.backlog = backlog;
            }
            None => {
                socket.tcp_state_mut()?.listener = Some(GuestTcpListenerState {
                    backlog,
                    queue: VecDeque::new(),
                });
            }
        }
        Ok(SocketOutcome::Completed(guest_address))
    }

    pub(super) fn accept_socket(
        &mut self,
        listener_id: u64,
        accepted_id: u64,
        readiness: ReadinessRegistration,
        snapshot: Arc<SocketSnapshot>,
        lifecycle: &SocketLifecycle,
    ) -> BrokerResult<SocketOutcome<AcceptedEndpoints>> {
        if self.sockets.contains_key(&accepted_id) {
            return Err(BrokerError::Internal);
        }
        let (
            listener_session_id,
            listener_tcp_no_delay,
            listener_tcp_keep_alive,
            queue_length,
            accepted_connector_socket_id,
            accepted_connector_session_id,
        ) = {
            let listener = self
                .sockets
                .get(&listener_id)
                .ok_or(BrokerError::Internal)?;
            let tcp = listener.tcp_state()?;
            let Some(listener_state) = tcp.listener.as_ref() else {
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            };
            (
                listener.session_id,
                tcp.no_delay,
                tcp.keep_alive,
                listener_state.queue.len(),
                listener_state
                    .queue
                    .front()
                    .map(|queued| queued.connector_socket_id),
                listener_state
                    .queue
                    .front()
                    .map(|queued| queued.connector_session_id),
            )
        };
        if queue_length == 0 {
            self.publish_listener_queue_readiness(listener_id)?;
            return Err(BrokerError::WouldBlock);
        }
        let accepted_connector_socket_id =
            accepted_connector_socket_id.ok_or(BrokerError::Internal)?;
        let accepted_connector_session_id =
            accepted_connector_session_id.ok_or(BrokerError::Internal)?;
        let listener_session = self
            .sessions
            .get(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        let next_listener_live_count = listener_session
            .live_socket_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        let transferred_pending = usize::from(accepted_connector_session_id == listener_session_id);
        let next_listener_total = next_listener_live_count
            .checked_add(listener_session.pending_guest_connection_count)
            .and_then(|count| count.checked_sub(transferred_pending))
            .ok_or(BrokerError::Internal)?;
        if next_listener_total > self.max_sockets_per_session {
            return Err(BrokerError::ResourceExhausted);
        }
        {
            let listener = self
                .sockets
                .get(&listener_id)
                .ok_or(BrokerError::Internal)?;
            let queued = listener
                .tcp_state()?
                .listener
                .as_ref()
                .and_then(|listener| listener.queue.front())
                .ok_or(BrokerError::Internal)?;
            if let Err(error) = epoll::add(
                &self.epoll,
                &queued.socket,
                epoll::EventData::new_u64(accepted_id),
                active_epoll_events(),
            ) {
                let error = broker_error_from_errno(error);
                self.purge_failed_accept_setup(listener_id, accepted_connector_socket_id);
                return Err(error);
            }
        }
        snapshot.store(ReadinessFlags::WRITE);
        if let Err(error) = readiness.publish(ReadinessFlags::WRITE) {
            self.purge_failed_accept_setup(listener_id, accepted_connector_socket_id);
            return Err(error);
        }
        if queue_length > 1
            && let Err(error) = self.publish_listener_queue_readiness(listener_id)
        {
            self.purge_failed_accept_setup(listener_id, accepted_connector_socket_id);
            return Err(error);
        }
        if !lifecycle.activate() {
            self.purge_failed_accept_setup(listener_id, accepted_connector_socket_id);
            return Err(BrokerError::Internal);
        }
        let queued = self
            .sockets
            .get_mut(&listener_id)
            .ok_or(BrokerError::Internal)?
            .tcp_state_mut()?
            .listener
            .as_mut()
            .ok_or(BrokerError::Internal)?
            .queue
            .pop_front()
            .ok_or(BrokerError::Internal)?;
        let QueuedGuestTcpConnection {
            socket,
            connector_socket_id,
            connector_session_id,
            local_address,
            guest_source_lease,
        } = queued;
        self.release_queued_guest_connection(connector_session_id);
        if let Some(connector) = self.sockets.get_mut(&connector_socket_id)
            && let Ok(tcp) = connector.tcp_state_mut()
            && let Some(endpoint) = tcp.guest_endpoint.as_mut()
            && endpoint.connector_socket_id == connector_socket_id
        {
            endpoint.queued_listener_id = None;
        }
        self.sockets.insert(
            accepted_id,
            SocketEntry {
                session_id: listener_session_id,
                transport: SocketTransportState::Tcp(TcpSocketState {
                    descriptor: TcpDescriptor::GuestUnix(socket),
                    listener: None,
                    guest_endpoint: Some(GuestTcpEndpoint {
                        connector_socket_id,
                        queued_listener_id: None,
                        reset_state: GuestTcpResetState::None,
                    }),
                    peek_waitall_threshold: None,
                    guest_read_shutdown: None,
                    abortive_close: false,
                    no_delay: listener_tcp_no_delay,
                    keep_alive: listener_tcp_keep_alive,
                }),
                readiness,
                snapshot,
                connection_status: SocketConnectionStatus::Connected,
                pending_error: None,
                read_shutdown: false,
                write_shutdown: false,
                guest_local_address: Some(local_address),
            },
        );
        let session = self
            .sessions
            .get_mut(&listener_session_id)
            .ok_or(BrokerError::Internal)?;
        session.live_socket_count = next_listener_live_count;
        if queue_length == 1 {
            let _ = self.publish_listener_queue_readiness(listener_id);
        }
        Ok(SocketOutcome::Completed(AcceptedEndpoints {
            local_address,
            guest_source_lease,
        }))
    }
}

pub(super) fn guest_reset_pending(socket: &SocketEntry) -> BrokerResult<bool> {
    Ok(socket
        .tcp_state()?
        .guest_endpoint
        .as_ref()
        .is_some_and(|endpoint| endpoint.reset_state == GuestTcpResetState::Pending))
}

pub(super) fn consume_pending_guest_reset(socket: &mut SocketEntry) -> BrokerResult<bool> {
    let consumed = {
        let tcp = socket.tcp_state_mut()?;
        let Some(endpoint) = tcp.guest_endpoint.as_mut() else {
            return Ok(false);
        };
        if endpoint.reset_state != GuestTcpResetState::Pending {
            return Ok(false);
        }
        endpoint.reset_state = GuestTcpResetState::Reported;
        true
    };
    if consumed {
        if socket.pending_error == Some(SocketError::ConnectionReset) {
            socket.pending_error = None;
        }
        let cleared_readiness = {
            let readiness = socket.snapshot.load();
            if socket.pending_error.is_none() && readiness.contains(ReadinessFlags::ERROR) {
                let readiness = ReadinessFlags(readiness.0 & !ReadinessFlags::ERROR.0);
                socket.snapshot.store(readiness);
                Some(readiness)
            } else {
                None
            }
        };
        if let Some(readiness) = cleared_readiness {
            // The synchronous operation reports the reset even if its
            // readiness notification cannot be delivered.
            let _ = socket.readiness.publish(readiness);
        }
    }
    Ok(consumed)
}
