// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux TCP socket state and transport-specific helpers.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddrV4;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use litebox_broker_core::socket::{
    GuestSocketBinding, GuestSourceLease, PlatformConnectError, host_socket_destination,
    is_internal_socket_address, normalize_socket_destination,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    MAX_SOCKET_PEEK_SIZE, MAX_SOCKET_TRANSFER_SIZE, ReceiveFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOptionName, SocketOptionValue, SocketOutcome,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use rustix::event::epoll;
use rustix::io::{Errno, ioctl_fionread};
use rustix::net::ipproto;
use rustix::net::{
    RecvFlags as LinuxRecvFlags, SendFlags as LinuxSendFlags, Shutdown as LinuxShutdown,
    SocketFlags as LinuxSocketFlags, connect, recv, send, shutdown, socket_with, socketpair,
    sockopt,
};

use super::{
    HookPoint, LinuxSocket, SocketEntry, SocketInbox, SocketKind, SocketState,
    SocketTransportState, Topology, broker_error_from_errno, can_consume_synchronous_error, lock,
    republish_snapshot, socket_error_from_errno, socket_operation_error_from_errno,
    take_socket_error, update_snapshot, zeroed_vec,
};

pub(super) struct AcceptedEndpoints {
    pub(super) local_address: SocketAddrV4,
    pub(super) guest_source_lease: GuestSourceLease,
}

pub(super) enum ReceiveOutcome {
    Received(Vec<u8>),
    EndOfStream,
    Failed(SocketError),
}

/// Bytes a multi-window peek read at offset zero, served to its later windows.
struct PeekCache {
    requested_length: usize,
    data: Vec<u8>,
}

/// Retains an error's source so a guest reset remains distinguishable from an
/// independent socket `ConnectionReset` even though both have the same public value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TcpPendingError {
    Socket(SocketError),
    GuestReset,
}

impl TcpPendingError {
    pub(super) fn error(self) -> SocketError {
        match self {
            Self::Socket(error) => error,
            Self::GuestReset => SocketError::ConnectionReset,
        }
    }
}

#[derive(Default)]
pub(super) struct TcpPendingErrors {
    current: Option<TcpPendingError>,
    next: Option<TcpPendingError>,
}

impl TcpPendingErrors {
    pub(super) fn append(&mut self, error: TcpPendingError) {
        if error == TcpPendingError::GuestReset && self.contains_guest_reset() {
            return;
        }
        if self.current.is_none() {
            self.current = Some(error);
        } else if self.next.is_none() {
            self.next = Some(error);
        }
    }

    pub(super) fn take(&mut self) -> Option<TcpPendingError> {
        let error = self.current.take();
        self.current = self.next.take();
        error
    }

    pub(super) fn contains_guest_reset(&self) -> bool {
        matches!(self.current, Some(TcpPendingError::GuestReset))
            || matches!(self.next, Some(TcpPendingError::GuestReset))
    }

    pub(super) fn remove_guest_reset(&mut self) {
        if matches!(self.next, Some(TcpPendingError::GuestReset)) {
            self.next = None;
        } else if matches!(self.current, Some(TcpPendingError::GuestReset)) {
            self.take();
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.current.is_none()
    }
}

/// TCP descriptor and transport-specific state guarded by the socket's `state`.
pub(super) struct TcpSocketState {
    pub(super) descriptor: TcpDescriptor,
    /// The socket is a listener; its queue lives in [`TcpTopology`].
    listening: bool,
    pub(super) guest_endpoint: Option<GuestTcpEndpoint>,
    pub(super) peek_waitall_threshold: Option<usize>,
    /// The reader whose peek the next request past offset zero may continue,
    /// as [`continue_peek`] describes.
    peek_reader: Option<ObjectHandle>,
    peek_cache: Option<PeekCache>,
    pub(super) pending_errors: TcpPendingErrors,
    guest_read_shutdown: Option<GuestTcpReadShutdown>,
    pub(super) abortive_close: bool,
    options: TcpOptions,
}

/// Socket options the broker applies to a TCP socket's host descriptor.
#[derive(Clone, Copy, Default)]
struct TcpOptions {
    no_delay: bool,
    keep_alive: bool,
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
    ExternalInet(OwnedFd),
    InternalUnix(OwnedFd),
}

impl TcpDescriptor {
    pub(super) fn socket(&self) -> BrokerResult<&OwnedFd> {
        match self {
            Self::ExternalInet(socket) | Self::InternalUnix(socket) => Ok(socket),
            Self::Unrealized => Err(BrokerError::Internal),
        }
    }

    pub(super) fn is_external(&self) -> bool {
        matches!(self, Self::ExternalInet(_))
    }

    fn is_internal(&self) -> bool {
        matches!(self, Self::InternalUnix(_))
    }
}

/// A guest listener's backlog and the internal connections queued on it.
struct TcpListener {
    inbox: Arc<SocketInbox>,
    backlog: usize,
    queue: VecDeque<QueuedGuestTcpConnection>,
}

struct QueuedGuestTcpConnection {
    socket: OwnedFd,
    connector_socket_id: u64,
    connector_process_authority: ProcessId,
    local_address: SocketAddrV4,
    guest_source_lease: GuestSourceLease,
}

/// One end of an internal connection, identified by its connector's socket ID.
pub(super) struct GuestTcpEndpoint {
    connector_socket_id: u64,
    reset_state: GuestTcpResetState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestTcpResetState {
    None,
    Pending,
    Reported,
}

/// The live ends of an internal connection, keyed in [`TcpTopology`] by its
/// connector's socket ID, so whichever end closes can reach the other.
struct TcpLink {
    connector: Arc<SocketInbox>,
    peer: TcpLinkPeer,
}

enum TcpLinkPeer {
    /// The accepted end is still queued on this listener.
    Queued {
        listener_id: u64,
    },
    Accepted(Arc<SocketInbox>),
}

impl SocketState {
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

fn tcp_socket_state(
    descriptor: TcpDescriptor,
    guest_endpoint: Option<GuestTcpEndpoint>,
    options: TcpOptions,
) -> TcpSocketState {
    TcpSocketState {
        descriptor,
        listening: false,
        guest_endpoint,
        peek_waitall_threshold: None,
        peek_reader: None,
        peek_cache: None,
        pending_errors: TcpPendingErrors::default(),
        guest_read_shutdown: None,
        abortive_close: false,
        options,
    }
}

pub(super) fn create_tcp_transport() -> SocketTransportState {
    SocketTransportState::Tcp(tcp_socket_state(
        TcpDescriptor::Unrealized,
        None,
        TcpOptions::default(),
    ))
}

/// Guest TCP bindings, listener queues, and internal connection links.
#[derive(Default)]
pub(super) struct TcpTopology {
    bindings: TcpBindings,
    listeners: HashMap<u64, TcpListener>,
    links: HashMap<u64, TcpLink>,
    pub(super) queued_guest_connection_count: usize,
}

#[derive(Default)]
struct TcpBindings {
    wildcard: HashMap<u16, TcpBinding>,
    exact: HashMap<SocketAddrV4, TcpBinding>,
}

impl TcpBindings {
    fn values(&self) -> impl Iterator<Item = &TcpBinding> {
        self.wildcard.values().chain(self.exact.values())
    }
}

fn readiness_from_epoll(socket: &SocketEntry<'_>, events: epoll::EventFlags) -> ReadinessFlags {
    let mut readiness = ReadinessFlags::default();
    if events.contains(epoll::EventFlags::IN) {
        readiness = readiness | ReadinessFlags::READ;
    }
    if events.contains(epoll::EventFlags::OUT) && !socket.write_shutdown {
        readiness = readiness | ReadinessFlags::WRITE;
    }
    if !socket.read_shutdown && events.intersects(epoll::EventFlags::RDHUP | epoll::EventFlags::HUP)
    {
        readiness = readiness | ReadinessFlags::READ | ReadinessFlags::HANGUP;
    }
    // A host hang-up closes both directions of an external connection, but on
    // an internal endpoint it only reports that the peer closed.
    if events.contains(epoll::EventFlags::HUP)
        && socket
            .tcp_state()
            .is_ok_and(|tcp| tcp.descriptor.is_external())
    {
        readiness = readiness | ReadinessFlags::CLOSED;
    }
    if events.contains(epoll::EventFlags::ERR) {
        readiness = readiness | ReadinessFlags::ERROR;
    }
    let previous = socket.own();
    with_tcp_closed(socket, ReadinessFlags(readiness.0 | previous.0))
}

/// Adds [`ReadinessFlags::CLOSED`] once both directions of a TCP socket are shut down.
fn with_tcp_closed(socket: &SocketEntry<'_>, readiness: ReadinessFlags) -> ReadinessFlags {
    if socket.write_shutdown && (socket.read_shutdown || readiness.contains(ReadinessFlags::HANGUP))
    {
        readiness | ReadinessFlags::CLOSED
    } else {
        readiness
    }
}

fn active_epoll_events() -> epoll::EventFlags {
    // Cached readiness turns these edge-triggered kernel events into the
    // level-triggered snapshots consumed by the broker protocol.
    epoll::EventFlags::IN
        | epoll::EventFlags::OUT
        | epoll::EventFlags::RDHUP
        | epoll::EventFlags::ET
}

fn add_readiness(socket: &SocketEntry<'_>, readiness: ReadinessFlags) {
    let current = socket.own();
    update_snapshot(socket, ReadinessFlags(current.0 | readiness.0));
}

fn clear_readiness(socket: &SocketEntry<'_>, readiness: ReadinessFlags) {
    let current = socket.own();
    update_snapshot(socket, ReadinessFlags(current.0 & !readiness.0));
}

fn consume_synchronous_error(socket: &mut SocketEntry<'_>) -> BrokerResult<()> {
    if !can_consume_synchronous_error(socket.connection_status) {
        return Ok(());
    }
    if let Some(error) = take_socket_error(socket)? {
        socket
            .tcp_state_mut()?
            .pending_errors
            .append(TcpPendingError::Socket(error));
    }
    let current = socket.own();
    let readiness = if socket.tcp_state()?.pending_errors.is_empty() {
        ReadinessFlags(current.0 & !ReadinessFlags::ERROR.0)
    } else {
        current | ReadinessFlags::ERROR
    };
    update_snapshot(socket, readiness);
    Ok(())
}

#[derive(Clone)]
struct TcpBinding {
    socket_id: u64,
    guest_binding: GuestSocketBinding,
}

enum ResolvedTcpDestination {
    Internal {
        listener_id: u64,
        concrete_address: SocketAddrV4,
    },
    External(SocketAddrV4),
}

impl TcpTopology {
    fn insert_binding(&mut self, binding: TcpBinding) -> BrokerResult<()> {
        let local_address = binding.guest_binding.local_address();
        if !binding.guest_binding.is_valid()
            || if binding.guest_binding.is_wildcard() {
                self.bindings.wildcard.contains_key(&local_address.port())
                    || self
                        .bindings
                        .exact
                        .keys()
                        .any(|address| address.port() == local_address.port())
            } else {
                self.bindings.wildcard.contains_key(&local_address.port())
                    || self.bindings.exact.contains_key(&local_address)
            }
        {
            return Err(BrokerError::Internal);
        }
        if binding.guest_binding.is_wildcard() {
            self.bindings
                .wildcard
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.bindings.wildcard.insert(local_address.port(), binding);
        } else {
            self.bindings
                .exact
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.bindings.exact.insert(local_address, binding);
        }
        Ok(())
    }

    fn remove_binding(&mut self, port: u16, socket_id: u64) {
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

    fn guest_binding(&self, address: SocketAddrV4) -> Option<TcpBinding> {
        self.bindings
            .exact
            .get(&address)
            .or_else(|| self.bindings.wildcard.get(&address.port()))
            .filter(|binding| binding.guest_binding.covers(address))
            .cloned()
    }

    fn binding_for_socket(&self, socket_id: u64) -> Option<TcpBinding> {
        self.bindings
            .values()
            .find(|binding| binding.socket_id == socket_id)
            .cloned()
    }

    fn resolve_destination(
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
        let Some(binding) = self.guest_binding(destination) else {
            return SocketOutcome::Failed(SocketError::ConnectionRefused);
        };
        if !self.listeners.contains_key(&binding.socket_id) {
            return SocketOutcome::Failed(SocketError::ConnectionRefused);
        }
        SocketOutcome::Completed(ResolvedTcpDestination::Internal {
            listener_id: binding.socket_id,
            concrete_address: destination,
        })
    }
}

impl Topology {
    /// Checks that `process_authority` may queue one more internal
    /// connection, which counts against the socket quotas until it is
    /// accepted or discarded.
    fn check_queued_connection(
        &self,
        process_authority: ProcessId,
        max_sockets: usize,
        max_sockets_per_process: usize,
    ) -> BrokerResult<()> {
        let combined_count = self
            .tcp
            .queued_guest_connection_count
            .checked_add(1)
            .and_then(|count| count.checked_add(self.socket_count))
            .ok_or(BrokerError::ResourceExhausted)?;
        let process = self
            .processes
            .get(&process_authority)
            .ok_or(BrokerError::Internal)?;
        let process_count = process
            .pending_guest_connection_count
            .checked_add(1)
            .and_then(|count| count.checked_add(process.live_socket_count))
            .ok_or(BrokerError::ResourceExhausted)?;
        if combined_count > max_sockets || process_count > max_sockets_per_process {
            return Err(BrokerError::ResourceExhausted);
        }
        Ok(())
    }

    fn charge_queued_connection(&mut self, process_authority: ProcessId) {
        self.tcp.queued_guest_connection_count += 1;
        self.process_mut(process_authority)
            .pending_guest_connection_count += 1;
    }

    fn release_queued_connections(&mut self, process_authority: ProcessId, count: usize) {
        self.tcp.queued_guest_connection_count = self
            .tcp
            .queued_guest_connection_count
            .checked_sub(count)
            .expect("queued guest connection count underflow");
        let process = self.process_mut(process_authority);
        process.pending_guest_connection_count = process
            .pending_guest_connection_count
            .checked_sub(count)
            .expect("process queued guest connection count underflow");
    }

    /// Turns a connection queued by `connector_process_authority` into a
    /// socket accepted by `listener_process_authority`, if the listener's
    /// process quota allows it.
    ///
    /// The global count is unchanged: one queued connection becomes one
    /// socket.
    fn accept_queued_connection(
        &mut self,
        connector_process_authority: ProcessId,
        listener_process_authority: ProcessId,
        max_sockets_per_process: usize,
    ) -> BrokerResult<()> {
        let listener_process = self
            .processes
            .get(&listener_process_authority)
            .ok_or(BrokerError::Internal)?;
        let transferred_pending =
            usize::from(connector_process_authority == listener_process_authority);
        let next_listener_total = listener_process
            .live_socket_count
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?
            .checked_add(listener_process.pending_guest_connection_count)
            .and_then(|count| count.checked_sub(transferred_pending))
            .ok_or(BrokerError::Internal)?;
        if next_listener_total > max_sockets_per_process {
            return Err(BrokerError::ResourceExhausted);
        }
        self.release_queued_connections(connector_process_authority, 1);
        self.process_mut(listener_process_authority)
            .live_socket_count += 1;
        self.socket_count += 1;
        Ok(())
    }

    /// Removes a connector's queued connection from its listener without
    /// resetting the connector.
    fn remove_queued_connection(&mut self, listener_id: u64, connector_socket_id: u64) {
        let Some(listener) = self.tcp.listeners.get_mut(&listener_id) else {
            return;
        };
        let Some(connection) = listener
            .queue
            .iter()
            .position(|connection| connection.connector_socket_id == connector_socket_id)
            .and_then(|index| listener.queue.remove(index))
        else {
            return;
        };
        publish_listener_queue(listener);
        self.release_queued_connections(connection.connector_process_authority, 1);
    }

    /// Discards a closed listener's queue, resetting each live connector.
    fn discard_listener_queue(&mut self, queue: VecDeque<QueuedGuestTcpConnection>) {
        for connection in queue {
            self.release_queued_connections(connection.connector_process_authority, 1);
            if let Some(link) = self.tcp.links.remove(&connection.connector_socket_id) {
                post_guest_reset(&link.connector);
            }
            // Dropping `connection` closes the connector's peer descriptor
            // only after its reset is posted.
        }
    }

    /// Removes every connection `process_authority` queued, after all of its
    /// sockets retired.
    pub(super) fn purge_connector_process_queues(&mut self, process_authority: ProcessId) {
        let mut purged = 0;
        for listener in self.tcp.listeners.values_mut() {
            let queued = listener.queue.len();
            listener
                .queue
                .retain(|connection| connection.connector_process_authority != process_authority);
            if listener.queue.len() != queued {
                purged += queued - listener.queue.len();
                publish_listener_queue(listener);
            }
        }
        if purged != 0 {
            self.release_queued_connections(process_authority, purged);
        }
    }
}

/// Recomputes a listener's READ from its queue, waking waiters while
/// connections remain queued.
///
/// A listener's queue and its READ change together under `topology`.
fn publish_listener_queue(listener: &TcpListener) {
    let mut inbox = listener.inbox.lock();
    inbox.queue_ready = !listener.queue.is_empty();
    if inbox.queue_ready {
        inbox.republish();
    } else {
        inbox.publish();
    }
}

/// Posts a guest reset to an internal endpoint, which applies it on its next
/// call or event.
fn post_guest_reset(inbox: &SocketInbox) {
    let mut inbox = inbox.lock();
    inbox.reset_posted = true;
    inbox.republish();
}

fn confirm_tcp_connected(socket: &mut SocketEntry<'_>) {
    if socket.connection_status != SocketConnectionStatus::Connecting {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Connected;
}

/// Records a terminal external operation while a connect is pending.
fn fail_connect(socket: &mut SocketEntry<'_>, error: SocketError) {
    if socket.connection_status != SocketConnectionStatus::Connecting {
        return;
    }
    socket.connection_status = SocketConnectionStatus::Failed(error);
    let readiness = socket.own() | ReadinessFlags::ERROR;
    update_snapshot(socket, readiness);
}

/// Records the receive by `reader` for the peek continuation check, failing
/// with `WouldBlock` if it is a request past offset zero that does not
/// continue `reader`'s peek.
///
/// A peek longer than one transfer takes one request at each offset. A
/// receive by another reader between them may consume bytes the earlier
/// requests returned, so the rest of the peek would not follow them. The
/// interrupted reader then returns the bytes it already has.
fn continue_peek(
    tcp: &mut TcpSocketState,
    reader: ObjectHandle,
    flags: ReceiveFlags,
    peek_offset: usize,
) -> BrokerResult<()> {
    if !flags.contains(ReceiveFlags::PEEK) {
        tcp.peek_reader = None;
    } else if peek_offset == 0 {
        tcp.peek_reader = Some(reader);
    } else if tcp.peek_reader != Some(reader) {
        return Err(BrokerError::WouldBlock);
    }
    Ok(())
}

fn validate_peek_window(
    length: usize,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<usize> {
    let peek_end = peek_offset
        .checked_add(length)
        .ok_or(BrokerError::UnsupportedOperation)?;
    let canonical_length = peek_length
        .checked_sub(peek_offset)
        .map(|remaining| remaining.min(MAX_SOCKET_TRANSFER_SIZE as usize));
    if !peek_offset.is_multiple_of(MAX_SOCKET_TRANSFER_SIZE as usize)
        || canonical_length != Some(length)
        || peek_length > MAX_SOCKET_PEEK_SIZE as usize
    {
        return Err(BrokerError::UnsupportedOperation);
    }
    Ok(peek_end)
}

/// Allocates the buffer a TCP receive reads into before its socket is
/// locked, so the lock is not held while zeroing a large peek window.
///
/// A receive or a peek at offset zero reads into it; a later peek window
/// is served from the peek cache. An invalid peek window gets an empty
/// buffer, and the receive reports the error after its other checks.
pub(super) fn tcp_receive_buffer(
    length: usize,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<Vec<u8>> {
    if !flags.contains(ReceiveFlags::PEEK) {
        return zeroed_vec(length);
    }
    if peek_offset != 0 || validate_peek_window(length, peek_offset, peek_length).is_err() {
        return Ok(Vec::new());
    }
    zeroed_vec(peek_length)
}

fn receive_socket(
    socket: &mut SocketEntry<'_>,
    buffer: Vec<u8>,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<ReceiveOutcome> {
    if socket.kind() != SocketKind::Tcp {
        return Ok(ReceiveOutcome::Failed(SocketError::InvalidArgument));
    }
    if socket.tcp_state()?.guest_read_shutdown.is_some() {
        if !flags.contains(ReceiveFlags::PEEK) {
            socket.tcp_state_mut()?.peek_cache = None;
        }
        if let Some(outcome) =
            receive_guest_read_shutdown(socket, length, flags, peek_offset, peek_length)?
        {
            return Ok(outcome);
        }
        if guest_reset_pending(socket)? {
            if !consume_pending_guest_reset(socket, true)? {
                return Err(BrokerError::Internal);
            }
            return Ok(ReceiveOutcome::Failed(SocketError::ConnectionReset));
        }
        return Ok(ReceiveOutcome::EndOfStream);
    }
    if guest_reset_pending(socket)? {
        let available = ioctl_fionread(socket.tcp_state()?.descriptor.socket()?)
            .map_err(broker_error_from_errno)?;
        if available == 0 {
            if !consume_pending_guest_reset(socket, true)? {
                return Err(BrokerError::Internal);
            }
            return Ok(ReceiveOutcome::Failed(SocketError::ConnectionReset));
        }
    }
    match socket.connection_status {
        SocketConnectionStatus::Unconnected => {
            return Ok(ReceiveOutcome::Failed(SocketError::NotConnected));
        }
        SocketConnectionStatus::Failed(error) => {
            return Ok(ReceiveOutcome::Failed(error));
        }
        _ => {}
    }
    let peek = flags.contains(ReceiveFlags::PEEK);
    if !peek {
        if peek_offset != 0 || peek_length != 0 {
            return Err(BrokerError::UnsupportedOperation);
        }
        socket.tcp_state_mut()?.peek_cache = None;
        return receive_socket_once(socket, buffer, LinuxRecvFlags::empty());
    }

    let peek_end = validate_peek_window(length, peek_offset, peek_length)?;
    if flags.contains(ReceiveFlags::WAITALL) {
        let readiness = socket.own();
        let terminal = socket.read_shutdown
            || readiness.contains(ReadinessFlags::HANGUP)
            || readiness.contains(ReadinessFlags::ERROR);
        if !terminal
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

    let refresh_exhausted_cache = match socket.tcp_state()?.peek_cache.as_ref() {
        Some(cache) if cache.requested_length == peek_length && cache.data.len() <= peek_offset => {
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
        || socket
            .tcp_state()?
            .peek_cache
            .as_ref()
            .is_none_or(|cache| cache.requested_length != peek_length)
        || refresh_exhausted_cache;
    if refresh {
        socket.tcp_state_mut()?.peek_cache = None;
        let buffer = if buffer.len() == peek_length {
            buffer
        } else {
            zeroed_vec(peek_length)?
        };
        let flags = if flags.contains(ReceiveFlags::WAITALL) {
            LinuxRecvFlags::PEEK | LinuxRecvFlags::WAITALL
        } else {
            LinuxRecvFlags::PEEK
        };
        match receive_socket_once(socket, buffer, flags)? {
            ReceiveOutcome::Received(data) => {
                socket.tcp_state_mut()?.peek_cache = Some(PeekCache {
                    requested_length: peek_length,
                    data,
                });
            }
            outcome => return Ok(outcome),
        }
    }

    let exhausted = socket
        .tcp_state()?
        .peek_cache
        .as_ref()
        .ok_or(BrokerError::Internal)?
        .data
        .len()
        <= peek_offset;
    if exhausted {
        let readiness = socket.own();
        let terminal = socket.read_shutdown
            || readiness.contains(ReadinessFlags::HANGUP)
            || readiness.contains(ReadinessFlags::ERROR);
        socket.tcp_state_mut()?.peek_cache = None;
        return if terminal {
            Ok(ReceiveOutcome::EndOfStream)
        } else {
            Err(BrokerError::WouldBlock)
        };
    }
    let tcp = socket.tcp_state_mut()?;
    let cache = tcp.peek_cache.as_ref().ok_or(BrokerError::Internal)?;
    let end = peek_end.min(cache.data.len());
    let mut data = Vec::new();
    data.try_reserve_exact(end - peek_offset)
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.extend_from_slice(&cache.data[peek_offset..end]);
    if end < peek_end || end == peek_length {
        tcp.peek_cache = None;
    }
    Ok(ReceiveOutcome::Received(data))
}

fn receive_socket_once(
    socket: &mut SocketEntry<'_>,
    mut data: Vec<u8>,
    flags: LinuxRecvFlags,
) -> BrokerResult<ReceiveOutcome> {
    socket.core().hook(HookPoint::Receiving(socket.id()));
    loop {
        match recv(
            socket.tcp_state()?.descriptor.socket()?,
            data.as_mut_slice(),
            flags,
        ) {
            Ok((_buffer, 0)) => {
                if take_late_guest_reset(socket)? {
                    return Ok(ReceiveOutcome::Failed(SocketError::ConnectionReset));
                }
                confirm_tcp_connected(socket);
                let readiness = if socket.read_shutdown {
                    ReadinessFlags::READ
                } else {
                    ReadinessFlags::READ | ReadinessFlags::HANGUP
                };
                add_readiness(socket, readiness);
                return Ok(ReceiveOutcome::EndOfStream);
            }
            Ok((_buffer, received)) => {
                confirm_tcp_connected(socket);
                data.truncate(received);
                let terminal_readable =
                    socket.read_shutdown || socket.own().contains(ReadinessFlags::HANGUP);
                if !flags.contains(LinuxRecvFlags::PEEK) && !terminal_readable {
                    let no_queued_data = ioctl_fionread(socket.tcp_state()?.descriptor.socket()?)
                        .is_ok_and(|available| available == 0);
                    if no_queued_data {
                        clear_readiness(socket, ReadinessFlags::READ);
                    }
                }
                return Ok(ReceiveOutcome::Received(data));
            }
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                socket.core().hook(HookPoint::Eagain(socket.id()));
                clear_readiness(socket, ReadinessFlags::READ);
                return Err(BrokerError::WouldBlock);
            }
            Err(error) => {
                if take_late_guest_reset(socket)? {
                    return Ok(ReceiveOutcome::Failed(SocketError::ConnectionReset));
                }
                let error = socket_operation_error_from_errno(error)?;
                fail_connect(socket, error);
                let _ = consume_synchronous_error(socket);
                return Ok(ReceiveOutcome::Failed(error));
            }
        }
    }
}

fn receive_guest_read_shutdown(
    socket: &mut SocketEntry<'_>,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: usize,
    peek_length: usize,
) -> BrokerResult<Option<ReceiveOutcome>> {
    let peek = flags.contains(ReceiveFlags::PEEK);
    let (relative_start, relative_end) = if peek {
        (
            peek_offset,
            validate_peek_window(length, peek_offset, peek_length)?,
        )
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
        return Ok(Some(ReceiveOutcome::EndOfStream));
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
    Ok(Some(ReceiveOutcome::Received(data)))
}

fn capture_guest_read_shutdown(socket: &SocketEntry<'_>, queued: &mut Vec<u8>) -> BrokerResult<()> {
    let mut received = 0;
    while received < queued.len() {
        match recv(
            socket.tcp_state()?.descriptor.socket()?,
            &mut queued[received..],
            LinuxRecvFlags::WAITALL,
        ) {
            Ok((_buffer, 0)) => {
                queued.truncate(received);
                return Err(BrokerError::Internal);
            }
            Ok((_buffer, count)) => {
                received += count;
            }
            Err(Errno::INTR) => {}
            Err(_) => {
                queued.truncate(received);
                return Err(BrokerError::Internal);
            }
        }
    }
    Ok(())
}

fn discard_guest_read_shutdown_data(socket: &mut SocketEntry<'_>) -> BrokerResult<()> {
    if socket.tcp_state()?.guest_read_shutdown.is_none() {
        return Ok(());
    }
    // Discard only what is queued now: the peer may keep sending, and each
    // later arrival raises its own event.
    let mut remaining = match ioctl_fionread(socket.tcp_state()?.descriptor.socket()?) {
        Ok(available) => usize::try_from(available).map_err(|_| BrokerError::Internal)?,
        Err(error) => {
            socket_operation_error_from_errno(error)?;
            return Ok(());
        }
    };
    let mut data = [0_u8; 8192];
    while remaining != 0 {
        let length = remaining.min(data.len());
        match recv(
            socket.tcp_state()?.descriptor.socket()?,
            &mut data[..length],
            LinuxRecvFlags::empty(),
        ) {
            Ok((_, 0)) | Err(Errno::AGAIN) => break,
            Ok((_buffer, received)) => {
                remaining = remaining.saturating_sub(received);
                socket
                    .tcp_state_mut()?
                    .guest_read_shutdown
                    .as_mut()
                    .ok_or(BrokerError::Internal)?
                    .discarded_data = true;
            }
            Err(Errno::INTR) => {}
            Err(error) => {
                socket_operation_error_from_errno(error)?;
                break;
            }
        }
    }
    Ok(())
}

fn apply_tcp_options(socket: &OwnedFd, options: TcpOptions) -> BrokerResult<()> {
    sockopt::set_tcp_nodelay(socket, options.no_delay).map_err(broker_error_from_errno)?;
    sockopt::set_socket_keepalive(socket, options.keep_alive).map_err(broker_error_from_errno)
}

fn shutdown_tcp_stream(
    socket: &mut SocketEntry<'_>,
    mode: ShutdownMode,
) -> BrokerResult<SocketOutcome<()>> {
    if mode == ShutdownMode::Abort {
        if socket.tcp_state()?.descriptor.is_external() {
            sockopt::set_socket_linger(
                socket.tcp_state()?.descriptor.socket()?,
                Some(Duration::ZERO),
            )
            .map_err(broker_error_from_errno)?;
        }
        socket.tcp_state_mut()?.abortive_close = true;
        return Ok(SocketOutcome::Completed(()));
    }
    if socket.tcp_state()?.listening {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    if matches!(socket.tcp_state()?.descriptor, TcpDescriptor::Unrealized) {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let internal_endpoint = socket.tcp_state()?.descriptor.is_internal();
    // AF_UNIX read shutdown changes peer write behavior, so guest read
    // shutdown remains logical while write shutdown reaches the kernel.
    let (kernel_shutdown, add, clear, shuts_down_read, shuts_down_write) = match mode {
        ShutdownMode::Read => (
            (!internal_endpoint).then_some(LinuxShutdown::Read),
            ReadinessFlags::READ | ReadinessFlags::HANGUP,
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
            Some(if internal_endpoint {
                LinuxShutdown::Write
            } else {
                LinuxShutdown::Both
            }),
            ReadinessFlags::READ | ReadinessFlags::HANGUP,
            ReadinessFlags::WRITE,
            true,
            true,
        ),
        _ => return Err(BrokerError::UnsupportedOperation),
    };
    let guest_read_shutdown_buffer =
        if internal_endpoint && shuts_down_read && !socket.read_shutdown {
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
    // Shutting down a pending connect aborts it with a reset; record that now
    // so the caller observes it.
    if socket.connection_status == SocketConnectionStatus::Connecting
        && socket.tcp_state()?.descriptor.is_external()
        && let Err(error) = sockopt::socket_error(socket.tcp_state()?.descriptor.socket()?)
            .map_err(broker_error_from_errno)?
    {
        socket.connection_status = SocketConnectionStatus::Failed(socket_error_from_errno(error));
        update_snapshot(socket, ReadinessFlags::ERROR);
        return Ok(SocketOutcome::Completed(()));
    }
    let shutdown_error = if let Some(mut queued) = guest_read_shutdown_buffer {
        let capture_error = capture_guest_read_shutdown(socket, &mut queued).err();
        socket.tcp_state_mut()?.guest_read_shutdown = Some(GuestTcpReadShutdown {
            queued,
            consumed: 0,
            discarded_data: capture_error.is_some(),
        });
        let discard_error = discard_guest_read_shutdown_data(socket).err();
        capture_error.or(discard_error)
    } else {
        None
    };
    socket.read_shutdown |= shuts_down_read;
    socket.write_shutdown |= shuts_down_write;
    let republish_readiness = shuts_down_read
        && socket
            .tcp_state_mut()?
            .peek_waitall_threshold
            .take()
            .is_some();
    let current = socket.own();
    let readiness = with_tcp_closed(socket, ReadinessFlags((current.0 & !clear.0) | add.0));
    if republish_readiness {
        republish_snapshot(socket, readiness);
    } else {
        update_snapshot(socket, readiness);
    }
    if let Some(error) = shutdown_error {
        return Err(error);
    }
    Ok(SocketOutcome::Completed(()))
}

pub(super) fn handle_socket_event(
    socket: &mut SocketEntry<'_>,
    events: epoll::EventFlags,
) -> BrokerResult<()> {
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
            update_snapshot(socket, readiness_from_epoll(socket, events));
        }
        SocketConnectionStatus::Failed(SocketError::NotConnected) if socket.read_shutdown => {
            update_snapshot(socket, ReadinessFlags::WRITE | ReadinessFlags::HANGUP);
        }
        SocketConnectionStatus::Failed(_) => {
            update_snapshot(socket, ReadinessFlags::ERROR);
        }
        _ => return Err(BrokerError::Internal),
    }
    if republish_readiness {
        socket.inbox().republish();
    }
    Ok(())
}

fn complete_connect(socket: &mut SocketEntry<'_>, events: epoll::EventFlags) -> BrokerResult<()> {
    if !socket.tcp_state()?.descriptor.is_external() {
        return Err(BrokerError::Internal);
    }
    let status = match sockopt::socket_error(socket.tcp_state()?.descriptor.socket()?) {
        Ok(Ok(())) if events.contains(epoll::EventFlags::OUT) => SocketConnectionStatus::Connected,
        Ok(Ok(())) => SocketConnectionStatus::Connecting,
        Ok(Err(error)) => SocketConnectionStatus::Failed(socket_error_from_errno(error)),
        Err(error) => return Err(broker_error_from_errno(error)),
    };
    let readiness = match status {
        SocketConnectionStatus::Connected => readiness_from_epoll(socket, events),
        SocketConnectionStatus::Connecting => ReadinessFlags::default(),
        SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
        _ => return Err(BrokerError::Internal),
    };
    socket.connection_status = status;
    update_snapshot(socket, readiness);
    Ok(())
}

impl SocketEntry<'_> {
    /// Applies a guest reset another socket posted to this socket's inbox.
    pub(super) fn drain_guest_reset(&mut self) -> BrokerResult<()> {
        let mut inbox = self.inbox();
        if !inbox.reset_posted {
            return Ok(());
        }
        inbox.reset_posted = false;
        let tcp = self.tcp_state_mut()?;
        if let Some(endpoint) = tcp.guest_endpoint.as_mut()
            && endpoint.reset_state == GuestTcpResetState::None
        {
            endpoint.reset_state = GuestTcpResetState::Pending;
            tcp.pending_errors.append(TcpPendingError::GuestReset);
            inbox.own = inbox.own
                | ReadinessFlags::READ
                | ReadinessFlags::ERROR
                | ReadinessFlags::HANGUP
                | ReadinessFlags::CLOSED;
        }
        inbox.publish();
        Ok(())
    }

    pub(super) fn send_tcp_socket(&mut self, data: &[u8]) -> BrokerResult<SocketOutcome<usize>> {
        if self.kind() != SocketKind::Tcp {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if self.write_shutdown {
            return Ok(SocketOutcome::Failed(SocketError::Shutdown));
        }
        if guest_reset_pending(self)? {
            if !consume_pending_guest_reset(self, true)? {
                return Err(BrokerError::Internal);
            }
            return Ok(SocketOutcome::Failed(SocketError::ConnectionReset));
        }
        match self.connection_status {
            SocketConnectionStatus::Unconnected => {
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            SocketConnectionStatus::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            _ => {}
        }
        loop {
            match send(
                self.tcp_state()?.descriptor.socket()?,
                data,
                LinuxSendFlags::NOSIGNAL,
            ) {
                Ok(sent) => {
                    if sent != 0 {
                        confirm_tcp_connected(self);
                    }
                    return Ok(SocketOutcome::Completed(sent));
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    clear_readiness(self, ReadinessFlags::WRITE);
                    return Err(BrokerError::WouldBlock);
                }
                Err(error) => {
                    if take_late_guest_reset(self)? {
                        return Ok(SocketOutcome::Failed(SocketError::ConnectionReset));
                    }
                    // `EPIPE` means the connection can no longer send, which is
                    // distinct from the reset that `ECONNRESET` reports.
                    let error = if error == Errno::PIPE {
                        SocketError::NotConnected
                    } else {
                        socket_operation_error_from_errno(error)?
                    };
                    fail_connect(self, error);
                    let _ = consume_synchronous_error(self);
                    return Ok(SocketOutcome::Failed(error));
                }
            }
        }
    }

    /// Receives into `buffer`, which [`tcp_receive_buffer`] allocated for
    /// this request.
    pub(super) fn receive_tcp_socket(
        &mut self,
        reader: ObjectHandle,
        buffer: Vec<u8>,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: usize,
        peek_length: usize,
    ) -> BrokerResult<ReceiveOutcome> {
        if self.kind() == SocketKind::Tcp {
            continue_peek(self.tcp_state_mut()?, reader, flags, peek_offset)?;
        }
        receive_socket(self, buffer, length, flags, peek_offset, peek_length)
    }

    pub(super) fn set_tcp_socket_option(&mut self, value: SocketOptionValue) -> BrokerResult<()> {
        if self.kind() != SocketKind::Tcp {
            return Err(BrokerError::UnsupportedOperation);
        }
        match value {
            SocketOptionValue::NoDelay(value) => {
                if self.tcp_state()?.descriptor.is_external() {
                    sockopt::set_tcp_nodelay(self.tcp_state()?.descriptor.socket()?, value)
                        .map_err(broker_error_from_errno)?;
                }
                self.tcp_state_mut()?.options.no_delay = value;
            }
            SocketOptionValue::KeepAlive(value) => {
                if self.tcp_state()?.descriptor.is_external() {
                    sockopt::set_socket_keepalive(self.tcp_state()?.descriptor.socket()?, value)
                        .map_err(broker_error_from_errno)?;
                }
                self.tcp_state_mut()?.options.keep_alive = value;
            }
            _ => return Err(BrokerError::UnsupportedOperation),
        }
        Ok(())
    }

    pub(super) fn get_tcp_socket_option(
        &self,
        name: SocketOptionName,
    ) -> BrokerResult<SocketOptionValue> {
        if self.kind() != SocketKind::Tcp {
            return Err(BrokerError::UnsupportedOperation);
        }
        match name {
            SocketOptionName::NoDelay if self.tcp_state()?.descriptor.is_external() => {
                sockopt::tcp_nodelay(self.tcp_state()?.descriptor.socket()?)
                    .map(SocketOptionValue::NoDelay)
                    .map_err(broker_error_from_errno)
            }
            SocketOptionName::NoDelay => Ok(SocketOptionValue::NoDelay(
                self.tcp_state()?.options.no_delay,
            )),
            SocketOptionName::KeepAlive if self.tcp_state()?.descriptor.is_external() => {
                sockopt::socket_keepalive(self.tcp_state()?.descriptor.socket()?)
                    .map(SocketOptionValue::KeepAlive)
                    .map_err(broker_error_from_errno)
            }
            SocketOptionName::KeepAlive => Ok(SocketOptionValue::KeepAlive(
                self.tcp_state()?.options.keep_alive,
            )),
            _ => Err(BrokerError::UnsupportedOperation),
        }
    }

    pub(super) fn shutdown_tcp_socket(
        &mut self,
        mode: ShutdownMode,
    ) -> BrokerResult<SocketOutcome<()>> {
        if self.kind() != SocketKind::Tcp {
            return Err(BrokerError::Internal);
        }
        self.tcp_state_mut()?.peek_cache = None;
        if mode != ShutdownMode::StopListening {
            return shutdown_tcp_stream(self, mode);
        }
        if !self.tcp_state()?.listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let mut topology = self.topology();
        let listener = topology
            .tcp
            .listeners
            .remove(&self.id())
            .ok_or(BrokerError::Internal)?;
        let tcp = self.tcp_state_mut()?;
        tcp.listening = false;
        tcp.peek_waitall_threshold = None;
        self.read_shutdown = true;
        self.connection_status = SocketConnectionStatus::Failed(SocketError::NotConnected);
        {
            let mut inbox = listener.inbox.lock();
            inbox.queue_ready = false;
            inbox.set_own(ReadinessFlags::WRITE | ReadinessFlags::HANGUP);
        }
        topology.discard_listener_queue(listener.queue);
        Ok(SocketOutcome::Completed(()))
    }

    pub(super) fn bind_tcp_socket(
        &mut self,
        binding: GuestSocketBinding,
        already_bound: bool,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if already_bound {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = binding.local_address();
        self.topology().tcp.insert_binding(TcpBinding {
            socket_id: self.id(),
            guest_binding: binding,
        })?;
        self.guest_local_address = Some(guest_address);
        Ok(SocketOutcome::Completed(guest_address))
    }

    pub(super) fn connect_tcp_destination(
        &mut self,
        requested_destination: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        if self.guest_local_address.is_none() {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let mut topology = self.topology();
        let binding = topology
            .tcp
            .binding_for_socket(self.id())
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        let destination = match topology.tcp.resolve_destination(requested_destination) {
            SocketOutcome::Completed(destination) => destination,
            SocketOutcome::Failed(error) => {
                drop(topology);
                drop(guest_source_lease);
                let status = SocketConnectionStatus::Failed(error);
                self.connection_status = status;
                update_snapshot(self, ReadinessFlags::ERROR);
                return Ok(status);
            }
        };
        match destination {
            ResolvedTcpDestination::Internal {
                listener_id,
                concrete_address,
            } => {
                let source_address = binding
                    .guest_binding
                    .source_address_for_destination(concrete_address)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                let guest_source_lease = guest_source_lease
                    .filter(|lease| lease.source_address() == source_address)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                self.connect_internal_tcp_socketpair(
                    &mut topology,
                    listener_id,
                    concrete_address,
                    guest_source_lease,
                )
            }
            ResolvedTcpDestination::External(external_destination) => {
                drop(topology);
                drop(guest_source_lease);
                let guest_local_address = binding
                    .guest_binding
                    .source_address_for_destination(external_destination)
                    .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
                self.connect_external_tcp_socket(
                    host_socket_destination(external_destination),
                    guest_local_address,
                )
            }
        }
    }

    fn connect_external_tcp_socket(
        &mut self,
        address: SocketAddrV4,
        guest_local_address: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        if self.connection_status != SocketConnectionStatus::Unconnected {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let (options, unrealized) = {
            let tcp = self
                .tcp_state()
                .map_err(PlatformConnectError::PeerUnchanged)?;
            (
                tcp.options,
                matches!(tcp.descriptor, TcpDescriptor::Unrealized),
            )
        };
        if !unrealized {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let external_socket = socket_with(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
            Some(ipproto::TCP),
        )
        .map_err(|error| PlatformConnectError::PeerUnchanged(broker_error_from_errno(error)))?;
        apply_tcp_options(&external_socket, options)
            .map_err(PlatformConnectError::PeerUnchanged)?;
        self.tcp_state_mut()
            .map_err(PlatformConnectError::PeerUnchanged)?
            .descriptor = TcpDescriptor::ExternalInet(external_socket);
        self.connection_status = SocketConnectionStatus::Connecting;
        let status = loop {
            match connect(
                self.tcp_state()
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
                            self.connection_status =
                                SocketConnectionStatus::Failed(SocketError::Other);
                            update_snapshot(self, ReadinessFlags::ERROR);
                            return Err(PlatformConnectError::PeerIndeterminate(error));
                        }
                    };
                    break SocketConnectionStatus::Failed(error);
                }
            }
        };
        self.connection_status = status;
        let readiness = match status {
            SocketConnectionStatus::Connected => ReadinessFlags::WRITE,
            SocketConnectionStatus::Connecting => ReadinessFlags::default(),
            SocketConnectionStatus::Failed(_) => ReadinessFlags::ERROR,
            _ => {
                return Err(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ));
            }
        };
        if matches!(
            status,
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ) {
            self.guest_local_address = Some(guest_local_address);
        }
        update_snapshot(self, readiness);
        // Adding the descriptor only after `connect()` and the initial
        // publication means every event describes it after the connect: a
        // fresh socket polls as OUT|HUP, which would otherwise mark a pending
        // handshake connected.
        self.core()
            .epoll_add(
                self.tcp_state()
                    .and_then(|tcp| tcp.descriptor.socket())
                    .map_err(PlatformConnectError::PeerIndeterminate)?,
                self.id(),
                active_epoll_events(),
            )
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        Ok(status)
    }

    fn connect_internal_tcp_socketpair(
        &mut self,
        topology: &mut Topology,
        listener_id: u64,
        local_address: SocketAddrV4,
        guest_source_lease: GuestSourceLease,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let source_address = guest_source_lease.source_address();
        let core = self.core();
        topology
            .check_queued_connection(
                self.process_authority(),
                core.max_sockets,
                core.max_sockets_per_process,
            )
            .map_err(PlatformConnectError::PeerUnchanged)?;
        if self.connection_status != SocketConnectionStatus::Unconnected
            || !matches!(
                self.tcp_state()
                    .map_err(PlatformConnectError::PeerUnchanged)?
                    .descriptor,
                TcpDescriptor::Unrealized
            )
        {
            return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
        }
        let listener = topology
            .tcp
            .listeners
            .get_mut(&listener_id)
            .ok_or(PlatformConnectError::PeerUnchanged(BrokerError::Internal))?;
        if listener.queue.len() >= listener.backlog {
            drop(guest_source_lease);
            let status = SocketConnectionStatus::Failed(SocketError::ConnectionRefused);
            self.connection_status = status;
            update_snapshot(self, ReadinessFlags::ERROR);
            return Ok(status);
        }
        listener
            .queue
            .try_reserve(1)
            .map_err(|_| PlatformConnectError::PeerUnchanged(BrokerError::OutOfMemory))?;
        topology
            .tcp
            .links
            .try_reserve(1)
            .map_err(|_| PlatformConnectError::PeerUnchanged(BrokerError::OutOfMemory))?;
        let (connector_socket, accepted_socket) = socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            LinuxSocketFlags::CLOEXEC | LinuxSocketFlags::NONBLOCK,
            None,
        )
        .map_err(|error| PlatformConnectError::PeerUnchanged(broker_error_from_errno(error)))?;
        core.epoll_add(&connector_socket, self.id(), active_epoll_events())
            .map_err(PlatformConnectError::PeerUnchanged)?;

        let connector_socket_id = self.id();
        let tcp = self
            .tcp_state_mut()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        tcp.descriptor = TcpDescriptor::InternalUnix(connector_socket);
        tcp.guest_endpoint = Some(GuestTcpEndpoint {
            connector_socket_id,
            reset_state: GuestTcpResetState::None,
        });
        self.guest_local_address = Some(source_address);
        self.connection_status = SocketConnectionStatus::Connected;
        update_snapshot(self, ReadinessFlags::WRITE);

        let listener = topology
            .tcp
            .listeners
            .get_mut(&listener_id)
            .expect("validated guest listener missing");
        listener.queue.push_back(QueuedGuestTcpConnection {
            socket: accepted_socket,
            connector_socket_id,
            connector_process_authority: self.process_authority(),
            local_address,
            guest_source_lease,
        });
        publish_listener_queue(listener);
        topology.charge_queued_connection(self.process_authority());
        topology.tcp.links.insert(
            connector_socket_id,
            TcpLink {
                connector: Arc::clone(&self.socket.inbox),
                peer: TcpLinkPeer::Queued { listener_id },
            },
        );
        Ok(SocketConnectionStatus::Connected)
    }

    pub(super) fn listen_socket(
        &mut self,
        backlog: u32,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        if self.kind() != SocketKind::Tcp {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        let guest_address = self.guest_local_address.ok_or(BrokerError::Internal)?;
        let mut topology = self.topology();
        topology
            .tcp
            .binding_for_socket(self.id())
            .filter(|binding| binding.guest_binding.local_address() == guest_address)
            .ok_or(BrokerError::Internal)?;
        let backlog = usize::try_from(backlog)
            .map_err(|_| BrokerError::UnsupportedOperation)?
            .max(1);
        if self.connection_status != SocketConnectionStatus::Unconnected
            || !matches!(self.tcp_state()?.descriptor, TcpDescriptor::Unrealized)
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if let Some(listener) = topology.tcp.listeners.get_mut(&self.id()) {
            listener.backlog = backlog;
        } else {
            topology
                .tcp
                .listeners
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            topology.tcp.listeners.insert(
                self.id(),
                TcpListener {
                    inbox: Arc::clone(&self.socket.inbox),
                    backlog,
                    queue: VecDeque::new(),
                },
            );
        }
        self.tcp_state_mut()?.listening = true;
        Ok(SocketOutcome::Completed(guest_address))
    }

    /// Accepts the first queued connection into `accepted`, a new closed
    /// socket.
    ///
    /// No other thread can reach `accepted` before it is registered, so
    /// holding its `state` along with the listener's cannot deadlock.
    pub(super) fn accept_socket(
        &mut self,
        accepted: &Arc<LinuxSocket>,
    ) -> BrokerResult<SocketOutcome<AcceptedEndpoints>> {
        if !self.tcp_state()?.listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let options = self.tcp_state()?.options;
        let mut state = lock(&accepted.state);
        let mut topology = self.topology();
        let listener = topology
            .tcp
            .listeners
            .get(&self.id())
            .ok_or(BrokerError::Internal)?;
        let Some(connector_process_authority) = listener
            .queue
            .front()
            .map(|connection| connection.connector_process_authority)
        else {
            publish_listener_queue(listener);
            return Err(BrokerError::WouldBlock);
        };
        let core = self.core();
        core.register(accepted)?;
        if let Err(error) = topology.accept_queued_connection(
            connector_process_authority,
            self.process_authority(),
            core.max_sockets_per_process,
        ) {
            core.unregister(accepted.id);
            return Err(error);
        }
        let listener = topology
            .tcp
            .listeners
            .get_mut(&self.id())
            .ok_or(BrokerError::Internal)?;
        let QueuedGuestTcpConnection {
            socket,
            connector_socket_id,
            local_address,
            guest_source_lease,
            ..
        } = listener.queue.pop_front().ok_or(BrokerError::Internal)?;
        publish_listener_queue(listener);
        if let Some(link) = topology.tcp.links.get_mut(&connector_socket_id) {
            link.peer = TcpLinkPeer::Accepted(Arc::clone(&accepted.inbox));
        }
        drop(topology);
        *state = SocketState {
            closed: false,
            transport: SocketTransportState::Tcp(tcp_socket_state(
                TcpDescriptor::InternalUnix(socket),
                Some(GuestTcpEndpoint {
                    connector_socket_id,
                    reset_state: GuestTcpResetState::None,
                }),
                options,
            )),
            connection_status: SocketConnectionStatus::Connected,
            pending_error: None,
            read_shutdown: false,
            write_shutdown: false,
            guest_local_address: Some(local_address),
        };
        let mut accepted = SocketEntry {
            socket: accepted,
            state,
        };
        update_snapshot(&accepted, ReadinessFlags::WRITE);
        let added = core.epoll_add(
            accepted.tcp_state()?.descriptor.socket()?,
            accepted.id(),
            active_epoll_events(),
        );
        if let Err(error) = added {
            accepted.tcp_state_mut()?.abortive_close = true;
            accepted.retire(false);
            return Err(error);
        }
        Ok(SocketOutcome::Completed(AcceptedEndpoints {
            local_address,
            guest_source_lease,
        }))
    }

    /// Unbinds and unlinks a retiring TCP socket, then closes its descriptor.
    pub(super) fn retire_tcp(&mut self) {
        let id = self.id();
        {
            let mut topology = self.topology();
            if let Some(address) = self.guest_local_address {
                topology.tcp.remove_binding(address.port(), id);
            }
            if let Some(listener) = topology.tcp.listeners.remove(&id) {
                topology.discard_listener_queue(listener.queue);
            }
            self.unlink_guest_endpoint(&mut topology);
            topology.release_socket(self.process_authority());
        }
        let core = self.core();
        core.unregister(id);
        let Ok(tcp) = self.tcp_state_mut() else {
            return;
        };
        match core::mem::replace(&mut tcp.descriptor, TcpDescriptor::Unrealized) {
            TcpDescriptor::ExternalInet(socket) => {
                if tcp.abortive_close {
                    // Abort may be requested before lazy external realization,
                    // so enforce it again at close.
                    let _ = sockopt::set_socket_linger(&socket, Some(Duration::ZERO));
                }
                core.epoll_delete(&socket);
            }
            TcpDescriptor::InternalUnix(socket) => {
                core.epoll_delete(&socket);
                drop(socket);
                core.hook(HookPoint::FdClosed(id));
            }
            TcpDescriptor::Unrealized => {}
        }
    }

    /// Detaches a retiring internal endpoint from its connection, posting a
    /// reset to the other end if this close loses data.
    ///
    /// A gracefully closed connector that is still queued stays queued, so
    /// its listener can accept the data it sent; an abortive one is removed.
    fn unlink_guest_endpoint(&mut self, topology: &mut Topology) {
        let Ok(tcp) = self.tcp_state() else {
            return;
        };
        let Some(connector_socket_id) = tcp
            .guest_endpoint
            .as_ref()
            .map(|endpoint| endpoint.connector_socket_id)
        else {
            return;
        };
        let Some(link) = topology.tcp.links.remove(&connector_socket_id) else {
            return;
        };
        let peer = if connector_socket_id == self.id() {
            match link.peer {
                TcpLinkPeer::Queued { listener_id } => {
                    if tcp.abortive_close {
                        topology.remove_queued_connection(listener_id, connector_socket_id);
                    }
                    return;
                }
                TcpLinkPeer::Accepted(peer) => peer,
            }
        } else {
            debug_assert!(matches!(link.peer, TcpLinkPeer::Accepted(_)));
            link.connector
        };
        let mut inbox = peer.lock();
        // Stop the peer's writes first, so no data arrives after the check
        // below; the peer then finds the reset when its write fails.
        if let Ok(socket) = tcp.descriptor.socket() {
            let _ = shutdown(socket, LinuxShutdown::Read);
        }
        if tcp.abortive_close || guest_tcp_has_unread_data(tcp) {
            inbox.reset_posted = true;
            inbox.republish();
        }
    }
}

/// Reports whether a guest reset is pending, applying a newly posted one
/// first.
pub(super) fn guest_reset_pending(socket: &mut SocketEntry<'_>) -> BrokerResult<bool> {
    socket.drain_guest_reset()?;
    Ok(socket
        .tcp_state()?
        .guest_endpoint
        .as_ref()
        .is_some_and(|endpoint| endpoint.reset_state == GuestTcpResetState::Pending))
}

pub(super) fn consume_pending_guest_reset(
    socket: &mut SocketEntry<'_>,
    remove_queued_error: bool,
) -> BrokerResult<bool> {
    let tcp = socket.tcp_state_mut()?;
    let Some(endpoint) = tcp.guest_endpoint.as_mut() else {
        return Ok(false);
    };
    if endpoint.reset_state != GuestTcpResetState::Pending {
        return Ok(false);
    }
    endpoint.reset_state = GuestTcpResetState::Reported;
    if remove_queued_error {
        tcp.pending_errors.remove_guest_reset();
    }
    if tcp.pending_errors.is_empty() {
        let mut inbox = socket.inbox();
        if inbox.own.contains(ReadinessFlags::ERROR) {
            inbox.own = ReadinessFlags(inbox.own.0 & !ReadinessFlags::ERROR.0);
            // The synchronous operation reports the reset even if its
            // readiness notification cannot be delivered.
            inbox.publish();
        }
    }
    Ok(true)
}

/// Reports a guest reset in place of the end of stream or error that the
/// peer's close caused during this call.
///
/// The peer posts its reset before closing its descriptor, so a terminal
/// result that the close caused always finds the reset.
fn take_late_guest_reset(socket: &mut SocketEntry<'_>) -> BrokerResult<bool> {
    if !socket.tcp_state()?.descriptor.is_internal() || !guest_reset_pending(socket)? {
        return Ok(false);
    }
    if !consume_pending_guest_reset(socket, true)? {
        return Err(BrokerError::Internal);
    }
    Ok(true)
}

#[cfg(test)]
impl super::ProviderCore {
    pub(super) fn queued_guest_connection_count(&self) -> usize {
        lock(&self.topology).tcp.queued_guest_connection_count
    }

    /// Counts live TCP sockets as (unrealized, external, internal).
    pub(super) fn tcp_descriptor_counts(&self) -> (usize, usize, usize) {
        let sockets: Vec<_> = super::read_lock(&self.registry)
            .sockets
            .values()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        let mut counts = (0, 0, 0);
        for socket in &sockets {
            let descriptor = socket.call(|socket| {
                Ok(match socket.tcp_state()?.descriptor {
                    TcpDescriptor::Unrealized => &mut counts.0,
                    TcpDescriptor::ExternalInet(_) => &mut counts.1,
                    TcpDescriptor::InternalUnix(_) => &mut counts.2,
                })
            });
            if let Ok(count) = descriptor {
                *count += 1;
            }
        }
        counts
    }
}
