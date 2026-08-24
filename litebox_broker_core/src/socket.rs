// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority for socket policy, guest-visible endpoints, and platform
//! lifecycle.

use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::HashSet;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    CreateSocketRequest, IpProtocol, MAX_SOCKET_TRANSFER_SIZE, MAX_TCP_LISTEN_BACKLOG,
    MAX_UDP_DATAGRAM_SIZE, ReceiveFlags, ReceiveFromFlags, SendFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOutcome, SocketStatusResponse, SocketType,
    TcpOptionName, TcpOptionValue,
};
use spin::Mutex;

use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result, SessionId};

const DEFAULT_TCP_LISTEN_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
const DEFAULT_LOCAL_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
const FIRST_EPHEMERAL_PORT: u16 = 49152;

/// Fixed broker-wide private IPv4 identity of the shared guest network.
pub const GUEST_IPV4_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

/// Fixed guest-visible address used to reach host-loopback services.
pub const HOST_GATEWAY_IPV4_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1);

pub(crate) fn is_internal_network_address(address: Ipv4Addr) -> bool {
    address.is_loopback() || address == GUEST_IPV4_ADDRESS
}

/// Returns whether a destination resolves within the sandbox's internal network.
#[must_use]
pub fn is_internal_socket_destination(destination: SocketAddrV4) -> bool {
    destination.ip().is_unspecified() || is_internal_network_address(*destination.ip())
}

/// Returns the host-socket destination for a normalized external destination.
#[must_use]
pub fn host_socket_destination(external_destination: SocketAddrV4) -> SocketAddrV4 {
    if *external_destination.ip() == HOST_GATEWAY_IPV4_ADDRESS {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, external_destination.port())
    } else {
        external_destination
    }
}

/// Normalizes and validates one guest-requested IPv4 destination.
///
/// Unspecified destinations use the Linux-compatible loopback interpretation.
/// Broadcast, multicast, reserved, and nonzero `0/8` destinations are rejected.
/// The fixed gateway remains guest-visible here and is translated only by
/// [`host_socket_destination`].
pub fn normalize_socket_destination(
    requested: SocketAddrV4,
) -> core::result::Result<SocketAddrV4, SocketError> {
    let destination = if requested.ip().is_unspecified() {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, requested.port())
    } else {
        requested
    };
    let destination_ip = *destination.ip();
    let first_octet = destination_ip.octets()[0];
    if first_octet == 0 || destination_ip.is_multicast() || first_octet >= 240 {
        return Err(SocketError::InvalidArgument);
    }
    Ok(destination)
}

/// Platform-observed socket state returned to the broker for reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformSocketStatus {
    /// Current platform connection state.
    pub status: SocketConnectionStatus,
    /// Local endpoint observed by the platform, if any.
    pub local_address: Option<SocketAddrV4>,
    /// Pending asynchronous socket error consumed by this observation.
    pub pending_error: Option<SocketError>,
}

#[derive(Default)]
struct BrokerSocketPortState {
    guest_tcp: GuestTransportBindingState,
    guest_udp: GuestTransportBindingState,
}

#[derive(Default)]
struct GuestTransportBindingState {
    wildcard: HashSet<u16>,
    exact: HashSet<SocketAddrV4>,
    next_ephemeral: Option<u16>,
}

impl GuestTransportBindingState {
    fn allocate_ephemeral(&mut self, requested_address: SocketAddrV4) -> Result<u16> {
        let start = self.next_ephemeral.unwrap_or(FIRST_EPHEMERAL_PORT);
        let mut port = start;
        loop {
            let candidate = SocketAddrV4::new(*requested_address.ip(), port);
            if !self.conflicts(candidate) {
                self.next_ephemeral = Some(if port == u16::MAX {
                    FIRST_EPHEMERAL_PORT
                } else {
                    port + 1
                });
                return Ok(port);
            }
            port = if port == u16::MAX {
                FIRST_EPHEMERAL_PORT
            } else {
                port + 1
            };
            if port == start {
                return Err(BrokerError::ResourceExhausted);
            }
        }
    }

    fn conflicts(&self, requested_address: SocketAddrV4) -> bool {
        if self.wildcard.contains(&requested_address.port()) {
            return true;
        }

        if requested_address.ip().is_unspecified() {
            self.exact
                .iter()
                .any(|address| address.port() == requested_address.port())
        } else {
            self.exact.contains(&requested_address)
        }
    }

    fn insert(&mut self, key: GuestBindingKey) -> Result<bool> {
        match key {
            GuestBindingKey::Wildcard(port) => {
                self.wildcard
                    .try_reserve(1)
                    .map_err(|_| BrokerError::OutOfMemory)?;
                Ok(self.wildcard.insert(port))
            }
            GuestBindingKey::Exact(address) => {
                self.exact
                    .try_reserve(1)
                    .map_err(|_| BrokerError::OutOfMemory)?;
                Ok(self.exact.insert(address))
            }
        }
    }

    fn remove(&mut self, key: GuestBindingKey) -> bool {
        match key {
            GuestBindingKey::Wildcard(port) => self.wildcard.remove(&port),
            GuestBindingKey::Exact(address) => self.exact.remove(&address),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuestBindingKey {
    Wildcard(u16),
    Exact(SocketAddrV4),
}

/// Shared registration for one guest transport port.
///
/// The final owner removes the binding from the broker-wide namespace.
struct GuestPortBinding {
    ports: BrokerSocketPorts,
    transport: GuestTransport,
    key: GuestBindingKey,
}

impl GuestPortBinding {
    fn requested_address(&self) -> SocketAddrV4 {
        match self.key {
            GuestBindingKey::Wildcard(port) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
            GuestBindingKey::Exact(address) => address,
        }
    }

    /// Retains a TCP source binding across queued and accepted connection lifetimes.
    ///
    /// UDP datagrams snapshot source metadata when sent and need no lease.
    fn source_lease_for(self: &Arc<Self>, destination: SocketAddrV4) -> Option<GuestSourceLease> {
        if self.transport != GuestTransport::Tcp {
            return None;
        }
        let source_address =
            GuestSocketBinding::new(self).source_address_for_destination(destination)?;
        Some(GuestSourceLease {
            _binding: Arc::clone(self),
            source_address,
        })
    }
}

/// Broker-wide authority for guest-visible transport port namespaces.
///
/// Socket resources own reservations. Sessions remain ownership, quota, and
/// teardown domains rather than separate network namespaces. TCP and UDP use
/// independent port spaces, and guest ports remain independent of native host
/// ports.
#[derive(Clone, Default)]
pub(crate) struct BrokerSocketPorts {
    state: Arc<Mutex<BrokerSocketPortState>>,
}

impl BrokerSocketPorts {
    fn reserve(
        &self,
        request: CreateSocketRequest,
        requested_address: SocketAddrV4,
    ) -> Result<SocketOutcome<(SocketAddrV4, Arc<GuestPortBinding>)>> {
        if !guest_binding_address_is_valid(requested_address) {
            return Ok(SocketOutcome::Failed(SocketError::AddressNotAvailable));
        }
        let transport = guest_transport(request).ok_or(BrokerError::Internal)?;
        let mut state = self.state.lock();
        let ports = match transport {
            GuestTransport::Tcp => &mut state.guest_tcp,
            GuestTransport::Udp => &mut state.guest_udp,
        };
        let port = if requested_address.port() == 0 {
            ports.allocate_ephemeral(requested_address)?
        } else if ports.conflicts(requested_address) {
            return Ok(SocketOutcome::Failed(SocketError::AddressInUse));
        } else {
            requested_address.port()
        };
        let local_address = SocketAddrV4::new(*requested_address.ip(), port);
        let key = if local_address.ip().is_unspecified() {
            GuestBindingKey::Wildcard(port)
        } else {
            GuestBindingKey::Exact(local_address)
        };
        if !ports.insert(key)? {
            return Err(BrokerError::Internal);
        }
        drop(state);
        Ok(SocketOutcome::Completed((
            local_address,
            Arc::new(GuestPortBinding {
                ports: self.clone(),
                transport,
                key,
            }),
        )))
    }
}

fn guest_binding_address_is_valid(address: SocketAddrV4) -> bool {
    address.ip().is_unspecified() || is_internal_network_address(*address.ip())
}

impl Drop for GuestPortBinding {
    fn drop(&mut self) {
        let mut state = self.ports.state.lock();
        let ports = match self.transport {
            GuestTransport::Tcp => &mut state.guest_tcp,
            GuestTransport::Udp => &mut state.guest_udp,
        };
        let removed = ports.remove(self.key);
        debug_assert!(removed, "live guest port binding must be registered");
    }
}

/// Broker-authorized guest binding passed to a platform provider.
#[derive(Clone)]
pub struct GuestSocketBinding {
    requested: SocketAddrV4,
    transport: GuestTransport,
}

impl GuestSocketBinding {
    fn new(binding: &GuestPortBinding) -> Self {
        Self {
            requested: binding.requested_address(),
            transport: binding.transport,
        }
    }

    /// Returns the broker-reserved guest-visible binding.
    #[must_use]
    pub const fn requested(&self) -> SocketAddrV4 {
        self.requested
    }

    /// Returns whether the original binding used the wildcard address.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.requested.ip().is_unspecified()
    }

    /// Checks that this value represents a supported guest binding.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.requested.port() != 0 && guest_binding_address_is_valid(self.requested)
    }

    /// Returns whether this binding belongs to the TCP guest namespace.
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.transport == GuestTransport::Tcp
    }

    /// Returns whether this binding covers one concrete guest-network address.
    #[must_use]
    pub fn covers(&self, address: SocketAddrV4) -> bool {
        self.is_valid()
            && if self.is_wildcard() {
                address.port() == self.requested.port()
                    && is_internal_network_address(*address.ip())
            } else {
                address == self.requested
            }
    }

    /// Selects this binding's guest-visible source for a routed destination.
    ///
    /// Exact loopback bindings cannot leave the guest namespace. Wildcard
    /// bindings use the primary loopback identity for guest loopback and the
    /// fixed private guest identity for private-guest and external routes.
    #[must_use]
    pub fn source_address_for_destination(
        &self,
        destination: SocketAddrV4,
    ) -> Option<SocketAddrV4> {
        if !self.is_valid() {
            return None;
        }
        let destination = normalize_socket_destination(destination).ok()?;
        if !self.is_wildcard() {
            if self.requested.ip().is_loopback() && !is_internal_socket_destination(destination) {
                return None;
            }
            return Some(self.requested);
        }
        let source_ip = if destination.ip().is_loopback() {
            Ipv4Addr::LOCALHOST
        } else {
            GUEST_IPV4_ADDRESS
        };
        Some(SocketAddrV4::new(source_ip, self.requested.port()))
    }
}

impl fmt::Debug for GuestSocketBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSocketBinding")
            .field("requested", &self.requested)
            .finish_non_exhaustive()
    }
}

impl PartialEq for GuestSocketBinding {
    fn eq(&self, other: &Self) -> bool {
        self.requested == other.requested && self.transport == other.transport
    }
}

impl Eq for GuestSocketBinding {}

/// Lease retaining one exact guest TCP source endpoint.
///
/// Core creates this value from a live guest binding when a TCP connection
/// targets the guest namespace. It grants no bind or listen authority. A
/// platform may move the lease through a queued guest-local connection and
/// return it from [`PlatformSocket::accept`]. Dropping the final binding
/// reference releases the namespace entry.
pub struct GuestSourceLease {
    _binding: Arc<GuestPortBinding>,
    source_address: SocketAddrV4,
}

impl GuestSourceLease {
    /// Returns the exact guest-visible source endpoint retained by this lease.
    #[must_use]
    pub const fn source_address(&self) -> SocketAddrV4 {
        self.source_address
    }
}

/// Platform socket and endpoint metadata returned by an accept operation.
pub struct AcceptedPlatformSocket {
    /// Accepted, connected nonblocking platform socket.
    pub socket: Arc<dyn PlatformSocket>,
    /// Exact guest destination reached by the connector.
    pub local_address: SocketAddrV4,
    /// Retains and identifies the connecting peer's guest-visible source.
    pub guest_source_lease: GuestSourceLease,
}

/// Broker failure from a platform connect operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformConnectError {
    /// The failed operation is known not to have changed the socket's peer.
    PeerUnchanged(BrokerError),
    /// The failure occurred after the socket's peer may have changed.
    ///
    /// Core retires the platform socket before permitting another operation.
    PeerIndeterminate(BrokerError),
}

/// Broker socket and endpoint metadata returned by an accept operation.
pub struct AcceptedBrokerSocket {
    /// Broker handle naming the accepted socket.
    pub handle: ObjectHandle,
    /// Guest-visible local endpoint of the accepted connection.
    pub local_address: SocketAddrV4,
    /// Guest-visible peer endpoint of the accepted connection.
    pub remote_address: SocketAddrV4,
}

/// Owned platform result for one stream receive.
#[derive(Debug, PartialEq, Eq)]
pub enum PlatformStreamReceive {
    /// Bytes received from the stream.
    Received(Vec<u8>),
    /// The stream's receive direction reached end of stream.
    EndOfStream,
}

/// Owned platform result for one datagram receive.
#[derive(Debug, PartialEq, Eq)]
pub struct PlatformDatagramReceive {
    /// Received datagram prefix, truncated to the requested capacity.
    pub data: Vec<u8>,
    /// Original datagram length before truncation.
    pub datagram_length: usize,
    /// Guest-visible source address of the datagram.
    ///
    /// Platforms must return the sender's stable guest-namespace endpoint for
    /// guest-to-guest datagrams. Broker-internal native endpoints must not be
    /// exposed.
    pub source_address: SocketAddrV4,
}

/// Broker-wide socket provider supplied by the host platform.
///
/// The provider creates per-socket [`PlatformSocket`] resources and owns any
/// bookkeeping shared across sockets and sessions. Sessions identify ownership
/// and accounting domains, not separate provider namespaces. Operations on an
/// individual socket belong to [`PlatformSocket`], not this shared provider.
pub trait SocketProvider: Send + Sync {
    /// Creates one nonblocking socket resource for a broker session.
    ///
    /// Any provider-retained clones must become inert when
    /// [`PlatformSocket::retire`] is called.
    fn create(
        &self,
        session_id: SessionId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformSocket>>;

    /// Releases remaining provider state charged to a session after its socket
    /// references close.
    ///
    /// This is a teardown and accounting boundary, not a separate network
    /// namespace; it must not disturb endpoints owned by other sessions.
    fn close_session(&self, session_id: SessionId);
}

/// One nonblocking socket resource created by [`SocketProvider`].
///
/// The broker retains this resource in an `Arc`, allowing an operation already
/// in flight to finish after its object handle closes. Before releasing its
/// portable authority, core explicitly retires the platform socket.
///
/// Implementations own their authoritative platform lifecycle state, including
/// any native resources. A request handler must record the start of a
/// transition before issuing it, and the corresponding synchronous result or
/// asynchronous completion handler must finish that transition.
/// [`status`](PlatformSocket::status) projects that platform-owned state for
/// the guest; core may cache the projection but does not reconstruct native
/// lifecycle state from status.
pub trait PlatformSocket: Send + Sync {
    /// Binds this socket to a local address and echoes the assigned address.
    ///
    /// A broker-managed TCP or UDP socket receives a broker-reserved,
    /// guest-visible address with a nonzero port and must echo it unchanged. A
    /// UDP bind may be entirely logical and need not allocate a native socket.
    /// A failed outcome or broker error must leave the socket unbound and
    /// retryable.
    fn bind(&self, binding: GuestSocketBinding) -> Result<SocketOutcome<SocketAddrV4>>;

    /// Starts a TCP listener and returns its unchanged guest-visible address.
    ///
    /// A failed outcome or broker error must leave the previous listener state
    /// unchanged and retryable.
    fn listen(&self, backlog: u32) -> Result<SocketOutcome<SocketAddrV4>>;

    /// Accepts one pending TCP connection without waiting.
    ///
    /// An empty backlog returns [`BrokerError::WouldBlock`].
    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> Result<SocketOutcome<AcceptedPlatformSocket>>;

    /// Starts a connection attempt.
    ///
    /// A stream attempt may return `Connecting` and stores ordinary failures as
    /// terminal state. A datagram connect completes immediately; the core
    /// permits replacing its peer and treats synchronous failures as retryable
    /// operation outcomes. A datagram `Failed` status must leave the previous
    /// peer unchanged. Platform failures must distinguish a peer known to be
    /// unchanged from one whose state is indeterminate. Once a native connect
    /// may have started, implementations must retain enough platform state to
    /// settle or conservatively retire it without reconstructing its lifecycle
    /// during teardown. A guest TCP attempt receives a source lease. A
    /// guest-local path must move it through to [`AcceptedPlatformSocket`];
    /// native paths may drop it. Returning
    /// [`PlatformConnectError::PeerUnchanged`] requires releasing the lease;
    /// [`PlatformSocket::retire`] must release one retained by an indeterminate
    /// or in-progress operation. `address` is the normalized guest-visible
    /// destination; the provider must validate it with
    /// [`normalize_socket_destination`] before choosing a host-socket target.
    fn connect(
        &self,
        address: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError>;

    /// Sends bytes without waiting for platform readiness.
    ///
    /// A temporarily full socket returns [`BrokerError::WouldBlock`]. Ordinary
    /// network failures return [`SocketOutcome::Failed`].
    fn send(&self, data: Vec<u8>, flags: SendFlags) -> Result<SocketOutcome<usize>>;

    /// Sends one complete datagram without waiting for platform readiness.
    ///
    /// A destination is required for an unconnected socket and omitted to use
    /// the socket's connected peer. An explicit destination is normalized but
    /// remains guest-visible; the provider must validate it with
    /// [`normalize_socket_destination`] before choosing a host-socket target.
    /// Partial successful sends are invalid. Resource failures are broker
    /// errors rather than ordinary socket failures.
    fn send_to(
        &self,
        data: Vec<u8>,
        flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> Result<SocketOutcome<usize>>;

    /// Receives bytes without waiting for platform readiness.
    ///
    /// A temporarily empty socket returns [`BrokerError::WouldBlock`]. End of
    /// stream returns [`PlatformStreamReceive::EndOfStream`]. The core handles
    /// zero-length receives without invoking the platform.
    fn receive(
        &self,
        length: usize,
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> Result<SocketOutcome<PlatformStreamReceive>>;

    /// Receives one datagram without waiting for platform readiness.
    ///
    /// The original datagram length is returned even when the caller's buffer
    /// is smaller, and zero-length datagrams are successful receives. The
    /// source address follows [`PlatformDatagramReceive::source_address`].
    fn receive_from(
        &self,
        length: usize,
        flags: ReceiveFromFlags,
    ) -> Result<SocketOutcome<PlatformDatagramReceive>>;

    /// Applies a directional or TCP lifecycle shutdown mode.
    ///
    /// UDP supports read, write, and both. TCP additionally supports aborting
    /// a connection and stopping a listener. For `StopListening`, completion
    /// or `Failed(NotConnected)` means the listener is stopped; any other
    /// failure must leave the listener active and retryable.
    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>>;

    /// Sets a typed TCP socket option.
    fn set_tcp_option(&self, value: TcpOptionValue) -> Result<()>;

    /// Reads a typed TCP socket option.
    fn get_tcp_option(&self, name: TcpOptionName) -> Result<TcpOptionValue>;

    /// Returns platform-observed socket state and consumes at most one pending
    /// error.
    ///
    /// For stream sockets, this advances an asynchronous connection attempt
    /// from `Connecting` to `Connected` or `Failed`. For datagram sockets, the
    /// broker owns the peer state; the platform reports pending asynchronous
    /// errors and may specialize the local IP address after external routing,
    /// but it must preserve the broker-reserved local port.
    fn status(&self) -> Result<PlatformSocketStatus>;

    /// Synchronously and idempotently ends this socket's platform authority.
    ///
    /// Provider-retained clones must be inert when this method returns.
    fn retire(&self);

    /// Returns the authoritative cached readiness snapshot.
    ///
    /// This must not require access to a native resource that retirement may
    /// already have removed.
    fn readiness(&self) -> ReadinessFlags;
}

/// Provider for broker configurations that deliberately disable sockets.
pub struct UnsupportedSocketProvider;

impl SocketProvider for UnsupportedSocketProvider {
    fn create(
        &self,
        _session_id: SessionId,
        _request: CreateSocketRequest,
        _readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformSocket>> {
        Err(BrokerError::UnsupportedOperation)
    }

    fn close_session(&self, _session_id: SessionId) {}
}

/// Creates a broker-owned socket.
pub fn create(
    session: &BrokerSession,
    request: CreateSocketRequest,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = session
        .core
        .policy
        .authorize_socket_create(session.caller_credential, request)?;
    let quota = Arc::new(SocketQuotaReservation::new(session)?);
    let reference = session.reserve_object_reference(rights)?;
    let readiness =
        ReadinessRegistration::new_with_retirement_guard(reference.handle(), readiness_sink, quota);
    let platform_socket =
        match session
            .core
            .socket_provider
            .create(session.session_id, request, readiness.clone())
        {
            Ok(socket) => socket,
            Err(error) => {
                // The provider may have retained its registration before
                // failing, so retirement cannot rely on the local clone being
                // the last one.
                readiness.retire();
                return Err(error);
            }
        };
    let resource = Arc::new(SocketResource {
        platform_socket,
        readiness,
        port_binding: Mutex::new(None),
        guest_source_lease: Mutex::new(None),
    });
    let handle = reference.commit(ObjectEntry::Socket(SocketObject::new(resource, request)))?;
    Ok(handle)
}

/// Starts a nonblocking connection attempt.
///
/// Policy denial is returned as a per-request [`SocketOutcome::Failed`] and
/// does not alter the socket's existing connection or peer state, so a later
/// authorized destination may still be attempted. An authorized attempt on an
/// unbound stream or datagram socket first reserves a guest-visible local
/// endpoint.
pub fn connect(
    session: &BrokerSession,
    handle: ObjectHandle,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let object = session.authorized_object(handle, ObjectRights::WRITE)?;
    let create_request = {
        let object = object.read();
        let ObjectEntry::Socket(socket) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
        socket.create_request
    };

    if address.port() == 0 {
        return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
    }
    let destination = match normalize_socket_destination(address) {
        Ok(destination) => destination,
        Err(error) => return Ok(SocketOutcome::Failed(error)),
    };

    // Destination denial is an operation-level socket failure. Failures while
    // evaluating policy remain broker errors.
    match session.core.policy.authorize_socket_connect(
        session.caller_credential,
        create_request.protocol,
        destination,
    ) {
        Ok(()) => {}
        Err(BrokerError::PolicyDenied) => {
            return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
        }
        Err(error) => return Err(error),
    }

    if is_udp(create_request) {
        return connect_datagram(session, &object, create_request, destination);
    }

    let (resource, needs_bind) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if socket.resource_retired {
            return Ok(SocketOutcome::Completed(socket.connection_status));
        }
        if socket.connect_in_flight {
            return Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting));
        }
        if socket.configuration_in_flight || socket.listening {
            return Ok(SocketOutcome::Failed(SocketError::Other));
        }
        if socket.connection_status != SocketConnectionStatus::Unconnected {
            return Ok(SocketOutcome::Completed(socket.connection_status));
        }
        socket.connect_in_flight = true;
        (Arc::clone(&socket.resource), socket.local_address.is_none())
    };
    if needs_bind {
        let binding =
            match reserve_and_bind(session, create_request, &resource, DEFAULT_LOCAL_ADDRESS) {
                Ok(binding) => binding,
                Err(error) => {
                    finish_connect(&object, SocketConnectionStatus::Unconnected);
                    return Err(error);
                }
            };
        match binding {
            ReserveAndBindOutcome::Completed(local_address, port_binding) => {
                attach_binding(&object, local_address, port_binding)?;
            }
            ReserveAndBindOutcome::Failed(error) => {
                finish_connect(&object, SocketConnectionStatus::Unconnected);
                return Ok(SocketOutcome::Failed(error));
            }
            ReserveAndBindOutcome::Retired(port_binding) => {
                finish_retired_connect(&object);
                retire_before_releasing_binding(&resource, port_binding);
                return Err(BrokerError::Internal);
            }
        }
    }
    if resource
        .source_address_for_destination(destination)
        .is_none()
    {
        finish_connect(&object, SocketConnectionStatus::Unconnected);
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let guest_source_lease = match resource.source_lease_for_connect(destination) {
        Ok(lease) => lease,
        Err(error) => {
            finish_retired_connect(&object);
            resource.retire();
            return Err(error);
        }
    };
    let status = match resource
        .platform_socket
        .connect(destination, guest_source_lease)
    {
        Ok(SocketConnectionStatus::Unconnected) => {
            finish_retired_connect(&object);
            resource.retire();
            return Err(BrokerError::Internal);
        }
        Ok(status) => status,
        Err(PlatformConnectError::PeerUnchanged(error)) => {
            finish_connect(&object, SocketConnectionStatus::Unconnected);
            return Err(error);
        }
        Err(PlatformConnectError::PeerIndeterminate(error)) => {
            finish_retired_connect(&object);
            resource.retire();
            return Err(error);
        }
    };
    finish_connect(&object, status);
    Ok(SocketOutcome::Completed(status))
}

/// Binds a socket to a supported guest-namespace address.
pub fn bind(
    session: &BrokerSession,
    handle: ObjectHandle,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketAddrV4>> {
    let object = session.authorized_object(handle, ObjectRights::WRITE)?;
    let (resource, create_request) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if socket.resource_retired {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        if socket.configuration_in_flight
            || socket.connect_in_flight
            || socket.listening
            || socket.local_address.is_some()
            || socket.connection_status != SocketConnectionStatus::Unconnected
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        socket.configuration_in_flight = true;
        (Arc::clone(&socket.resource), socket.create_request)
    };
    match reserve_and_bind(session, create_request, &resource, address) {
        Ok(ReserveAndBindOutcome::Completed(local_address, port_binding)) => {
            finish_configuration(&object, Some(local_address), Some(port_binding), false)?;
            Ok(SocketOutcome::Completed(local_address))
        }
        Ok(ReserveAndBindOutcome::Failed(error)) => {
            finish_configuration(&object, None, None, false)?;
            Ok(SocketOutcome::Failed(error))
        }
        Ok(ReserveAndBindOutcome::Retired(port_binding)) => {
            finish_retired_configuration(&object, None, None)?;
            retire_before_releasing_binding(&resource, port_binding);
            Err(BrokerError::Internal)
        }
        Err(error) => {
            finish_configuration(&object, None, None, false)?;
            Err(error)
        }
    }
}

/// Starts a TCP listener in the broker's guest network namespace.
pub fn listen(
    session: &BrokerSession,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<SocketOutcome<SocketAddrV4>> {
    if backlog > MAX_TCP_LISTEN_BACKLOG {
        return Err(BrokerError::UnsupportedOperation);
    }
    let object = session.authorized_object(handle, ObjectRights::WRITE)?;
    let (resource, create_request, existing_local_address) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if !is_tcp(socket.create_request) {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if socket.resource_retired {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        if socket.configuration_in_flight
            || socket.connect_in_flight
            || socket.connection_status != SocketConnectionStatus::Unconnected
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        socket.configuration_in_flight = true;
        (
            Arc::clone(&socket.resource),
            socket.create_request,
            socket.local_address,
        )
    };

    let mut local_address = existing_local_address;
    let mut port_binding = None;
    if local_address.is_none() {
        let binding = match reserve_and_bind(
            session,
            create_request,
            &resource,
            DEFAULT_TCP_LISTEN_ADDRESS,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                finish_configuration(&object, None, None, false)?;
                return Err(error);
            }
        };
        match binding {
            ReserveAndBindOutcome::Completed(address, binding) => {
                local_address = Some(address);
                port_binding = Some(binding);
            }
            ReserveAndBindOutcome::Failed(error) => {
                finish_configuration(&object, None, None, false)?;
                return Ok(SocketOutcome::Failed(error));
            }
            ReserveAndBindOutcome::Retired(port_binding) => {
                finish_retired_configuration(&object, None, None)?;
                retire_before_releasing_binding(&resource, port_binding);
                return Err(BrokerError::Internal);
            }
        }
    }

    match resource.platform_socket.listen(backlog) {
        Ok(SocketOutcome::Completed(address)) => {
            if local_address != Some(address) {
                finish_retired_configuration(&object, local_address, port_binding)?;
                resource.retire();
                return Err(BrokerError::Internal);
            }
            finish_configuration(&object, local_address, port_binding, true)?;
            Ok(SocketOutcome::Completed(address))
        }
        Ok(SocketOutcome::Failed(error)) => {
            finish_configuration(&object, local_address, port_binding, false)?;
            Ok(SocketOutcome::Failed(error))
        }
        Err(error) => {
            finish_configuration(&object, local_address, port_binding, false)?;
            Err(error)
        }
    }
}

/// Accepts one pending TCP connection and creates a broker socket capability.
pub fn accept(
    session: &BrokerSession,
    handle: ObjectHandle,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<SocketOutcome<AcceptedBrokerSocket>> {
    let listener = session.authorized_object(handle, ObjectRights::WAIT)?;
    let (listener_resource, create_request) = {
        let listener = listener.read();
        let ObjectEntry::Socket(socket) = &*listener else {
            return Err(BrokerError::InvalidRights);
        };
        if !is_tcp(socket.create_request) {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if !socket.listening {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        (Arc::clone(&socket.resource), socket.create_request)
    };
    let rights = session
        .core
        .policy
        .principal_object_rights(session.caller_credential)?;
    let quota = Arc::new(SocketQuotaReservation::new(session)?);
    let reference = session.reserve_object_reference(rights)?;
    let readiness =
        ReadinessRegistration::new_with_retirement_guard(reference.handle(), readiness_sink, quota);
    let accepted = match listener_resource.platform_socket.accept(readiness.clone()) {
        Ok(SocketOutcome::Completed(accepted)) => accepted,
        Ok(SocketOutcome::Failed(error)) => {
            readiness.retire();
            return Ok(SocketOutcome::Failed(error));
        }
        Err(error) => {
            readiness.retire();
            return Err(error);
        }
    };
    let AcceptedPlatformSocket {
        socket,
        local_address,
        guest_source_lease,
    } = accepted;
    if !listener_resource.port_binding_covers(local_address) {
        socket.retire();
        readiness.retire();
        return Err(BrokerError::Internal);
    }
    let remote_address = guest_source_lease.source_address();
    let resource = Arc::new(SocketResource {
        platform_socket: socket,
        readiness,
        port_binding: Mutex::new(None),
        guest_source_lease: Mutex::new(Some(guest_source_lease)),
    });
    let accepted_socket = SocketObject::new_connected(resource, create_request, local_address);
    let handle = reference.commit(ObjectEntry::Socket(accepted_socket))?;
    Ok(SocketOutcome::Completed(AcceptedBrokerSocket {
        handle,
        local_address,
        remote_address,
    }))
}

/// Sends TCP stream bytes without waiting for readiness.
pub fn send(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: Vec<u8>,
    flags: SendFlags,
) -> Result<SocketOutcome<usize>> {
    if flags.has_unsupported_bits() || data.len() > MAX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let length = data.len();
    let (resource, create_request, _, resource_retired) =
        socket_state(session, handle, ObjectRights::WRITE)?;
    if !is_tcp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if resource_retired {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let outcome = resource.platform_socket.send(data, flags)?;
    if let SocketOutcome::Completed(sent) = outcome
        && (sent > length || (length != 0 && sent == 0))
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Sends one complete datagram without waiting for readiness.
///
/// The first valid send with an explicit destination on an unbound datagram
/// socket reserves and binds a guest-visible local endpoint before invoking
/// the platform.
pub fn send_to(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: Vec<u8>,
    flags: SendFlags,
    destination: Option<SocketAddrV4>,
) -> Result<SocketOutcome<usize>> {
    if flags.has_unsupported_bits() || data.len() > MAX_UDP_DATAGRAM_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let length = data.len();
    let object = session.authorized_object(handle, ObjectRights::WRITE)?;
    let create_request = {
        let object = object.read();
        let ObjectEntry::Socket(socket) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
        socket.create_request
    };
    let destination = match destination {
        Some(destination) if destination.port() == 0 => {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        Some(destination) => match normalize_socket_destination(destination) {
            Ok(destination) => Some(destination),
            Err(error) => return Ok(SocketOutcome::Failed(error)),
        },
        None => None,
    };
    if let Some(destination) = destination {
        match session.core.policy.authorize_socket_connect(
            session.caller_credential,
            create_request.protocol,
            destination,
        ) {
            Ok(()) => {}
            Err(BrokerError::PolicyDenied) => {
                return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
            }
            Err(error) => return Err(error),
        }
    }
    let (resource, needs_bind) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if !is_udp(socket.create_request) {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if socket.resource_retired {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        if destination.is_none() && socket.connection_status != SocketConnectionStatus::Connected {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let needs_bind = socket.local_address.is_none();
        if needs_bind {
            if socket.configuration_in_flight || socket.connect_in_flight || socket.listening {
                return Ok(SocketOutcome::Failed(SocketError::Other));
            }
            socket.configuration_in_flight = true;
        }
        (Arc::clone(&socket.resource), needs_bind)
    };
    if needs_bind {
        match reserve_and_bind(session, create_request, &resource, DEFAULT_LOCAL_ADDRESS) {
            Ok(ReserveAndBindOutcome::Completed(local_address, port_binding)) => {
                finish_configuration(&object, Some(local_address), Some(port_binding), false)?;
            }
            Ok(ReserveAndBindOutcome::Failed(error)) => {
                finish_configuration(&object, None, None, false)?;
                return Ok(SocketOutcome::Failed(error));
            }
            Ok(ReserveAndBindOutcome::Retired(port_binding)) => {
                finish_retired_configuration(&object, None, None)?;
                retire_before_releasing_binding(&resource, port_binding);
                return Err(BrokerError::Internal);
            }
            Err(error) => {
                finish_configuration(&object, None, None, false)?;
                return Err(error);
            }
        }
    }
    if destination.is_some_and(|destination| {
        resource
            .source_address_for_destination(destination)
            .is_none()
    }) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let outcome = resource.platform_socket.send_to(data, flags, destination)?;
    if let SocketOutcome::Completed(sent) = outcome
        && sent != length
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Receives TCP stream bytes without waiting for readiness.
pub fn receive(
    session: &BrokerSession,
    handle: ObjectHandle,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: u32,
    peek_length: u32,
) -> Result<SocketOutcome<PlatformStreamReceive>> {
    if flags.has_unsupported_bits() || length > MAX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let peek = flags.contains(ReceiveFlags::PEEK);
    if flags.contains(ReceiveFlags::WAITALL) && !peek {
        return Err(BrokerError::UnsupportedOperation);
    }
    let canonical_peek_length = peek_length
        .checked_sub(peek_offset)
        .and_then(|remaining| usize::try_from(remaining.min(MAX_SOCKET_TRANSFER_SIZE)).ok());
    if (!peek && (peek_offset != 0 || peek_length != 0))
        || (peek
            && (!peek_offset.is_multiple_of(MAX_SOCKET_TRANSFER_SIZE)
                || canonical_peek_length != Some(length)
                || peek_length > litebox_broker_protocol::socket::MAX_SOCKET_PEEK_SIZE))
    {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (resource, create_request, _, resource_retired) =
        socket_state(session, handle, ObjectRights::WAIT)?;
    if !is_tcp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if resource_retired {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    if length == 0 {
        return Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
            Vec::new(),
        )));
    }
    let outcome = resource
        .platform_socket
        .receive(length, flags, peek_offset, peek_length)?;
    if let SocketOutcome::Completed(PlatformStreamReceive::Received(received)) = &outcome
        && (received.len() > length || received.is_empty())
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Receives one datagram without waiting for readiness.
pub fn receive_from(
    session: &BrokerSession,
    handle: ObjectHandle,
    length: usize,
    flags: ReceiveFromFlags,
) -> Result<SocketOutcome<PlatformDatagramReceive>> {
    if flags.has_unsupported_bits() || length > MAX_UDP_DATAGRAM_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (resource, create_request, _, resource_retired) =
        socket_state(session, handle, ObjectRights::WAIT)?;
    if !is_udp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if resource_retired {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let outcome = resource.platform_socket.receive_from(length, flags)?;
    if let SocketOutcome::Completed(received) = &outcome
        && (received.data.len() != received.datagram_length.min(length)
            || received.datagram_length > MAX_UDP_DATAGRAM_SIZE as usize
            || normalize_socket_destination(received.source_address) != Ok(received.source_address))
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Sets a typed option on a broker-owned TCP socket.
pub fn set_tcp_option(
    session: &BrokerSession,
    handle: ObjectHandle,
    value: TcpOptionValue,
) -> Result<()> {
    let (resource, create_request, _, resource_retired) =
        socket_state(session, handle, ObjectRights::WRITE)?;
    if !is_tcp(create_request) {
        return Err(BrokerError::UnsupportedOperation);
    }
    if resource_retired {
        return Err(BrokerError::Internal);
    }
    resource.platform_socket.set_tcp_option(value)
}

/// Reads a typed option from a broker-owned TCP socket.
pub fn get_tcp_option(
    session: &BrokerSession,
    handle: ObjectHandle,
    name: TcpOptionName,
) -> Result<TcpOptionValue> {
    let (resource, create_request, _, resource_retired) =
        socket_state(session, handle, ObjectRights::WAIT)?;
    if !is_tcp(create_request) {
        return Err(BrokerError::UnsupportedOperation);
    }
    if resource_retired {
        return Err(BrokerError::Internal);
    }
    let value = resource.platform_socket.get_tcp_option(name)?;
    if !matches!(
        (name, value),
        (TcpOptionName::NoDelay, TcpOptionValue::NoDelay(_))
            | (TcpOptionName::KeepAlive, TcpOptionValue::KeepAlive(_))
    ) {
        return Err(BrokerError::Internal);
    }
    Ok(value)
}

/// Applies a directional or TCP lifecycle shutdown mode.
///
/// Read, write, and both apply to TCP and UDP. Abort and stop-listening are
/// TCP-only.
pub fn shutdown(
    session: &BrokerSession,
    handle: ObjectHandle,
    mode: ShutdownMode,
) -> Result<SocketOutcome<()>> {
    let object = session.authorized_object(handle, ObjectRights::WRITE)?;
    let (resource, serializes_configuration, shuts_down_listener) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if is_udp(socket.create_request)
            && matches!(mode, ShutdownMode::Abort | ShutdownMode::StopListening)
        {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if socket.resource_retired {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        if socket.listening && !matches!(mode, ShutdownMode::Abort | ShutdownMode::StopListening) {
            return Ok(SocketOutcome::Failed(SocketError::NotConnected));
        }
        let serializes_configuration = mode == ShutdownMode::StopListening;
        if serializes_configuration {
            if socket.configuration_in_flight {
                return Ok(SocketOutcome::Failed(SocketError::Other));
            }
            socket.configuration_in_flight = true;
        }
        (
            Arc::clone(&socket.resource),
            serializes_configuration,
            socket.listening && mode == ShutdownMode::StopListening,
        )
    };
    let outcome = resource.platform_socket.shutdown(mode);
    if serializes_configuration {
        let mut object = object.write();
        if let ObjectEntry::Socket(socket) = &mut *object {
            socket.configuration_in_flight = false;
            if shuts_down_listener
                && matches!(
                    &outcome,
                    Ok(SocketOutcome::Completed(())
                        | SocketOutcome::Failed(SocketError::NotConnected))
                )
            {
                socket.listening = false;
                socket.connection_status =
                    SocketConnectionStatus::Failed(SocketError::NotConnected);
            }
        }
    }
    outcome
}

/// Returns broker-authoritative socket state and consumes at most one pending
/// asynchronous error.
///
/// Stream status reconciles an asynchronous platform connection attempt.
/// Datagram connects complete synchronously and may replace the peer, so
/// datagram status preserves the broker-owned connection state while querying
/// the platform only for pending errors and local-address specialization.
pub fn status(session: &BrokerSession, handle: ObjectHandle) -> Result<SocketStatusResponse> {
    let object = session.authorized_object(handle, ObjectRights::WAIT)?;
    let datagram = {
        let object = object.read();
        let ObjectEntry::Socket(socket) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
        is_udp(socket.create_request)
    };

    if datagram {
        datagram_status(&object)
    } else {
        stream_status(&object)
    }
}

/// Reconciles broker stream state with an asynchronous platform connection.
fn stream_status(object: &spin::RwLock<ObjectEntry>) -> Result<SocketStatusResponse> {
    let (resource, status, local_address, connect_in_flight) = {
        let object = object.read();
        let ObjectEntry::Socket(socket) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
        (
            Arc::clone(&socket.resource),
            socket.connection_status,
            socket.local_address,
            socket.connect_in_flight,
        )
    };
    if connect_in_flight {
        return Ok(SocketStatusResponse {
            status: SocketConnectionStatus::Connecting,
            local_address,
            pending_error: None,
        });
    }
    if matches!(
        status,
        SocketConnectionStatus::Unconnected | SocketConnectionStatus::Failed(_)
    ) {
        return Ok(SocketStatusResponse {
            status,
            local_address,
            pending_error: None,
        });
    }

    let platform_status = resource.platform_socket.status()?;
    let mut object = object.write();
    let ObjectEntry::Socket(socket) = &mut *object else {
        return Err(BrokerError::InvalidRights);
    };
    let Some(broker_local_address) = socket.local_address else {
        socket.listening = false;
        socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
        socket.resource_retired = true;
        drop(object);
        resource.retire();
        return Err(BrokerError::Internal);
    };
    if let Some(observed) = platform_status.local_address {
        let invalid_local_address = observed.port() != broker_local_address.port()
            || !is_internal_network_address(*observed.ip());
        if invalid_local_address {
            socket.listening = false;
            socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
            socket.resource_retired = true;
            drop(object);
            resource.retire();
            return Err(BrokerError::Internal);
        }
        if broker_local_address.ip().is_unspecified() {
            socket.local_address = Some(observed);
        }
    }
    if platform_status.status == SocketConnectionStatus::Unconnected {
        socket.listening = false;
        socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
        socket.resource_retired = true;
        drop(object);
        resource.retire();
        return Err(BrokerError::Internal);
    }
    if socket.connection_status == SocketConnectionStatus::Connecting {
        socket.connection_status = platform_status.status;
    }
    // Return the latest broker state rather than this potentially stale platform snapshot.
    Ok(SocketStatusResponse {
        status: socket.connection_status,
        local_address: socket.local_address,
        pending_error: platform_status.pending_error,
    })
}

/// Queries datagram errors and address refinement without surrendering the
/// broker-owned peer state to a potentially stale platform snapshot.
fn datagram_status(object: &spin::RwLock<ObjectEntry>) -> Result<SocketStatusResponse> {
    let (
        resource,
        status,
        local_address,
        configuration_in_flight,
        datagram_connect_generation,
        resource_retired,
        wildcard_binding,
    ) = {
        let object = object.read();
        let ObjectEntry::Socket(socket) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
        (
            Arc::clone(&socket.resource),
            socket.connection_status,
            socket.local_address,
            socket.configuration_in_flight,
            socket.datagram_connect_generation,
            socket.resource_retired,
            socket.resource.port_binding_is_wildcard(),
        )
    };
    if configuration_in_flight || resource_retired {
        return Ok(SocketStatusResponse {
            status,
            local_address,
            pending_error: None,
        });
    }
    let mut expected_datagram_generation = datagram_connect_generation;
    let mut retried_datagram_status = false;
    let mut pending_error = None;
    loop {
        let (resource_retired, status, local_address) = {
            let object = object.read();
            let ObjectEntry::Socket(socket) = &*object else {
                return Err(BrokerError::InvalidRights);
            };
            (
                socket.resource_retired,
                socket.connection_status,
                socket.local_address,
            )
        };
        if resource_retired {
            return Ok(SocketStatusResponse {
                status,
                local_address,
                pending_error: None,
            });
        }
        let platform_status = match resource.platform_socket.status() {
            Ok(status) => status,
            Err(error) => {
                let object = object.read();
                let ObjectEntry::Socket(socket) = &*object else {
                    return Err(BrokerError::InvalidRights);
                };
                if socket.resource_retired {
                    return Ok(SocketStatusResponse {
                        status: socket.connection_status,
                        local_address: socket.local_address,
                        pending_error: None,
                    });
                }
                return Err(error);
            }
        };
        pending_error = pending_error.or(platform_status.pending_error);
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if socket.resource_retired {
            return Ok(SocketStatusResponse {
                status: socket.connection_status,
                local_address: socket.local_address,
                pending_error: None,
            });
        }
        if socket.configuration_in_flight {
            return Ok(SocketStatusResponse {
                status: socket.connection_status,
                local_address: socket.local_address,
                pending_error,
            });
        }
        let invalid_local_address = match (socket.local_address, platform_status.local_address) {
            (None, Some(_)) => true,
            (Some(broker_address), Some(observed)) => {
                broker_address.port() != observed.port()
                    || !guest_binding_address_is_valid(observed)
            }
            _ => false,
        };
        if invalid_local_address {
            socket.configuration_in_flight = false;
            socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
            socket.resource_retired = true;
            drop(object);
            resource.retire();
            return Err(BrokerError::Internal);
        }
        if matches!(
            platform_status.status,
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Failed(_)
        ) {
            socket.configuration_in_flight = false;
            socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
            socket.resource_retired = true;
            drop(object);
            resource.retire();
            return Err(BrokerError::Internal);
        }
        if socket.datagram_connect_generation != expected_datagram_generation {
            if !retried_datagram_status && pending_error.is_none() {
                expected_datagram_generation = socket.datagram_connect_generation;
                retried_datagram_status = true;
                drop(object);
                continue;
            }
            // Continuous peer replacement can race both bounded queries.
            // Do not let an unordered platform snapshot overwrite newer
            // broker observations.
            return Ok(SocketStatusResponse {
                status: socket.connection_status,
                local_address: socket.local_address,
                pending_error,
            });
        }
        let local_address_refinement = match (socket.local_address, platform_status.local_address) {
            (Some(broker_address), Some(observed))
                if wildcard_binding || broker_address.ip().is_unspecified() =>
            {
                Some(observed)
            }
            _ => None,
        };
        socket.local_address = local_address_refinement.or(socket.local_address);
        return Ok(SocketStatusResponse {
            status: socket.connection_status,
            local_address: socket.local_address,
            pending_error,
        });
    }
}

#[cfg(test)]
fn socket_resource(
    session: &BrokerSession,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<Arc<SocketResource>> {
    let object = session.authorized_object(handle, required_rights)?;
    let object = object.read();
    let ObjectEntry::Socket(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok(Arc::clone(&socket.resource))
}

fn socket_state(
    session: &BrokerSession,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<(
    Arc<SocketResource>,
    CreateSocketRequest,
    SocketConnectionStatus,
    bool,
)> {
    let object = session.authorized_object(handle, required_rights)?;
    let object = object.read();
    let ObjectEntry::Socket(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok((
        Arc::clone(&socket.resource),
        socket.create_request,
        socket.connection_status,
        socket.resource_retired,
    ))
}

enum ReserveAndBindOutcome {
    Completed(SocketAddrV4, Arc<GuestPortBinding>),
    Failed(SocketError),
    Retired(Arc<GuestPortBinding>),
}

fn reserve_and_bind(
    session: &BrokerSession,
    create_request: CreateSocketRequest,
    resource: &SocketResource,
    requested_address: SocketAddrV4,
) -> Result<ReserveAndBindOutcome> {
    let (local_address, port_binding) = match session
        .core
        .socket_ports
        .reserve(create_request, requested_address)?
    {
        SocketOutcome::Completed(binding) => binding,
        SocketOutcome::Failed(error) => return Ok(ReserveAndBindOutcome::Failed(error)),
    };
    let binding = GuestSocketBinding::new(&port_binding);
    match resource.platform_socket.bind(binding)? {
        SocketOutcome::Completed(bound_address) if bound_address == local_address => Ok(
            ReserveAndBindOutcome::Completed(local_address, port_binding),
        ),
        SocketOutcome::Completed(_) => Ok(ReserveAndBindOutcome::Retired(port_binding)),
        SocketOutcome::Failed(error) => Ok(ReserveAndBindOutcome::Failed(error)),
    }
}

fn retire_before_releasing_binding(resource: &SocketResource, port_binding: Arc<GuestPortBinding>) {
    resource.retire();
    drop(port_binding);
}

fn connect_datagram(
    session: &BrokerSession,
    object: &spin::RwLock<ObjectEntry>,
    create_request: CreateSocketRequest,
    destination: SocketAddrV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let (resource, previous_status, needs_bind) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if socket.resource_retired {
            return Ok(SocketOutcome::Completed(socket.connection_status));
        }
        if socket.configuration_in_flight || socket.connect_in_flight || socket.listening {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        socket.configuration_in_flight = true;
        (
            Arc::clone(&socket.resource),
            socket.connection_status,
            socket.local_address.is_none(),
        )
    };
    if needs_bind {
        let binding =
            match reserve_and_bind(session, create_request, &resource, DEFAULT_LOCAL_ADDRESS) {
                Ok(binding) => binding,
                Err(error) => {
                    finish_datagram_connect(object, previous_status, false);
                    return Err(error);
                }
            };
        match binding {
            ReserveAndBindOutcome::Completed(local_address, port_binding) => {
                attach_datagram_binding(object, local_address, port_binding)?;
            }
            ReserveAndBindOutcome::Failed(error) => {
                finish_datagram_connect(object, previous_status, false);
                return Ok(SocketOutcome::Failed(error));
            }
            ReserveAndBindOutcome::Retired(port_binding) => {
                finish_retired_datagram_connect(object);
                retire_before_releasing_binding(&resource, port_binding);
                return Err(BrokerError::Internal);
            }
        }
    }
    if resource
        .source_address_for_destination(destination)
        .is_none()
    {
        finish_datagram_connect(object, previous_status, false);
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    match resource.platform_socket.connect(destination, None) {
        Ok(SocketConnectionStatus::Connected) => {
            finish_datagram_connect(object, SocketConnectionStatus::Connected, true);
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        }
        Ok(SocketConnectionStatus::Failed(error)) => {
            finish_datagram_connect(object, previous_status, false);
            Ok(SocketOutcome::Failed(error))
        }
        Ok(_) => {
            finish_retired_datagram_connect(object);
            resource.retire();
            Err(BrokerError::Internal)
        }
        Err(PlatformConnectError::PeerUnchanged(error)) => {
            finish_datagram_connect(object, previous_status, false);
            Err(error)
        }
        Err(PlatformConnectError::PeerIndeterminate(error)) => {
            finish_retired_datagram_connect(object);
            resource.retire();
            Err(error)
        }
    }
}

fn attach_datagram_binding(
    object: &spin::RwLock<ObjectEntry>,
    local_address: SocketAddrV4,
    port_binding: Arc<GuestPortBinding>,
) -> Result<()> {
    let duplicate = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::Internal);
        };
        if socket.local_address.is_some() {
            Some((Arc::clone(&socket.resource), port_binding))
        } else {
            match socket.resource.set_port_binding(port_binding) {
                Ok(()) => {
                    socket.local_address = Some(local_address);
                    None
                }
                Err(port_binding) => Some((Arc::clone(&socket.resource), port_binding)),
            }
        }
    };
    if let Some((resource, port_binding)) = duplicate {
        finish_retired_datagram_connect(object);
        resource.retire();
        drop(port_binding);
        return Err(BrokerError::Internal);
    }
    Ok(())
}

fn finish_datagram_connect(
    object: &spin::RwLock<ObjectEntry>,
    status: SocketConnectionStatus,
    peer_state_changed: bool,
) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.configuration_in_flight = false;
        socket.connection_status = status;
        if peer_state_changed {
            // This distinguishes status snapshots from before a successful
            // peer replacement. A status call cannot overlap enough connects
            // for wrapping to make a stale snapshot appear current.
            socket.datagram_connect_generation = socket.datagram_connect_generation.wrapping_add(1);
        }
    }
}

fn finish_retired_datagram_connect(object: &spin::RwLock<ObjectEntry>) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.configuration_in_flight = false;
        socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
        socket.resource_retired = true;
    }
}

fn finish_connect(object: &spin::RwLock<ObjectEntry>, status: SocketConnectionStatus) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.connect_in_flight = false;
        socket.connection_status = status;
    }
}

fn finish_retired_connect(object: &spin::RwLock<ObjectEntry>) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.connect_in_flight = false;
        socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
        socket.resource_retired = true;
    }
}

fn attach_binding(
    object: &spin::RwLock<ObjectEntry>,
    local_address: SocketAddrV4,
    port_binding: Arc<GuestPortBinding>,
) -> Result<()> {
    let duplicate = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::Internal);
        };
        match socket.resource.set_port_binding(port_binding) {
            Ok(()) => {
                socket.local_address = Some(local_address);
                None
            }
            Err(port_binding) => {
                socket.connect_in_flight = false;
                socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
                socket.resource_retired = true;
                Some((Arc::clone(&socket.resource), port_binding))
            }
        }
    };
    if let Some((resource, port_binding)) = duplicate {
        resource.retire();
        drop(port_binding);
        return Err(BrokerError::Internal);
    }
    Ok(())
}

fn finish_configuration(
    object: &spin::RwLock<ObjectEntry>,
    local_address: Option<SocketAddrV4>,
    port_binding: Option<Arc<GuestPortBinding>>,
    listening: bool,
) -> Result<()> {
    let duplicate = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::Internal);
        };
        socket.configuration_in_flight = false;
        let duplicate = port_binding.and_then(|port_binding| {
            socket
                .resource
                .set_port_binding(port_binding)
                .err()
                .map(|port_binding| (Arc::clone(&socket.resource), port_binding))
        });
        if duplicate.is_some() {
            socket.listening = false;
            socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
            socket.resource_retired = true;
        } else {
            socket.local_address = socket.local_address.or(local_address);
            socket.listening |= listening;
        }
        duplicate
    };
    if let Some((resource, port_binding)) = duplicate {
        resource.retire();
        drop(port_binding);
        return Err(BrokerError::Internal);
    }
    Ok(())
}

fn finish_retired_configuration(
    object: &spin::RwLock<ObjectEntry>,
    local_address: Option<SocketAddrV4>,
    port_binding: Option<Arc<GuestPortBinding>>,
) -> Result<()> {
    let duplicate = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::Internal);
        };
        socket.configuration_in_flight = false;
        let duplicate = port_binding.and_then(|port_binding| {
            socket
                .resource
                .set_port_binding(port_binding)
                .err()
                .map(|port_binding| (Arc::clone(&socket.resource), port_binding))
        });
        socket.local_address = socket.local_address.or(local_address);
        socket.listening = false;
        socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
        socket.resource_retired = true;
        duplicate
    };
    if let Some((resource, port_binding)) = duplicate {
        resource.retire();
        drop(port_binding);
        return Err(BrokerError::Internal);
    }
    Ok(())
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "socket lifecycle latches are independent"
)]
pub(crate) struct SocketObject {
    resource: Arc<SocketResource>,
    create_request: CreateSocketRequest,
    connection_status: SocketConnectionStatus,
    local_address: Option<SocketAddrV4>,
    connect_in_flight: bool,
    configuration_in_flight: bool,
    listening: bool,
    datagram_connect_generation: u64,
    resource_retired: bool,
}

impl SocketObject {
    fn new(resource: Arc<SocketResource>, create_request: CreateSocketRequest) -> Self {
        Self {
            resource,
            create_request,
            connection_status: SocketConnectionStatus::Unconnected,
            local_address: None,
            connect_in_flight: false,
            configuration_in_flight: false,
            listening: false,
            datagram_connect_generation: 0,
            resource_retired: false,
        }
    }

    fn new_connected(
        resource: Arc<SocketResource>,
        create_request: CreateSocketRequest,
        local_address: SocketAddrV4,
    ) -> Self {
        let mut socket = Self::new(resource, create_request);
        socket.connection_status = SocketConnectionStatus::Connected;
        socket.local_address = Some(local_address);
        socket
    }

    pub(crate) fn resource(&self) -> Arc<SocketResource> {
        Arc::clone(&self.resource)
    }
}

pub(crate) struct SocketResource {
    platform_socket: Arc<dyn PlatformSocket>,
    readiness: ReadinessRegistration,
    port_binding: Mutex<Option<Arc<GuestPortBinding>>>,
    guest_source_lease: Mutex<Option<GuestSourceLease>>,
}

impl SocketResource {
    fn set_port_binding(
        &self,
        binding: Arc<GuestPortBinding>,
    ) -> core::result::Result<(), Arc<GuestPortBinding>> {
        let mut slot = self.port_binding.lock();
        if slot.is_some() {
            return Err(binding);
        }
        *slot = Some(binding);
        Ok(())
    }

    fn port_binding_covers(&self, address: SocketAddrV4) -> bool {
        self.port_binding
            .lock()
            .as_ref()
            .is_some_and(|binding| GuestSocketBinding::new(binding).covers(address))
    }

    fn port_binding_is_wildcard(&self) -> bool {
        self.port_binding
            .lock()
            .as_ref()
            .is_some_and(|binding| GuestSocketBinding::new(binding).is_wildcard())
    }

    fn source_lease_for_connect(
        &self,
        destination: SocketAddrV4,
    ) -> Result<Option<GuestSourceLease>> {
        if !is_internal_socket_destination(destination) {
            return Ok(None);
        }
        self.port_binding
            .lock()
            .as_ref()
            .and_then(|binding| binding.source_lease_for(destination))
            .map(Some)
            .ok_or(BrokerError::Internal)
    }

    fn source_address_for_destination(&self, destination: SocketAddrV4) -> Option<SocketAddrV4> {
        self.port_binding.lock().as_ref().and_then(|binding| {
            GuestSocketBinding::new(binding).source_address_for_destination(destination)
        })
    }

    fn retire(&self) {
        self.platform_socket.retire();
        let port_binding = self.port_binding.lock().take();
        let guest_source_lease = self.guest_source_lease.lock().take();
        drop(port_binding);
        drop(guest_source_lease);
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.platform_socket.readiness()
    }
}

const fn is_tcp(request: CreateSocketRequest) -> bool {
    matches!(
        (request.socket_type, request.protocol),
        (SocketType::Stream, IpProtocol::Tcp)
    )
}

const fn is_udp(request: CreateSocketRequest) -> bool {
    matches!(
        (request.socket_type, request.protocol),
        (SocketType::Datagram, IpProtocol::Udp)
    )
}

const fn guest_transport(request: CreateSocketRequest) -> Option<GuestTransport> {
    if is_tcp(request) {
        Some(GuestTransport::Tcp)
    } else if is_udp(request) {
        Some(GuestTransport::Udp)
    } else {
        None
    }
}

impl Drop for SocketResource {
    fn drop(&mut self) {
        self.retire();
        self.readiness.retire();
    }
}

struct SocketQuotaReservation {
    global: Arc<AtomicUsize>,
    session: Arc<AtomicUsize>,
}

impl SocketQuotaReservation {
    fn new(session: &BrokerSession) -> Result<Self> {
        reserve_socket(
            &session.core.reserved_sockets,
            session.core.limits.max_sockets,
        )?;
        if reserve_socket(
            &session.reserved_sockets,
            session.core.limits.max_sockets_per_session,
        )
        .is_err()
        {
            session
                .core
                .reserved_sockets
                .fetch_sub(1, Ordering::Relaxed);
            return Err(BrokerError::ResourceExhausted);
        }
        Ok(Self {
            global: Arc::clone(&session.core.reserved_sockets),
            session: Arc::clone(&session.reserved_sockets),
        })
    }
}

impl Drop for SocketQuotaReservation {
    fn drop(&mut self) {
        self.session.fetch_sub(1, Ordering::Relaxed);
        self.global.fetch_sub(1, Ordering::Relaxed);
    }
}

fn reserve_socket(counter: &AtomicUsize, limit: usize) -> Result<()> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
            reserved.checked_add(1).filter(|next| *next <= limit)
        })
        .map(|_| ())
        .map_err(|_| BrokerError::ResourceExhausted)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::readiness::tests::TestReadinessSink;
    use crate::{BrokerCore, CallerCredential};
    use litebox_broker_protocol::socket::{AddressFamily, IpProtocol, SocketType};
    use std::net::Ipv4Addr;
    use std::sync::{Mutex as StdMutex, mpsc};
    use std::time::Duration;
    use std::vec;

    fn destination_rule(address: Ipv4Addr, port: u16) -> crate::DestinationRule {
        crate::DestinationRule::new(
            CallerCredential::Unauthenticated,
            crate::Ipv4Cidr::new(
                litebox_broker_protocol::socket::Ipv4Address(address.octets()),
                32,
            )
            .unwrap(),
            crate::DestinationPortRange::new(
                litebox_broker_protocol::socket::Port(port),
                litebox_broker_protocol::socket::Port(port),
            )
            .unwrap(),
        )
    }

    #[test]
    fn socket_destinations_are_normalized_validated_and_routed() {
        let port = 8080;
        let unspecified = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        assert!(is_internal_socket_destination(unspecified));
        let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        assert_eq!(normalize_socket_destination(unspecified), Ok(loopback));
        assert!(is_internal_socket_destination(loopback));
        let loopback_alias = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), port);
        assert_eq!(
            normalize_socket_destination(loopback_alias),
            Ok(loopback_alias)
        );
        assert!(is_internal_socket_destination(loopback_alias));
        let guest = SocketAddrV4::new(GUEST_IPV4_ADDRESS, port);
        assert_eq!(normalize_socket_destination(guest), Ok(guest));
        assert!(is_internal_socket_destination(guest));
        let gateway = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, port);
        assert_eq!(normalize_socket_destination(gateway), Ok(gateway));
        assert!(!is_internal_socket_destination(gateway));
        assert_eq!(
            host_socket_destination(gateway),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
        );
        let native = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port);
        assert_eq!(normalize_socket_destination(native), Ok(native));
        assert!(!is_internal_socket_destination(native));
        assert_eq!(host_socket_destination(native), native);
        for invalid in [
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert_eq!(
                normalize_socket_destination(SocketAddrV4::new(invalid, port)),
                Err(SocketError::InvalidArgument)
            );
        }
    }

    #[test]
    fn gateway_destinations_require_external_policy() {
        let provider = Arc::new(TestSocketProvider::default());
        let broker = test_broker(Arc::clone(&provider) as Arc<dyn SocketProvider>);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let tcp = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let udp = create(
            &session,
            create_udp_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let gateway = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 8080);

        assert_eq!(
            connect(&session, tcp, gateway),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(
            send_to(&session, udp, b"x".to_vec(), SendFlags::NONE, Some(gateway),),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert!(provider.state.binds.lock().unwrap().is_empty());
        assert_eq!(provider.state.connect_calls.load(Ordering::Relaxed), 0);
        assert!(provider.state.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn gateway_destinations_reach_the_platform_untranslated() {
        let provider = Arc::new(TestSocketProvider::default());
        let tcp_rule = destination_rule(HOST_GATEWAY_IPV4_ADDRESS, 8080);
        let udp_rule = destination_rule(HOST_GATEWAY_IPV4_ADDRESS, 8080);
        let policy = crate::SocketPolicy::guest_network()
            .with_tcp_destination_rules(&[tcp_rule])
            .unwrap()
            .with_udp_destination_rules(&[udp_rule])
            .unwrap();
        let broker =
            test_broker_with_policy(Arc::clone(&provider) as Arc<dyn SocketProvider>, &policy);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let tcp = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let udp = create(
            &session,
            create_udp_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let gateway = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 8080);

        assert_eq!(
            connect(&session, tcp, gateway),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        assert_eq!(
            send_to(&session, udp, b"x".to_vec(), SendFlags::NONE, Some(gateway),),
            Ok(SocketOutcome::Completed(1))
        );
        assert_eq!(
            connect(&session, udp, gateway),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert_eq!(
            provider
                .state
                .connect_destinations
                .lock()
                .unwrap()
                .as_slice(),
            [gateway, gateway]
        );
        assert_eq!(
            provider.state.send_destinations.lock().unwrap().as_slice(),
            [Some(gateway)]
        );
        assert_eq!(
            host_socket_destination(gateway),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, gateway.port())
        );
    }

    #[test]
    fn guest_transport_port_namespaces_are_broker_wide_and_independent() {
        let ports = BrokerSocketPorts::default();
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80);

        let SocketOutcome::Completed((_, first_binding)) =
            ports.reserve(create_request(), address).unwrap()
        else {
            panic!("first TCP port binding failed");
        };
        assert!(matches!(
            ports.reserve(create_request(), address),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        let SocketOutcome::Completed((_, udp_binding)) =
            ports.reserve(create_udp_request(), address).unwrap()
        else {
            panic!("UDP port binding must be independent from TCP");
        };
        assert!(matches!(
            ports.reserve(create_udp_request(), address),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));

        drop(first_binding);
        assert!(matches!(
            ports.reserve(create_request(), address),
            Ok(SocketOutcome::Completed(_))
        ));
        assert!(matches!(
            ports.reserve(create_udp_request(), address),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        drop(udp_binding);
        assert!(matches!(
            ports.reserve(create_udp_request(), address),
            Ok(SocketOutcome::Completed(_))
        ));
    }

    #[test]
    fn guest_binding_namespaces_support_exact_and_wildcard_guest_addresses() {
        let ports = BrokerSocketPorts::default();
        let first = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
        let second = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 8080);
        let private = SocketAddrV4::new(GUEST_IPV4_ADDRESS, 8080);
        let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8080);

        let SocketOutcome::Completed((_, first_binding)) =
            ports.reserve(create_request(), first).unwrap()
        else {
            panic!("first exact port binding failed");
        };
        let SocketOutcome::Completed((_, second_binding)) =
            ports.reserve(create_request(), second).unwrap()
        else {
            panic!("second exact port binding failed");
        };
        let SocketOutcome::Completed((_, private_binding)) =
            ports.reserve(create_request(), private).unwrap()
        else {
            panic!("private exact port binding failed");
        };
        assert!(matches!(
            ports.reserve(create_request(), wildcard),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));

        drop(first_binding);
        drop(second_binding);
        drop(private_binding);
        let SocketOutcome::Completed((_, wildcard_binding)) =
            ports.reserve(create_request(), wildcard).unwrap()
        else {
            panic!("wildcard port binding failed");
        };
        assert!(matches!(
            ports.reserve(create_request(), first),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        assert!(matches!(
            ports.reserve(create_request(), private),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        let binding = GuestSocketBinding::new(&wildcard_binding);
        assert!(binding.covers(first));
        assert!(binding.covers(second));
        assert!(binding.covers(private));
        assert_eq!(
            binding.source_address_for_destination(first),
            Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080))
        );
        assert_eq!(
            binding.source_address_for_destination(second),
            Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080))
        );
        assert_eq!(
            binding.source_address_for_destination(private),
            Some(private)
        );
        let external = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 8080);
        assert_eq!(
            binding.source_address_for_destination(external),
            Some(SocketAddrV4::new(GUEST_IPV4_ADDRESS, 8080))
        );
        assert_eq!(
            GuestSocketBinding {
                requested: private,
                transport: GuestTransport::Tcp,
            }
            .source_address_for_destination(external),
            Some(private)
        );
    }

    #[test]
    fn exact_loopback_binding_cannot_use_an_external_route() {
        let ports = BrokerSocketPorts::default();
        let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
        let SocketOutcome::Completed((_, port_binding)) =
            ports.reserve(create_request(), loopback).unwrap()
        else {
            panic!("loopback port binding failed");
        };
        let binding = GuestSocketBinding::new(&port_binding);
        for destination in [
            SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 80),
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80),
        ] {
            assert_eq!(binding.source_address_for_destination(destination), None);
        }
    }

    #[test]
    fn rejected_external_route_preserves_an_exact_loopback_socket() {
        let provider = Arc::new(TestSocketProvider::default());
        let gateway_rule = destination_rule(HOST_GATEWAY_IPV4_ADDRESS, 8080);
        let external_rule = destination_rule(Ipv4Addr::new(192, 0, 2, 1), 8080);
        let policy = crate::SocketPolicy::guest_network()
            .with_tcp_destination_rules(&[gateway_rule, external_rule])
            .unwrap();
        let broker =
            test_broker_with_policy(Arc::clone(&provider) as Arc<dyn SocketProvider>, &policy);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let socket = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let local = loopback_address();
        assert_eq!(
            bind(&session, socket, local),
            Ok(SocketOutcome::Completed(local))
        );
        for destination in [
            SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 8080),
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 8080),
        ] {
            assert_eq!(
                connect(&session, socket, destination),
                Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
            );
        }
        assert_eq!(provider.state.connect_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            status(&session, socket),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(local),
                pending_error: None,
            })
        );
        assert_eq!(
            connect(&session, socket, local),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        assert_eq!(provider.state.retired_sockets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejected_udp_external_routes_preserve_an_exact_loopback_socket() {
        let provider = Arc::new(TestSocketProvider::default());
        let gateway_rule = destination_rule(HOST_GATEWAY_IPV4_ADDRESS, 8080);
        let external_rule = destination_rule(Ipv4Addr::new(192, 0, 2, 1), 8080);
        let policy = crate::SocketPolicy::guest_network()
            .with_udp_destination_rules(&[gateway_rule, external_rule])
            .unwrap();
        let broker =
            test_broker_with_policy(Arc::clone(&provider) as Arc<dyn SocketProvider>, &policy);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let socket = create(
            &session,
            create_udp_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let local = loopback_address();
        assert_eq!(
            bind(&session, socket, local),
            Ok(SocketOutcome::Completed(local))
        );

        for destination in [
            SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 8080),
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 8080),
        ] {
            assert_eq!(
                send_to(
                    &session,
                    socket,
                    b"x".to_vec(),
                    SendFlags::NONE,
                    Some(destination),
                ),
                Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
            );
            assert_eq!(
                connect(&session, socket, destination),
                Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
            );
        }
        assert!(provider.state.sent.lock().unwrap().is_empty());
        assert_eq!(provider.state.connect_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            status(&session, socket),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(local),
                pending_error: None,
            })
        );
        assert_eq!(
            send_to(
                &session,
                socket,
                b"x".to_vec(),
                SendFlags::NONE,
                Some(local),
            ),
            Ok(SocketOutcome::Completed(1))
        );
    }

    #[test]
    fn guest_binding_validation_and_ephemeral_allocation_are_address_aware() {
        let ports = BrokerSocketPorts::default();
        for invalid_ip in [Ipv4Addr::new(192, 0, 2, 1), HOST_GATEWAY_IPV4_ADDRESS] {
            assert!(matches!(
                ports.reserve(create_request(), SocketAddrV4::new(invalid_ip, 8080)),
                Ok(SocketOutcome::Failed(SocketError::AddressNotAvailable))
            ));
        }

        let occupied = SocketAddrV4::new(Ipv4Addr::LOCALHOST, FIRST_EPHEMERAL_PORT);
        let SocketOutcome::Completed((_, occupied_binding)) =
            ports.reserve(create_request(), occupied).unwrap()
        else {
            panic!("exact port binding failed");
        };
        let SocketOutcome::Completed((wildcard, wildcard_binding)) = ports
            .reserve(
                create_request(),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            )
            .unwrap()
        else {
            panic!("wildcard ephemeral port binding failed");
        };
        assert_eq!(wildcard.port(), FIRST_EPHEMERAL_PORT + 1);
        drop(occupied_binding);
        drop(wildcard_binding);
    }

    #[test]
    fn provider_binding_metadata_does_not_own_the_port_binding() {
        let ports = BrokerSocketPorts::default();
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
        let SocketOutcome::Completed((_, port_binding)) =
            ports.reserve(create_request(), address).unwrap()
        else {
            panic!("port binding failed");
        };
        let binding = GuestSocketBinding::new(&port_binding);
        drop(port_binding);
        assert!(binding.is_valid());
        assert!(binding.covers(address));
        assert!(matches!(
            ports.reserve(create_request(), address),
            Ok(SocketOutcome::Completed(_))
        ));
    }

    #[test]
    fn guest_source_lease_retains_the_original_binding_key() {
        let ports = BrokerSocketPorts::default();
        let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8081);
        let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, wildcard.port());
        let private = SocketAddrV4::new(GUEST_IPV4_ADDRESS, wildcard.port());
        let SocketOutcome::Completed((_, port_binding)) =
            ports.reserve(create_request(), wildcard).unwrap()
        else {
            panic!("wildcard port binding failed");
        };
        let lease = port_binding.source_lease_for(loopback).unwrap();
        assert_eq!(lease.source_address(), loopback);
        drop(port_binding);
        assert!(matches!(
            ports.reserve(create_request(), private),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        drop(lease);
        assert!(matches!(
            ports.reserve(create_request(), wildcard),
            Ok(SocketOutcome::Completed(_))
        ));

        let exact = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8082);
        let other_exact = SocketAddrV4::new(GUEST_IPV4_ADDRESS, exact.port());
        let SocketOutcome::Completed((_, port_binding)) =
            ports.reserve(create_request(), exact).unwrap()
        else {
            panic!("exact port binding failed");
        };
        let lease = port_binding.source_lease_for(loopback_address()).unwrap();
        assert_eq!(lease.source_address(), exact);
        drop(port_binding);
        assert!(matches!(
            ports.reserve(create_request(), exact),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        assert!(matches!(
            ports.reserve(create_request(), other_exact),
            Ok(SocketOutcome::Completed(_))
        ));
        drop(lease);
        assert!(matches!(
            ports.reserve(create_request(), exact),
            Ok(SocketOutcome::Completed(_))
        ));
    }

    #[test]
    fn guest_source_leases_release_after_the_last_owner() {
        let ports = BrokerSocketPorts::default();
        let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8083);
        let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, wildcard.port());
        let private = SocketAddrV4::new(GUEST_IPV4_ADDRESS, wildcard.port());
        let SocketOutcome::Completed((_, port_binding)) =
            ports.reserve(create_request(), wildcard).unwrap()
        else {
            panic!("wildcard port binding failed");
        };
        let loopback_lease = port_binding.source_lease_for(loopback).unwrap();
        let private_lease = port_binding.source_lease_for(private).unwrap();
        assert_eq!(loopback_lease.source_address(), loopback);
        assert_eq!(private_lease.source_address(), private);

        drop(port_binding);
        drop(loopback_lease);
        assert!(matches!(
            ports.reserve(create_request(), private),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        drop(private_lease);
        assert!(matches!(
            ports.reserve(create_request(), wildcard),
            Ok(SocketOutcome::Completed(_))
        ));
    }

    #[derive(Clone, Default)]
    pub(crate) struct TestSocketProvider {
        state: Arc<TestSocketState>,
    }

    #[derive(Default)]
    struct TestSocketState {
        creates: StdMutex<std::vec::Vec<(SessionId, CreateSocketRequest)>>,
        closed_sessions: StdMutex<std::vec::Vec<SessionId>>,
        sent: StdMutex<std::vec::Vec<u8>>,
        next_send_count: StdMutex<Option<usize>>,
        connect_calls: AtomicUsize,
        connect_destinations: StdMutex<std::vec::Vec<SocketAddrV4>>,
        connect_source_addresses: StdMutex<std::vec::Vec<Option<SocketAddrV4>>>,
        send_destinations: StdMutex<std::vec::Vec<Option<SocketAddrV4>>>,
        send_calls: AtomicUsize,
        receive_calls: AtomicUsize,
        receive_from_calls: AtomicUsize,
        next_stream_receive: StdMutex<Option<PlatformStreamReceive>>,
        next_datagram_receive: StdMutex<Option<PlatformDatagramReceive>>,
        status_calls: AtomicUsize,
        fail_status: core::sync::atomic::AtomicBool,
        status_responses: StdMutex<std::collections::VecDeque<PlatformSocketStatus>>,
        status_block: StdMutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
        binds: StdMutex<std::vec::Vec<SocketAddrV4>>,
        listens: StdMutex<std::vec::Vec<u32>>,
        listen_block: StdMutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
        accept_failure: StdMutex<Option<TestAcceptFailure>>,
        failed_accept_readiness: StdMutex<Option<ReadinessRegistration>>,
        shutdown_calls: AtomicUsize,
        retired_sockets: AtomicUsize,
        dropped_sockets: AtomicUsize,
        retire_block: StdMutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
        retained_platform_sockets: StdMutex<std::vec::Vec<Arc<TestPlatformSocket>>>,
        retain_next_socket: core::sync::atomic::AtomicBool,
        fail_create: core::sync::atomic::AtomicBool,
        fail_connect: core::sync::atomic::AtomicBool,
        fail_connect_indeterminate: core::sync::atomic::AtomicBool,
        return_unconnected_connect: core::sync::atomic::AtomicBool,
        invalid_bind_address: StdMutex<Option<TestInvalidAddress>>,
        invalid_accept_address: StdMutex<Option<TestInvalidAddress>>,
        fail_shutdown: core::sync::atomic::AtomicBool,
        tcp_option_sets: StdMutex<std::vec::Vec<TcpOptionValue>>,
        failed_readiness: StdMutex<Option<ReadinessRegistration>>,
        live_readiness: StdMutex<Option<ReadinessRegistration>>,
        queue_next_guest_connect: core::sync::atomic::AtomicBool,
        pending_accept: StdMutex<Option<PendingAcceptedConnection>>,
    }

    struct PendingAcceptedConnection {
        destination: SocketAddrV4,
        guest_source_lease: GuestSourceLease,
    }

    #[derive(Clone, Copy)]
    enum TestAcceptFailure {
        Socket,
        Broker,
    }

    #[derive(Clone, Copy)]
    enum TestInvalidAddress {
        WrongPort,
        Gateway,
        LoopbackAlias,
    }

    #[derive(Clone, Copy)]
    enum TestAutomaticBindOperation {
        TcpConnect,
        TcpListen,
        UdpSend,
        UdpConnect,
    }

    fn invalid_address(address: SocketAddrV4, kind: TestInvalidAddress) -> SocketAddrV4 {
        match kind {
            TestInvalidAddress::WrongPort => SocketAddrV4::new(
                *address.ip(),
                if address.port() == u16::MAX {
                    address.port() - 1
                } else {
                    address.port() + 1
                },
            ),
            TestInvalidAddress::Gateway => {
                SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, address.port())
            }
            TestInvalidAddress::LoopbackAlias => {
                let ip = if *address.ip() == Ipv4Addr::LOCALHOST {
                    Ipv4Addr::new(127, 0, 0, 2)
                } else {
                    Ipv4Addr::LOCALHOST
                };
                SocketAddrV4::new(ip, address.port())
            }
        }
    }

    impl TestSocketProvider {
        pub(crate) fn fail_next_create(&self) {
            self.state.fail_create.store(true, Ordering::Relaxed);
        }

        fn fail_next_connect(&self) {
            self.state.fail_connect.store(true, Ordering::Relaxed);
        }

        fn fail_next_connect_indeterminate(&self) {
            self.state
                .fail_connect_indeterminate
                .store(true, Ordering::Relaxed);
        }

        fn return_unconnected_connect_once(&self) {
            self.state
                .return_unconnected_connect
                .store(true, Ordering::Relaxed);
        }

        fn return_invalid_bind_address_once(&self, invalid_address: TestInvalidAddress) {
            *self.state.invalid_bind_address.lock().unwrap() = Some(invalid_address);
        }

        fn return_invalid_accept_address_once(&self, invalid_address: TestInvalidAddress) {
            *self.state.invalid_accept_address.lock().unwrap() = Some(invalid_address);
        }

        fn fail_next_shutdown(&self) {
            self.state.fail_shutdown.store(true, Ordering::Relaxed);
        }

        fn retain_next_socket(&self) {
            self.state.retain_next_socket.store(true, Ordering::Relaxed);
        }

        fn queue_next_guest_connect(&self) {
            self.state
                .queue_next_guest_connect
                .store(true, Ordering::Relaxed);
        }

        fn fail_next_accept(&self, failure: TestAcceptFailure) {
            *self.state.accept_failure.lock().unwrap() = Some(failure);
        }

        fn return_next_send_count(&self, count: usize) {
            *self.state.next_send_count.lock().unwrap() = Some(count);
        }

        fn return_next_stream_receive(&self, received: PlatformStreamReceive) {
            *self.state.next_stream_receive.lock().unwrap() = Some(received);
        }

        fn return_next_datagram_receive(&self, received: PlatformDatagramReceive) {
            *self.state.next_datagram_receive.lock().unwrap() = Some(received);
        }

        fn fail_next_status(&self) {
            self.state.fail_status.store(true, Ordering::Relaxed);
        }
    }

    impl SocketProvider for TestSocketProvider {
        fn create(
            &self,
            session_id: SessionId,
            request: CreateSocketRequest,
            readiness: ReadinessRegistration,
        ) -> Result<Arc<dyn PlatformSocket>> {
            self.state
                .creates
                .lock()
                .unwrap()
                .push((session_id, request));
            if self.state.fail_create.swap(false, Ordering::Relaxed) {
                *self.state.failed_readiness.lock().unwrap() = Some(readiness);
                return Err(BrokerError::OutOfMemory);
            }
            *self.state.live_readiness.lock().unwrap() = Some(readiness.clone());
            let socket = Arc::new(TestPlatformSocket {
                state: Arc::clone(&self.state),
                readiness,
                create_request: request,
                tcp_options: StdMutex::new(TestTcpOptions::default()),
                guest_local_address: StdMutex::new(None),
                guest_binding: StdMutex::new(None),
                active: core::sync::atomic::AtomicBool::new(true),
            });
            if self.state.retain_next_socket.swap(false, Ordering::Relaxed) {
                self.state
                    .retained_platform_sockets
                    .lock()
                    .unwrap()
                    .push(Arc::clone(&socket));
            }
            Ok(socket)
        }

        fn close_session(&self, session_id: SessionId) {
            self.state.closed_sessions.lock().unwrap().push(session_id);
        }
    }

    struct TestPlatformSocket {
        state: Arc<TestSocketState>,
        readiness: ReadinessRegistration,
        create_request: CreateSocketRequest,
        tcp_options: StdMutex<TestTcpOptions>,
        guest_local_address: StdMutex<Option<SocketAddrV4>>,
        guest_binding: StdMutex<Option<GuestSocketBinding>>,
        active: core::sync::atomic::AtomicBool,
    }

    #[derive(Default)]
    struct TestTcpOptions {
        no_delay: bool,
        keep_alive: bool,
    }

    impl TestPlatformSocket {
        fn discard_pending_accept(&self) {
            if let Some(binding) = self.guest_binding.lock().unwrap().clone() {
                let mut pending = self.state.pending_accept.lock().unwrap();
                if pending
                    .as_ref()
                    .is_some_and(|pending| binding.covers(pending.destination))
                {
                    pending.take();
                }
            }
        }
    }

    impl PlatformSocket for TestPlatformSocket {
        fn bind(&self, binding: GuestSocketBinding) -> Result<SocketOutcome<SocketAddrV4>> {
            let address = binding.requested();
            *self.guest_binding.lock().unwrap() = Some(binding);
            self.state.binds.lock().unwrap().push(address);
            let bound_address = self
                .state
                .invalid_bind_address
                .lock()
                .unwrap()
                .take()
                .map_or(address, |kind| invalid_address(address, kind));
            if is_tcp(self.create_request) {
                *self.guest_local_address.lock().unwrap() = Some(bound_address);
                return Ok(SocketOutcome::Completed(bound_address));
            }
            Ok(SocketOutcome::Completed(bound_address))
        }

        fn listen(&self, backlog: u32) -> Result<SocketOutcome<SocketAddrV4>> {
            self.state.listens.lock().unwrap().push(backlog);
            let listen_block = self.state.listen_block.lock().unwrap().take();
            if let Some((started, release)) = listen_block {
                started.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            self.guest_local_address
                .lock()
                .unwrap()
                .ok_or(BrokerError::Internal)
                .map(SocketOutcome::Completed)
        }

        fn accept(
            &self,
            readiness: ReadinessRegistration,
        ) -> Result<SocketOutcome<AcceptedPlatformSocket>> {
            if let Some(failure) = self.state.accept_failure.lock().unwrap().take() {
                *self.state.failed_accept_readiness.lock().unwrap() = Some(readiness);
                return match failure {
                    TestAcceptFailure::Socket => {
                        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
                    }
                    TestAcceptFailure::Broker => Err(BrokerError::OutOfMemory),
                };
            }
            let binding = self
                .guest_binding
                .lock()
                .unwrap()
                .clone()
                .ok_or(BrokerError::Internal)?;
            let pending = {
                let mut pending = self.state.pending_accept.lock().unwrap();
                if !pending
                    .as_ref()
                    .is_some_and(|pending| binding.covers(pending.destination))
                {
                    return Err(BrokerError::WouldBlock);
                }
                pending.take().ok_or(BrokerError::Internal)?
            };
            let local_address = self
                .state
                .invalid_accept_address
                .lock()
                .unwrap()
                .take()
                .map_or(pending.destination, |kind| {
                    invalid_address(pending.destination, kind)
                });
            let socket = Arc::new(TestPlatformSocket {
                state: Arc::clone(&self.state),
                readiness,
                create_request: self.create_request,
                tcp_options: StdMutex::new(TestTcpOptions::default()),
                guest_local_address: StdMutex::new(Some(local_address)),
                guest_binding: StdMutex::new(None),
                active: core::sync::atomic::AtomicBool::new(true),
            });
            if self.state.retain_next_socket.swap(false, Ordering::Relaxed) {
                self.state
                    .retained_platform_sockets
                    .lock()
                    .unwrap()
                    .push(Arc::clone(&socket));
            }
            Ok(SocketOutcome::Completed(AcceptedPlatformSocket {
                socket,
                local_address,
                guest_source_lease: pending.guest_source_lease,
            }))
        }

        fn connect(
            &self,
            address: SocketAddrV4,
            guest_source_lease: Option<GuestSourceLease>,
        ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
            self.state.connect_calls.fetch_add(1, Ordering::Relaxed);
            self.state
                .connect_destinations
                .lock()
                .unwrap()
                .push(address);
            self.state.connect_source_addresses.lock().unwrap().push(
                guest_source_lease
                    .as_ref()
                    .map(GuestSourceLease::source_address),
            );
            if self.state.fail_connect.swap(false, Ordering::Relaxed) {
                return Err(PlatformConnectError::PeerUnchanged(BrokerError::Internal));
            }
            if self
                .state
                .fail_connect_indeterminate
                .swap(false, Ordering::Relaxed)
            {
                return Err(PlatformConnectError::PeerIndeterminate(
                    BrokerError::Internal,
                ));
            }
            if self
                .state
                .return_unconnected_connect
                .swap(false, Ordering::Relaxed)
            {
                return Ok(SocketConnectionStatus::Unconnected);
            }
            self.readiness
                .publish(ReadinessFlags::WRITE)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            if is_udp(self.create_request) {
                Ok(SocketConnectionStatus::Connected)
            } else {
                if self
                    .state
                    .queue_next_guest_connect
                    .swap(false, Ordering::Relaxed)
                {
                    let Some(guest_source_lease) = guest_source_lease else {
                        return Err(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ));
                    };
                    let mut pending = self.state.pending_accept.lock().unwrap();
                    if pending.is_some() {
                        return Err(PlatformConnectError::PeerIndeterminate(
                            BrokerError::Internal,
                        ));
                    }
                    *pending = Some(PendingAcceptedConnection {
                        destination: address,
                        guest_source_lease,
                    });
                }
                Ok(SocketConnectionStatus::Connecting)
            }
        }

        fn send(&self, data: Vec<u8>, _flags: SendFlags) -> Result<SocketOutcome<usize>> {
            self.state.send_calls.fetch_add(1, Ordering::Relaxed);
            self.state.sent.lock().unwrap().extend_from_slice(&data);
            let sent = self
                .state
                .next_send_count
                .lock()
                .unwrap()
                .take()
                .unwrap_or(data.len());
            Ok(SocketOutcome::Completed(sent))
        }

        fn send_to(
            &self,
            data: Vec<u8>,
            _flags: SendFlags,
            destination: Option<SocketAddrV4>,
        ) -> Result<SocketOutcome<usize>> {
            self.state.send_calls.fetch_add(1, Ordering::Relaxed);
            self.state
                .send_destinations
                .lock()
                .unwrap()
                .push(destination);
            self.state.sent.lock().unwrap().extend_from_slice(&data);
            let sent = self
                .state
                .next_send_count
                .lock()
                .unwrap()
                .take()
                .unwrap_or(data.len());
            Ok(SocketOutcome::Completed(sent))
        }

        fn receive(
            &self,
            length: usize,
            _flags: ReceiveFlags,
            _peek_offset: u32,
            _peek_length: u32,
        ) -> Result<SocketOutcome<PlatformStreamReceive>> {
            self.state.receive_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(received) = self.state.next_stream_receive.lock().unwrap().take() {
                return Ok(SocketOutcome::Completed(received));
            }
            let received = length.min(2);
            Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                [7, 9][..received].to_vec(),
            )))
        }

        fn receive_from(
            &self,
            length: usize,
            _flags: ReceiveFromFlags,
        ) -> Result<SocketOutcome<PlatformDatagramReceive>> {
            self.state
                .receive_from_calls
                .fetch_add(1, Ordering::Relaxed);
            if let Some(received) = self.state.next_datagram_receive.lock().unwrap().take() {
                return Ok(SocketOutcome::Completed(received));
            }
            let received = length.min(2);
            Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                data: [7, 9][..received].to_vec(),
                datagram_length: 4,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            }))
        }

        fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>> {
            self.state.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            if self.state.fail_shutdown.swap(false, Ordering::Relaxed) {
                return Err(BrokerError::ResourceExhausted);
            }
            if mode == ShutdownMode::StopListening {
                self.discard_pending_accept();
            }
            Ok(SocketOutcome::Completed(()))
        }

        fn set_tcp_option(&self, value: TcpOptionValue) -> Result<()> {
            self.state.tcp_option_sets.lock().unwrap().push(value);
            let mut options = self.tcp_options.lock().unwrap();
            match value {
                TcpOptionValue::NoDelay(value) => options.no_delay = value,
                TcpOptionValue::KeepAlive(value) => options.keep_alive = value,
                _ => return Err(BrokerError::UnsupportedOperation),
            }
            Ok(())
        }

        fn get_tcp_option(&self, name: TcpOptionName) -> Result<TcpOptionValue> {
            let options = self.tcp_options.lock().unwrap();
            match name {
                TcpOptionName::NoDelay => Ok(TcpOptionValue::NoDelay(options.no_delay)),
                TcpOptionName::KeepAlive => Ok(TcpOptionValue::KeepAlive(options.keep_alive)),
                _ => Err(BrokerError::UnsupportedOperation),
            }
        }

        fn status(&self) -> Result<PlatformSocketStatus> {
            self.state.status_calls.fetch_add(1, Ordering::Relaxed);
            let fail = self.state.fail_status.swap(false, Ordering::Relaxed);
            let status = self
                .state
                .status_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(PlatformSocketStatus {
                    status: SocketConnectionStatus::Connected,
                    local_address: None,
                    pending_error: None,
                });
            let status_block = self.state.status_block.lock().unwrap().take();
            if let Some((started, release)) = status_block {
                started.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            if fail {
                return Err(BrokerError::Internal);
            }
            Ok(status)
        }

        fn retire(&self) {
            if self.active.swap(false, Ordering::AcqRel) {
                self.discard_pending_accept();
                let retire_block = self.state.retire_block.lock().unwrap().take();
                if let Some((started, release)) = retire_block {
                    started.send(()).unwrap();
                    release.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                self.state.retired_sockets.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn readiness(&self) -> ReadinessFlags {
            ReadinessFlags::READ | ReadinessFlags::WRITE
        }
    }

    impl Drop for TestPlatformSocket {
        fn drop(&mut self) {
            self.retire();
            self.state.dropped_sockets.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn zero_port_connect_fails_before_platform_dispatch() {
        let provider = Arc::new(TestSocketProvider::default());
        let broker = test_broker(Arc::clone(&provider) as Arc<dyn SocketProvider>);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let socket = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();

        assert_eq!(
            connect(&session, socket, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),),
            Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
        );
        assert_eq!(
            provider
                .state
                .connect_source_addresses
                .lock()
                .unwrap()
                .as_slice(),
            &[]
        );
        assert_eq!(provider.state.retired_sockets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn accepted_guest_source_lease_is_retained() {
        let provider = Arc::new(TestSocketProvider::default());
        let broker = test_broker(Arc::clone(&provider) as Arc<dyn SocketProvider>);
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let listener = create(
            &listener_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let listener_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44000);
        assert_eq!(
            bind(&listener_session, listener, listener_address),
            Ok(SocketOutcome::Completed(listener_address))
        );
        assert_eq!(
            listen(&listener_session, listener, 1),
            Ok(SocketOutcome::Completed(listener_address))
        );

        let wildcard_source = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 44002);
        let concrete_source = SocketAddrV4::new(Ipv4Addr::LOCALHOST, wildcard_source.port());
        let connector = create(
            &connector_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&connector_session, connector, wildcard_source),
            Ok(SocketOutcome::Completed(wildcard_source))
        );
        provider.queue_next_guest_connect();
        assert_eq!(
            connect(&connector_session, connector, listener_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        connector_session.close_object_reference(connector).unwrap();
        assert!(matches!(
            broker.socket_ports.reserve(
                create_request(),
                SocketAddrV4::new(GUEST_IPV4_ADDRESS, wildcard_source.port())
            ),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));

        let SocketOutcome::Completed(accepted) = accept(
            &listener_session,
            listener,
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap() else {
            panic!("guest-local accept failed");
        };
        assert_eq!(accepted.local_address, listener_address);
        assert_eq!(accepted.remote_address, concrete_source);
        listener_session.close_object_reference(listener).unwrap();
        assert!(matches!(
            broker
                .socket_ports
                .reserve(create_request(), listener_address),
            Ok(SocketOutcome::Completed(_))
        ));
        assert!(matches!(
            broker.socket_ports.reserve(
                create_request(),
                SocketAddrV4::new(GUEST_IPV4_ADDRESS, wildcard_source.port())
            ),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        listener_session
            .close_object_reference(accepted.handle)
            .unwrap();
        assert!(matches!(
            broker
                .socket_ports
                .reserve(create_request(), wildcard_source),
            Ok(SocketOutcome::Completed(_))
        ));
    }

    #[test]
    fn queued_guest_source_lease_is_released_when_listener_retires() {
        check_queued_guest_source_lease_release(false);
    }

    #[test]
    fn queued_guest_source_lease_is_released_when_listener_stops() {
        check_queued_guest_source_lease_release(true);
    }

    fn check_queued_guest_source_lease_release(stop_listener: bool) {
        let provider = Arc::new(TestSocketProvider::default());
        let broker = test_broker(Arc::clone(&provider) as Arc<dyn SocketProvider>);
        let listener_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let connector_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let listener_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44010);
        let listener = create(
            &listener_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&listener_session, listener, listener_address),
            Ok(SocketOutcome::Completed(listener_address))
        );
        assert_eq!(
            listen(&listener_session, listener, 1),
            Ok(SocketOutcome::Completed(listener_address))
        );

        let wildcard_source = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 44012);
        let connector = create(
            &connector_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&connector_session, connector, wildcard_source),
            Ok(SocketOutcome::Completed(wildcard_source))
        );
        provider.queue_next_guest_connect();
        assert_eq!(
            connect(&connector_session, connector, listener_address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        connector_session.close_object_reference(connector).unwrap();
        assert!(matches!(
            broker
                .socket_ports
                .reserve(create_request(), wildcard_source),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));

        if stop_listener {
            assert_eq!(
                shutdown(&listener_session, listener, ShutdownMode::StopListening),
                Ok(SocketOutcome::Completed(()))
            );
            assert!(matches!(
                accept(
                    &listener_session,
                    listener,
                    Arc::new(TestReadinessSink::default())
                ),
                Ok(SocketOutcome::Failed(SocketError::NotConnected))
            ));
        } else {
            listener_session.close_object_reference(listener).unwrap();
        }
        let source_binding = broker
            .socket_ports
            .reserve(create_request(), wildcard_source)
            .unwrap();
        assert!(matches!(source_binding, SocketOutcome::Completed(_)));

        if stop_listener {
            listener_session.close_object_reference(listener).unwrap();
            return;
        }

        let replacement = create(
            &listener_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&listener_session, replacement, listener_address),
            Ok(SocketOutcome::Completed(listener_address))
        );
        assert_eq!(
            listen(&listener_session, replacement, 1),
            Ok(SocketOutcome::Completed(listener_address))
        );
        assert!(matches!(
            accept(
                &listener_session,
                replacement,
                Arc::new(TestReadinessSink::default())
            ),
            Err(BrokerError::WouldBlock)
        ));
        listener_session
            .close_object_reference(replacement)
            .unwrap();
    }

    fn test_broker(socket_provider: Arc<dyn SocketProvider>) -> BrokerCore {
        test_broker_with_policy(socket_provider, &crate::SocketPolicy::guest_network())
    }

    fn test_broker_with_policy(
        socket_provider: Arc<dyn SocketProvider>,
        socket_policy: &crate::SocketPolicy,
    ) -> BrokerCore {
        BrokerCore {
            policy: Arc::new(
                crate::PolicyEngine::with_unauthenticated_rights(crate::ObjectRights::all())
                    .with_socket_policy(*socket_policy),
            ),
            limits: crate::BrokerCoreLimits::new_with_all_limits(16, 4, 8, 8),
            next_session_id: Arc::new(spin::RwLock::new(1)),
            next_reference_handle: Arc::new(spin::RwLock::new(1)),
            references: Arc::new(spin::RwLock::new(hashbrown::HashMap::new())),
            pending_references: Arc::new(AtomicUsize::new(0)),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            socket_provider,
            socket_ports: BrokerSocketPorts::default(),
        }
    }

    pub(crate) fn check_socket_lifecycle(broker: &BrokerCore, provider: &TestSocketProvider) {
        check_failed_create_rolls_back(broker, provider);
        check_socket_operations_and_policy(broker, provider);
        check_in_flight_connect_preserves_local_address(broker);
        check_private_tcp_connect_uses_private_source_for_wildcard_binding(broker, provider);
        check_tcp_option_state_is_per_socket(broker);
        check_udp_socket_operations(broker, provider);
        check_udp_status_validates_local_address(broker, provider);
        check_concurrent_udp_status_does_not_regress_connection(broker, provider);
        check_server_socket_operations(broker, provider);
        check_failed_listener_shutdown_preserves_state(broker, provider);
        check_listener_shutdown_does_not_race_listen(broker, provider);
        check_connect_errors_classify_peer_state(broker, provider);
        check_concurrent_status_preserves_terminal_state(broker, provider);
        check_stream_status_validates_local_address(broker, provider);
        check_failed_status_preserves_local_address(broker, provider);
        check_quota_waits_for_deferred_retirement(broker, provider);
        check_platform_socket_retires_before_last_arc_drop(broker, provider);
        check_socket_quotas(broker);
        check_invalid_bind_response_retires_socket(broker, provider);
        check_automatic_bind_retains_reservation_during_retirement(broker, provider);
        check_duplicate_port_binding_retires_socket(broker, provider);
    }

    fn check_platform_socket_retires_before_last_arc_drop(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        let dropped_before = provider.state.dropped_sockets.load(Ordering::Relaxed);

        provider.retain_next_socket();
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        session.close_object_reference(handle).unwrap();

        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        assert_eq!(
            provider.state.dropped_sockets.load(Ordering::Relaxed),
            dropped_before
        );

        provider
            .state
            .retained_platform_sockets
            .lock()
            .unwrap()
            .clear();
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        assert_eq!(
            provider.state.dropped_sockets.load(Ordering::Relaxed),
            dropped_before + 1
        );
    }

    fn check_failed_create_rolls_back(broker: &BrokerCore, provider: &TestSocketProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        provider.fail_next_create();
        let readiness = Arc::new(TestReadinessSink::default());
        assert_eq!(
            create(&session, create_request(), readiness.clone()),
            Err(BrokerError::OutOfMemory)
        );
        provider
            .state
            .failed_readiness
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .publish(ReadinessFlags::READ)
            .unwrap();
        assert!(readiness.published.lock().unwrap().is_empty());
        assert_eq!(readiness.retired.lock().unwrap().len(), 1);
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
        assert_eq!(session.reserved_sockets.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn failed_accept_rolls_back_readiness_and_quota() {
        let provider = Arc::new(TestSocketProvider::default());
        let broker = test_broker(Arc::clone(&provider) as Arc<dyn SocketProvider>);
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let listener = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41999);
        assert_eq!(
            bind(&session, listener, local_address),
            Ok(SocketOutcome::Completed(local_address))
        );
        assert_eq!(
            listen(&session, listener, 1),
            Ok(SocketOutcome::Completed(local_address))
        );
        let reserved_sockets = broker.reserved_sockets.load(Ordering::Relaxed);
        let session_sockets = session.reserved_sockets.load(Ordering::Relaxed);

        for failure in [TestAcceptFailure::Socket, TestAcceptFailure::Broker] {
            let readiness = Arc::new(TestReadinessSink::default());
            provider.fail_next_accept(failure);
            let result = accept(&session, listener, readiness.clone());
            match failure {
                TestAcceptFailure::Socket => assert!(matches!(
                    result,
                    Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
                )),
                TestAcceptFailure::Broker => {
                    assert!(matches!(result, Err(BrokerError::OutOfMemory)));
                }
            }
            let registration = provider
                .state
                .failed_accept_readiness
                .lock()
                .unwrap()
                .take()
                .expect("failed accept did not retain readiness");
            registration.publish(ReadinessFlags::READ).unwrap();
            assert!(readiness.published.lock().unwrap().is_empty());
            assert_eq!(readiness.retired.lock().unwrap().len(), 1);
            assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
            assert_eq!(
                broker.reserved_sockets.load(Ordering::Relaxed),
                reserved_sockets
            );
            assert_eq!(
                session.reserved_sockets.load(Ordering::Relaxed),
                session_sockets
            );
        }

        session.close_object_reference(listener).unwrap();
    }

    #[test]
    fn invalid_accepted_metadata_retires_socket_readiness_and_quota() {
        let provider = Arc::new(TestSocketProvider::default());
        let broker = test_broker(Arc::clone(&provider) as Arc<dyn SocketProvider>);
        for (requested_listener, invalid_address) in [
            (
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41997),
                TestInvalidAddress::WrongPort,
            ),
            (
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                TestInvalidAddress::Gateway,
            ),
            (
                SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 41996),
                TestInvalidAddress::LoopbackAlias,
            ),
        ] {
            let listener_session = broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap();
            let connector_session = broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap();
            let listener = create(
                &listener_session,
                create_request(),
                Arc::new(TestReadinessSink::default()),
            )
            .unwrap();
            let SocketOutcome::Completed(local_address) =
                bind(&listener_session, listener, requested_listener).unwrap()
            else {
                panic!("listener bind failed");
            };
            assert_eq!(
                listen(&listener_session, listener, 1),
                Ok(SocketOutcome::Completed(local_address))
            );
            let destination = if local_address.ip().is_unspecified() {
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_address.port())
            } else {
                local_address
            };
            let connector = create(
                &connector_session,
                create_request(),
                Arc::new(TestReadinessSink::default()),
            )
            .unwrap();
            provider.queue_next_guest_connect();
            assert_eq!(
                connect(&connector_session, connector, destination),
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
            );
            connector_session.close_object_reference(connector).unwrap();

            let readiness = Arc::new(TestReadinessSink::default());
            provider.return_invalid_accept_address_once(invalid_address);
            provider.retain_next_socket();
            let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
            assert!(matches!(
                accept(&listener_session, listener, readiness.clone()),
                Err(BrokerError::Internal)
            ));
            assert_eq!(
                provider.state.retired_sockets.load(Ordering::Relaxed),
                retired_before + 1
            );
            let registration = provider
                .state
                .retained_platform_sockets
                .lock()
                .unwrap()
                .last()
                .expect("rejected accepted socket was not retained")
                .readiness
                .clone();
            registration.publish(ReadinessFlags::READ).unwrap();
            assert!(readiness.published.lock().unwrap().is_empty());
            assert_eq!(readiness.retired.lock().unwrap().len(), 1);
            assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
            assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
            assert_eq!(listener_session.reserved_sockets.load(Ordering::Relaxed), 1);
            assert_eq!(
                connector_session.reserved_sockets.load(Ordering::Relaxed),
                0
            );
            provider
                .state
                .retained_platform_sockets
                .lock()
                .unwrap()
                .clear();
            listener_session.close_object_reference(listener).unwrap();
        }
    }

    fn check_in_flight_connect_preserves_local_address(broker: &BrokerCore) {
        let session = Arc::new(
            broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap(),
        );
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let readiness = Arc::new(BlockingReadinessSink {
            started: StdMutex::new(Some(started_tx)),
            release: StdMutex::new(release_rx),
            retired: AtomicUsize::new(0),
        });
        let handle = create(&session, create_request(), readiness).unwrap();
        let local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41998);
        assert_eq!(
            bind(&session, handle, local_address),
            Ok(SocketOutcome::Completed(local_address))
        );

        let connect_session = Arc::clone(&session);
        let connecting =
            std::thread::spawn(move || connect(&connect_session, handle, loopback_address()));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Connecting,
                local_address: Some(local_address),
                pending_error: None,
            })
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            connecting.join().unwrap(),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        session.close_object_reference(handle).unwrap();
    }

    fn check_invalid_bind_response_retires_socket(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let first_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let second_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let readiness = Arc::new(TestReadinessSink::default());
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42000);

        let invalid = create(&first_session, create_request(), readiness.clone()).unwrap();
        provider.return_invalid_bind_address_once(TestInvalidAddress::WrongPort);
        assert_eq!(
            bind(&first_session, invalid, address),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        assert_eq!(
            status(&first_session, invalid),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: None,
                pending_error: None,
            })
        );
        assert_eq!(
            bind(&first_session, invalid, address),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );

        let replacement = create(&second_session, create_request(), readiness.clone()).unwrap();
        assert_eq!(
            bind(&second_session, replacement, address),
            Ok(SocketOutcome::Completed(address))
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        first_session.close_object_reference(invalid).unwrap();
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        second_session.close_object_reference(replacement).unwrap();

        let invalid_ip = create(
            &first_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let retired_before_invalid_ip = provider.state.retired_sockets.load(Ordering::Relaxed);
        provider.return_invalid_bind_address_once(TestInvalidAddress::Gateway);
        assert_eq!(
            bind(
                &first_session,
                invalid_ip,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42004),
            ),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_invalid_ip + 1
        );
        first_session.close_object_reference(invalid_ip).unwrap();

        let blocking_session = Arc::new(
            broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap(),
        );
        let invalid = create(
            &blocking_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42003);
        provider.return_invalid_bind_address_once(TestInvalidAddress::WrongPort);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *provider.state.retire_block.lock().unwrap() = Some((started_tx, release_rx));
        let bind_session = Arc::clone(&blocking_session);
        let binding = std::thread::spawn(move || bind(&bind_session, invalid, address));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let reservation_while_retiring = broker.socket_ports.reserve(create_request(), address);
        release_tx.send(()).unwrap();
        assert_eq!(binding.join().unwrap(), Err(BrokerError::Internal));
        assert!(matches!(
            reservation_while_retiring,
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        ));
        blocking_session.close_object_reference(invalid).unwrap();

        let invalid_connect = create(&first_session, create_request(), readiness).unwrap();
        let retired_before_connect = provider.state.retired_sockets.load(Ordering::Relaxed);
        provider.return_invalid_bind_address_once(TestInvalidAddress::WrongPort);
        assert_eq!(
            connect(&first_session, invalid_connect, loopback_address()),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_connect + 1
        );
        assert_eq!(
            status(&first_session, invalid_connect),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: None,
                pending_error: None,
            })
        );
        assert_eq!(
            connect(&first_session, invalid_connect, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::Other
            )))
        );
        first_session
            .close_object_reference(invalid_connect)
            .unwrap();
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_connect + 1
        );
    }

    fn check_automatic_bind_retains_reservation_during_retirement(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        for operation in [
            TestAutomaticBindOperation::TcpConnect,
            TestAutomaticBindOperation::TcpListen,
            TestAutomaticBindOperation::UdpSend,
            TestAutomaticBindOperation::UdpConnect,
        ] {
            let request =
                match operation {
                    TestAutomaticBindOperation::TcpConnect
                    | TestAutomaticBindOperation::TcpListen => create_request(),
                    TestAutomaticBindOperation::UdpSend
                    | TestAutomaticBindOperation::UdpConnect => create_udp_request(),
                };
            let session = Arc::new(
                broker
                    .create_session(CallerCredential::Unauthenticated)
                    .unwrap(),
            );
            let handle = create(&session, request, Arc::new(TestReadinessSink::default())).unwrap();
            provider.return_invalid_bind_address_once(TestInvalidAddress::WrongPort);
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            *provider.state.retire_block.lock().unwrap() = Some((started_tx, release_rx));
            let operation_session = Arc::clone(&session);
            let in_flight = std::thread::spawn(move || match operation {
                TestAutomaticBindOperation::TcpConnect => {
                    connect(&operation_session, handle, loopback_address()).map(|_| ())
                }
                TestAutomaticBindOperation::TcpListen => {
                    listen(&operation_session, handle, 1).map(|_| ())
                }
                TestAutomaticBindOperation::UdpSend => send_to(
                    &operation_session,
                    handle,
                    b"x".to_vec(),
                    SendFlags::NONE,
                    Some(loopback_address()),
                )
                .map(|_| ()),
                TestAutomaticBindOperation::UdpConnect => {
                    connect(&operation_session, handle, loopback_address()).map(|_| ())
                }
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let local_address = *provider
                .state
                .binds
                .lock()
                .unwrap()
                .last()
                .expect("automatic bind was not recorded");
            let reservation_while_retiring = broker.socket_ports.reserve(request, local_address);
            release_tx.send(()).unwrap();
            assert_eq!(in_flight.join().unwrap(), Err(BrokerError::Internal));
            assert!(matches!(
                reservation_while_retiring,
                Ok(SocketOutcome::Failed(SocketError::AddressInUse))
            ));
            session.close_object_reference(handle).unwrap();
        }
    }

    fn check_duplicate_port_binding_retires_socket(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let original_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42001);
        assert_eq!(
            bind(&session, handle, original_address),
            Ok(SocketOutcome::Completed(original_address))
        );

        let duplicate_ports = BrokerSocketPorts::default();
        let duplicate_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42002);
        let SocketOutcome::Completed((duplicate_address, duplicate_binding)) = duplicate_ports
            .reserve(create_request(), duplicate_address)
            .unwrap()
        else {
            panic!("duplicate-binding test could not reserve a port");
        };
        let object = session
            .authorized_object(handle, ObjectRights::WRITE)
            .unwrap();
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        assert_eq!(
            attach_binding(&object, duplicate_address, duplicate_binding),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: Some(original_address),
                pending_error: None,
            })
        );
        assert!(matches!(
            broker
                .socket_ports
                .reserve(create_request(), original_address),
            Ok(SocketOutcome::Completed(_))
        ));
        assert!(matches!(
            duplicate_ports.reserve(create_request(), duplicate_address),
            Ok(SocketOutcome::Completed(_))
        ));

        session.close_object_reference(handle).unwrap();
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
    }

    fn check_socket_operations_and_policy(broker: &BrokerCore, provider: &TestSocketProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let other = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let readiness = Arc::new(TestReadinessSink::default());
        let handle = create(&session, create_request(), readiness.clone()).unwrap();
        assert_eq!(
            provider.state.creates.lock().unwrap().last(),
            Some(&(session.session_id, create_request()))
        );
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(session.reserved_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(status(&other, handle), Err(BrokerError::UnknownObject));
        assert_eq!(
            connect(
                &session,
                handle,
                SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80),
            ),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Unconnected,
                local_address: None,
                pending_error: None,
            })
        );
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        let local_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic TCP bind was not recorded");
        assert_eq!(
            provider
                .state
                .connect_source_addresses
                .lock()
                .unwrap()
                .last(),
            Some(&Some(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                local_address.port(),
            )))
        );
        assert_eq!(
            readiness.published.lock().unwrap().as_slice(),
            [(handle, ReadinessFlags::WRITE)]
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(local_address),
                pending_error: None,
            })
        );
        assert_eq!(
            session.check_readiness(handle),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            send(&session, handle, vec![1, 2, 3], SendFlags::NONE),
            Ok(SocketOutcome::Completed(3))
        );
        provider.return_next_send_count(4);
        assert_eq!(
            send(&session, handle, vec![1, 2, 3], SendFlags::NONE),
            Err(BrokerError::Internal)
        );
        provider.return_next_send_count(0);
        assert_eq!(
            send(&session, handle, vec![1, 2, 3], SendFlags::NONE),
            Err(BrokerError::Internal)
        );
        provider.return_next_send_count(2);
        assert_eq!(
            send(&session, handle, vec![1, 2, 3], SendFlags::NONE),
            Ok(SocketOutcome::Completed(2))
        );
        assert_eq!(
            send(&session, handle, Vec::new(), SendFlags::NONE),
            Ok(SocketOutcome::Completed(0))
        );
        let sent_before = provider.state.sent.lock().unwrap().len();
        assert_eq!(
            send(
                &session,
                handle,
                vec![0; MAX_SOCKET_TRANSFER_SIZE as usize + 1],
                SendFlags::NONE,
            ),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(provider.state.sent.lock().unwrap().len(), sent_before);
        let receive_calls = provider.state.receive_calls.load(Ordering::Relaxed);
        assert_eq!(
            receive(&session, handle, 1, ReceiveFlags::WAITALL, 0, 0),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            provider.state.receive_calls.load(Ordering::Relaxed),
            receive_calls
        );
        assert_eq!(
            receive(&session, handle, 4, ReceiveFlags::PEEK, 0, 4),
            Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                vec![7, 9],
            )))
        );
        provider.return_next_stream_receive(PlatformStreamReceive::Received(Vec::new()));
        assert_eq!(
            receive(&session, handle, 1, ReceiveFlags::NONE, 0, 0),
            Err(BrokerError::Internal)
        );
        provider.return_next_stream_receive(PlatformStreamReceive::Received(vec![7, 9]));
        assert_eq!(
            receive(&session, handle, 1, ReceiveFlags::NONE, 0, 0),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            receive(&session, handle, 1, ReceiveFlags::PEEK, 1, 2),
            Err(BrokerError::UnsupportedOperation)
        );
        let receive_calls = provider.state.receive_calls.load(Ordering::Relaxed);
        assert_eq!(
            receive(
                &session,
                handle,
                MAX_SOCKET_TRANSFER_SIZE as usize + 1,
                ReceiveFlags::NONE,
                0,
                0,
            ),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            provider.state.receive_calls.load(Ordering::Relaxed),
            receive_calls
        );
        assert_eq!(
            set_tcp_option(&session, handle, TcpOptionValue::NoDelay(true)),
            Ok(())
        );
        assert_eq!(
            get_tcp_option(&session, handle, TcpOptionName::NoDelay),
            Ok(TcpOptionValue::NoDelay(true))
        );
        assert_eq!(
            set_tcp_option(&session, handle, TcpOptionValue::KeepAlive(true)),
            Ok(())
        );
        assert_eq!(
            get_tcp_option(&session, handle, TcpOptionName::KeepAlive),
            Ok(TcpOptionValue::KeepAlive(true))
        );
        assert_eq!(
            shutdown(&session, handle, ShutdownMode::Both),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            send(&session, handle, Vec::new(), SendFlags(1)),
            Err(BrokerError::UnsupportedOperation)
        );
        let in_flight = socket_resource(&session, handle, ObjectRights::WAIT).unwrap();
        assert_eq!(session.close_object_reference(handle), Ok(()));
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(readiness.retired.lock().unwrap().as_slice(), []);
        drop(in_flight);
        assert_eq!(readiness.retired.lock().unwrap().as_slice(), [handle]);
        assert_eq!(provider.state.dropped_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
        assert_eq!(session.reserved_sockets.load(Ordering::Relaxed), 0);
        assert_eq!(
            provider.state.sent.lock().unwrap().as_slice(),
            [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3]
        );
        assert_eq!(provider.state.connect_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.state.status_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.state.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            provider.state.tcp_option_sets.lock().unwrap().as_slice(),
            [
                TcpOptionValue::NoDelay(true),
                TcpOptionValue::KeepAlive(true),
            ]
        );
        let session_id = session.session_id;
        drop(other);
        drop(session);
        assert!(
            provider
                .state
                .closed_sessions
                .lock()
                .unwrap()
                .contains(&session_id)
        );
    }

    fn check_tcp_option_state_is_per_socket(broker: &BrokerCore) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let first = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();

        assert_eq!(
            set_tcp_option(&session, first, TcpOptionValue::NoDelay(true)),
            Ok(())
        );
        assert_eq!(
            set_tcp_option(&session, first, TcpOptionValue::KeepAlive(true)),
            Ok(())
        );
        assert_eq!(session.close_object_reference(first), Ok(()));

        let second = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            get_tcp_option(&session, second, TcpOptionName::NoDelay),
            Ok(TcpOptionValue::NoDelay(false))
        );
        assert_eq!(
            get_tcp_option(&session, second, TcpOptionName::KeepAlive),
            Ok(TcpOptionValue::KeepAlive(false))
        );

        assert_eq!(session.close_object_reference(second), Ok(()));
    }

    fn check_private_tcp_connect_uses_private_source_for_wildcard_binding(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert!(matches!(
            connect(&session, handle, SocketAddrV4::new(GUEST_IPV4_ADDRESS, 80),),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        let bound_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic private TCP bind was not recorded");
        assert!(bound_address.ip().is_unspecified());
        assert_ne!(bound_address.port(), 0);
        assert_eq!(
            provider
                .state
                .connect_source_addresses
                .lock()
                .unwrap()
                .last(),
            Some(&Some(SocketAddrV4::new(
                GUEST_IPV4_ADDRESS,
                bound_address.port(),
            )))
        );
        session.close_object_reference(handle).unwrap();
    }

    fn check_udp_socket_operations(broker: &BrokerCore, provider: &TestSocketProvider) {
        let connect_calls_before = provider.state.connect_calls.load(Ordering::Relaxed);
        let connect_sources_before = provider
            .state
            .connect_source_addresses
            .lock()
            .unwrap()
            .len();
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let readiness = Arc::new(TestReadinessSink::default());
        let request = CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
        };
        let handle = create(&session, request, readiness).unwrap();

        assert_eq!(
            set_tcp_option(&session, handle, TcpOptionValue::NoDelay(true)),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            get_tcp_option(&session, handle, TcpOptionName::NoDelay),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            send_to(&session, handle, b"x".to_vec(), SendFlags::NONE, None),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            send_to(
                &session,
                handle,
                b"x".to_vec(),
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53)),
            ),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(
            send_to(
                &session,
                handle,
                b"udp".to_vec(),
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            ),
            Ok(SocketOutcome::Completed(3))
        );
        provider.return_next_send_count(2);
        assert_eq!(
            send_to(
                &session,
                handle,
                b"udp".to_vec(),
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            ),
            Err(BrokerError::Internal)
        );
        provider.return_next_send_count(4);
        assert_eq!(
            send_to(
                &session,
                handle,
                b"udp".to_vec(),
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            ),
            Err(BrokerError::Internal)
        );
        let send_calls = provider.state.send_calls.load(Ordering::Relaxed);
        assert_eq!(
            send_to(
                &session,
                handle,
                vec![0; MAX_UDP_DATAGRAM_SIZE as usize + 1],
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            ),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            provider.state.send_calls.load(Ordering::Relaxed),
            send_calls
        );
        assert_eq!(
            send_to(
                &session,
                handle,
                b"udp".to_vec(),
                SendFlags(1),
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            ),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            provider.state.send_calls.load(Ordering::Relaxed),
            send_calls
        );
        assert_eq!(
            receive_from(&session, handle, 2, ReceiveFromFlags::PEEK),
            Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                data: vec![7, 9],
                datagram_length: 4,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            }))
        );
        let receive_from_calls = provider.state.receive_from_calls.load(Ordering::Relaxed);
        assert_eq!(
            receive_from(
                &session,
                handle,
                MAX_UDP_DATAGRAM_SIZE as usize + 1,
                ReceiveFromFlags::NONE,
            ),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            provider.state.receive_from_calls.load(Ordering::Relaxed),
            receive_from_calls
        );
        assert_eq!(
            receive_from(&session, handle, 2, ReceiveFromFlags(2)),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            provider.state.receive_from_calls.load(Ordering::Relaxed),
            receive_from_calls
        );
        for (length, data, datagram_length) in [
            (4, vec![7], 4),
            (2, vec![7], 4),
            (2, vec![7, 9, 11], 3),
            (2, vec![7, 9], 1),
            (2, vec![7, 9], MAX_UDP_DATAGRAM_SIZE as usize + 1),
        ] {
            provider.return_next_datagram_receive(PlatformDatagramReceive {
                data,
                datagram_length,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            });
            assert_eq!(
                receive_from(&session, handle, length, ReceiveFromFlags::NONE),
                Err(BrokerError::Internal)
            );
        }
        for source_ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            provider.return_next_datagram_receive(PlatformDatagramReceive {
                data: vec![7, 9],
                datagram_length: 4,
                source_address: SocketAddrV4::new(source_ip, 49153),
            });
            assert_eq!(
                receive_from(&session, handle, 2, ReceiveFromFlags::NONE),
                Err(BrokerError::Internal)
            );
        }
        provider.return_next_datagram_receive(PlatformDatagramReceive {
            data: vec![7, 9],
            datagram_length: 4,
            source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
        });
        assert_eq!(
            receive_from(&session, handle, 2, ReceiveFromFlags::NONE),
            Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                data: vec![7, 9],
                datagram_length: 4,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            }))
        );
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        provider.fail_next_connect();
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54),),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            status(&session, handle).unwrap().status,
            SocketConnectionStatus::Connected
        );
        assert_eq!(
            send_to(&session, handle, b"peer".to_vec(), SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(4))
        );
        provider.fail_next_connect_indeterminate();
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54),),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 49152)),
                pending_error: None,
            })
        );
        assert_eq!(
            send_to(&session, handle, b"peer".to_vec(), SendFlags::NONE, None),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            send_to(
                &session,
                handle,
                b"peer".to_vec(),
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54)),
            ),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            receive_from(&session, handle, 1, ReceiveFromFlags::NONE),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        let shutdown_calls = provider.state.shutdown_calls.load(Ordering::Relaxed);
        assert_eq!(
            shutdown(&session, handle, ShutdownMode::Both),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            provider.state.shutdown_calls.load(Ordering::Relaxed),
            shutdown_calls
        );
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54),),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::Other
            )))
        );
        assert_eq!(
            send_to(&session, handle, b"peer".to_vec(), SendFlags::NONE, None),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        session.close_object_reference(handle).unwrap();

        let handle = create(
            &session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            },
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            send(&session, handle, b"x".to_vec(), SendFlags::NONE),
            Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
        );
        assert_eq!(
            listen(&session, handle, 1),
            Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
        );
        assert_eq!(
            shutdown(&session, handle, ShutdownMode::Abort),
            Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
        );
        assert_eq!(
            shutdown(&session, handle, ShutdownMode::Both),
            Ok(SocketOutcome::Completed(()))
        );
        session.close_object_reference(handle).unwrap();
        assert_eq!(
            provider.state.connect_calls.load(Ordering::Relaxed),
            connect_calls_before + 3
        );
        assert!(
            provider.state.connect_source_addresses.lock().unwrap()[connect_sources_before..]
                .iter()
                .all(Option::is_none)
        );
    }

    fn check_udp_status_validates_local_address(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let unbound = create(
            &session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            },
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152)),
                pending_error: None,
            });
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        assert_eq!(status(&session, unbound), Err(BrokerError::Internal));
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        session.close_object_reference(unbound).unwrap();

        for platform_status in [
            SocketConnectionStatus::Connecting,
            SocketConnectionStatus::Failed(SocketError::ConnectionRefused),
        ] {
            let invalid = create(
                &session,
                create_udp_request(),
                Arc::new(TestReadinessSink::default()),
            )
            .unwrap();
            provider
                .state
                .status_responses
                .lock()
                .unwrap()
                .push_back(PlatformSocketStatus {
                    status: platform_status,
                    local_address: None,
                    pending_error: None,
                });
            let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
            assert_eq!(status(&session, invalid), Err(BrokerError::Internal));
            assert_eq!(
                provider.state.retired_sockets.load(Ordering::Relaxed),
                retired_before + 1
            );
            let status_calls = provider.state.status_calls.load(Ordering::Relaxed);
            assert_eq!(
                status(&session, invalid),
                Ok(SocketStatusResponse {
                    status: SocketConnectionStatus::Failed(SocketError::Other),
                    local_address: None,
                    pending_error: None,
                })
            );
            assert_eq!(
                provider.state.status_calls.load(Ordering::Relaxed),
                status_calls
            );
            session.close_object_reference(invalid).unwrap();
        }

        let handle = create(
            &session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Datagram,
                protocol: IpProtocol::Udp,
            },
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            send_to(
                &session,
                handle,
                b"x".to_vec(),
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            ),
            Ok(SocketOutcome::Completed(1))
        );
        let reserved_address = status(&session, handle).unwrap().local_address.unwrap();
        let changed_port = if reserved_address.port() == u16::MAX {
            reserved_address.port() - 1
        } else {
            reserved_address.port() + 1
        };
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, changed_port)),
                pending_error: None,
            });
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        assert_eq!(status(&session, handle), Err(BrokerError::Internal));
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        let status_calls = provider.state.status_calls.load(Ordering::Relaxed);
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: Some(reserved_address),
                pending_error: None,
            })
        );
        assert_eq!(
            provider.state.status_calls.load(Ordering::Relaxed),
            status_calls
        );
        let connect_calls = provider.state.connect_calls.load(Ordering::Relaxed);
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::Other
            )))
        );
        assert_eq!(
            provider.state.connect_calls.load(Ordering::Relaxed),
            connect_calls
        );
        session.close_object_reference(handle).unwrap();

        let exact = create(
            &session,
            create_udp_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let exact_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 40000);
        assert_eq!(
            bind(&session, exact, exact_address),
            Ok(SocketOutcome::Completed(exact_address))
        );
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, exact_address.port())),
                pending_error: None,
            });
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        assert_eq!(
            status(&session, exact),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(exact_address),
                pending_error: None,
            })
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before
        );
        session.close_object_reference(exact).unwrap();

        for invalid_ip in [Ipv4Addr::new(192, 168, 1, 10), HOST_GATEWAY_IPV4_ADDRESS] {
            let external_local = create(
                &session,
                create_udp_request(),
                Arc::new(TestReadinessSink::default()),
            )
            .unwrap();
            let SocketOutcome::Completed(wildcard_address) = bind(
                &session,
                external_local,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            )
            .unwrap() else {
                panic!("guest UDP wildcard bind failed");
            };
            provider
                .state
                .status_responses
                .lock()
                .unwrap()
                .push_back(PlatformSocketStatus {
                    status: SocketConnectionStatus::Unconnected,
                    local_address: Some(SocketAddrV4::new(invalid_ip, wildcard_address.port())),
                    pending_error: None,
                });
            let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
            assert_eq!(status(&session, external_local), Err(BrokerError::Internal));
            assert_eq!(
                provider.state.retired_sockets.load(Ordering::Relaxed),
                retired_before + 1
            );
            session.close_object_reference(external_local).unwrap();
        }

        for observed_ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            GUEST_IPV4_ADDRESS,
        ] {
            let wildcard = create(
                &session,
                create_udp_request(),
                Arc::new(TestReadinessSink::default()),
            )
            .unwrap();
            let SocketOutcome::Completed(wildcard_address) = bind(
                &session,
                wildcard,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            )
            .unwrap() else {
                panic!("guest UDP wildcard bind failed");
            };
            let observed_address = SocketAddrV4::new(observed_ip, wildcard_address.port());
            provider
                .state
                .status_responses
                .lock()
                .unwrap()
                .push_back(PlatformSocketStatus {
                    status: SocketConnectionStatus::Unconnected,
                    local_address: Some(observed_address),
                    pending_error: None,
                });
            let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
            assert_eq!(
                status(&session, wildcard),
                Ok(SocketStatusResponse {
                    status: SocketConnectionStatus::Unconnected,
                    local_address: Some(observed_address),
                    pending_error: None,
                })
            );
            assert_eq!(
                provider.state.retired_sockets.load(Ordering::Relaxed),
                retired_before
            );
            session.close_object_reference(wildcard).unwrap();
        }
    }

    fn check_server_socket_operations(broker: &BrokerCore, provider: &TestSocketProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let readiness = Arc::new(TestReadinessSink::default());
        let listener = create(&session, create_request(), readiness.clone()).unwrap();
        let non_loopback = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080);
        let binds_before = provider.state.binds.lock().unwrap().len();
        assert_eq!(
            bind(&session, listener, non_loopback),
            Ok(SocketOutcome::Failed(SocketError::AddressNotAvailable))
        );
        assert_eq!(provider.state.binds.lock().unwrap().len(), binds_before);

        let requested_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let SocketOutcome::Completed(local_address) =
            bind(&session, listener, requested_address).unwrap()
        else {
            panic!("guest TCP bind failed");
        };
        assert!(local_address.ip().is_loopback());
        assert_ne!(local_address.port(), 0);
        assert_eq!(
            status(&session, listener),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(local_address),
                pending_error: None,
            })
        );
        assert_eq!(
            listen(&session, listener, 128),
            Ok(SocketOutcome::Completed(local_address))
        );
        assert_eq!(
            listen(&session, listener, MAX_TCP_LISTEN_BACKLOG + 1),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(
            connect(&session, listener, loopback_address()),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        assert_eq!(
            shutdown(&session, listener, ShutdownMode::Write),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert!(matches!(
            accept(&session, listener, readiness.clone()),
            Err(BrokerError::ResourceExhausted)
        ));
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(
            shutdown(&session, listener, ShutdownMode::StopListening),
            Ok(SocketOutcome::Completed(()))
        );
        assert_eq!(
            status(&session, listener),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::NotConnected),
                local_address: Some(local_address),
                pending_error: None,
            })
        );
        assert!(matches!(
            accept(&session, listener, readiness.clone()),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        ));
        assert_eq!(
            connect(&session, listener, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::NotConnected
            )))
        );

        let competing_session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let competitor = create(
            &competing_session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&competing_session, competitor, local_address),
            Ok(SocketOutcome::Failed(SocketError::AddressInUse))
        );
        session.close_object_reference(listener).unwrap();
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(
            bind(&competing_session, competitor, local_address),
            Ok(SocketOutcome::Completed(local_address))
        );
        competing_session
            .close_object_reference(competitor)
            .unwrap();
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);

        let auto_bound = create(&session, create_request(), readiness).unwrap();
        let SocketOutcome::Completed(auto_bound_address) = listen(&session, auto_bound, 0).unwrap()
        else {
            panic!("automatic TCP listen failed");
        };
        assert_ne!(auto_bound_address.port(), 0);
        assert_eq!(
            provider.state.binds.lock().unwrap().last(),
            Some(&auto_bound_address)
        );
        session.close_object_reference(auto_bound).unwrap();
    }

    fn check_concurrent_udp_status_does_not_regress_connection(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = Arc::new(
            broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap(),
        );
        let handle = create(
            &session,
            create_udp_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        *provider.state.status_responses.lock().unwrap() = std::collections::VecDeque::from([
            PlatformSocketStatus {
                status: SocketConnectionStatus::Unconnected,
                local_address: None,
                pending_error: None,
            },
            PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: None,
                pending_error: None,
            },
        ]);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *provider.state.status_block.lock().unwrap() = Some((started_tx, release_rx));

        let status_session = Arc::clone(&session);
        let in_flight = std::thread::spawn(move || status(&status_session, handle).unwrap());
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        let local_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic UDP bind was not recorded");
        release_tx.send(()).unwrap();
        let stale = in_flight.join().unwrap();
        assert_eq!(stale.status, SocketConnectionStatus::Connected);
        assert_eq!(stale.local_address, Some(local_address));
        assert_eq!(stale.pending_error, None);

        let next_local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_address.port());
        let stale_local_address =
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), local_address.port());
        *provider.state.status_responses.lock().unwrap() = std::collections::VecDeque::from([
            PlatformSocketStatus {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(stale_local_address),
                pending_error: Some(SocketError::ConnectionRefused),
            },
            PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: Some(next_local_address),
                pending_error: Some(SocketError::NetworkUnreachable),
            },
        ]);
        let status_calls = provider.state.status_calls.load(Ordering::Relaxed);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *provider.state.status_block.lock().unwrap() = Some((started_tx, release_rx));
        let status_session = Arc::clone(&session);
        let in_flight = std::thread::spawn(move || status(&status_session, handle).unwrap());
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54),),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        release_tx.send(()).unwrap();
        let status_with_error = in_flight.join().unwrap();
        assert_eq!(
            status_with_error.pending_error,
            Some(SocketError::ConnectionRefused)
        );
        assert_eq!(status_with_error.local_address, Some(local_address));
        assert_eq!(
            provider.state.status_calls.load(Ordering::Relaxed),
            status_calls + 1
        );
        let next_status = status(&session, handle).unwrap();
        assert_eq!(
            next_status.pending_error,
            Some(SocketError::NetworkUnreachable)
        );
        assert_eq!(next_status.local_address, Some(next_local_address));
        assert_eq!(
            status(&session, handle).unwrap().status,
            SocketConnectionStatus::Connected
        );

        provider.fail_next_status();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *provider.state.status_block.lock().unwrap() = Some((started_tx, release_rx));
        let status_session = Arc::clone(&session);
        let in_flight = std::thread::spawn(move || status(&status_session, handle));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        provider.fail_next_connect_indeterminate();
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 55),),
            Err(BrokerError::Internal)
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            in_flight.join().unwrap(),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: Some(next_local_address),
                pending_error: None,
            })
        );
    }

    fn check_failed_listener_shutdown_preserves_state(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert!(matches!(
            listen(&session, handle, 8),
            Ok(SocketOutcome::Completed(_))
        ));
        provider.fail_next_shutdown();
        assert_eq!(
            shutdown(&session, handle, ShutdownMode::StopListening),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        session.close_object_reference(handle).unwrap();
    }

    fn check_listener_shutdown_does_not_race_listen(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = Arc::new(
            broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap(),
        );
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *provider.state.listen_block.lock().unwrap() = Some((started_tx, release_rx));

        let listen_session = Arc::clone(&session);
        let listening = std::thread::spawn(move || listen(&listen_session, handle, 8));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let shutdown_calls = provider.state.shutdown_calls.load(Ordering::Relaxed);
        assert_eq!(
            shutdown(&session, handle, ShutdownMode::StopListening),
            Ok(SocketOutcome::Failed(SocketError::Other))
        );
        assert_eq!(
            provider.state.shutdown_calls.load(Ordering::Relaxed),
            shutdown_calls
        );
        release_tx.send(()).unwrap();
        assert!(matches!(
            listening.join().unwrap(),
            Ok(SocketOutcome::Completed(_))
        ));
        assert_eq!(
            shutdown(&session, handle, ShutdownMode::StopListening),
            Ok(SocketOutcome::Completed(()))
        );
        session.close_object_reference(handle).unwrap();
    }

    fn check_socket_quotas(broker: &BrokerCore) {
        let first = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let second = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let third = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let first_handle = create(
            &first,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            create(
                &first,
                create_request(),
                Arc::new(TestReadinessSink::default())
            ),
            Err(BrokerError::ResourceExhausted)
        );
        let second_handle = create(
            &second,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            create(
                &third,
                create_request(),
                Arc::new(TestReadinessSink::default())
            ),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 2);
        first.close_object_reference(first_handle).unwrap();
        second.close_object_reference(second_handle).unwrap();
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
    }

    struct BlockingReadinessSink {
        started: StdMutex<Option<mpsc::Sender<()>>>,
        release: StdMutex<mpsc::Receiver<()>>,
        retired: AtomicUsize,
    }

    impl ReadinessSink for BlockingReadinessSink {
        fn max_tracked_objects(&self) -> usize {
            usize::MAX
        }

        fn publish(&self, _handle: ObjectHandle, _readiness: ReadinessFlags) -> Result<()> {
            if let Some(started) = self.started.lock().unwrap().take() {
                started.send(()).map_err(|_| BrokerError::Internal)?;
            }
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| BrokerError::Internal)
        }

        fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
            self.publish(handle, readiness)
        }

        fn retire(&self, _handle: ObjectHandle) {
            self.retired.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn check_quota_waits_for_deferred_retirement(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let readiness = Arc::new(BlockingReadinessSink {
            started: StdMutex::new(Some(started_tx)),
            release: StdMutex::new(release_rx),
            retired: AtomicUsize::new(0),
        });
        let handle = create(&session, create_request(), readiness.clone()).unwrap();
        let registration = provider
            .state
            .live_readiness
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        let publisher = std::thread::spawn(move || registration.publish(ReadinessFlags::READ));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        session.close_object_reference(handle).unwrap();
        assert_eq!(readiness.retired.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(session.reserved_sockets.load(Ordering::Relaxed), 1);

        release_tx.send(()).unwrap();
        publisher.join().unwrap().unwrap();
        assert_eq!(readiness.retired.load(Ordering::Relaxed), 1);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
        assert_eq!(session.reserved_sockets.load(Ordering::Relaxed), 0);
        *provider.state.live_readiness.lock().unwrap() = None;
    }

    fn check_connect_errors_classify_peer_state(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let retryable = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let calls_before = provider.state.connect_calls.load(Ordering::Relaxed);
        provider.fail_next_connect();
        assert_eq!(
            connect(&session, retryable, loopback_address()),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            status(&session, retryable).unwrap().status,
            SocketConnectionStatus::Unconnected
        );
        assert_eq!(
            connect(&session, retryable, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        session.close_object_reference(retryable).unwrap();

        let poisoned = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let retired_before_poisoned = provider.state.retired_sockets.load(Ordering::Relaxed);
        provider.fail_next_connect_indeterminate();
        assert_eq!(
            connect(&session, poisoned, loopback_address()),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_poisoned + 1
        );
        let poisoned_local_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic TCP bind was not recorded");
        assert_eq!(
            connect(&session, poisoned, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::Other
            )))
        );
        assert_eq!(
            status(&session, poisoned),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: Some(poisoned_local_address),
                pending_error: None,
            })
        );
        let sent_before = provider.state.sent.lock().unwrap().len();
        assert_eq!(
            send(&session, poisoned, vec![1], SendFlags::NONE),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(provider.state.sent.lock().unwrap().len(), sent_before);
        assert_eq!(
            receive(&session, poisoned, 1, ReceiveFlags::NONE, 0, 0),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        let shutdown_calls_before = provider.state.shutdown_calls.load(Ordering::Relaxed);
        assert_eq!(
            shutdown(&session, poisoned, ShutdownMode::Both),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            provider.state.shutdown_calls.load(Ordering::Relaxed),
            shutdown_calls_before
        );
        assert_eq!(
            set_tcp_option(&session, poisoned, TcpOptionValue::NoDelay(true)),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            get_tcp_option(&session, poisoned, TcpOptionName::NoDelay),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            bind(&session, poisoned, loopback_address()),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            listen(&session, poisoned, 1),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        session.close_object_reference(poisoned).unwrap();
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_poisoned + 1
        );

        let poisoned_datagram = create(
            &session,
            create_udp_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let retired_before_datagram = provider.state.retired_sockets.load(Ordering::Relaxed);
        provider.fail_next_connect_indeterminate();
        assert_eq!(
            connect(&session, poisoned_datagram, loopback_address()),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_datagram + 1
        );
        let status_calls_before = provider.state.status_calls.load(Ordering::Relaxed);
        assert_eq!(
            status(&session, poisoned_datagram).unwrap().status,
            SocketConnectionStatus::Failed(SocketError::Other)
        );
        assert_eq!(
            provider.state.status_calls.load(Ordering::Relaxed),
            status_calls_before
        );
        session.close_object_reference(poisoned_datagram).unwrap();
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_datagram + 1
        );

        let invalid_status = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let retired_before_invalid_status = provider.state.retired_sockets.load(Ordering::Relaxed);
        provider.return_unconnected_connect_once();
        assert_eq!(
            connect(&session, invalid_status, loopback_address()),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_invalid_status + 1
        );
        assert_eq!(
            status(&session, invalid_status).unwrap().status,
            SocketConnectionStatus::Failed(SocketError::Other)
        );
        session.close_object_reference(invalid_status).unwrap();
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before_invalid_status + 1
        );
        assert_eq!(
            provider.state.connect_calls.load(Ordering::Relaxed),
            calls_before + 5
        );
    }

    fn check_concurrent_status_preserves_terminal_state(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = Arc::new(
            broker
                .create_session(CallerCredential::Unauthenticated)
                .unwrap(),
        );
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );

        let local_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic TCP bind was not recorded");
        let platform_local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_address.port());
        *provider.state.status_responses.lock().unwrap() = std::collections::VecDeque::from([
            PlatformSocketStatus {
                status: SocketConnectionStatus::Connecting,
                local_address: None,
                pending_error: None,
            },
            PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: Some(platform_local_address),
                pending_error: Some(SocketError::ConnectionReset),
            },
        ]);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *provider.state.status_block.lock().unwrap() = Some((started_tx, release_rx));

        let first_session = Arc::clone(&session);
        let first = std::thread::spawn(move || status(&first_session, handle).unwrap());
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert_eq!(
            status(&session, handle).unwrap(),
            SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(platform_local_address),
                pending_error: Some(SocketError::ConnectionReset),
            }
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            first.join().unwrap(),
            SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(platform_local_address),
                pending_error: None,
            }
        );
        session.close_object_reference(handle).unwrap();

        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        let local_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic TCP bind was not recorded");
        let platform_local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_address.port());
        *provider.state.status_responses.lock().unwrap() = std::collections::VecDeque::from([
            PlatformSocketStatus {
                status: SocketConnectionStatus::Unconnected,
                local_address: None,
                pending_error: None,
            },
            PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: Some(platform_local_address),
                pending_error: None,
            },
        ]);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *provider.state.status_block.lock().unwrap() = Some((started_tx, release_rx));
        let first_session = Arc::clone(&session);
        let first = std::thread::spawn(move || status(&first_session, handle));
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(platform_local_address),
                pending_error: None,
            })
        );
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Err(BrokerError::Internal));
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: Some(platform_local_address),
                pending_error: None,
            })
        );
        session.close_object_reference(handle).unwrap();
    }

    fn check_stream_status_validates_local_address(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let valid = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let SocketOutcome::Completed(wildcard_address) =
            bind(&session, valid, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap()
        else {
            panic!("guest TCP wildcard bind failed");
        };
        assert_eq!(
            connect(&session, valid, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        let observed_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, wildcard_address.port());
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: Some(observed_address),
                pending_error: None,
            });
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        assert_eq!(
            status(&session, valid),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(observed_address),
                pending_error: None,
            })
        );
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before
        );
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: Some(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 1, 10),
                    observed_address.port(),
                )),
                pending_error: None,
            });
        assert_eq!(status(&session, valid), Err(BrokerError::Internal));
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        session.close_object_reference(valid).unwrap();

        let missing_local = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            connect(&session, missing_local, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        {
            let object = session
                .authorized_object(missing_local, ObjectRights::WRITE)
                .unwrap();
            let mut object = object.write();
            let ObjectEntry::Socket(socket) = &mut *object else {
                panic!("socket handle resolved to another object kind");
            };
            socket.local_address = None;
        }
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Connected,
                local_address: None,
                pending_error: None,
            });
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        assert_eq!(status(&session, missing_local), Err(BrokerError::Internal));
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        session.close_object_reference(missing_local).unwrap();

        let invalid_status = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            connect(&session, invalid_status, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );
        let reserved_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic TCP bind was not recorded");
        let observed_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserved_address.port());
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(observed_address),
                pending_error: None,
            });
        let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
        assert_eq!(status(&session, invalid_status), Err(BrokerError::Internal));
        assert_eq!(
            provider.state.retired_sockets.load(Ordering::Relaxed),
            retired_before + 1
        );
        assert_eq!(
            status(&session, invalid_status),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: Some(observed_address),
                pending_error: None,
            })
        );
        session.close_object_reference(invalid_status).unwrap();

        for (platform_connection_status, observed_ip, wrong_port) in [
            (
                SocketConnectionStatus::Connected,
                Ipv4Addr::new(10, 0, 0, 1),
                false,
            ),
            (
                SocketConnectionStatus::Unconnected,
                Ipv4Addr::new(10, 0, 0, 1),
                false,
            ),
            (
                SocketConnectionStatus::Connected,
                HOST_GATEWAY_IPV4_ADDRESS,
                false,
            ),
            (SocketConnectionStatus::Connected, Ipv4Addr::LOCALHOST, true),
        ] {
            let handle = create(
                &session,
                create_request(),
                Arc::new(TestReadinessSink::default()),
            )
            .unwrap();
            let SocketOutcome::Completed(wildcard_address) = bind(
                &session,
                handle,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            )
            .unwrap() else {
                panic!("guest TCP wildcard bind failed");
            };
            assert_eq!(
                connect(&session, handle, loopback_address()),
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
            );
            let observed_port = if wrong_port {
                if wildcard_address.port() == u16::MAX {
                    wildcard_address.port() - 1
                } else {
                    wildcard_address.port() + 1
                }
            } else {
                wildcard_address.port()
            };
            provider
                .state
                .status_responses
                .lock()
                .unwrap()
                .push_back(PlatformSocketStatus {
                    status: platform_connection_status,
                    local_address: Some(SocketAddrV4::new(observed_ip, observed_port)),
                    pending_error: None,
                });

            let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
            assert_eq!(status(&session, handle), Err(BrokerError::Internal));
            assert_eq!(
                provider.state.retired_sockets.load(Ordering::Relaxed),
                retired_before + 1
            );
            let status_calls = provider.state.status_calls.load(Ordering::Relaxed);
            assert_eq!(
                status(&session, handle),
                Ok(SocketStatusResponse {
                    status: SocketConnectionStatus::Failed(SocketError::Other),
                    local_address: Some(wildcard_address),
                    pending_error: None,
                })
            );
            assert_eq!(
                provider.state.status_calls.load(Ordering::Relaxed),
                status_calls
            );
            assert_eq!(
                send(&session, handle, vec![1], SendFlags::NONE),
                Ok(SocketOutcome::Failed(SocketError::NotConnected))
            );
            session.close_object_reference(handle).unwrap();
            assert_eq!(
                provider.state.retired_sockets.load(Ordering::Relaxed),
                retired_before + 1
            );
        }
    }

    fn check_failed_status_preserves_local_address(
        broker: &BrokerCore,
        provider: &TestSocketProvider,
    ) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
        );

        let local_address = *provider
            .state
            .binds
            .lock()
            .unwrap()
            .last()
            .expect("automatic TCP bind was not recorded");
        let observed_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_address.port());
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(PlatformSocketStatus {
                status: SocketConnectionStatus::Failed(SocketError::TimedOut),
                local_address: Some(observed_address),
                pending_error: None,
            });

        let expected = SocketStatusResponse {
            status: SocketConnectionStatus::Failed(SocketError::TimedOut),
            local_address: Some(observed_address),
            pending_error: None,
        };
        assert_eq!(status(&session, handle), Ok(expected));
        assert_eq!(status(&session, handle), Ok(expected));
    }

    const fn create_request() -> CreateSocketRequest {
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Stream,
            protocol: IpProtocol::Tcp,
        }
    }

    const fn create_udp_request() -> CreateSocketRequest {
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
        }
    }

    const fn loopback_address() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)
    }
}
