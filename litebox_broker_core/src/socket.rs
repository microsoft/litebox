// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority for socket policy, guest-visible endpoints, and platform
//! lifecycle.

use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::HashSet;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    CreateSocketRequest, IpProtocol, MAX_SOCKET_TRANSFER_SIZE, MAX_TCP_LISTEN_BACKLOG,
    MAX_UDP_DATAGRAM_SIZE, ReceiveFlags, ReceiveFromFlags, SendFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOutcome, SocketStatusResponse, SocketType,
    TcpOptionName, TcpOptionValue,
};
use litebox_broker_protocol::{BrokerCapabilities, ObjectHandle};
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

/// Fixed guest-visible address of the broker-provided DNS service.
pub const BROKER_DNS_IPV4_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);

fn is_concrete_internal_address(address: Ipv4Addr) -> bool {
    address.is_loopback() || address == GUEST_IPV4_ADDRESS
}

/// Returns whether the IP is unspecified, loopback, or [`GUEST_IPV4_ADDRESS`].
///
/// The port is ignored. [`HOST_GATEWAY_IPV4_ADDRESS`] remains external and
/// subject to destination policy.
#[must_use]
pub fn is_internal_socket_address(address: SocketAddrV4) -> bool {
    address.ip().is_unspecified() || is_concrete_internal_address(*address.ip())
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

/// Shared registration for one exact or wildcard guest transport binding.
///
/// The final owner removes the binding from the broker-wide namespace.
struct GuestPortBinding {
    ports: BrokerSocketPorts,
    transport: GuestTransport,
    key: GuestBindingKey,
}

impl GuestPortBinding {
    fn local_address(&self) -> SocketAddrV4 {
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
/// independent port spaces, and guest ports remain independent of host ports.
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
        if !is_internal_socket_address(requested_address) {
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
    local_address: SocketAddrV4,
    transport: GuestTransport,
}

impl GuestSocketBinding {
    fn new(binding: &GuestPortBinding) -> Self {
        Self {
            local_address: binding.local_address(),
            transport: binding.transport,
        }
    }

    /// Returns the broker-reserved guest-visible local address.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddrV4 {
        self.local_address
    }

    /// Returns whether the original binding used the wildcard address.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.local_address.ip().is_unspecified()
    }

    /// Checks that this value represents a supported guest binding.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.local_address.port() != 0 && is_internal_socket_address(self.local_address)
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
                address.port() == self.local_address.port()
                    && is_concrete_internal_address(*address.ip())
            } else {
                address == self.local_address
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
            if self.local_address.ip().is_loopback() && !is_internal_socket_address(destination) {
                return None;
            }
            return Some(self.local_address);
        }
        let source_ip = if destination.ip().is_loopback() {
            Ipv4Addr::LOCALHOST
        } else {
            GUEST_IPV4_ADDRESS
        };
        Some(SocketAddrV4::new(source_ip, self.local_address.port()))
    }
}

impl fmt::Debug for GuestSocketBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestSocketBinding")
            .field("local_address", &self.local_address)
            .finish_non_exhaustive()
    }
}

impl PartialEq for GuestSocketBinding {
    fn eq(&self, other: &Self) -> bool {
        self.local_address == other.local_address && self.transport == other.transport
    }
}

impl Eq for GuestSocketBinding {}

/// Lease retaining one exact guest TCP source endpoint.
///
/// Core creates this value from a live guest binding when a TCP connection
/// targets the guest namespace. It grants no bind or listen authority. A
/// internal platform path must carry the lease through any queued connection
/// and return it from [`PlatformSocket::accept`]. Dropping the final binding
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
    /// Nonempty bytes received from the stream, no longer than requested.
    Received(Vec<u8>),
    /// The stream's receive direction reached end of stream.
    EndOfStream,
}

/// Owned platform result for one datagram receive.
#[derive(Debug, PartialEq, Eq)]
pub struct PlatformDatagramReceive {
    /// Received prefix, sized to the lesser of the datagram and requested lengths.
    pub data: Vec<u8>,
    /// Original datagram length, no greater than [`MAX_UDP_DATAGRAM_SIZE`].
    pub datagram_length: usize,
    /// Normalized guest-visible source address of the datagram.
    ///
    /// This must be unchanged by [`normalize_socket_destination`]. Platforms
    /// must return a guest sender's stable guest-namespace endpoint and never
    /// expose host-socket endpoints.
    pub source_address: SocketAddrV4,
}

/// Broker-wide socket provider supplied by the host platform.
///
/// The provider creates per-socket [`PlatformSocket`] resources and owns any
/// bookkeeping shared across sockets and sessions. Sessions identify ownership
/// and accounting domains, not separate provider namespaces. Operations on an
/// individual socket belong to [`PlatformSocket`], not this shared provider.
pub trait SocketProvider: Send + Sync {
    /// Returns immutable features implemented by this provider.
    fn capabilities(&self) -> BrokerCapabilities;

    /// Resolves a normalized guest-requested address into a trusted platform route.
    ///
    /// The core authorizes the route's policy address before handing the route
    /// to a platform socket.
    fn route_destination(
        &self,
        destination: SocketAddrV4,
    ) -> Result<SocketOutcome<PlatformSocketDestination>>;

    /// Creates one nonblocking socket resource for a broker session.
    ///
    /// Any provider-retained clones must become inert when
    /// [`PlatformSocket::retire`] is called. On success, the returned socket
    /// retains `readiness` and publishes any nonempty initial snapshot before
    /// returning. On error, the provider releases all resources and session
    /// accounting allocated by the attempt.
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
/// any host resources. A request handler must record the start of a
/// transition before issuing it, and the corresponding synchronous result or
/// asynchronous completion handler must finish that transition.
/// [`status`](PlatformSocket::status) projects that platform-owned state for
/// the guest; core may cache the projection but does not reconstruct
/// host-resource lifecycle state from status.
pub trait PlatformSocket: Send + Sync {
    /// Binds this socket to a local address and echoes the assigned address.
    ///
    /// A broker-managed TCP or UDP socket receives a broker-reserved,
    /// guest-visible address with a nonzero port and must echo it unchanged. A
    /// UDP bind may be entirely logical and need not allocate a host socket.
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
    /// When no connection is pending, returns [`BrokerError::WouldBlock`]. The
    /// returned socket follows the readiness contract of
    /// [`SocketProvider::create`]. On a non-completed return, the provider
    /// releases all resources allocated for an unreturned socket.
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
    /// unchanged from one whose state is indeterminate. Once an external
    /// host-socket connect may have started, implementations must retain enough
    /// platform state to settle or conservatively retire it without
    /// reconstructing its lifecycle during teardown. A guest TCP attempt
    /// receives a source lease. An internal path must move it through to
    /// [`AcceptedPlatformSocket`]; external paths may drop it. Returning
    /// [`PlatformConnectError::PeerUnchanged`] requires releasing the lease;
    /// [`PlatformSocket::retire`] must release one retained by an indeterminate
    /// or in-progress operation. `destination` is a provider-resolved route
    /// already validated and authorized by core.
    fn connect(
        &self,
        destination: PlatformSocketDestination,
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
    /// the socket's connected peer. An explicit destination is a
    /// provider-resolved route already validated and authorized by core.
    /// A temporarily full socket returns [`BrokerError::WouldBlock`]. Partial
    /// successful sends are invalid. Resource failures are broker errors rather
    /// than ordinary socket failures.
    fn send_to(
        &self,
        data: Vec<u8>,
        flags: SendFlags,
        destination: Option<PlatformSocketDestination>,
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
    /// is smaller, and zero-length datagrams are successful receives. When no
    /// datagram is available, returns [`BrokerError::WouldBlock`]. The source
    /// address follows [`PlatformDatagramReceive::source_address`].
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
    /// from `Connecting` to `Connected` or `Failed`; it must not report
    /// `Unconnected`. For datagram sockets, the broker owns the peer state, so
    /// the platform reports `Unconnected` or `Connected` and uses
    /// `pending_error` for asynchronous failures. Any reported local address
    /// must preserve the broker-reserved port and have an IP accepted by
    /// [`is_internal_socket_address`]. An unbound datagram must not report a
    /// local address, and host addresses must never be exposed.
    fn status(&self) -> Result<PlatformSocketStatus>;

    /// Synchronously and idempotently ends this socket's platform authority.
    ///
    /// Provider-retained clones must be inert when this method returns.
    fn retire(&self);

    /// Returns the authoritative cached readiness snapshot.
    ///
    /// Update this snapshot before publishing the corresponding readiness
    /// change. Reading it must not require access to a host resource that
    /// retirement may already have removed.
    fn readiness(&self) -> ReadinessFlags;
}

/// A trusted platform route for a normalized guest-requested destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformSocketDestination {
    /// A destination served by another guest socket in this broker core.
    Internal(SocketAddrV4),
    /// A destination served by the host networking stack.
    External {
        /// The address visible to the guest.
        guest_address: SocketAddrV4,
        /// The address against which broker policy is evaluated.
        policy_address: SocketAddrV4,
        /// The address passed to the host networking stack.
        host_address: SocketAddrV4,
    },
    /// The broker-provided DNS service.
    BrokerDns(SocketAddrV4),
}

impl PlatformSocketDestination {
    /// Constructs the ordinary internal or external route for a normalized address.
    #[must_use]
    pub fn standard(destination: SocketAddrV4) -> Self {
        if is_internal_socket_address(destination) {
            Self::Internal(destination)
        } else {
            Self::External {
                guest_address: destination,
                policy_address: destination,
                host_address: host_socket_destination(destination),
            }
        }
    }

    /// Returns the address visible to the guest.
    #[must_use]
    pub fn guest_address(self) -> SocketAddrV4 {
        match self {
            Self::Internal(address) | Self::BrokerDns(address) => address,
            Self::External { guest_address, .. } => guest_address,
        }
    }

    /// Returns the address against which broker policy is evaluated.
    ///
    /// Broker services do not require a native destination policy rule.
    #[must_use]
    pub fn policy_address(self) -> Option<SocketAddrV4> {
        match self {
            Self::Internal(address) => Some(address),
            Self::External { policy_address, .. } => Some(policy_address),
            Self::BrokerDns(_) => None,
        }
    }

    fn is_valid_for(self, requested: SocketAddrV4) -> bool {
        if self.guest_address() != requested {
            return false;
        }
        match self {
            Self::Internal(address) => is_internal_socket_address(address),
            Self::External {
                policy_address,
                host_address,
                ..
            } => {
                !is_internal_socket_address(requested)
                    && policy_address.port() == requested.port()
                    && normalize_socket_destination(policy_address) == Ok(policy_address)
                    && !is_internal_socket_address(policy_address)
                    && host_address == host_socket_destination(policy_address)
            }
            Self::BrokerDns(address) => address == SocketAddrV4::new(BROKER_DNS_IPV4_ADDRESS, 53),
        }
    }
}

/// Provider for broker configurations that deliberately disable sockets.
pub struct UnsupportedSocketProvider;

impl SocketProvider for UnsupportedSocketProvider {
    fn capabilities(&self) -> BrokerCapabilities {
        BrokerCapabilities::NONE
    }

    fn route_destination(
        &self,
        destination: SocketAddrV4,
    ) -> Result<SocketOutcome<PlatformSocketDestination>> {
        Ok(SocketOutcome::Completed(
            PlatformSocketDestination::standard(destination),
        ))
    }

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

fn route_and_authorize_destination(
    session: &BrokerSession,
    create_request: CreateSocketRequest,
    requested: SocketAddrV4,
) -> Result<SocketOutcome<PlatformSocketDestination>> {
    let destination = match session.core.socket_provider.route_destination(requested)? {
        SocketOutcome::Completed(destination) => destination,
        SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
    };
    let broker_dns_address = SocketAddrV4::new(BROKER_DNS_IPV4_ADDRESS, 53);
    if requested == broker_dns_address {
        match destination {
            PlatformSocketDestination::BrokerDns(_) => {
                if !is_udp(create_request)
                    || !session
                        .core
                        .socket_provider
                        .capabilities()
                        .contains(BrokerCapabilities::BROKER_DNS)
                {
                    return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
                }
            }
            PlatformSocketDestination::Internal(_) | PlatformSocketDestination::External { .. } => {
                return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
            }
        }
    }
    if destination.policy_address() == Some(broker_dns_address) {
        return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
    }
    if !destination.is_valid_for(requested) {
        return Err(BrokerError::Internal);
    }

    let Some(policy_address) = destination.policy_address() else {
        return if is_udp(create_request) {
            Ok(SocketOutcome::Completed(destination))
        } else {
            Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
        };
    };

    // Destination denial is an operation-level socket failure. Failures while
    // evaluating policy remain broker errors.
    match session.core.policy.authorize_socket_connect(
        session.caller_credential,
        create_request.protocol,
        policy_address,
    ) {
        Ok(()) => Ok(SocketOutcome::Completed(destination)),
        Err(BrokerError::PolicyDenied) => Ok(SocketOutcome::Failed(SocketError::PolicyDenied)),
        Err(error) => Err(error),
    }
}

/// Starts a nonblocking connection attempt.
///
/// An authorized attempt first binds an unbound socket. TCP connected and
/// failed states are terminal. UDP connects complete synchronously, and a
/// failed attempt preserves the previous peer. Policy denial is a per-request
/// [`SocketOutcome::Failed`] that also preserves existing state.
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
    let requested_destination = match normalize_socket_destination(address) {
        Ok(destination) => destination,
        Err(error) => return Ok(SocketOutcome::Failed(error)),
    };

    let destination =
        match route_and_authorize_destination(session, create_request, requested_destination)? {
            SocketOutcome::Completed(destination) => destination,
            SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
        };

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
        .source_address_for_destination(destination.guest_address())
        .is_none()
    {
        finish_connect(&object, SocketConnectionStatus::Unconnected);
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let guest_source_lease = match resource.source_lease_for_connect(destination.guest_address()) {
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

/// Starts or reconfigures a TCP listener in the broker's guest network
/// namespace.
///
/// An unbound socket is first bound to an ephemeral loopback endpoint.
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
    let (resource, create_request, resource_retired) =
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
/// the platform. A temporarily full socket returns
/// [`BrokerError::WouldBlock`].
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
            Ok(destination) => {
                match route_and_authorize_destination(session, create_request, destination)? {
                    SocketOutcome::Completed(destination) => Some(destination),
                    SocketOutcome::Failed(error) => {
                        return Ok(SocketOutcome::Failed(error));
                    }
                }
            }
            Err(error) => return Ok(SocketOutcome::Failed(error)),
        },
        None => None,
    };
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
            .source_address_for_destination(destination.guest_address())
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
    let (resource, create_request, resource_retired) =
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
///
/// When no datagram is available, returns [`BrokerError::WouldBlock`].
pub fn receive_from(
    session: &BrokerSession,
    handle: ObjectHandle,
    length: usize,
    flags: ReceiveFromFlags,
) -> Result<SocketOutcome<PlatformDatagramReceive>> {
    if flags.has_unsupported_bits() || length > MAX_UDP_DATAGRAM_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (resource, create_request, resource_retired) =
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
    let (resource, create_request, resource_retired) =
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
    let (resource, create_request, resource_retired) =
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
/// Read, write, and both apply to TCP and UDP but return `NotConnected` for a
/// TCP listener. Abort and stop-listening are TCP-only. Stopping an active
/// listener with `Completed` or `Failed(NotConnected)` transitions it to
/// `Failed(NotConnected)`.
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
/// Stream queries reconcile asynchronous connection completion. Datagram
/// queries preserve broker-owned peer state while consuming platform errors,
/// refining the local address, and validating the snapshot. A platform report
/// that contradicts broker-owned state retires the socket, latches
/// `Failed(Other)`, and returns [`BrokerError::Internal`].
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
    let Some(broker_local_address) = socket.local_address else {
        socket.listening = false;
        socket.connection_status = SocketConnectionStatus::Failed(SocketError::Other);
        socket.resource_retired = true;
        drop(object);
        resource.retire();
        return Err(BrokerError::Internal);
    };
    if let Some(observed) = platform_status.local_address {
        let invalid_local_address =
            observed.port() != broker_local_address.port() || !is_internal_socket_address(observed);
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
    // Do not overwrite a concurrent terminal transition.
    if socket.connection_status == SocketConnectionStatus::Connecting {
        socket.connection_status = platform_status.status;
    }
    Ok(SocketStatusResponse {
        status: socket.connection_status,
        local_address: socket.local_address,
        pending_error: platform_status.pending_error,
    })
}

/// Retries once if a concurrent datagram connect replaces the peer mid-query.
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
                broker_address.port() != observed.port() || !is_internal_socket_address(observed)
            }
            _ => false,
        };
        if invalid_local_address {
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
            // A retry after consuming an error could consume another; after
            // one retry, return broker state rather than apply an unordered
            // snapshot.
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
) -> Result<(Arc<SocketResource>, CreateSocketRequest, bool)> {
    let object = session.authorized_object(handle, required_rights)?;
    let object = object.read();
    let ObjectEntry::Socket(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok((
        Arc::clone(&socket.resource),
        socket.create_request,
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
    destination: PlatformSocketDestination,
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
        .source_address_for_destination(destination.guest_address())
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
        if !is_internal_socket_address(destination) {
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
pub(crate) mod tests;
