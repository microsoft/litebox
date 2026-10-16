// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority for socket policy, guest-visible endpoints, and platform
//! lifecycle.

use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::AtomicUsize;
use core::time::Duration;

use hashbrown::HashSet;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    CreateSocketRequest, IpProtocol, MAX_SOCKET_TRANSFER_SIZE, MAX_TCP_LISTEN_BACKLOG,
    MAX_UDP_DATAGRAM_SIZE, ReceiveFlags, ReceiveFromFlags, SendFlags, ShutdownMode,
    SocketConnectionStatus, SocketError, SocketOptionName, SocketOptionValue, SocketOutcome,
    SocketType,
};
use spin::{Mutex, RwLock};

use crate::id::IdAllocator;
use crate::object::{ObjectEntry, ObjectRights, StatusFlags};
use crate::process::PendingObjectReference;
use crate::quota::QuotaReservation;
use crate::readiness::{ReadinessRegistration, ReadinessSink, SharedReadinessWatchers};
use crate::{BrokerCore, BrokerError, BrokerProcess, ProcessId, Result};

const DEFAULT_TCP_LISTEN_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
const DEFAULT_LOCAL_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
const FIRST_EPHEMERAL_PORT: u16 = 49152;

/// Fixed broker-wide private IPv4 identity of the shared guest network.
pub const GUEST_IPV4_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

/// Fixed guest-visible address used to reach host-loopback services.
pub const HOST_GATEWAY_IPV4_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1);

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
/// Socket resources own reservations. Processes remain ownership, quota, and
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
/// bookkeeping shared across sockets and processes. Authority keys identify ownership
/// and accounting domains, not separate provider namespaces. Operations on an
/// individual socket belong to [`PlatformSocket`], not this shared provider.
pub trait SocketProvider: Send + Sync {
    /// Creates one nonblocking socket resource for a broker process.
    ///
    /// Any provider-retained clones must become inert when
    /// [`PlatformSocket::retire`] is called. On success, the returned socket
    /// retains `readiness` and publishes any nonempty initial snapshot before
    /// returning. On error, the provider releases all resources and process
    /// process accounting allocated by the attempt.
    fn create(
        &self,
        process_authority: ProcessId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformSocket>>;

    /// Releases remaining provider state charged to a process.
    ///
    /// Core calls this once, after the process has released its references
    /// and every socket charged to it has retired, and does not reuse the
    /// process's ID before then. A socket stays charged to the process that
    /// created it, even while other processes share it.
    ///
    /// This is a teardown and accounting boundary, not a separate network
    /// namespace; it must not disturb endpoints owned by other processes.
    fn close_process(&self, process_authority: ProcessId);
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
    /// [`SocketProvider::create`] and is charged to the process this listener
    /// is charged to. On a non-completed return, the provider releases all
    /// resources allocated for an unreturned socket.
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
    /// A temporarily full socket returns [`BrokerError::WouldBlock`]. A socket
    /// shut down for writing fails with `Shutdown`. Ordinary network failures
    /// return [`SocketOutcome::Failed`].
    fn send(&self, data: Vec<u8>, flags: SendFlags) -> Result<SocketOutcome<usize>>;

    /// Sends one complete datagram without waiting for platform readiness.
    ///
    /// A destination is required for an unconnected socket and omitted to use
    /// the socket's connected peer. An explicit destination is normalized but
    /// remains guest-visible; the provider must validate it with
    /// [`normalize_socket_destination`] before choosing a host-socket target.
    /// A temporarily full socket returns [`BrokerError::WouldBlock`], and a
    /// socket shut down for writing fails with `Shutdown`. Partial successful
    /// sends are invalid. Resource failures are broker errors rather than
    /// ordinary socket failures.
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
    ///
    /// `reader` identifies the reference receiving. A peek longer than one
    /// transfer takes one request at each offset, starting from zero, by the
    /// same reader. A request past offset zero returns
    /// [`BrokerError::WouldBlock`] if another receive came after that reader's
    /// request at offset zero, since the bytes it would return might not
    /// follow those already returned.
    fn receive(
        &self,
        reader: ObjectHandle,
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

    /// Sets a TCP socket's [`SocketOptionValue::NoDelay`] or
    /// [`SocketOptionValue::KeepAlive`], which the transport implements.
    ///
    /// A socket accepted from a listener starts with the listener's values.
    fn set_tcp_option(&self, value: SocketOptionValue) -> Result<()>;

    /// Reads a TCP socket's [`SocketOptionName::NoDelay`] or
    /// [`SocketOptionName::KeepAlive`].
    fn get_tcp_option(&self, name: SocketOptionName) -> Result<SocketOptionValue>;

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

/// Provider for broker configurations that deliberately disable sockets.
pub struct UnsupportedSocketProvider;

impl SocketProvider for UnsupportedSocketProvider {
    fn create(
        &self,
        _process_authority: ProcessId,
        _request: CreateSocketRequest,
        _readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformSocket>> {
        Err(BrokerError::UnsupportedOperation)
    }

    fn close_process(&self, _process_authority: ProcessId) {}
}

/// Creates a broker-owned socket.
///
/// The socket starts with the status flags `request.flags`, which must be
/// within [`FileOpenFlags::STATUS`].
pub fn create(
    process: &BrokerProcess,
    request: CreateSocketRequest,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let status = StatusFlags::new(request.flags)?;
    let rights = process
        .core
        .policy
        .authorize_socket_create(process.caller_credential, request)?;
    let account = process.socket_account()?;
    let quota = Arc::new(reserve_socket(&process.core, &account)?);
    let reference = process.reserve_object_reference(rights)?;
    let (registration, socket_sink, readiness) =
        socket_readiness(&reference, readiness_sink, quota)?;
    let platform_socket =
        match process
            .core
            .socket_provider
            .create(process.id, request, readiness.clone())
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
        readiness_sink: socket_sink,
        port_binding: Mutex::new(None),
        guest_source_lease: Mutex::new(None),
        error_queries: Mutex::new(()),
        account,
    });
    let socket = SocketObject::new(resource, request, status);
    socket.sync_readiness();
    reference.commit_with_readiness(ObjectEntry::Socket(socket), Some(registration))
}

/// Starts a nonblocking connection attempt, or reports one already started.
///
/// A stream that is listening or has reported its connection fails with
/// `AlreadyConnected`, and while an earlier attempt is unreported, a stream
/// reports it as [`check_connect`] does, except that an attempt still in
/// progress fails with `AlreadyInProgress`. Port zero and the unspecified
/// address fail with `ConnectionRefused` without changing the socket.
/// Otherwise an authorized attempt first binds an unbound socket.
/// Connect never reports [`SocketConnectionStatus::Failed`]: a failed attempt
/// is a [`SocketOutcome::Failed`], after which a stream is unconnected but
/// fails every later attempt the same way. UDP connects complete
/// synchronously, and a failed attempt preserves the previous peer. Policy
/// denial is also a [`SocketOutcome::Failed`] that preserves existing state.
pub fn connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let result = if read_socket(&object, |socket| is_udp(socket.create_request))? {
        connect_datagram(process, &object, address)
    } else {
        connect_stream(process, &object, address)
    };
    sync_readiness(&object);
    result
}

fn connect_stream(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    loop {
        let (view, connected) = read_socket(object, |socket| {
            (socket.view(), socket.listening || socket.connect_reported)
        })?;
        // The socket's state is reported before any problem with the address.
        if connected {
            return Ok(SocketOutcome::Failed(SocketError::AlreadyConnected));
        }
        if view == SocketConnectionStatus::Unconnected {
            break;
        }
        match check_connect_stream(object)? {
            SocketOutcome::Completed(SocketConnectionStatus::Connecting) => {
                return Ok(SocketOutcome::Failed(SocketError::AlreadyInProgress));
            }
            // The attempt seen above was abandoned without effect, so this connect starts over
            // on the unconnected socket.
            SocketOutcome::Completed(SocketConnectionStatus::Unconnected) => {}
            outcome => return Ok(outcome),
        }
    }
    if is_unaddressable(address) {
        return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
    }
    let status = match transport_connect(process, object, address)? {
        SocketOutcome::Completed(status) => status,
        SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
    };
    write_socket(object, |socket| match status {
        SocketConnectionStatus::Connected => {
            socket.connect_reported = true;
            SocketOutcome::Completed(status)
        }
        SocketConnectionStatus::Failed(error) => {
            // This attempt reports the failure, so it is not also pending.
            let _ = socket.disconnect();
            SocketOutcome::Failed(error)
        }
        status => SocketOutcome::Completed(status),
    })
}

fn connect_datagram(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    if is_unaddressable(address) {
        return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
    }
    Ok(match transport_connect(process, object, address)? {
        SocketOutcome::Completed(SocketConnectionStatus::Failed(error)) => {
            SocketOutcome::Failed(error)
        }
        outcome => outcome,
    })
}

/// Returns whether a connect to `address` is refused without an attempt.
fn is_unaddressable(address: SocketAddrV4) -> bool {
    address.port() == 0 || address.ip().is_unspecified()
}

/// Reports the progress of a connection attempt.
///
/// A connected stream is reported connected, so a later [`connect`] fails
/// with `AlreadyConnected`. A failed stream attempt is reported as a
/// [`SocketOutcome::Failed`] with its error, unless another operation already
/// reported it, leaving `ConnectionAborted`, and leaves the socket
/// unconnected. A socket without an attempt reports `Unconnected`.
pub fn check_connect(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let result = if read_socket(&object, |socket| is_udp(socket.create_request))? {
        refresh(&object, true);
        read_socket(&object, |socket| match socket.view() {
            SocketConnectionStatus::Failed(error) => SocketOutcome::Failed(error),
            SocketConnectionStatus::Connected => {
                SocketOutcome::Completed(SocketConnectionStatus::Connected)
            }
            _ => SocketOutcome::Completed(SocketConnectionStatus::Unconnected),
        })
    } else {
        check_connect_stream(&object)
    };
    sync_readiness(&object);
    result
}

fn check_connect_stream(
    object: &RwLock<ObjectEntry>,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let (status, _) = transport_status(object, true)?;
    write_socket(object, |socket| match status.status {
        SocketConnectionStatus::Failed(_) => SocketOutcome::Failed(
            socket
                .disconnect()
                .unwrap_or(SocketError::ConnectionAborted),
        ),
        SocketConnectionStatus::Connected => {
            socket.connect_reported = true;
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        }
        status => SocketOutcome::Completed(status),
    })
}

/// Returns a socket's local address, or if `peer` is set, the peer's address
/// while connected.
pub fn get_name(
    process: &BrokerProcess,
    handle: ObjectHandle,
    peer: bool,
) -> Result<Option<SocketAddrV4>> {
    let object = process
        .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    read_socket(&object, |_| ())?;
    refresh(&object, !peer);
    let address = read_socket(&object, |socket| {
        if peer {
            socket
                .peer_address
                .filter(|_| socket.view() == SocketConnectionStatus::Connected)
        } else {
            socket.local_address
        }
    });
    sync_readiness(&object);
    address
}

/// Takes a socket's oldest pending error.
pub fn take_error(process: &BrokerProcess, handle: ObjectHandle) -> Result<Option<SocketError>> {
    let object = process
        .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    read_socket(&object, |_| ())?;
    refresh(&object, true);
    let error = take_pending_error(&object);
    sync_readiness(&object);
    Ok(error)
}

/// Makes `error` a socket's oldest pending error.
///
/// A socket keeps at most two pending errors, so this may discard the newest.
pub fn set_error(process: &BrokerProcess, handle: ObjectHandle, error: SocketError) -> Result<()> {
    let object = process
        .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    write_socket(&object, |socket| socket.errors.prepend(error))?;
    sync_readiness(&object);
    Ok(())
}

/// Starts a transport connection attempt.
///
/// TCP connected and failed states are terminal. UDP connects complete
/// synchronously, and a failed attempt preserves the previous peer.
fn transport_connect(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let create_request = read_socket(object, |socket| socket.create_request)?;

    if address.port() == 0 {
        return Ok(SocketOutcome::Failed(SocketError::ConnectionRefused));
    }
    let destination = match normalize_socket_destination(address) {
        Ok(destination) => destination,
        Err(error) => return Ok(SocketOutcome::Failed(error)),
    };

    // Destination denial is an operation-level socket failure. Failures while
    // evaluating policy remain broker errors.
    match process.core.policy.authorize_socket_connect(
        process.caller_credential,
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
        return transport_connect_datagram(process, object, create_request, destination);
    }

    let (resource, needs_bind) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        // Another connect may have changed the state since the caller checked it.
        if socket.listening || socket.connect_reported {
            return Ok(SocketOutcome::Failed(SocketError::AlreadyConnected));
        }
        if socket.view() == SocketConnectionStatus::Connecting {
            return Ok(SocketOutcome::Failed(SocketError::AlreadyInProgress));
        }
        if socket.resource_retired {
            return Ok(SocketOutcome::Completed(socket.connection_status));
        }
        if socket.configuration_in_flight {
            return Ok(SocketOutcome::Failed(SocketError::Other));
        }
        if socket.connection_status != SocketConnectionStatus::Unconnected {
            return Ok(SocketOutcome::Completed(socket.connection_status));
        }
        socket.connect_in_flight = true;
        // The attempt replaces any earlier disconnection.
        socket.disconnected = false;
        (Arc::clone(&socket.resource), socket.local_address.is_none())
    };
    if needs_bind {
        let binding =
            match reserve_and_bind(process, create_request, &resource, DEFAULT_LOCAL_ADDRESS) {
                Ok(binding) => binding,
                Err(error) => {
                    abandon_connect(object);
                    return Err(error);
                }
            };
        match binding {
            ReserveAndBindOutcome::Completed(local_address, port_binding) => {
                attach_binding(object, local_address, port_binding)?;
            }
            ReserveAndBindOutcome::Failed(error) => {
                abandon_connect(object);
                return Ok(SocketOutcome::Failed(error));
            }
            ReserveAndBindOutcome::Retired(port_binding) => {
                finish_retired_connect(object);
                retire_before_releasing_binding(&resource, port_binding);
                return Err(BrokerError::Internal);
            }
        }
    }
    if resource
        .source_address_for_destination(destination)
        .is_none()
    {
        abandon_connect(object);
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let guest_source_lease = match resource.source_lease_for_connect(destination) {
        Ok(lease) => lease,
        Err(error) => {
            finish_retired_connect(object);
            resource.retire();
            return Err(error);
        }
    };
    let status = match resource
        .platform_socket
        .connect(destination, guest_source_lease)
    {
        Ok(SocketConnectionStatus::Unconnected) => {
            finish_retired_connect(object);
            resource.retire();
            return Err(BrokerError::Internal);
        }
        Ok(status) => status,
        Err(PlatformConnectError::PeerUnchanged(error)) => {
            abandon_connect(object);
            return Err(error);
        }
        Err(PlatformConnectError::PeerIndeterminate(error)) => {
            finish_retired_connect(object);
            resource.retire();
            return Err(error);
        }
    };
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.connect_in_flight = false;
        socket.connection_status = status;
        socket.peer_address = Some(destination);
    }
    Ok(SocketOutcome::Completed(status))
}

/// Binds a socket to a supported guest-namespace address.
pub fn bind(
    process: &BrokerProcess,
    handle: ObjectHandle,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketAddrV4>> {
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let result = transport_bind(process, &object, address);
    sync_readiness(&object);
    result
}

fn transport_bind(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketAddrV4>> {
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
    match reserve_and_bind(process, create_request, &resource, address) {
        Ok(ReserveAndBindOutcome::Completed(local_address, port_binding)) => {
            finish_configuration(object, Some(local_address), Some(port_binding), false)?;
            Ok(SocketOutcome::Completed(local_address))
        }
        Ok(ReserveAndBindOutcome::Failed(error)) => {
            finish_configuration(object, None, None, false)?;
            Ok(SocketOutcome::Failed(error))
        }
        Ok(ReserveAndBindOutcome::Retired(port_binding)) => {
            finish_retired_configuration(object, None, None)?;
            retire_before_releasing_binding(&resource, port_binding);
            Err(BrokerError::Internal)
        }
        Err(error) => {
            finish_configuration(object, None, None, false)?;
            Err(error)
        }
    }
}

/// Starts or reconfigures a TCP listener in the broker's guest network
/// namespace.
///
/// An unbound socket is first bound to an ephemeral loopback endpoint.
pub fn listen(
    process: &BrokerProcess,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<SocketOutcome<SocketAddrV4>> {
    if backlog > MAX_TCP_LISTEN_BACKLOG {
        return Err(BrokerError::UnsupportedOperation);
    }
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let result = transport_listen(process, &object, backlog);
    sync_readiness(&object);
    result
}

fn transport_listen(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    backlog: u32,
) -> Result<SocketOutcome<SocketAddrV4>> {
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
            process,
            create_request,
            &resource,
            DEFAULT_TCP_LISTEN_ADDRESS,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                finish_configuration(object, None, None, false)?;
                return Err(error);
            }
        };
        match binding {
            ReserveAndBindOutcome::Completed(address, binding) => {
                local_address = Some(address);
                port_binding = Some(binding);
            }
            ReserveAndBindOutcome::Failed(error) => {
                finish_configuration(object, None, None, false)?;
                return Ok(SocketOutcome::Failed(error));
            }
            ReserveAndBindOutcome::Retired(port_binding) => {
                finish_retired_configuration(object, None, None)?;
                retire_before_releasing_binding(&resource, port_binding);
                return Err(BrokerError::Internal);
            }
        }
    }

    match resource.platform_socket.listen(backlog) {
        Ok(SocketOutcome::Completed(address)) => {
            if local_address != Some(address) {
                finish_retired_configuration(object, local_address, port_binding)?;
                resource.retire();
                return Err(BrokerError::Internal);
            }
            finish_configuration(object, local_address, port_binding, true)?;
            Ok(SocketOutcome::Completed(address))
        }
        Ok(SocketOutcome::Failed(error)) => {
            finish_configuration(object, local_address, port_binding, false)?;
            Ok(SocketOutcome::Failed(error))
        }
        Err(error) => {
            finish_configuration(object, local_address, port_binding, false)?;
            Err(error)
        }
    }
}

/// Accepts one pending TCP connection and creates a broker socket capability.
///
/// The accepted socket starts with the status flags `flags`, which must be
/// within [`FileOpenFlags::STATUS`], and default options other than those
/// [`PlatformSocket::set_tcp_option`] sets. When no connection is pending,
/// fails with [`BrokerError::WouldBlock`], or with
/// [`BrokerError::NonBlockingWouldBlock`] if the listener is non-blocking.
pub fn accept(
    process: &BrokerProcess,
    handle: ObjectHandle,
    flags: FileOpenFlags,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<SocketOutcome<AcceptedBrokerSocket>> {
    let status = StatusFlags::new(flags)?;
    let listener = process.authorized_object(handle, ObjectRights::WAIT)?;
    let (listener_resource, create_request, nonblocking) = {
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
        (
            Arc::clone(&socket.resource),
            socket.create_request,
            socket.status.nonblocking(),
        )
    };
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    // The provider charges an accepted socket to its listener's process.
    let quota = Arc::new(reserve_socket(&process.core, &listener_resource.account)?);
    let reference = process.reserve_object_reference(rights)?;
    let (registration, socket_sink, readiness) =
        socket_readiness(&reference, readiness_sink, quota)?;
    let accepted = match listener_resource.platform_socket.accept(readiness.clone()) {
        Ok(SocketOutcome::Completed(accepted)) => accepted,
        Ok(SocketOutcome::Failed(error)) => {
            readiness.retire();
            return Ok(SocketOutcome::Failed(error));
        }
        Err(error) => {
            readiness.retire();
            return Err(would_block_error(error, nonblocking));
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
        readiness_sink: socket_sink,
        port_binding: Mutex::new(None),
        guest_source_lease: Mutex::new(Some(guest_source_lease)),
        error_queries: Mutex::new(()),
        account: Arc::clone(&listener_resource.account),
    });
    let accepted_socket = SocketObject::new_connected(
        resource,
        create_request,
        status,
        local_address,
        remote_address,
    );
    accepted_socket.sync_readiness();
    let handle = reference
        .commit_with_readiness(ObjectEntry::Socket(accepted_socket), Some(registration))?;
    Ok(SocketOutcome::Completed(AcceptedBrokerSocket {
        handle,
        local_address,
        remote_address,
    }))
}

/// Sends TCP stream bytes without waiting for readiness.
///
/// A socket shut down for writing fails with `Shutdown` once any connection
/// attempt has finished, and an unconnected socket fails with `NotConnected`.
/// A temporarily full socket, or one whose connection attempt is still being
/// started, fails with [`BrokerError::WouldBlock`], or with
/// [`BrokerError::NonBlockingWouldBlock`] if the socket is non-blocking.
pub fn send(
    process: &BrokerProcess,
    handle: ObjectHandle,
    data: Vec<u8>,
    flags: SendFlags,
) -> Result<SocketOutcome<usize>> {
    if flags.has_unsupported_bits() || data.len() > MAX_SOCKET_TRANSFER_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let result = send_stream(&object, data, flags);
    sync_readiness(&object);
    result
}

fn send_stream(
    object: &RwLock<ObjectEntry>,
    data: Vec<u8>,
    flags: SendFlags,
) -> Result<SocketOutcome<usize>> {
    let (create_request, write_shutdown, view, connect_in_flight, nonblocking) =
        read_socket(object, |socket| {
            (
                socket.create_request,
                socket.write_shutdown,
                socket.view(),
                socket.connect_in_flight,
                socket.status.nonblocking(),
            )
        })?;
    if !is_tcp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if write_shutdown {
        // Wait for a connection attempt, and report its failure, before
        // reporting a shutdown recorded while connecting.
        if view == SocketConnectionStatus::Connecting {
            refresh(object, false);
            let connecting = read_socket(object, |socket| {
                socket.view() == SocketConnectionStatus::Connecting && socket.errors.is_empty()
            })?;
            if connecting {
                return Err(would_block_error(BrokerError::WouldBlock, nonblocking));
            }
        }
        return Ok(SocketOutcome::Failed(SocketError::Shutdown));
    }
    if matches!(
        view,
        SocketConnectionStatus::Unconnected | SocketConnectionStatus::Failed(_)
    ) {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    // The transport may not have started connecting yet.
    if connect_in_flight {
        return Err(would_block_error(BrokerError::WouldBlock, nonblocking));
    }
    let outcome = transport_send(object, data, flags)?;
    if let SocketOutcome::Failed(_) = outcome {
        refresh_after_failure(object);
    }
    Ok(outcome)
}

fn transport_send(
    object: &RwLock<ObjectEntry>,
    data: Vec<u8>,
    flags: SendFlags,
) -> Result<SocketOutcome<usize>> {
    let length = data.len();
    let state = socket_state(object)?;
    if state.resource_retired {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let outcome = state
        .resource
        .platform_socket
        .send(data, flags)
        .map_err(|error| would_block_error(error, state.nonblocking))?;
    if let SocketOutcome::Completed(sent) = outcome
        && (sent > length || (length != 0 && sent == 0))
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Sends one complete datagram without waiting for readiness.
///
/// A pending error fails the send and is consumed, and a socket shut down for
/// writing fails with `Shutdown`. Without `destination`, an unconnected
/// socket fails with `DestinationAddressRequired`. The first valid send with
/// an explicit destination on an unbound datagram socket reserves and binds a
/// guest-visible local endpoint before invoking the platform. A temporarily
/// full socket fails with a pending error if there is one, and otherwise with
/// [`BrokerError::WouldBlock`], or with [`BrokerError::NonBlockingWouldBlock`]
/// if the socket is non-blocking.
pub fn send_to(
    process: &BrokerProcess,
    handle: ObjectHandle,
    data: Vec<u8>,
    flags: SendFlags,
    destination: Option<SocketAddrV4>,
) -> Result<SocketOutcome<usize>> {
    if flags.has_unsupported_bits() || data.len() > MAX_UDP_DATAGRAM_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let result = send_datagram(process, &object, data, flags, destination);
    sync_readiness(&object);
    result
}

fn send_datagram(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    data: Vec<u8>,
    flags: SendFlags,
    destination: Option<SocketAddrV4>,
) -> Result<SocketOutcome<usize>> {
    if !read_socket(object, |socket| is_udp(socket.create_request))? {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if let Some(error) = take_pending_error(object) {
        return Ok(SocketOutcome::Failed(error));
    }
    let (write_shutdown, view) =
        read_socket(object, |socket| (socket.write_shutdown, socket.view()))?;
    if write_shutdown {
        return Ok(SocketOutcome::Failed(SocketError::Shutdown));
    }
    if destination.is_none() && view != SocketConnectionStatus::Connected {
        return Ok(SocketOutcome::Failed(
            SocketError::DestinationAddressRequired,
        ));
    }
    finish_datagram_transfer(
        object,
        transport_send_to(process, object, data, flags, destination),
    )
}

/// Reports a datagram transfer's pending error in place of a would-block
/// failure, and records any error that follows a failed transfer.
fn finish_datagram_transfer<T>(
    object: &RwLock<ObjectEntry>,
    result: Result<SocketOutcome<T>>,
) -> Result<SocketOutcome<T>> {
    match result {
        Err(error @ (BrokerError::WouldBlock | BrokerError::NonBlockingWouldBlock)) => {
            match take_pending_error(object) {
                Some(error) => Ok(SocketOutcome::Failed(error)),
                None => Err(error),
            }
        }
        Ok(SocketOutcome::Failed(error)) => {
            refresh(object, true);
            Ok(SocketOutcome::Failed(error))
        }
        result => result,
    }
}

/// Sends one datagram, first binding an unbound socket.
fn transport_send_to(
    process: &BrokerProcess,
    object: &RwLock<ObjectEntry>,
    data: Vec<u8>,
    flags: SendFlags,
    destination: Option<SocketAddrV4>,
) -> Result<SocketOutcome<usize>> {
    let length = data.len();
    let create_request = read_socket(object, |socket| socket.create_request)?;
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
        match process.core.policy.authorize_socket_connect(
            process.caller_credential,
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
    let (resource, needs_bind, nonblocking) = {
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
        (
            Arc::clone(&socket.resource),
            needs_bind,
            socket.status.nonblocking(),
        )
    };
    if needs_bind {
        match reserve_and_bind(process, create_request, &resource, DEFAULT_LOCAL_ADDRESS) {
            Ok(ReserveAndBindOutcome::Completed(local_address, port_binding)) => {
                finish_configuration(object, Some(local_address), Some(port_binding), false)?;
            }
            Ok(ReserveAndBindOutcome::Failed(error)) => {
                finish_configuration(object, None, None, false)?;
                return Ok(SocketOutcome::Failed(error));
            }
            Ok(ReserveAndBindOutcome::Retired(port_binding)) => {
                finish_retired_configuration(object, None, None)?;
                retire_before_releasing_binding(&resource, port_binding);
                return Err(BrokerError::Internal);
            }
            Err(error) => {
                finish_configuration(object, None, None, false)?;
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
    let outcome = resource
        .platform_socket
        .send_to(data, flags, destination)
        .map_err(|error| would_block_error(error, nonblocking))?;
    if let SocketOutcome::Completed(sent) = outcome
        && sent != length
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Receives TCP stream bytes without waiting for readiness.
///
/// An unconnected socket fails with `NotConnected`, or with `Shutdown` if it
/// was shut down for reading and has no pending error, and a failed
/// connection reports end of stream. A socket shut down for reading fails
/// with `Shutdown` instead of waiting. A temporarily empty socket, or one
/// whose connection attempt is still being started, fails with
/// [`BrokerError::WouldBlock`], or with [`BrokerError::NonBlockingWouldBlock`]
/// if the socket is non-blocking.
pub fn receive(
    process: &BrokerProcess,
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
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let result = receive_stream(&object, handle, length, flags, peek_offset, peek_length);
    sync_readiness(&object);
    result
}

fn receive_stream(
    object: &RwLock<ObjectEntry>,
    reader: ObjectHandle,
    length: usize,
    mut flags: ReceiveFlags,
    peek_offset: u32,
    peek_length: u32,
) -> Result<SocketOutcome<PlatformStreamReceive>> {
    let (create_request, read_shutdown, connect_in_flight, nonblocking, precheck) =
        read_socket(object, |socket| {
            let precheck = match socket.view() {
                // A listener ignores shutdowns, and a pending error is reported
                // before a shutdown.
                SocketConnectionStatus::Unconnected
                    if socket.read_shutdown && !socket.listening && socket.errors.is_empty() =>
                {
                    Some(SocketOutcome::Failed(SocketError::Shutdown))
                }
                SocketConnectionStatus::Unconnected => {
                    Some(SocketOutcome::Failed(SocketError::NotConnected))
                }
                SocketConnectionStatus::Failed(_) => {
                    Some(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream))
                }
                _ => None,
            };
            (
                socket.create_request,
                socket.read_shutdown,
                socket.connect_in_flight,
                socket.status.nonblocking(),
                precheck,
            )
        })?;
    if !is_tcp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if let Some(outcome) = precheck {
        return Ok(outcome);
    }
    // The transport does not know about a shutdown recorded before the
    // connection, so it must not wait for more data than is queued.
    if read_shutdown {
        flags = ReceiveFlags(flags.0 & !ReceiveFlags::WAITALL.0);
    }
    // The transport may not have started connecting yet.
    let result = if connect_in_flight && length != 0 {
        Err(would_block_error(BrokerError::WouldBlock, nonblocking))
    } else {
        transport_receive(object, reader, length, flags, peek_offset, peek_length)
    };
    match result {
        Err(BrokerError::WouldBlock | BrokerError::NonBlockingWouldBlock) if read_shutdown => {
            Ok(SocketOutcome::Failed(SocketError::Shutdown))
        }
        Ok(SocketOutcome::Failed(error)) => {
            refresh_after_failure(object);
            Ok(SocketOutcome::Failed(error))
        }
        result => result,
    }
}

fn transport_receive(
    object: &RwLock<ObjectEntry>,
    reader: ObjectHandle,
    length: usize,
    flags: ReceiveFlags,
    peek_offset: u32,
    peek_length: u32,
) -> Result<SocketOutcome<PlatformStreamReceive>> {
    let state = socket_state(object)?;
    if state.resource_retired {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    if length == 0 {
        return Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
            Vec::new(),
        )));
    }
    let outcome = state
        .resource
        .platform_socket
        .receive(reader, length, flags, peek_offset, peek_length)
        .map_err(|error| would_block_error(error, state.nonblocking))?;
    if let SocketOutcome::Completed(PlatformStreamReceive::Received(received)) = &outcome
        && (received.len() > length || received.is_empty())
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Receives one datagram without waiting for readiness.
///
/// A pending error fails the receive and is consumed, and a socket shut down
/// for reading fails with `Shutdown`. When no datagram is available, fails
/// with a pending error if there is one, and otherwise with
/// [`BrokerError::WouldBlock`], or with [`BrokerError::NonBlockingWouldBlock`]
/// if the socket is non-blocking.
pub fn receive_from(
    process: &BrokerProcess,
    handle: ObjectHandle,
    length: usize,
    flags: ReceiveFromFlags,
) -> Result<SocketOutcome<PlatformDatagramReceive>> {
    if flags.has_unsupported_bits() || length > MAX_UDP_DATAGRAM_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let result = receive_datagram(&object, length, flags);
    sync_readiness(&object);
    result
}

fn receive_datagram(
    object: &RwLock<ObjectEntry>,
    length: usize,
    flags: ReceiveFromFlags,
) -> Result<SocketOutcome<PlatformDatagramReceive>> {
    if !read_socket(object, |socket| is_udp(socket.create_request))? {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if let Some(error) = take_pending_error(object) {
        return Ok(SocketOutcome::Failed(error));
    }
    if read_socket(object, |socket| socket.read_shutdown)? {
        return Ok(SocketOutcome::Failed(SocketError::Shutdown));
    }
    match transport_receive_from(object, length, flags) {
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
            if read_socket(object, |socket| socket.read_shutdown)? =>
        {
            Ok(SocketOutcome::Failed(SocketError::Shutdown))
        }
        result => finish_datagram_transfer(object, result),
    }
}

fn transport_receive_from(
    object: &RwLock<ObjectEntry>,
    length: usize,
    flags: ReceiveFromFlags,
) -> Result<SocketOutcome<PlatformDatagramReceive>> {
    let state = socket_state(object)?;
    if state.resource_retired {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let outcome = state
        .resource
        .platform_socket
        .receive_from(length, flags)
        .map_err(|error| would_block_error(error, state.nonblocking))?;
    if let SocketOutcome::Completed(received) = &outcome
        && (received.data.len() != received.datagram_length.min(length)
            || received.datagram_length > MAX_UDP_DATAGRAM_SIZE as usize
            || normalize_socket_destination(received.source_address) != Ok(received.source_address))
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Sets one option of a broker-owned socket.
///
/// The transport implements a TCP socket's `NoDelay` and `KeepAlive`; the
/// broker stores the other options, and fails with `UnsupportedOperation` for
/// `NoDelay` on a datagram socket.
pub fn set_option(
    process: &BrokerProcess,
    handle: ObjectHandle,
    value: SocketOptionValue,
) -> Result<()> {
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let mut object = object.write();
    let ObjectEntry::Socket(socket) = &mut *object else {
        return Err(BrokerError::InvalidRights);
    };
    if !is_tcp_option(socket.create_request, value.name()) {
        return socket.options.set(value);
    }
    if socket.resource_retired {
        return Err(BrokerError::Internal);
    }
    let resource = Arc::clone(&socket.resource);
    drop(object);
    resource.platform_socket.set_tcp_option(value)
}

/// Returns one option of a broker-owned socket.
pub fn get_option(
    process: &BrokerProcess,
    handle: ObjectHandle,
    name: SocketOptionName,
) -> Result<SocketOptionValue> {
    let object = process
        .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
    let object = object.read();
    let ObjectEntry::Socket(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    if !is_tcp_option(socket.create_request, name) {
        return socket.options.get(name);
    }
    if socket.resource_retired {
        return Err(BrokerError::Internal);
    }
    let resource = Arc::clone(&socket.resource);
    drop(object);
    let value = resource.platform_socket.get_tcp_option(name)?;
    if value.name() != name {
        return Err(BrokerError::Internal);
    }
    Ok(value)
}

/// Returns whether the transport of a socket created by `create_request`
/// implements the option `name`.
fn is_tcp_option(create_request: CreateSocketRequest, name: SocketOptionName) -> bool {
    is_tcp(create_request)
        && matches!(
            name,
            SocketOptionName::NoDelay | SocketOptionName::KeepAlive
        )
}

/// Returns `error`, reporting [`BrokerError::WouldBlock`] as
/// [`BrokerError::NonBlockingWouldBlock`] for a non-blocking socket.
fn would_block_error(error: BrokerError, nonblocking: bool) -> BrokerError {
    match error {
        BrokerError::WouldBlock if nonblocking => BrokerError::NonBlockingWouldBlock,
        error => error,
    }
}

/// Applies a directional or TCP lifecycle shutdown mode.
///
/// Read, write, and both apply to TCP and UDP and are recorded even when the
/// socket is unconnected, which fails with `NotConnected`; they fail with
/// `Listening` for a TCP listener. Shutting down a connecting TCP socket may
/// abort its attempt, leaving it unconnected with the attempt's error
/// pending. Abort and stop-listening are TCP-only. Stopping a listener leaves
/// it unconnected, and stopping any other socket fails with `NotConnected`.
pub fn shutdown(
    process: &BrokerProcess,
    handle: ObjectHandle,
    mode: ShutdownMode,
) -> Result<SocketOutcome<()>> {
    let object = process.authorized_object(handle, ObjectRights::WRITE)?;
    let result = if read_socket(&object, |socket| is_udp(socket.create_request))? {
        shutdown_datagram(&object, mode)
    } else {
        shutdown_stream(&object, mode)
    };
    sync_readiness(&object);
    result
}

fn shutdown_stream(object: &RwLock<ObjectEntry>, mode: ShutdownMode) -> Result<SocketOutcome<()>> {
    let (listening, view) = read_socket(object, |socket| (socket.listening, socket.view()))?;
    match mode {
        ShutdownMode::StopListening => {
            if !listening {
                return Ok(SocketOutcome::Failed(SocketError::NotConnected));
            }
            let outcome = transport_shutdown(object, mode)?;
            write_socket(object, |socket| {
                // A stopped listener returns to the unconnected state.
                if !socket.listening {
                    socket.reset_connection();
                }
            })?;
            Ok(outcome)
        }
        ShutdownMode::Read | ShutdownMode::Write | ShutdownMode::Both => {
            if listening {
                return Ok(SocketOutcome::Failed(SocketError::Listening));
            }
            match transport_shutdown(object, mode)? {
                SocketOutcome::Completed(()) => {
                    let aborted = view == SocketConnectionStatus::Connecting
                        && matches!(
                            transport_status(object, true),
                            Ok((
                                PlatformSocketStatus {
                                    status: SocketConnectionStatus::Failed(_),
                                    ..
                                },
                                _
                            ))
                        );
                    write_socket(object, |socket| {
                        if aborted {
                            socket.reset_connection();
                        } else {
                            socket.record_shutdown(mode);
                        }
                    })?;
                    Ok(SocketOutcome::Completed(()))
                }
                SocketOutcome::Failed(SocketError::NotConnected) => {
                    // An unconnected socket records the shutdown even though
                    // the call fails.
                    write_socket(object, |socket| socket.record_shutdown(mode))?;
                    Ok(SocketOutcome::Failed(SocketError::NotConnected))
                }
                outcome @ SocketOutcome::Failed(_) => Ok(outcome),
            }
        }
        _ => transport_shutdown(object, mode),
    }
}

fn shutdown_datagram(
    object: &RwLock<ObjectEntry>,
    mode: ShutdownMode,
) -> Result<SocketOutcome<()>> {
    let view = read_socket(object, SocketObject::view)?;
    let outcome = transport_shutdown(object, mode)?;
    let SocketOutcome::Completed(()) = outcome else {
        return Ok(outcome);
    };
    write_socket(object, |socket| socket.record_shutdown(mode))?;
    Ok(if view == SocketConnectionStatus::Connected {
        SocketOutcome::Completed(())
    } else {
        SocketOutcome::Failed(SocketError::NotConnected)
    })
}

/// Applies a shutdown mode to the transport.
///
/// Read, write, and both return `NotConnected` for a TCP listener. Abort and
/// stop-listening are TCP-only. Stopping an active listener with `Completed`
/// or `Failed(NotConnected)` transitions it to `Failed(NotConnected)`.
fn transport_shutdown(
    object: &RwLock<ObjectEntry>,
    mode: ShutdownMode,
) -> Result<SocketOutcome<()>> {
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

/// Returns a socket's broker-authoritative transport state, consuming at
/// most one pending platform error, and whether this call found an error.
///
/// With `queue_errors`, a found error is queued on the socket, and such
/// queries of one socket run one at a time. Stream queries
/// reconcile asynchronous connection completion, and a connection failure
/// they observe is a found error. Datagram queries preserve broker-owned peer
/// state while consuming platform errors, refining the local address, and
/// validating the snapshot. A platform report that contradicts broker-owned
/// state retires the socket, latches `Failed(Other)`, and returns
/// [`BrokerError::Internal`].
fn transport_status(
    object: &RwLock<ObjectEntry>,
    queue_errors: bool,
) -> Result<(PlatformSocketStatus, bool)> {
    let (resource, udp) = read_socket(object, |socket| {
        (Arc::clone(&socket.resource), is_udp(socket.create_request))
    })?;
    let _error_queries = queue_errors.then(|| resource.error_queries.lock());
    if udp {
        datagram_status(object, queue_errors)
    } else {
        stream_status(object, queue_errors)
    }
}

/// Returns a socket's transport state, consuming at most one pending platform
/// error without queuing it.
#[cfg(any(test, feature = "test-support"))]
pub fn status(process: &BrokerProcess, handle: ObjectHandle) -> Result<PlatformSocketStatus> {
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let result = transport_status(&object, false).map(|(status, _)| status);
    sync_readiness(&object);
    result
}

fn stream_status(
    object: &RwLock<ObjectEntry>,
    queue_errors: bool,
) -> Result<(PlatformSocketStatus, bool)> {
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
        return Ok((
            PlatformSocketStatus {
                status: SocketConnectionStatus::Connecting,
                local_address,
                pending_error: None,
            },
            false,
        ));
    }
    if matches!(
        status,
        SocketConnectionStatus::Unconnected | SocketConnectionStatus::Failed(_)
    ) {
        return Ok((
            PlatformSocketStatus {
                status,
                local_address,
                pending_error: None,
            },
            false,
        ));
    }

    let platform_status = match resource.platform_socket.status() {
        Ok(status) => status,
        Err(error) => {
            let object = object.read();
            let ObjectEntry::Socket(socket) = &*object else {
                return Err(BrokerError::InvalidRights);
            };
            if socket.resource_retired {
                return Ok((
                    PlatformSocketStatus {
                        status: socket.connection_status,
                        local_address: socket.local_address,
                        pending_error: None,
                    },
                    false,
                ));
            }
            return Err(error);
        }
    };
    let mut object = object.write();
    let ObjectEntry::Socket(socket) = &mut *object else {
        return Err(BrokerError::InvalidRights);
    };
    if socket.resource_retired {
        return Ok((
            PlatformSocketStatus {
                status: socket.connection_status,
                local_address: socket.local_address,
                pending_error: None,
            },
            false,
        ));
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
    let mut found = platform_status.pending_error.map(QueuedSocketError::Other);
    // Do not overwrite a concurrent terminal transition.
    if socket.connection_status == SocketConnectionStatus::Connecting {
        socket.connection_status = platform_status.status;
        if let SocketConnectionStatus::Failed(error) = platform_status.status {
            found = found.or(Some(QueuedSocketError::ConnectionFailure(error)));
        }
    }
    if queue_errors && let Some(error) = found {
        socket.errors.append(error);
    }
    Ok((
        PlatformSocketStatus {
            status: socket.connection_status,
            local_address: socket.local_address,
            pending_error: platform_status.pending_error,
        },
        found.is_some(),
    ))
}

/// Retries once if a concurrent datagram connect replaces the peer mid-query.
fn datagram_status(
    object: &RwLock<ObjectEntry>,
    queue_errors: bool,
) -> Result<(PlatformSocketStatus, bool)> {
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
        return Ok((
            PlatformSocketStatus {
                status,
                local_address,
                pending_error: None,
            },
            false,
        ));
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
            return Ok((
                PlatformSocketStatus {
                    status,
                    local_address,
                    pending_error: None,
                },
                false,
            ));
        }
        let platform_status = match resource.platform_socket.status() {
            Ok(status) => status,
            Err(error) => {
                let object = object.read();
                let ObjectEntry::Socket(socket) = &*object else {
                    return Err(BrokerError::InvalidRights);
                };
                if socket.resource_retired {
                    return Ok((
                        PlatformSocketStatus {
                            status: socket.connection_status,
                            local_address: socket.local_address,
                            pending_error: None,
                        },
                        false,
                    ));
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
            return Ok((
                PlatformSocketStatus {
                    status: socket.connection_status,
                    local_address: socket.local_address,
                    pending_error: None,
                },
                false,
            ));
        }
        // A retry follows only an iteration without an error, so this queues
        // each consumed error once.
        if queue_errors && let Some(error) = platform_status.pending_error {
            socket.errors.append(QueuedSocketError::Other(error));
        }
        if socket.configuration_in_flight {
            return Ok((
                PlatformSocketStatus {
                    status: socket.connection_status,
                    local_address: socket.local_address,
                    pending_error,
                },
                pending_error.is_some(),
            ));
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
            return Ok((
                PlatformSocketStatus {
                    status: socket.connection_status,
                    local_address: socket.local_address,
                    pending_error,
                },
                pending_error.is_some(),
            ));
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
        return Ok((
            PlatformSocketStatus {
                status: socket.connection_status,
                local_address: socket.local_address,
                pending_error,
            },
            pending_error.is_some(),
        ));
    }
}

#[cfg(test)]
fn socket_resource(
    process: &BrokerProcess,
    handle: ObjectHandle,
    required_rights: ObjectRights,
) -> Result<Arc<SocketResource>> {
    let object = process.authorized_object(handle, required_rights)?;
    let object = object.read();
    let ObjectEntry::Socket(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok(Arc::clone(&socket.resource))
}

/// A snapshot of the state of a socket that an operation needs after
/// releasing the object lock.
struct SocketState {
    resource: Arc<SocketResource>,
    resource_retired: bool,
    nonblocking: bool,
}

fn socket_state(object: &RwLock<ObjectEntry>) -> Result<SocketState> {
    read_socket(object, |socket| SocketState {
        resource: Arc::clone(&socket.resource),
        resource_retired: socket.resource_retired,
        nonblocking: socket.status.nonblocking(),
    })
}

/// Returns `f` applied to the socket `object`.
fn read_socket<T>(object: &RwLock<ObjectEntry>, f: impl FnOnce(&SocketObject) -> T) -> Result<T> {
    let object = object.read();
    let ObjectEntry::Socket(socket) = &*object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok(f(socket))
}

/// Returns `f` applied to the socket `object`, which it may change.
fn write_socket<T>(
    object: &RwLock<ObjectEntry>,
    f: impl FnOnce(&mut SocketObject) -> T,
) -> Result<T> {
    let mut object = object.write();
    let ObjectEntry::Socket(socket) = &mut *object else {
        return Err(BrokerError::InvalidRights);
    };
    Ok(f(socket))
}

/// Publishes the readiness of `object`, if it is a socket, after a change to
/// its state.
///
/// This holds the object lock so that publications follow state changes in
/// order.
fn sync_readiness(object: &RwLock<ObjectEntry>) {
    if let ObjectEntry::Socket(socket) = &*object.read() {
        socket.sync_readiness();
    }
}

/// Queues the transport's pending error if the socket has no queued error
/// and its transport may have one: a datagram socket, or a stream that is
/// connecting or, with `include_connected`, connected.
fn refresh(object: &RwLock<ObjectEntry>, include_connected: bool) {
    let needed = read_socket(object, |socket| {
        socket.errors.is_empty()
            && (is_udp(socket.create_request)
                || match socket.view() {
                    SocketConnectionStatus::Connecting => true,
                    SocketConnectionStatus::Connected => include_connected,
                    _ => false,
                })
    });
    if matches!(needed, Ok(true)) && transport_status(object, true).is_err() {
        let _ = write_socket(object, |socket| socket.errors.prepend(SocketError::Other));
    }
}

/// Queues the errors that follow a failed stream transfer, draining both of
/// the transport's error slots, and discards a queued connection failure,
/// which the transfer reported.
fn refresh_after_failure(object: &RwLock<ObjectEntry>) {
    for _ in 0..2 {
        if !matches!(
            read_socket(object, SocketObject::view),
            Ok(SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected)
        ) {
            break;
        }
        match transport_status(object, true) {
            Ok((_, true)) => {}
            Ok((_, false)) => break,
            Err(_) => {
                let _ = write_socket(object, |socket| {
                    socket
                        .errors
                        .append(QueuedSocketError::Other(SocketError::Other));
                });
                break;
            }
        }
    }
    let _ = write_socket(object, |socket| socket.errors.take_connection_failure());
}

/// Takes a socket's oldest pending error, and then queues the transport's
/// next one if that emptied the queue.
fn take_pending_error(object: &RwLock<ObjectEntry>) -> Option<SocketError> {
    let (error, empty) = write_socket(object, |socket| {
        let error = socket.errors.take();
        (error, socket.errors.is_empty())
    })
    .ok()?;
    if error.is_some() && empty {
        refresh(object, true);
    }
    error
}

/// Brings a socket's readiness up to date before it is reported, queuing a
/// pending transport error and observing a connection attempt's progress.
pub(crate) fn refresh_readiness(object: &RwLock<ObjectEntry>) {
    let Ok((resource, udp)) = read_socket(object, |socket| {
        (Arc::clone(&socket.resource), is_udp(socket.create_request))
    }) else {
        return;
    };
    let error = resource
        .platform_socket
        .readiness()
        .contains(ReadinessFlags::ERROR);
    if !udp || error {
        refresh(object, error);
    }
    sync_readiness(object);
}

enum ReserveAndBindOutcome {
    Completed(SocketAddrV4, Arc<GuestPortBinding>),
    Failed(SocketError),
    Retired(Arc<GuestPortBinding>),
}

fn reserve_and_bind(
    process: &BrokerProcess,
    create_request: CreateSocketRequest,
    resource: &SocketResource,
    requested_address: SocketAddrV4,
) -> Result<ReserveAndBindOutcome> {
    let (local_address, port_binding) = match process
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

fn transport_connect_datagram(
    process: &BrokerProcess,
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
            match reserve_and_bind(process, create_request, &resource, DEFAULT_LOCAL_ADDRESS) {
                Ok(binding) => binding,
                Err(error) => {
                    finish_datagram_connect(object, previous_status, None);
                    return Err(error);
                }
            };
        match binding {
            ReserveAndBindOutcome::Completed(local_address, port_binding) => {
                attach_datagram_binding(object, local_address, port_binding)?;
            }
            ReserveAndBindOutcome::Failed(error) => {
                finish_datagram_connect(object, previous_status, None);
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
        finish_datagram_connect(object, previous_status, None);
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    match resource.platform_socket.connect(destination, None) {
        Ok(SocketConnectionStatus::Connected) => {
            finish_datagram_connect(object, SocketConnectionStatus::Connected, Some(destination));
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        }
        Ok(SocketConnectionStatus::Failed(error)) => {
            finish_datagram_connect(object, previous_status, None);
            Ok(SocketOutcome::Failed(error))
        }
        Ok(_) => {
            finish_retired_datagram_connect(object);
            resource.retire();
            Err(BrokerError::Internal)
        }
        Err(PlatformConnectError::PeerUnchanged(error)) => {
            finish_datagram_connect(object, previous_status, None);
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
    peer: Option<SocketAddrV4>,
) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.configuration_in_flight = false;
        socket.connection_status = status;
        if peer.is_some() {
            socket.peer_address = peer;
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

/// Abandons a claimed stream connection attempt that had no effect, leaving
/// the stream unconnected.
///
/// The stream returns to its readiness before the claim, so this republishes
/// that readiness to wake waiters that saw the attempt in progress.
fn abandon_connect(object: &spin::RwLock<ObjectEntry>) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.connect_in_flight = false;
        socket.connection_status = SocketConnectionStatus::Unconnected;
        socket
            .resource
            .readiness_sink
            .set_overlay(socket.readiness_overlay(), true);
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

/// Options a socket stores without its transport implementing them, which
/// every reference to the socket shares.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SocketOptions {
    receive_timeout: Option<Duration>,
    send_timeout: Option<Duration>,
    linger: Option<Duration>,
    reuse_address: bool,
    keep_alive: bool,
    broadcast: bool,
}

impl SocketOptions {
    /// Stores `value`, failing with `UnsupportedOperation` for
    /// [`SocketOptionValue::NoDelay`], which only a TCP transport implements.
    pub(crate) fn set(&mut self, value: SocketOptionValue) -> Result<()> {
        match value {
            SocketOptionValue::ReceiveTimeout(timeout) => self.receive_timeout = timeout,
            SocketOptionValue::SendTimeout(timeout) => self.send_timeout = timeout,
            SocketOptionValue::Linger(timeout) => self.linger = timeout,
            SocketOptionValue::ReuseAddress(value) => self.reuse_address = value,
            SocketOptionValue::KeepAlive(value) => self.keep_alive = value,
            SocketOptionValue::Broadcast(value) => self.broadcast = value,
            SocketOptionValue::NoDelay(_) => return Err(BrokerError::UnsupportedOperation),
        }
        Ok(())
    }

    /// Returns the stored value of the option `name`, failing with
    /// `UnsupportedOperation` for [`SocketOptionName::NoDelay`].
    pub(crate) fn get(&self, name: SocketOptionName) -> Result<SocketOptionValue> {
        Ok(match name {
            SocketOptionName::ReceiveTimeout => {
                SocketOptionValue::ReceiveTimeout(self.receive_timeout)
            }
            SocketOptionName::SendTimeout => SocketOptionValue::SendTimeout(self.send_timeout),
            SocketOptionName::Linger => SocketOptionValue::Linger(self.linger),
            SocketOptionName::ReuseAddress => SocketOptionValue::ReuseAddress(self.reuse_address),
            SocketOptionName::KeepAlive => SocketOptionValue::KeepAlive(self.keep_alive),
            SocketOptionName::Broadcast => SocketOptionValue::Broadcast(self.broadcast),
            SocketOptionName::NoDelay => return Err(BrokerError::UnsupportedOperation),
        })
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "socket lifecycle latches are independent"
)]
pub(crate) struct SocketObject {
    resource: Arc<SocketResource>,
    create_request: CreateSocketRequest,
    status: StatusFlags,
    /// Options other than those [`is_tcp_option`] selects.
    options: SocketOptions,
    /// The transport's connection state, which [`Self::view`] refines.
    connection_status: SocketConnectionStatus,
    local_address: Option<SocketAddrV4>,
    /// The peer of the latest successful connection attempt.
    peer_address: Option<SocketAddrV4>,
    connect_in_flight: bool,
    configuration_in_flight: bool,
    listening: bool,
    datagram_connect_generation: u64,
    resource_retired: bool,
    errors: SocketErrorQueue,
    /// Whether a stream reported its connection, so that connecting again
    /// fails with `AlreadyConnected`.
    connect_reported: bool,
    read_shutdown: bool,
    write_shutdown: bool,
    /// Whether a stream returned to the unconnected state after its
    /// transport stopped listening or failed, which the transport cannot.
    disconnected: bool,
}

impl SocketObject {
    fn new(
        resource: Arc<SocketResource>,
        create_request: CreateSocketRequest,
        status: StatusFlags,
    ) -> Self {
        Self {
            resource,
            create_request,
            status,
            options: SocketOptions::default(),
            connection_status: SocketConnectionStatus::Unconnected,
            local_address: None,
            peer_address: None,
            connect_in_flight: false,
            configuration_in_flight: false,
            listening: false,
            datagram_connect_generation: 0,
            resource_retired: false,
            errors: SocketErrorQueue::default(),
            connect_reported: false,
            read_shutdown: false,
            write_shutdown: false,
            disconnected: false,
        }
    }

    fn new_connected(
        resource: Arc<SocketResource>,
        create_request: CreateSocketRequest,
        status: StatusFlags,
        local_address: SocketAddrV4,
        remote_address: SocketAddrV4,
    ) -> Self {
        let mut socket = Self::new(resource, create_request, status);
        socket.connection_status = SocketConnectionStatus::Connected;
        socket.local_address = Some(local_address);
        socket.peer_address = Some(remote_address);
        socket.connect_reported = true;
        socket
    }

    /// Returns the socket's connection state.
    fn view(&self) -> SocketConnectionStatus {
        if self.connect_in_flight {
            SocketConnectionStatus::Connecting
        } else if self.disconnected {
            SocketConnectionStatus::Unconnected
        } else {
            self.connection_status
        }
    }

    /// Returns a stream to the unconnected state, discarding its shutdowns.
    fn reset_connection(&mut self) {
        self.disconnected = true;
        self.read_shutdown = false;
        self.write_shutdown = false;
    }

    /// Returns a stream to the unconnected state once `connect` has reported
    /// the failure of its connection attempt, claiming that failure unless
    /// another operation has already reported it.
    fn disconnect(&mut self) -> Option<SocketError> {
        let error = self.errors.take_connection_failure();
        self.reset_connection();
        error
    }

    /// Records a shutdown, which also reports an established connection so
    /// that a later `connect` fails.
    fn record_shutdown(&mut self, mode: ShutdownMode) {
        if self.view() == SocketConnectionStatus::Connected {
            self.connect_reported = true;
        }
        if matches!(mode, ShutdownMode::Read | ShutdownMode::Both) {
            self.read_shutdown = true;
        }
        if matches!(mode, ShutdownMode::Write | ShutdownMode::Both) {
            self.write_shutdown = true;
        }
    }

    /// Returns how the socket's state changes its transport's readiness.
    fn readiness_overlay(&self) -> ReadinessOverlay {
        let view = self.view();
        let mut overlay = ReadinessOverlay::default();
        if !is_udp(self.create_request) {
            overlay.base = match view {
                SocketConnectionStatus::Failed(_) => Some(
                    ReadinessFlags::READ
                        | ReadinessFlags::WRITE
                        | ReadinessFlags::HANGUP
                        | ReadinessFlags::CLOSED,
                ),
                SocketConnectionStatus::Unconnected if !self.listening => {
                    Some(ReadinessFlags::WRITE | ReadinessFlags::CLOSED)
                }
                _ => None,
            };
        }
        // A listener ignores shutdowns.
        if !self.listening {
            if self.read_shutdown {
                overlay.add = overlay.add | ReadinessFlags::READ | ReadinessFlags::HANGUP;
            }
            // A send waits for a connection attempt despite a shutdown.
            if self.write_shutdown && view != SocketConnectionStatus::Connecting {
                overlay.add = overlay.add | ReadinessFlags::WRITE;
            }
            overlay.close_on_hangup = self.write_shutdown;
        }
        if !self.errors.is_empty() {
            overlay.add = overlay.add | ReadinessFlags::ERROR;
        }
        overlay
    }

    /// Publishes the socket's readiness after a change to its state.
    fn sync_readiness(&self) {
        self.resource
            .readiness_sink
            .set_overlay(self.readiness_overlay(), false);
    }

    pub(crate) fn resource(&self) -> Arc<SocketResource> {
        Arc::clone(&self.resource)
    }

    /// Returns the socket's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(FileAccessMode::ReadWrite)
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }

    /// Publishes this socket's later readiness changes through
    /// `registration` until every clone of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.resource.readiness_sink.watchers.watch(registration)
    }
}

pub(crate) struct SocketResource {
    platform_socket: Arc<dyn PlatformSocket>,
    /// The provider's registration, whose publications `readiness_sink`
    /// forwards.
    readiness: ReadinessRegistration,
    readiness_sink: Arc<SocketReadinessSink>,
    port_binding: Mutex<Option<Arc<GuestPortBinding>>>,
    guest_source_lease: Mutex<Option<GuestSourceLease>>,
    /// Serializes queries that queue the transport's pending error, so none
    /// misses an error another has taken from the transport but not yet
    /// queued.
    error_queries: Mutex<()>,
    /// The account the provider charges this socket to, which drops after the
    /// socket retires.
    account: Arc<SocketAccount>,
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
        let transport = self.platform_socket.readiness();
        self.readiness_sink.state.lock().overlay.apply(transport)
    }
}

/// A pending socket error, and whether it reports a failed connection
/// attempt, which `connect` may claim.
#[derive(Clone, Copy)]
enum QueuedSocketError {
    Other(SocketError),
    ConnectionFailure(SocketError),
}

impl QueuedSocketError {
    fn error(self) -> SocketError {
        match self {
            Self::Other(error) | Self::ConnectionFailure(error) => error,
        }
    }
}

/// A socket's pending errors, oldest first.
///
/// This holds at most two: the socket's current error, and the next one,
/// which becomes current once the current one is taken.
#[derive(Default)]
struct SocketErrorQueue {
    head: Option<QueuedSocketError>,
    next: Option<QueuedSocketError>,
}

impl SocketErrorQueue {
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Makes `error` the oldest error, discarding the newest if full.
    fn prepend(&mut self, error: SocketError) {
        self.next = self.head;
        self.head = Some(QueuedSocketError::Other(error));
    }

    /// Makes `error` the newest error, discarding it if full.
    fn append(&mut self, error: QueuedSocketError) {
        if self.head.is_none() {
            self.head = Some(error);
        } else if self.next.is_none() {
            self.next = Some(error);
        }
    }

    fn take(&mut self) -> Option<SocketError> {
        let error = self.head.take();
        self.head = self.next.take();
        error.map(QueuedSocketError::error)
    }

    /// Takes the newest connection failure.
    fn take_connection_failure(&mut self) -> Option<SocketError> {
        if let Some(QueuedSocketError::ConnectionFailure(error)) = self.next {
            self.next = None;
            Some(error)
        } else if let Some(QueuedSocketError::ConnectionFailure(_)) = self.head {
            self.take()
        } else {
            None
        }
    }
}

/// How a socket's state changes its transport's readiness.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct ReadinessOverlay {
    /// Readiness that replaces the transport's.
    base: Option<ReadinessFlags>,
    /// Readiness added to the base.
    add: ReadinessFlags,
    /// Whether a hangup also closes the socket, because it cannot send.
    close_on_hangup: bool,
}

impl ReadinessOverlay {
    fn apply(self, transport: ReadinessFlags) -> ReadinessFlags {
        let readiness = self.base.unwrap_or(transport) | self.add;
        if self.close_on_hangup && readiness.contains(ReadinessFlags::HANGUP) {
            readiness | ReadinessFlags::CLOSED
        } else {
            readiness
        }
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

/// Charges one socket resource to the broker and to the process of `account`.
fn reserve_socket(core: &BrokerCore, account: &SocketAccount) -> Result<QuotaReservation> {
    QuotaReservation::new(
        &core.reserved_sockets,
        core.limits.max_sockets,
        &account.reserved_sockets,
        core.limits.max_sockets_per_process,
    )
}

/// Creates the readiness state of a new socket for `reference`: the
/// reference's registration with `readiness_sink`, which already watches the
/// socket so it receives the provider's initial publication, the socket's
/// sink, and the provider's registration with that sink, which holds `quota`
/// until its retirement is delivered.
fn socket_readiness(
    reference: &PendingObjectReference<'_>,
    readiness_sink: Arc<dyn ReadinessSink>,
    quota: Arc<QuotaReservation>,
) -> Result<(
    ReadinessRegistration,
    Arc<SocketReadinessSink>,
    ReadinessRegistration,
)> {
    let registration = ReadinessRegistration::new(reference.handle(), readiness_sink);
    let socket_sink = Arc::new(SocketReadinessSink::default());
    socket_sink.watchers.watch(&registration)?;
    let readiness = ReadinessRegistration::new_with_retirement_guard(
        reference.handle(),
        socket_sink.clone(),
        quota,
    );
    Ok((registration, socket_sink, readiness))
}

/// The provider socket state and socket quota charged to one process, whose
/// provider state [`SocketProvider::close_process`] releases once the process
/// has released its references and every socket charged to it has retired.
///
/// Each socket charged to the process holds this, and so does the process
/// until it releases its references. It keeps the process's ID allocated, so
/// a later process cannot reuse the ID while the provider still charges
/// state to it.
pub(crate) struct SocketAccount {
    process_id: ProcessId,
    /// Socket quota held by the pending, live, and closing in-flight
    /// resources charged to the process.
    reserved_sockets: Arc<AtomicUsize>,
    socket_provider: Arc<dyn SocketProvider>,
    ids: Arc<Mutex<IdAllocator>>,
}

impl SocketAccount {
    /// Creates the account of the process with the allocated ID `process_id`.
    pub(crate) fn new(core: &BrokerCore, process_id: ProcessId) -> Self {
        core.ids.lock().retain(process_id.0);
        Self {
            process_id,
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            socket_provider: Arc::clone(&core.socket_provider),
            ids: Arc::clone(&core.ids),
        }
    }
}

impl Drop for SocketAccount {
    fn drop(&mut self) {
        self.socket_provider.close_process(self.process_id);
        self.ids.lock().release(self.process_id.0);
    }
}

/// Readiness sink of one socket resource, which forwards its provider's
/// publications, changed by the socket's state, to the socket's watchers: the
/// registrations of every reference to the socket and of readiness queue
/// entries watching it.
#[derive(Default)]
struct SocketReadinessSink {
    watchers: SharedReadinessWatchers,
    state: Mutex<SocketReadinessState>,
}

#[derive(Default)]
struct SocketReadinessState {
    /// The provider's latest publication.
    transport: ReadinessFlags,
    overlay: ReadinessOverlay,
    retired: bool,
}

impl SocketReadinessSink {
    /// Changes how the socket's state changes its transport's readiness,
    /// publishing the socket's readiness if that changes it or, with
    /// `republish`, regardless.
    fn set_overlay(&self, overlay: ReadinessOverlay, republish: bool) {
        let mut state = self.state.lock();
        if state.retired {
            return;
        }
        let before = state.overlay.apply(state.transport);
        let after = overlay.apply(state.transport);
        state.overlay = overlay;
        if republish {
            self.watchers.publish(after);
        } else if before != after {
            self.watchers.publish_if_changed(after);
        }
    }

    fn forward(&self, transport: ReadinessFlags, republish: bool) {
        // Publishing under the lock keeps publications in order.
        let mut state = self.state.lock();
        if state.retired {
            return;
        }
        state.transport = transport;
        let readiness = state.overlay.apply(transport);
        if republish {
            self.watchers.publish(readiness);
        } else {
            self.watchers.publish_if_changed(readiness);
        }
    }
}

impl ReadinessSink for SocketReadinessSink {
    fn max_tracked_objects(&self) -> usize {
        1
    }

    fn publish(&self, _handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.forward(readiness, false);
        Ok(())
    }

    fn republish(&self, _handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.forward(readiness, true);
        Ok(())
    }

    fn retire(&self, _handle: ObjectHandle) {
        self.state.lock().retired = true;
    }
}

#[cfg(test)]
pub(crate) mod tests;
