// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned platform socket authority.

use alloc::sync::Arc;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    CreateSocketRequest, IpProtocol, MAX_SOCKET_TRANSFER_SIZE, MAX_TCP_LISTEN_BACKLOG,
    MAX_UDP_DATAGRAM_SIZE, ReceiveFlags, ReceiveFromFlags, ReceiveSocketResponse, SendFlags,
    ShutdownMode, SocketConnectionStatus, SocketError, SocketOutcome, SocketStatusResponse,
    SocketType, TcpOptionName, TcpOptionValue,
};
use spin::Once;

use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result, SessionId};

const DEFAULT_TCP_LISTEN_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);

/// Platform socket and endpoint metadata returned by an accept operation.
pub struct AcceptedPlatformSocket {
    /// Accepted nonblocking platform socket.
    pub socket: Arc<dyn PlatformSocket>,
    /// Local endpoint of the accepted connection.
    pub local_address: SocketAddrV4,
    /// Remote endpoint of the accepted connection.
    pub remote_address: SocketAddrV4,
}

/// Broker failure from a platform connect operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformConnectError {
    /// The operation did not change the socket's peer.
    PeerUnchanged(BrokerError),
    /// The operation may have changed the socket's peer.
    PeerIndeterminate(BrokerError),
}

/// Broker socket and endpoint metadata returned by an accept operation.
pub struct AcceptedBrokerSocket {
    /// Broker handle naming the accepted socket.
    pub handle: ObjectHandle,
    /// Local endpoint of the accepted connection.
    pub local_address: SocketAddrV4,
    /// Remote endpoint of the accepted connection.
    pub remote_address: SocketAddrV4,
}

/// Platform result for one datagram receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedPlatformDatagram {
    /// Number of bytes copied into the caller's buffer.
    pub received: usize,
    /// Original datagram length before truncation.
    pub datagram_length: usize,
    /// Source address of the datagram.
    pub source_address: SocketAddrV4,
}

/// Broker-wide socket provider supplied by the host platform.
///
/// The provider creates per-socket [`PlatformSocket`] resources and owns any
/// bookkeeping shared across the sockets of a broker session. Operations on an
/// individual socket belong to [`PlatformSocket`], not this shared provider.
pub trait SocketProvider: Send + Sync {
    /// Creates one nonblocking socket resource for an authenticated session.
    ///
    /// The returned socket must not retain authority beyond its `Arc` lifetime.
    fn create(
        &self,
        session_id: SessionId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
    ) -> Result<Arc<dyn PlatformSocket>>;

    /// Releases provider state associated with a session after its references close.
    fn close_session(&self, session_id: SessionId);
}

/// One nonblocking socket resource created by [`SocketProvider`].
///
/// The broker retains this resource in an `Arc`, allowing an operation already
/// in flight to finish after its object handle closes. Dropping the final `Arc`
/// releases the platform socket.
pub trait PlatformSocket: Send + Sync {
    /// Binds this socket to a local address.
    fn bind(&self, address: SocketAddrV4) -> Result<SocketOutcome<SocketAddrV4>>;

    /// Makes this socket listen for incoming connections.
    fn listen(&self, backlog: u32) -> Result<SocketOutcome<SocketAddrV4>>;

    /// Accepts one pending connection without waiting.
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
    /// unchanged from one whose state is indeterminate.
    fn connect(
        &self,
        address: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError>;

    /// Sends bytes without waiting for platform readiness.
    ///
    /// A temporarily full socket returns [`BrokerError::WouldBlock`]. Ordinary
    /// network failures return [`SocketOutcome::Failed`].
    fn send(&self, data: &[u8], flags: SendFlags) -> Result<SocketOutcome<usize>>;

    /// Sends one complete datagram without waiting for platform readiness.
    ///
    /// A destination is required for an unconnected socket and omitted to use
    /// the socket's connected peer. Partial successful sends are invalid.
    fn send_to(
        &self,
        data: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> Result<SocketOutcome<usize>>;

    /// Receives bytes without waiting for platform readiness.
    ///
    /// A temporarily empty socket returns [`BrokerError::WouldBlock`]. End of
    /// stream returns [`ReceiveSocketResponse::EndOfStream`]; `Received(0)` is
    /// reserved for a zero-length input buffer handled by the core.
    fn receive(
        &self,
        data: &mut [u8],
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> Result<SocketOutcome<ReceiveSocketResponse>>;

    /// Receives one datagram without waiting for platform readiness.
    ///
    /// The original datagram length is returned even when the caller's buffer
    /// is smaller, and zero-length datagrams are successful receives.
    fn receive_from(
        &self,
        data: &mut [u8],
        flags: ReceiveFromFlags,
    ) -> Result<SocketOutcome<ReceivedPlatformDatagram>>;

    /// Shuts down one or both socket directions.
    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>>;

    /// Sets a typed TCP socket option.
    fn set_tcp_option(&self, value: TcpOptionValue) -> Result<()>;

    /// Reads a typed TCP socket option.
    fn get_tcp_option(&self, name: TcpOptionName) -> Result<TcpOptionValue>;

    /// Returns the authoritative connection status.
    ///
    /// Stream sockets with an attempted connection return `Connecting`,
    /// `Connected`, or `Failed`. Datagram sockets return `Unconnected` or
    /// `Connected` and may change between those states through peer updates.
    fn status(&self) -> Result<SocketStatusResponse>;

    /// Returns the current readiness snapshot.
    fn readiness(&self) -> ReadinessFlags;
}

/// Placeholder provider for broker configurations that deliberately disable sockets.
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
    let readiness = ReadinessRegistration::new_with_retirement_guard(
        reference.handle(),
        readiness_sink,
        Arc::clone(&quota),
    );
    let resource = Arc::new(SocketResource {
        platform_socket: Once::new(),
        readiness,
        _quota: quota,
    });
    let platform_socket = match session.core.socket_provider.create(
        session.session_id,
        request,
        resource.readiness.clone(),
    ) {
        Ok(socket) => socket,
        Err(error) => {
            // The provider may have retained its registration before
            // failing, so retirement cannot rely on the local clone being
            // the last one.
            resource.readiness.retire();
            return Err(error);
        }
    };
    resource.platform_socket.call_once(|| platform_socket);
    let handle = reference.commit(ObjectEntry::Socket(SocketObject::new(resource, request)))?;
    Ok(handle)
}

/// Starts a nonblocking connection attempt.
///
/// Policy denial is returned as a per-request [`SocketOutcome::Failed`] and
/// leaves the socket unconnected, so a later authorized destination may still
/// be attempted.
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

    // Destination denial is an operation-level socket failure. Failures while
    // evaluating policy remain broker errors.
    match session.core.policy.authorize_socket_connect(
        session.caller_credential,
        create_request,
        address,
    ) {
        Ok(()) => {}
        Err(BrokerError::PolicyDenied) => {
            return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
        }
        Err(error) => return Err(error),
    }

    if is_udp(create_request) {
        return connect_datagram(&object, address);
    }

    let resource = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
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
        Arc::clone(&socket.resource)
    };
    let status = match resource.connect(address) {
        Ok(SocketConnectionStatus::Unconnected) => {
            finish_connect(&object, SocketConnectionStatus::Failed(SocketError::Other));
            return Err(BrokerError::Internal);
        }
        Ok(status) => status,
        Err(PlatformConnectError::PeerUnchanged(error)) => {
            finish_connect(&object, SocketConnectionStatus::Unconnected);
            return Err(error);
        }
        Err(PlatformConnectError::PeerIndeterminate(error)) => {
            finish_connect(&object, SocketConnectionStatus::Failed(SocketError::Other));
            return Err(error);
        }
    };
    finish_connect(&object, status);
    Ok(SocketOutcome::Completed(status))
}

/// Binds a socket to an authorized loopback address.
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
    match session.core.policy.authorize_socket_bind(
        session.caller_credential,
        create_request,
        address,
    ) {
        Ok(()) => {}
        Err(BrokerError::PolicyDenied) => {
            finish_configuration(&object, None, false);
            return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
        }
        Err(error) => {
            finish_configuration(&object, None, false);
            return Err(error);
        }
    }
    let outcome = resource.bind(address);
    match outcome {
        Ok(SocketOutcome::Completed(local_address)) => {
            finish_configuration(&object, Some(local_address), false);
            Ok(SocketOutcome::Completed(local_address))
        }
        Ok(SocketOutcome::Failed(error)) => {
            finish_configuration(&object, None, false);
            Ok(SocketOutcome::Failed(error))
        }
        Err(error) => {
            finish_configuration(&object, None, false);
            Err(error)
        }
    }
}

/// Makes a socket listen for incoming loopback connections.
pub fn listen(
    session: &BrokerSession,
    handle: ObjectHandle,
    backlog: u32,
) -> Result<SocketOutcome<SocketAddrV4>> {
    if backlog > MAX_TCP_LISTEN_BACKLOG {
        return Err(BrokerError::UnsupportedOperation);
    }
    let object = session.authorized_object(handle, ObjectRights::WRITE)?;
    let (resource, create_request, needs_bind) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if !is_tcp(socket.create_request) {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
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
            socket.local_address.is_none(),
        )
    };

    let mut local_address = None;
    if needs_bind {
        match session.core.policy.authorize_socket_bind(
            session.caller_credential,
            create_request,
            DEFAULT_TCP_LISTEN_ADDRESS,
        ) {
            Ok(()) => {}
            Err(BrokerError::PolicyDenied) => {
                finish_configuration(&object, None, false);
                return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
            }
            Err(error) => {
                finish_configuration(&object, None, false);
                return Err(error);
            }
        }
        match resource.bind(DEFAULT_TCP_LISTEN_ADDRESS) {
            Ok(SocketOutcome::Completed(address)) => local_address = Some(address),
            Ok(SocketOutcome::Failed(error)) => {
                finish_configuration(&object, None, false);
                return Ok(SocketOutcome::Failed(error));
            }
            Err(error) => {
                finish_configuration(&object, None, false);
                return Err(error);
            }
        }
    }

    match resource.listen(backlog) {
        Ok(SocketOutcome::Completed(address)) => {
            local_address = Some(address);
            finish_configuration(&object, local_address, true);
            Ok(SocketOutcome::Completed(address))
        }
        Ok(SocketOutcome::Failed(error)) => {
            finish_configuration(&object, local_address, false);
            Ok(SocketOutcome::Failed(error))
        }
        Err(error) => {
            finish_configuration(&object, local_address, false);
            Err(error)
        }
    }
}

/// Accepts one pending connection and creates a new broker socket capability.
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
    let readiness = ReadinessRegistration::new_with_retirement_guard(
        reference.handle(),
        readiness_sink,
        Arc::clone(&quota),
    );
    let resource = Arc::new(SocketResource {
        platform_socket: Once::new(),
        readiness,
        _quota: quota,
    });
    let accepted = match listener_resource.accept(resource.readiness.clone()) {
        Ok(SocketOutcome::Completed(accepted)) => accepted,
        Ok(SocketOutcome::Failed(error)) => {
            resource.readiness.retire();
            return Ok(SocketOutcome::Failed(error));
        }
        Err(error) => {
            resource.readiness.retire();
            return Err(error);
        }
    };
    resource.platform_socket.call_once(|| accepted.socket);
    let accepted_socket =
        SocketObject::new_connected(resource, create_request, accepted.local_address);
    let handle = reference.commit(ObjectEntry::Socket(accepted_socket))?;
    Ok(SocketOutcome::Completed(AcceptedBrokerSocket {
        handle,
        local_address: accepted.local_address,
        remote_address: accepted.remote_address,
    }))
}

/// Sends bytes without waiting for readiness.
pub fn send(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &[u8],
    flags: SendFlags,
) -> Result<SocketOutcome<usize>> {
    if flags.has_unsupported_bits() {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (resource, create_request, _) = socket_state(session, handle, ObjectRights::WRITE)?;
    if !is_tcp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let outcome = resource.send(data, flags)?;
    if let SocketOutcome::Completed(sent) = outcome
        && sent > data.len()
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Sends one complete datagram without waiting for readiness.
pub fn send_to(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &[u8],
    flags: SendFlags,
    destination: Option<SocketAddrV4>,
) -> Result<SocketOutcome<usize>> {
    if flags.has_unsupported_bits() || data.len() > MAX_UDP_DATAGRAM_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (resource, create_request, connection_status) =
        socket_state(session, handle, ObjectRights::WRITE)?;
    if !is_udp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if let Some(destination) = destination {
        match session.core.policy.authorize_socket_connect(
            session.caller_credential,
            create_request,
            destination,
        ) {
            Ok(()) => {}
            Err(BrokerError::PolicyDenied) => {
                return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
            }
            Err(error) => return Err(error),
        }
    } else if connection_status != SocketConnectionStatus::Connected {
        return Ok(SocketOutcome::Failed(SocketError::NotConnected));
    }
    let outcome = resource.send_to(data, flags, destination)?;
    if let SocketOutcome::Completed(sent) = outcome
        && sent != data.len()
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Receives bytes without waiting for readiness.
pub fn receive(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &mut [u8],
    flags: ReceiveFlags,
    peek_offset: u32,
    peek_length: u32,
) -> Result<SocketOutcome<ReceiveSocketResponse>> {
    if flags.has_unsupported_bits() {
        return Err(BrokerError::UnsupportedOperation);
    }
    let peek = flags.contains(ReceiveFlags::PEEK);
    let end = peek_offset
        .checked_add(data.len().try_into().map_err(|_| BrokerError::Internal)?)
        .ok_or(BrokerError::UnsupportedOperation)?;
    let canonical_peek_length = peek_length
        .checked_sub(peek_offset)
        .map(|remaining| remaining.min(MAX_SOCKET_TRANSFER_SIZE));
    if (!peek && (peek_offset != 0 || peek_length != 0))
        || (peek
            && (!peek_offset.is_multiple_of(MAX_SOCKET_TRANSFER_SIZE)
                || canonical_peek_length != data.len().try_into().ok()
                || peek_length < end
                || peek_length > litebox_broker_protocol::socket::MAX_SOCKET_PEEK_SIZE))
    {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (resource, create_request, _) = socket_state(session, handle, ObjectRights::WAIT)?;
    if !is_tcp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    if data.is_empty() {
        return Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(0)));
    }
    let outcome = resource.receive(data, flags, peek_offset, peek_length)?;
    if let SocketOutcome::Completed(ReceiveSocketResponse::Received(received)) = outcome
        && (received as usize > data.len() || received == 0)
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Receives one datagram without waiting for readiness.
pub fn receive_from(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &mut [u8],
    flags: ReceiveFromFlags,
) -> Result<SocketOutcome<ReceivedPlatformDatagram>> {
    if flags.has_unsupported_bits() || data.len() > MAX_UDP_DATAGRAM_SIZE as usize {
        return Err(BrokerError::UnsupportedOperation);
    }
    let (resource, create_request, _) = socket_state(session, handle, ObjectRights::WAIT)?;
    if !is_udp(create_request) {
        return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
    }
    let outcome = resource.receive_from(data, flags)?;
    if let SocketOutcome::Completed(received) = outcome
        && (received.received > data.len()
            || received.datagram_length < received.received
            || received.datagram_length > MAX_UDP_DATAGRAM_SIZE as usize)
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
    let (resource, create_request, _) = socket_state(session, handle, ObjectRights::WRITE)?;
    if !is_tcp(create_request) {
        return Err(BrokerError::UnsupportedOperation);
    }
    resource.set_tcp_option(value)
}

/// Reads a typed option from a broker-owned TCP socket.
pub fn get_tcp_option(
    session: &BrokerSession,
    handle: ObjectHandle,
    name: TcpOptionName,
) -> Result<TcpOptionValue> {
    let (resource, create_request, _) = socket_state(session, handle, ObjectRights::WAIT)?;
    if !is_tcp(create_request) {
        return Err(BrokerError::UnsupportedOperation);
    }
    let value = resource.get_tcp_option(name)?;
    if !matches!(
        (name, value),
        (TcpOptionName::NoDelay, TcpOptionValue::NoDelay(_))
            | (TcpOptionName::KeepAlive, TcpOptionValue::KeepAlive(_))
    ) {
        return Err(BrokerError::Internal);
    }
    Ok(value)
}

/// Shuts down one or both socket directions.
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
    let outcome = resource.shutdown(mode);
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

/// Returns broker-authoritative socket status and consumes its pending asynchronous error.
pub fn status(session: &BrokerSession, handle: ObjectHandle) -> Result<SocketStatusResponse> {
    let object = session.authorized_object(handle, ObjectRights::WAIT)?;
    let (
        resource,
        create_request,
        status,
        local_address,
        connect_in_flight,
        datagram_connect_generation,
    ) = {
        let object = object.read();
        let ObjectEntry::Socket(socket) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
        (
            Arc::clone(&socket.resource),
            socket.create_request,
            socket.connection_status,
            socket.local_address,
            socket.connect_in_flight,
            socket.datagram_connect_generation,
        )
    };
    if connect_in_flight {
        return Ok(SocketStatusResponse {
            status: SocketConnectionStatus::Connecting,
            local_address: None,
            pending_error: None,
        });
    }
    if matches!(status, SocketConnectionStatus::Unconnected) && !is_udp(create_request) {
        return Ok(SocketStatusResponse {
            status,
            local_address,
            pending_error: None,
        });
    }
    if matches!(status, SocketConnectionStatus::Failed(_)) && !is_udp(create_request) {
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
        let mut response = resource.status()?;
        pending_error = pending_error.or(response.pending_error);
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if is_udp(socket.create_request) {
            if matches!(
                response.status,
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Failed(_)
            ) {
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
                response.status = socket.connection_status;
                socket.local_address = socket.local_address.or(response.local_address);
                response.local_address = socket.local_address;
                response.pending_error = pending_error;
                return Ok(response);
            }
        } else if socket.connection_status == SocketConnectionStatus::Connecting
            && response.status == SocketConnectionStatus::Unconnected
        {
            return Err(BrokerError::Internal);
        }
        socket.local_address = if is_udp(socket.create_request) {
            response.local_address.or(socket.local_address)
        } else {
            socket.local_address.or(response.local_address)
        };
        response.local_address = socket.local_address;
        response.pending_error = pending_error;
        if is_udp(socket.create_request) {
            response.status = socket.connection_status;
        } else if socket.connection_status == SocketConnectionStatus::Connecting {
            socket.connection_status = response.status;
        } else {
            // Another status call reached a terminal state while this platform query was in flight.
            response.status = socket.connection_status;
        }
        return Ok(response);
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
    ))
}

fn connect_datagram(
    object: &spin::RwLock<ObjectEntry>,
    address: SocketAddrV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let (resource, previous_status) = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if socket.configuration_in_flight || socket.connect_in_flight || socket.listening {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        socket.configuration_in_flight = true;
        (Arc::clone(&socket.resource), socket.connection_status)
    };
    match resource.connect(address) {
        Ok(SocketConnectionStatus::Connected) => {
            finish_datagram_connect(object, SocketConnectionStatus::Connected, true);
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        }
        Ok(SocketConnectionStatus::Failed(error)) => {
            finish_datagram_connect(object, previous_status, false);
            Ok(SocketOutcome::Failed(error))
        }
        Ok(_) => {
            finish_datagram_connect(
                object,
                SocketConnectionStatus::Failed(SocketError::Other),
                true,
            );
            Err(BrokerError::Internal)
        }
        Err(PlatformConnectError::PeerUnchanged(error)) => {
            finish_datagram_connect(object, previous_status, false);
            Err(error)
        }
        Err(PlatformConnectError::PeerIndeterminate(error)) => {
            finish_datagram_connect(
                object,
                SocketConnectionStatus::Failed(SocketError::Other),
                true,
            );
            Err(error)
        }
    }
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
            // peer replacement or an indeterminate platform failure. A status
            // call cannot overlap enough connects for wrapping to make a stale
            // snapshot appear current.
            socket.datagram_connect_generation = socket.datagram_connect_generation.wrapping_add(1);
        }
    }
}

fn finish_connect(object: &spin::RwLock<ObjectEntry>, status: SocketConnectionStatus) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.connect_in_flight = false;
        socket.connection_status = status;
    }
}

fn finish_configuration(
    object: &spin::RwLock<ObjectEntry>,
    local_address: Option<SocketAddrV4>,
    listening: bool,
) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.configuration_in_flight = false;
        socket.local_address = socket.local_address.or(local_address);
        socket.listening |= listening;
    }
}

pub(crate) struct SocketObject {
    resource: Arc<SocketResource>,
    create_request: CreateSocketRequest,
    connection_status: SocketConnectionStatus,
    local_address: Option<SocketAddrV4>,
    connect_in_flight: bool,
    configuration_in_flight: bool,
    listening: bool,
    datagram_connect_generation: u64,
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
        }
    }

    fn new_connected(
        resource: Arc<SocketResource>,
        create_request: CreateSocketRequest,
        local_address: SocketAddrV4,
    ) -> Self {
        Self {
            resource,
            create_request,
            connection_status: SocketConnectionStatus::Connected,
            local_address: Some(local_address),
            connect_in_flight: false,
            configuration_in_flight: false,
            listening: false,
            datagram_connect_generation: 0,
        }
    }

    pub(crate) fn resource(&self) -> Arc<SocketResource> {
        Arc::clone(&self.resource)
    }
}

pub(crate) struct SocketResource {
    platform_socket: Once<Arc<dyn PlatformSocket>>,
    readiness: ReadinessRegistration,
    _quota: Arc<SocketQuotaReservation>,
}

impl SocketResource {
    fn platform_socket(&self) -> &dyn PlatformSocket {
        self.platform_socket
            .get()
            .expect("committed socket resources are initialized")
            .as_ref()
    }

    fn connect(
        &self,
        address: SocketAddrV4,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        self.platform_socket().connect(address)
    }

    fn bind(&self, address: SocketAddrV4) -> Result<SocketOutcome<SocketAddrV4>> {
        self.platform_socket().bind(address)
    }

    fn listen(&self, backlog: u32) -> Result<SocketOutcome<SocketAddrV4>> {
        self.platform_socket().listen(backlog)
    }

    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> Result<SocketOutcome<AcceptedPlatformSocket>> {
        self.platform_socket().accept(readiness)
    }

    fn send(&self, data: &[u8], flags: SendFlags) -> Result<SocketOutcome<usize>> {
        self.platform_socket().send(data, flags)
    }

    fn send_to(
        &self,
        data: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> Result<SocketOutcome<usize>> {
        self.platform_socket().send_to(data, flags, destination)
    }

    fn receive(
        &self,
        data: &mut [u8],
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> Result<SocketOutcome<ReceiveSocketResponse>> {
        self.platform_socket()
            .receive(data, flags, peek_offset, peek_length)
    }

    fn receive_from(
        &self,
        data: &mut [u8],
        flags: ReceiveFromFlags,
    ) -> Result<SocketOutcome<ReceivedPlatformDatagram>> {
        self.platform_socket().receive_from(data, flags)
    }

    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>> {
        self.platform_socket().shutdown(mode)
    }

    fn set_tcp_option(&self, value: TcpOptionValue) -> Result<()> {
        self.platform_socket().set_tcp_option(value)
    }

    fn get_tcp_option(&self, name: TcpOptionName) -> Result<TcpOptionValue> {
        self.platform_socket().get_tcp_option(name)
    }

    fn status(&self) -> Result<SocketStatusResponse> {
        self.platform_socket().status()
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.platform_socket().readiness()
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

impl Drop for SocketResource {
    fn drop(&mut self) {
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
    use std::sync::{Mutex as StdMutex, mpsc};
    use std::time::Duration;

    #[derive(Clone, Default)]
    pub(crate) struct TestSocketProvider {
        state: Arc<TestSocketState>,
    }

    #[derive(Default)]
    struct TestSocketState {
        creates: StdMutex<std::vec::Vec<(SessionId, CreateSocketRequest)>>,
        closed_sessions: StdMutex<std::vec::Vec<SessionId>>,
        sent: StdMutex<std::vec::Vec<u8>>,
        connect_calls: AtomicUsize,
        status_calls: AtomicUsize,
        status_responses: StdMutex<std::collections::VecDeque<SocketStatusResponse>>,
        status_block: StdMutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
        binds: StdMutex<std::vec::Vec<SocketAddrV4>>,
        listens: StdMutex<std::vec::Vec<u32>>,
        listen_block: StdMutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
        shutdown_calls: AtomicUsize,
        dropped_sockets: AtomicUsize,
        fail_create: core::sync::atomic::AtomicBool,
        fail_connect: core::sync::atomic::AtomicBool,
        fail_connect_indeterminate: core::sync::atomic::AtomicBool,
        fail_shutdown: core::sync::atomic::AtomicBool,
        tcp_options: StdMutex<std::vec::Vec<TcpOptionValue>>,
        failed_readiness: StdMutex<Option<ReadinessRegistration>>,
        live_readiness: StdMutex<Option<ReadinessRegistration>>,
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

        fn fail_next_shutdown(&self) {
            self.state.fail_shutdown.store(true, Ordering::Relaxed);
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
            Ok(Arc::new(TestPlatformSocket {
                state: Arc::clone(&self.state),
                readiness,
                create_request: request,
            }))
        }

        fn close_session(&self, session_id: SessionId) {
            self.state.closed_sessions.lock().unwrap().push(session_id);
        }
    }

    struct TestPlatformSocket {
        state: Arc<TestSocketState>,
        readiness: ReadinessRegistration,
        create_request: CreateSocketRequest,
    }

    impl PlatformSocket for TestPlatformSocket {
        fn bind(&self, address: SocketAddrV4) -> Result<SocketOutcome<SocketAddrV4>> {
            self.state.binds.lock().unwrap().push(address);
            let address = if address.port() == 0 {
                SocketAddrV4::new(*address.ip(), 49152)
            } else {
                address
            };
            Ok(SocketOutcome::Completed(address))
        }

        fn listen(&self, backlog: u32) -> Result<SocketOutcome<SocketAddrV4>> {
            self.state.listens.lock().unwrap().push(backlog);
            let listen_block = self.state.listen_block.lock().unwrap().take();
            if let Some((started, release)) = listen_block {
                started.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            Ok(SocketOutcome::Completed(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                49152,
            )))
        }

        fn accept(
            &self,
            _readiness: ReadinessRegistration,
        ) -> Result<SocketOutcome<AcceptedPlatformSocket>> {
            Err(BrokerError::WouldBlock)
        }

        fn connect(
            &self,
            _address: SocketAddrV4,
        ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
            self.state.connect_calls.fetch_add(1, Ordering::Relaxed);
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
            self.readiness
                .publish(ReadinessFlags::WRITE)
                .map_err(PlatformConnectError::PeerIndeterminate)?;
            if is_udp(self.create_request) {
                Ok(SocketConnectionStatus::Connected)
            } else {
                Ok(SocketConnectionStatus::Connecting)
            }
        }

        fn send(&self, data: &[u8], _flags: SendFlags) -> Result<SocketOutcome<usize>> {
            self.state.sent.lock().unwrap().extend_from_slice(data);
            Ok(SocketOutcome::Completed(data.len()))
        }

        fn send_to(
            &self,
            data: &[u8],
            _flags: SendFlags,
            _destination: Option<SocketAddrV4>,
        ) -> Result<SocketOutcome<usize>> {
            self.state.sent.lock().unwrap().extend_from_slice(data);
            Ok(SocketOutcome::Completed(data.len()))
        }

        fn receive(
            &self,
            data: &mut [u8],
            _flags: ReceiveFlags,
            _peek_offset: u32,
            _peek_length: u32,
        ) -> Result<SocketOutcome<ReceiveSocketResponse>> {
            let received = data.len().min(2);
            data[..received].copy_from_slice(&[7, 9][..received]);
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
                u32::try_from(received).unwrap(),
            )))
        }

        fn receive_from(
            &self,
            data: &mut [u8],
            _flags: ReceiveFromFlags,
        ) -> Result<SocketOutcome<ReceivedPlatformDatagram>> {
            let received = data.len().min(2);
            data[..received].copy_from_slice(&[7, 9][..received]);
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received,
                datagram_length: 4,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            }))
        }

        fn shutdown(&self, _mode: ShutdownMode) -> Result<SocketOutcome<()>> {
            self.state.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            if self.state.fail_shutdown.swap(false, Ordering::Relaxed) {
                return Err(BrokerError::ResourceExhausted);
            }
            Ok(SocketOutcome::Completed(()))
        }

        fn set_tcp_option(&self, value: TcpOptionValue) -> Result<()> {
            self.state.tcp_options.lock().unwrap().push(value);
            Ok(())
        }

        fn get_tcp_option(&self, name: TcpOptionName) -> Result<TcpOptionValue> {
            let options = self.state.tcp_options.lock().unwrap();
            let default = match name {
                TcpOptionName::NoDelay => TcpOptionValue::NoDelay(false),
                TcpOptionName::KeepAlive => TcpOptionValue::KeepAlive(false),
                _ => return Err(BrokerError::UnsupportedOperation),
            };
            Ok(options
                .iter()
                .rev()
                .copied()
                .find(|value| {
                    matches!(
                        (name, value),
                        (TcpOptionName::NoDelay, TcpOptionValue::NoDelay(_))
                            | (TcpOptionName::KeepAlive, TcpOptionValue::KeepAlive(_))
                    )
                })
                .unwrap_or(default))
        }

        fn status(&self) -> Result<SocketStatusResponse> {
            self.state.status_calls.fetch_add(1, Ordering::Relaxed);
            let response = self
                .state
                .status_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(SocketStatusResponse {
                    status: SocketConnectionStatus::Connected,
                    local_address: None,
                    pending_error: None,
                });
            let status_block = self.state.status_block.lock().unwrap().take();
            if let Some((started, release)) = status_block {
                started.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            Ok(response)
        }

        fn readiness(&self) -> ReadinessFlags {
            ReadinessFlags::READ | ReadinessFlags::WRITE
        }
    }

    impl Drop for TestPlatformSocket {
        fn drop(&mut self) {
            self.state.dropped_sockets.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn check_socket_lifecycle(broker: &BrokerCore, provider: &TestSocketProvider) {
        check_failed_create_rolls_back(broker, provider);
        check_socket_operations_and_policy(broker, provider);
        check_udp_socket_operations(broker, provider);
        check_concurrent_udp_status_does_not_regress_connection(broker, provider);
        check_server_socket_operations(broker, provider);
        check_failed_listener_shutdown_preserves_state(broker, provider);
        check_listener_shutdown_does_not_race_listen(broker, provider);
        check_connect_errors_classify_peer_state(broker, provider);
        check_concurrent_status_preserves_terminal_state(broker, provider);
        check_failed_status_preserves_local_address(broker, provider);
        check_quota_waits_for_deferred_retirement(broker, provider);
        check_socket_quotas(broker);
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
        assert_eq!(
            readiness.published.lock().unwrap().as_slice(),
            [(handle, ReadinessFlags::WRITE)]
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: None,
                pending_error: None,
            })
        );
        assert_eq!(
            session.check_readiness(handle),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            send(&session, handle, &[1, 2, 3], SendFlags::NONE),
            Ok(SocketOutcome::Completed(3))
        );
        let mut data = [0; 4];
        assert_eq!(
            receive(&session, handle, &mut data, ReceiveFlags::PEEK, 0, 4),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(2)))
        );
        assert_eq!(data, [7, 9, 0, 0]);
        assert_eq!(
            receive(&session, handle, &mut data[..1], ReceiveFlags::PEEK, 1, 2),
            Err(BrokerError::UnsupportedOperation)
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
            send(&session, handle, &[], SendFlags(1)),
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
        assert_eq!(provider.state.sent.lock().unwrap().as_slice(), [1, 2, 3]);
        assert_eq!(provider.state.connect_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.state.status_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.state.shutdown_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            provider.state.tcp_options.lock().unwrap().as_slice(),
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

    fn check_udp_socket_operations(broker: &BrokerCore, provider: &TestSocketProvider) {
        let connect_calls_before = provider.state.connect_calls.load(Ordering::Relaxed);
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
            send_to(&session, handle, b"x", SendFlags::NONE, None),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            send_to(
                &session,
                handle,
                b"x",
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53)),
            ),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(
            send_to(
                &session,
                handle,
                b"udp",
                SendFlags::NONE,
                Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            ),
            Ok(SocketOutcome::Completed(3))
        );
        let mut data = [0; 2];
        assert_eq!(
            receive_from(&session, handle, &mut data, ReceiveFromFlags::PEEK),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 2,
                datagram_length: 4,
                source_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153),
            }))
        );
        assert_eq!(data, [7, 9]);
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
            send_to(&session, handle, b"peer", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(4))
        );
        provider.fail_next_connect_indeterminate();
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54),),
            Err(BrokerError::Internal)
        );
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: None,
                pending_error: Some(SocketError::ConnectionRefused),
            });
        assert_eq!(
            status(&session, handle),
            Ok(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::Other),
                local_address: None,
                pending_error: Some(SocketError::ConnectionRefused),
            })
        );
        assert_eq!(
            send_to(&session, handle, b"peer", SendFlags::NONE, None),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
        assert_eq!(
            connect(&session, handle, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 54),),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert_eq!(
            send_to(&session, handle, b"peer", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(4))
        );
        assert_eq!(
            send(&session, handle, b"x", SendFlags::NONE),
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
            connect_calls_before + 4
        );
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
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(provider.state.binds.lock().unwrap().len(), binds_before);

        let requested_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152);
        assert_eq!(
            bind(&session, listener, requested_address),
            Ok(SocketOutcome::Completed(local_address))
        );
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

        session.close_object_reference(listener).unwrap();
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);

        let auto_bound = create(&session, create_request(), readiness).unwrap();
        assert_eq!(
            listen(&session, auto_bound, 0),
            Ok(SocketOutcome::Completed(local_address))
        );
        assert_eq!(
            provider.state.binds.lock().unwrap().last(),
            Some(&DEFAULT_TCP_LISTEN_ADDRESS)
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
        let local_address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 49152);
        *provider.state.status_responses.lock().unwrap() = std::collections::VecDeque::from([
            SocketStatusResponse {
                status: SocketConnectionStatus::Unconnected,
                local_address: None,
                pending_error: None,
            },
            SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(local_address),
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
        release_tx.send(()).unwrap();
        let stale = in_flight.join().unwrap();
        assert_eq!(stale.status, SocketConnectionStatus::Connected);
        assert_eq!(stale.local_address, Some(local_address));
        assert_eq!(stale.pending_error, None);

        let next_local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153);
        let stale_local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49154);
        *provider.state.status_responses.lock().unwrap() = std::collections::VecDeque::from([
            SocketStatusResponse {
                status: SocketConnectionStatus::Unconnected,
                local_address: Some(stale_local_address),
                pending_error: Some(SocketError::ConnectionRefused),
            },
            SocketStatusResponse {
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
        provider.fail_next_connect_indeterminate();
        assert_eq!(
            connect(&session, poisoned, loopback_address()),
            Err(BrokerError::Internal)
        );
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
                local_address: None,
                pending_error: None,
            })
        );
        assert_eq!(
            provider.state.connect_calls.load(Ordering::Relaxed),
            calls_before + 3
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

        let local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49152);
        *provider.state.status_responses.lock().unwrap() = std::collections::VecDeque::from([
            SocketStatusResponse {
                status: SocketConnectionStatus::Connecting,
                local_address: None,
                pending_error: None,
            },
            SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(local_address),
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
                local_address: Some(local_address),
                pending_error: Some(SocketError::ConnectionReset),
            }
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            first.join().unwrap(),
            SocketStatusResponse {
                status: SocketConnectionStatus::Connected,
                local_address: Some(local_address),
                pending_error: None,
            }
        );
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

        let local_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49153);
        provider
            .state
            .status_responses
            .lock()
            .unwrap()
            .push_back(SocketStatusResponse {
                status: SocketConnectionStatus::Failed(SocketError::TimedOut),
                local_address: Some(local_address),
                pending_error: None,
            });

        let expected = SocketStatusResponse {
            status: SocketConnectionStatus::Failed(SocketError::TimedOut),
            local_address: Some(local_address),
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
