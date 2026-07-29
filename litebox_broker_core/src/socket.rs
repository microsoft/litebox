// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned platform socket authority.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    CreateSocketRequest, ReceiveFlags, ReceiveSocketResponse, SendFlags, ShutdownMode,
    SocketAddressV4, SocketConnectionStatus, SocketError,
};

use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::session::{ObjectEntry, ObjectRights};
use crate::{BrokerError, BrokerSession, Result, SessionId};

/// Result of a platform socket operation that can fail with a network outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum SocketOutcome<T> {
    /// The operation completed successfully.
    Completed(T),
    /// The platform reported an ordinary network failure.
    Failed(SocketError),
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
    /// Starts a connection attempt.
    ///
    /// `Unconnected` is not a valid result once the attempt reaches the
    /// platform. A pending attempt returns `Connecting`, and ordinary network
    /// failures return `Failed`. A broker error is surfaced for that call and
    /// leaves the socket terminally failed, because retrying a platform call
    /// that may already have side effects is unsafe.
    fn connect(&self, address: SocketAddressV4) -> Result<SocketConnectionStatus>;

    /// Sends bytes without waiting for platform readiness.
    ///
    /// A temporarily full socket returns [`BrokerError::WouldBlock`]. Ordinary
    /// network failures return [`SocketOutcome::Failed`].
    fn send(&self, data: &[u8], flags: SendFlags) -> Result<SocketOutcome<usize>>;

    /// Receives bytes without waiting for platform readiness.
    ///
    /// A temporarily empty socket returns [`BrokerError::WouldBlock`]. End of
    /// stream returns [`ReceiveSocketResponse::EndOfStream`]; `Received(0)` is
    /// reserved for a zero-length input buffer handled by the core.
    fn receive(
        &self,
        data: &mut [u8],
        flags: ReceiveFlags,
    ) -> Result<SocketOutcome<ReceiveSocketResponse>>;

    /// Shuts down one or both socket directions.
    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>>;

    /// Returns the authoritative connection status.
    ///
    /// Once a connection attempt starts this returns `Connecting`, `Connected`,
    /// or `Failed`, never `Unconnected`.
    fn status(&self) -> Result<SocketConnectionStatus>;

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
    let quota = SocketQuotaReservation::new(session)?;
    let reference = session.reserve_object_reference(rights)?;
    let readiness = ReadinessRegistration::new(reference.handle(), readiness_sink);
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
    let handle = reference.commit(ObjectEntry::Socket(SocketObject::new(
        platform_socket,
        readiness,
        quota,
    )))?;
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
    address: SocketAddressV4,
) -> Result<SocketOutcome<SocketConnectionStatus>> {
    let object = session.authorized_object(handle, ObjectRights::WRITE)?;
    {
        let object = object.read();
        let ObjectEntry::Socket(_) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
    }

    if let Err(error) = session
        .core
        .policy
        .authorize_socket_connect(session.caller_credential, address)
    {
        // Only a definitive authorization denial is a per-request socket outcome.
        // Any other error means the broker could not evaluate or serve policy
        // and must not be cached as if it were a network failure.
        if error != BrokerError::PolicyDenied {
            return Err(error);
        }
        return Ok(SocketOutcome::Failed(SocketError::PolicyDenied));
    }

    let resource = {
        let mut object = object.write();
        let ObjectEntry::Socket(socket) = &mut *object else {
            return Err(BrokerError::InvalidRights);
        };
        if socket.connect_in_flight {
            return Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting));
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
        Err(error) => {
            finish_connect(&object, SocketConnectionStatus::Failed(SocketError::Other));
            return Err(error);
        }
    };
    finish_connect(&object, status);
    Ok(SocketOutcome::Completed(status))
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
    let resource = socket_resource(session, handle, ObjectRights::WRITE)?;
    let outcome = resource.send(data, flags)?;
    if let SocketOutcome::Completed(sent) = outcome
        && sent > data.len()
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
) -> Result<SocketOutcome<ReceiveSocketResponse>> {
    if flags.has_unsupported_bits() {
        return Err(BrokerError::UnsupportedOperation);
    }
    let resource = socket_resource(session, handle, ObjectRights::WAIT)?;
    if data.is_empty() {
        return Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(0)));
    }
    let outcome = resource.receive(data, flags)?;
    if let SocketOutcome::Completed(ReceiveSocketResponse::Received(received)) = outcome
        && (received as usize > data.len() || received == 0)
    {
        return Err(BrokerError::Internal);
    }
    Ok(outcome)
}

/// Shuts down one or both socket directions.
pub fn shutdown(
    session: &BrokerSession,
    handle: ObjectHandle,
    mode: ShutdownMode,
) -> Result<SocketOutcome<()>> {
    socket_resource(session, handle, ObjectRights::WRITE)?.shutdown(mode)
}

/// Returns the broker-authoritative connection status.
pub fn status(session: &BrokerSession, handle: ObjectHandle) -> Result<SocketConnectionStatus> {
    let object = session.authorized_object(handle, ObjectRights::WAIT)?;
    let (resource, status, connect_in_flight) = {
        let object = object.read();
        let ObjectEntry::Socket(socket) = &*object else {
            return Err(BrokerError::InvalidRights);
        };
        (
            Arc::clone(&socket.resource),
            socket.connection_status,
            socket.connect_in_flight,
        )
    };
    if connect_in_flight {
        return Ok(SocketConnectionStatus::Connecting);
    }
    if status != SocketConnectionStatus::Connecting {
        return Ok(status);
    }
    let status = resource.status()?;
    if status == SocketConnectionStatus::Unconnected {
        return Err(BrokerError::Internal);
    }
    let mut object = object.write();
    let ObjectEntry::Socket(socket) = &mut *object else {
        return Err(BrokerError::InvalidRights);
    };
    let status = if socket.connection_status == SocketConnectionStatus::Connecting {
        socket.connection_status = status;
        status
    } else {
        socket.connection_status
    };
    Ok(status)
}

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

fn finish_connect(object: &spin::RwLock<ObjectEntry>, status: SocketConnectionStatus) {
    let mut object = object.write();
    if let ObjectEntry::Socket(socket) = &mut *object {
        socket.connect_in_flight = false;
        socket.connection_status = status;
    }
}

pub(crate) struct SocketObject {
    resource: Arc<SocketResource>,
    connection_status: SocketConnectionStatus,
    connect_in_flight: bool,
}

impl SocketObject {
    fn new(
        platform_socket: Arc<dyn PlatformSocket>,
        readiness: ReadinessRegistration,
        quota: SocketQuotaReservation,
    ) -> Self {
        Self {
            resource: Arc::new(SocketResource {
                platform_socket,
                readiness,
                _quota: quota,
            }),
            connection_status: SocketConnectionStatus::Unconnected,
            connect_in_flight: false,
        }
    }

    pub(crate) fn resource(&self) -> Arc<SocketResource> {
        Arc::clone(&self.resource)
    }
}

pub(crate) struct SocketResource {
    platform_socket: Arc<dyn PlatformSocket>,
    readiness: ReadinessRegistration,
    _quota: SocketQuotaReservation,
}

impl SocketResource {
    fn connect(&self, address: SocketAddressV4) -> Result<SocketConnectionStatus> {
        self.platform_socket.connect(address)
    }

    fn send(&self, data: &[u8], flags: SendFlags) -> Result<SocketOutcome<usize>> {
        self.platform_socket.send(data, flags)
    }

    fn receive(
        &self,
        data: &mut [u8],
        flags: ReceiveFlags,
    ) -> Result<SocketOutcome<ReceiveSocketResponse>> {
        self.platform_socket.receive(data, flags)
    }

    fn shutdown(&self, mode: ShutdownMode) -> Result<SocketOutcome<()>> {
        self.platform_socket.shutdown(mode)
    }

    fn status(&self) -> Result<SocketConnectionStatus> {
        self.platform_socket.status()
    }

    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.platform_socket.readiness()
    }
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
    use crate::{BrokerCore, CallerCredential};
    use litebox_broker_protocol::socket::{
        AddressFamily, IpProtocol, Ipv4Address, Port, SocketType,
    };
    use std::sync::Mutex as StdMutex;

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
        shutdown_calls: AtomicUsize,
        dropped_sockets: AtomicUsize,
        fail_create: core::sync::atomic::AtomicBool,
        fail_connect: core::sync::atomic::AtomicBool,
        failed_readiness: StdMutex<Option<ReadinessRegistration>>,
    }

    impl TestSocketProvider {
        pub(crate) fn fail_next_create(&self) {
            self.state.fail_create.store(true, Ordering::Relaxed);
        }

        fn fail_next_connect(&self) {
            self.state.fail_connect.store(true, Ordering::Relaxed);
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
            Ok(Arc::new(TestPlatformSocket {
                state: Arc::clone(&self.state),
                readiness,
            }))
        }

        fn close_session(&self, session_id: SessionId) {
            self.state.closed_sessions.lock().unwrap().push(session_id);
        }
    }

    struct TestPlatformSocket {
        state: Arc<TestSocketState>,
        readiness: ReadinessRegistration,
    }

    impl PlatformSocket for TestPlatformSocket {
        fn connect(&self, _address: SocketAddressV4) -> Result<SocketConnectionStatus> {
            self.state.connect_calls.fetch_add(1, Ordering::Relaxed);
            if self.state.fail_connect.swap(false, Ordering::Relaxed) {
                return Err(BrokerError::Internal);
            }
            self.readiness.publish(ReadinessFlags::WRITE)?;
            Ok(SocketConnectionStatus::Connecting)
        }

        fn send(&self, data: &[u8], _flags: SendFlags) -> Result<SocketOutcome<usize>> {
            self.state.sent.lock().unwrap().extend_from_slice(data);
            Ok(SocketOutcome::Completed(data.len()))
        }

        fn receive(
            &self,
            data: &mut [u8],
            _flags: ReceiveFlags,
        ) -> Result<SocketOutcome<ReceiveSocketResponse>> {
            let received = data.len().min(2);
            data[..received].copy_from_slice(&[7, 9][..received]);
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
                u32::try_from(received).unwrap(),
            )))
        }

        fn shutdown(&self, _mode: ShutdownMode) -> Result<SocketOutcome<()>> {
            self.state.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SocketOutcome::Completed(()))
        }

        fn status(&self) -> Result<SocketConnectionStatus> {
            self.state.status_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SocketConnectionStatus::Connected)
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

    #[derive(Default)]
    struct TestReadinessSink {
        published: StdMutex<std::vec::Vec<(ObjectHandle, ReadinessFlags)>>,
        retired: StdMutex<std::vec::Vec<ObjectHandle>>,
    }

    impl ReadinessSink for TestReadinessSink {
        fn max_tracked_objects(&self) -> usize {
            usize::MAX
        }

        fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
            self.published.lock().unwrap().push((handle, readiness));
            Ok(())
        }

        fn retire(&self, handle: ObjectHandle) {
            self.retired.lock().unwrap().push(handle);
        }
    }

    pub(crate) fn check_socket_lifecycle(broker: &BrokerCore, provider: &TestSocketProvider) {
        check_failed_create_rolls_back(broker, provider);
        check_retired_registration_discards_updates();
        check_socket_operations_and_policy(broker, provider);
        check_connect_error_is_terminal(broker, provider);
        check_socket_quotas(broker);
    }

    fn check_retired_registration_discards_updates() {
        let sink = Arc::new(TestReadinessSink::default());
        let registration = ReadinessRegistration::new(ObjectHandle(99), sink.clone());
        let delayed = registration.clone();
        registration.retire();
        delayed.publish(ReadinessFlags::READ).unwrap();
        assert!(sink.published.lock().unwrap().is_empty());
        assert_eq!(sink.retired.lock().unwrap().as_slice(), [ObjectHandle(99)]);
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
                SocketAddressV4 {
                    address: Ipv4Address([10, 0, 0, 1]),
                    port: Port(80),
                },
            ),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketConnectionStatus::Unconnected)
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
            Ok(SocketConnectionStatus::Connected)
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
            receive(&session, handle, &mut data, ReceiveFlags::PEEK),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(2)))
        );
        assert_eq!(data, [7, 9, 0, 0]);
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

    fn check_connect_error_is_terminal(broker: &BrokerCore, provider: &TestSocketProvider) {
        let session = broker
            .create_session(CallerCredential::Unauthenticated)
            .unwrap();
        let handle = create(
            &session,
            create_request(),
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        let calls_before = provider.state.connect_calls.load(Ordering::Relaxed);
        provider.fail_next_connect();
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            connect(&session, handle, loopback_address()),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
                SocketError::Other
            )))
        );
        assert_eq!(
            status(&session, handle),
            Ok(SocketConnectionStatus::Failed(SocketError::Other))
        );
        assert_eq!(
            provider.state.connect_calls.load(Ordering::Relaxed),
            calls_before + 1
        );
    }

    const fn create_request() -> CreateSocketRequest {
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Stream,
            protocol: IpProtocol::Tcp,
        }
    }

    const fn loopback_address() -> SocketAddressV4 {
        SocketAddressV4 {
            address: Ipv4Address([127, 0, 0, 1]),
            port: Port(8080),
        }
    }
}
