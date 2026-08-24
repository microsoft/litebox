// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Read as _, Write as _};
use std::net::Ipv4Addr;
use std::net::{Shutdown, TcpListener, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use super::*;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::socket::{GUEST_IPV4_ADDRESS, HOST_GATEWAY_IPV4_ADDRESS};
use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, BrokerSession, CallerCredential, DestinationPortRange,
    DestinationRule, Ipv4Cidr, ObjectRights, PolicyEngine, SocketPolicy,
};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::socket::{Ipv4Address, Port, ReceiveSocketResponse};

use super::udp::{
    MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND, MAX_UDP_EXTERNAL_PEERS_PER_SOCKET,
    MAX_UDP_NATIVE_RECEIVE_BUFFER, MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE,
};

mod tcp;
mod udp;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn gateway_tcp_policy() -> SocketPolicy {
    SocketPolicy::guest_network()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        )])
        .unwrap()
}

fn gateway_address(host_address: SocketAddrV4) -> SocketAddrV4 {
    SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, host_address.port())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceivedPlatformDatagram {
    received: usize,
    datagram_length: usize,
    source_address: SocketAddrV4,
}

#[test]
fn pending_socket_retirement_prevents_reactor_activation() {
    let lifecycle = SocketLifecycle::pending();
    lifecycle.retire(|| panic!("pending sockets have no reactor resource to close"));
    assert!(!lifecycle.activate());
    assert_eq!(lifecycle.load(), SocketLifecycleState::Retired);
}

#[test]
fn concurrent_socket_retirement_waits_for_close_acknowledgement() {
    let lifecycle = Arc::new(SocketLifecycle::pending());
    assert!(lifecycle.activate());
    let (close_started, close_started_receive) = sync_channel(1);
    let (release_close, release_close_receive) = sync_channel(1);
    let first_lifecycle = Arc::clone(&lifecycle);
    let first = thread::spawn(move || {
        first_lifecycle.retire(|| {
            close_started.send(()).unwrap();
            release_close_receive.recv_timeout(TEST_TIMEOUT).unwrap();
        });
    });
    close_started_receive.recv_timeout(TEST_TIMEOUT).unwrap();

    let (second_waiting, second_waiting_receive) = sync_channel(1);
    let (second_finished, second_finished_receive) = sync_channel(1);
    let second_lifecycle = Arc::clone(&lifecycle);
    let second = thread::spawn(move || {
        second_lifecycle.retire_with_wait_observer(
            || panic!("only the active caller may close the socket"),
            || second_waiting.send(()).unwrap(),
        );
        second_finished.send(()).unwrap();
    });
    second_waiting_receive.recv_timeout(TEST_TIMEOUT).unwrap();
    assert!(
        second_finished_receive
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );

    release_close.send(()).unwrap();
    first.join().unwrap();
    second_finished_receive.recv_timeout(TEST_TIMEOUT).unwrap();
    second.join().unwrap();
    assert_eq!(lifecycle.load(), SocketLifecycleState::Retired);
}

fn send_bytes(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &[u8],
    flags: SendFlags,
) -> BrokerResult<SocketOutcome<usize>> {
    litebox_broker_core::socket::send(session, handle, data.to_vec(), flags)
}

fn send_datagram(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &[u8],
    flags: SendFlags,
    destination: Option<SocketAddrV4>,
) -> BrokerResult<SocketOutcome<usize>> {
    litebox_broker_core::socket::send_to(session, handle, data.to_vec(), flags, destination)
}

fn receive_into(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &mut [u8],
    flags: ReceiveFlags,
    peek_offset: u32,
    peek_length: u32,
) -> BrokerResult<SocketOutcome<ReceiveSocketResponse>> {
    match litebox_broker_core::socket::receive(
        session,
        handle,
        data.len(),
        flags,
        peek_offset,
        peek_length,
    )? {
        SocketOutcome::Completed(PlatformStreamReceive::Received(received)) => {
            data[..received.len()].copy_from_slice(&received);
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
                received
                    .len()
                    .try_into()
                    .map_err(|_| BrokerError::Internal)?,
            )))
        }
        SocketOutcome::Completed(PlatformStreamReceive::EndOfStream) => {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
        }
        SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
    }
}

fn receive_datagram_into(
    session: &BrokerSession,
    handle: ObjectHandle,
    data: &mut [u8],
    flags: ReceiveFromFlags,
) -> BrokerResult<SocketOutcome<ReceivedPlatformDatagram>> {
    match litebox_broker_core::socket::receive_from(session, handle, data.len(), flags)? {
        SocketOutcome::Completed(received) => {
            data[..received.data.len()].copy_from_slice(&received.data);
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: received.data.len(),
                datagram_length: received.datagram_length,
                source_address: received.source_address,
            }))
        }
        SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
    }
}

#[test]
fn cached_socket_error_precedes_a_new_kernel_error() {
    assert_eq!(
        shift_pending_error(
            Some(SocketError::ConnectionRefused),
            Some(SocketError::NetworkUnreachable),
        ),
        (
            Some(SocketError::ConnectionRefused),
            Some(SocketError::NetworkUnreachable),
        )
    );
    assert_eq!(
        shift_pending_error(None, Some(SocketError::NetworkUnreachable)),
        (Some(SocketError::NetworkUnreachable), None)
    );
}

#[test]
fn synchronous_errors_do_not_consume_tcp_connect_status() {
    assert!(!can_consume_synchronous_error(
        SocketKind::Tcp,
        SocketConnectionStatus::Connecting,
    ));
    assert!(can_consume_synchronous_error(
        SocketKind::Tcp,
        SocketConnectionStatus::Connected,
    ));
    assert!(can_consume_synchronous_error(
        SocketKind::Udp,
        SocketConnectionStatus::Unconnected,
    ));
}

struct TestReadinessSink {
    published: Sender<(ObjectHandle, ReadinessFlags)>,
    retired: Sender<ObjectHandle>,
}

impl ReadinessSink for TestReadinessSink {
    fn max_tracked_objects(&self) -> usize {
        8
    }

    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        self.published
            .send((handle, readiness))
            .map_err(|_| BrokerError::Internal)
    }

    fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        self.publish(handle, readiness)
    }

    fn retire(&self, handle: ObjectHandle) {
        let _ = self.retired.send(handle);
    }
}

struct PendingPublishFailure {
    handle: Option<ObjectHandle>,
    required: ReadinessFlags,
    forbidden: ReadinessFlags,
}

struct FailingReadinessSink {
    inner: TestReadinessSink,
    fail_next_publish: Mutex<Option<PendingPublishFailure>>,
}

impl FailingReadinessSink {
    fn fail_next_publish_for(&self, handle: ObjectHandle) {
        self.fail_next_publish_matching(
            handle,
            ReadinessFlags::default(),
            ReadinessFlags::default(),
        );
    }

    fn fail_next_publish_matching(
        &self,
        handle: ObjectHandle,
        required: ReadinessFlags,
        forbidden: ReadinessFlags,
    ) {
        *self.fail_next_publish.lock().unwrap() = Some(PendingPublishFailure {
            handle: Some(handle),
            required,
            forbidden,
        });
    }

    fn fail_next_publish_matching_any(&self, required: ReadinessFlags, forbidden: ReadinessFlags) {
        *self.fail_next_publish.lock().unwrap() = Some(PendingPublishFailure {
            handle: None,
            required,
            forbidden,
        });
    }

    fn assert_no_pending_publish_failure(&self) {
        assert!(self.fail_next_publish.lock().unwrap().is_none());
    }

    fn wait_for_publish_failure_consumed(&self) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            if self.fail_next_publish.lock().unwrap().is_none() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for readiness failure injection"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl ReadinessSink for FailingReadinessSink {
    fn max_tracked_objects(&self) -> usize {
        self.inner.max_tracked_objects()
    }

    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        let mut fail_next_publish = self.fail_next_publish.lock().unwrap();
        let should_fail = fail_next_publish.as_ref().is_some_and(|failure| {
            failure.handle.is_none_or(|failed| failed == handle)
                && readiness.contains(failure.required)
                && readiness.0 & failure.forbidden.0 == 0
        });
        if should_fail {
            *fail_next_publish = None;
            return Err(BrokerError::ResourceExhausted);
        }
        drop(fail_next_publish);
        self.inner.publish(handle, readiness)
    }

    fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> BrokerResult<()> {
        self.publish(handle, readiness)
    }

    fn retire(&self, handle: ObjectHandle) {
        self.inner.retire(handle);
    }
}

#[test]
fn directional_shutdown_survives_readiness_publication_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (release_server, wait_to_release_server) = channel();
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        wait_to_release_server.recv_timeout(TEST_TIMEOUT).unwrap();
    });

    let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider,
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });

    let tcp = create_socket(&session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &session,
            tcp,
            gateway_address(socket_address_v4(address)),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&session, tcp, &publications);
    readiness.fail_next_publish_matching(tcp, ReadinessFlags::READ, ReadinessFlags::WRITE);
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, tcp, ShutdownMode::Both),
        Ok(SocketOutcome::Completed(()))
    );
    readiness.assert_no_pending_publish_failure();
    let tcp_readiness = session.check_readiness(tcp).unwrap();
    assert!(tcp_readiness.contains(ReadinessFlags::READ));
    assert!(!tcp_readiness.contains(ReadinessFlags::WRITE));

    let udp = create_udp_socket(&session, readiness.clone());
    readiness.fail_next_publish_matching(udp, ReadinessFlags::READ, ReadinessFlags::WRITE);
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, udp, ShutdownMode::Both),
        Ok(SocketOutcome::Completed(()))
    );
    readiness.assert_no_pending_publish_failure();
    let udp_readiness = session.check_readiness(udp).unwrap();
    assert!(udp_readiness.contains(ReadinessFlags::READ));
    assert!(!udp_readiness.contains(ReadinessFlags::WRITE));

    release_server.send(()).unwrap();
    server.join().unwrap();
}

fn socket_address_v4(address: std::net::SocketAddr) -> SocketAddrV4 {
    let std::net::SocketAddr::V4(address) = address else {
        panic!("loopback TCP test unexpectedly used IPv6");
    };
    address
}

fn non_loopback_local_ipv4() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let address = socket_address_v4(probe.local_addr().ok()?);
    (!address.ip().is_unspecified()
        && !address.ip().is_loopback()
        && *address.ip() != GUEST_IPV4_ADDRESS)
        .then_some(*address.ip())
}

fn create_socket(
    session: &litebox_broker_core::BrokerSession,
    readiness: Arc<dyn ReadinessSink>,
) -> ObjectHandle {
    litebox_broker_core::socket::create(
        session,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Stream,
            protocol: IpProtocol::Tcp,
        },
        readiness,
    )
    .unwrap()
}

fn create_udp_socket(
    session: &litebox_broker_core::BrokerSession,
    readiness: Arc<dyn ReadinessSink>,
) -> ObjectHandle {
    litebox_broker_core::socket::create(
        session,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
        },
        readiness,
    )
    .unwrap()
}

fn wait_until_connected(
    session: &litebox_broker_core::BrokerSession,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match litebox_broker_core::socket::status(session, handle)
            .unwrap()
            .status
        {
            SocketConnectionStatus::Connected => return,
            SocketConnectionStatus::Connecting => {
                wait_for_readiness_until(
                    publications,
                    handle,
                    ReadinessFlags::WRITE | ReadinessFlags::ERROR,
                    deadline,
                );
            }
            status => panic!("unexpected connect status: {status:?}"),
        }
    }
}

fn wait_until_failed(
    session: &litebox_broker_core::BrokerSession,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
) -> SocketError {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match litebox_broker_core::socket::status(session, handle)
            .unwrap()
            .status
        {
            SocketConnectionStatus::Connecting => {
                wait_for_readiness_until(publications, handle, ReadinessFlags::ERROR, deadline);
            }
            SocketConnectionStatus::Failed(error) => return error,
            status => panic!("unexpected connect status: {status:?}"),
        }
    }
}

fn wait_for_end_of_stream(
    session: &litebox_broker_core::BrokerSession,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let mut byte = [0_u8; 1];
        match receive_into(session, handle, &mut byte, ReceiveFlags::NONE, 0, 0) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream)) => return,
            Err(BrokerError::WouldBlock) => {
                wait_for_readiness_until(
                    publications,
                    handle,
                    ReadinessFlags::READ | ReadinessFlags::HANGUP,
                    deadline,
                );
            }
            outcome => panic!("unexpected receive outcome: {outcome:?}"),
        }
    }
}

fn wait_for_readiness(
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
) {
    wait_for_readiness_until(
        publications,
        handle,
        readiness,
        Instant::now() + TEST_TIMEOUT,
    );
}

fn wait_for_readiness_publication(
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out waiting for socket readiness publication");
        let (published_handle, published) = publications.recv_timeout(remaining).unwrap();
        if published_handle == handle && published.contains(readiness) {
            return;
        }
    }
}

fn wait_until_ready(
    session: &litebox_broker_core::BrokerSession,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
) {
    wait_until_ready_until(
        session,
        publications,
        handle,
        readiness,
        Instant::now() + TEST_TIMEOUT,
    );
}

fn wait_until_ready_until(
    session: &litebox_broker_core::BrokerSession,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
    deadline: Instant,
) {
    loop {
        if session.check_readiness(handle).unwrap().contains(readiness) {
            return;
        }
        // Notifications are wake hints and may be stale by the time the
        // test receives them; readiness is authoritative.
        wait_for_readiness_until(publications, handle, readiness, deadline);
    }
}

fn wait_for_readiness_until(
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
    readiness: ReadinessFlags,
    deadline: Instant,
) {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out waiting for socket readiness");
        let (published_handle, published) = publications.recv_timeout(remaining).unwrap();
        if published_handle == handle && published.0 & readiness.0 != 0 {
            return;
        }
    }
}
