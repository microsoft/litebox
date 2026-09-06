// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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
    assert!(is_internal_socket_address(unspecified));
    let loopback = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    assert_eq!(normalize_socket_destination(unspecified), Ok(loopback));
    assert!(is_internal_socket_address(loopback));
    let loopback_alias = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), port);
    assert_eq!(
        normalize_socket_destination(loopback_alias),
        Ok(loopback_alias)
    );
    assert!(is_internal_socket_address(loopback_alias));
    let guest = SocketAddrV4::new(GUEST_IPV4_ADDRESS, port);
    assert_eq!(normalize_socket_destination(guest), Ok(guest));
    assert!(is_internal_socket_address(guest));
    let gateway = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, port);
    assert_eq!(normalize_socket_destination(gateway), Ok(gateway));
    assert!(!is_internal_socket_address(gateway));
    assert_eq!(
        host_socket_destination(gateway),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
    );
    let native = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port);
    assert_eq!(normalize_socket_destination(native), Ok(native));
    assert!(!is_internal_socket_address(native));
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
    let broker = test_broker_with_policy(Arc::clone(&provider) as Arc<dyn SocketProvider>, &policy);
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
            local_address: private,
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
    let broker = test_broker_with_policy(Arc::clone(&provider) as Arc<dyn SocketProvider>, &policy);
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
    let broker = test_broker_with_policy(Arc::clone(&provider) as Arc<dyn SocketProvider>, &policy);
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
        TestInvalidAddress::Gateway => SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, address.port()),
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
    fn fail_next_create(&self) {
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
        let address = binding.local_address();
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
        random_provider: Arc::new(crate::random::TestRandomProvider),
        stdio_provider: Arc::new(crate::stdio::UnsupportedStdioProvider),
        socket_provider,
        fs_provider: Arc::new(crate::fs::UnsupportedFilesystemProvider),
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
    check_terminal_stream_status_preserves_refined_address(broker, provider);
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

fn check_invalid_bind_response_retires_socket(broker: &BrokerCore, provider: &TestSocketProvider) {
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
        let request = match operation {
            TestAutomaticBindOperation::TcpConnect | TestAutomaticBindOperation::TcpListen => {
                create_request()
            }
            TestAutomaticBindOperation::UdpSend | TestAutomaticBindOperation::UdpConnect => {
                create_udp_request()
            }
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

fn check_duplicate_port_binding_retires_socket(broker: &BrokerCore, provider: &TestSocketProvider) {
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

fn check_udp_status_validates_local_address(broker: &BrokerCore, provider: &TestSocketProvider) {
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
    let stale_local_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), local_address.port());
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

fn check_quota_waits_for_deferred_retirement(broker: &BrokerCore, provider: &TestSocketProvider) {
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

fn check_connect_errors_classify_peer_state(broker: &BrokerCore, provider: &TestSocketProvider) {
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
            status: SocketConnectionStatus::Connected,
            local_address: Some(platform_local_address),
            pending_error: None,
        },
        PlatformSocketStatus {
            status: SocketConnectionStatus::Unconnected,
            local_address: Some(platform_local_address),
            pending_error: None,
        },
    ]);
    provider.fail_next_status();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *provider.state.status_block.lock().unwrap() = Some((started_tx, release_rx));
    let status_session = Arc::clone(&session);
    let in_flight = std::thread::spawn(move || status(&status_session, handle));
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
    assert_eq!(status(&session, handle), Err(BrokerError::Internal));
    assert_eq!(
        provider.state.retired_sockets.load(Ordering::Relaxed),
        retired_before + 1
    );
    release_tx.send(()).unwrap();
    assert_eq!(
        in_flight.join().unwrap(),
        Ok(SocketStatusResponse {
            status: SocketConnectionStatus::Failed(SocketError::Other),
            local_address: Some(platform_local_address),
            pending_error: None,
        })
    );
    session.close_object_reference(handle).unwrap();
}

fn check_stream_status_validates_local_address(broker: &BrokerCore, provider: &TestSocketProvider) {
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
            local_address: Some(wildcard_address),
            pending_error: None,
        });
    let retired_before = provider.state.retired_sockets.load(Ordering::Relaxed);
    assert_eq!(
        status(&session, valid),
        Ok(SocketStatusResponse {
            status: SocketConnectionStatus::Connected,
            local_address: Some(wildcard_address),
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
            local_address: Some(observed_address),
            pending_error: None,
        });
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

fn check_terminal_stream_status_preserves_refined_address(
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
