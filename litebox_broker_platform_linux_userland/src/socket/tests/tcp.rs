// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::super::tcp::{TcpDescriptor, create_tcp_transport};
use super::*;
use std::collections::VecDeque;

struct GuestTcpPair {
    listener_process: Arc<BrokerProcess>,
    connector_process: Arc<BrokerProcess>,
    connector: ObjectHandle,
    accepted: ObjectHandle,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
    retirements: Receiver<ObjectHandle>,
}

fn connected_guest_tcp_pair(port: u16) -> GuestTcpPair {
    let provider = Arc::new(LinuxSocketProvider::new(4, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider,
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    let connector = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let SocketOutcome::Completed(accepted) =
        litebox_broker_core::socket::accept(&listener_process, listener, readiness)
            .expect("guest accept failed")
    else {
        panic!("guest accept returned a socket failure");
    };
    GuestTcpPair {
        listener_process,
        connector_process,
        connector,
        accepted: accepted.handle,
        publications,
        retirements,
    }
}

fn abort_and_close_accepted_peer(pair: &GuestTcpPair) {
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &pair.listener_process,
            pair.accepted,
            ShutdownMode::Abort,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    pair.listener_process
        .close_object_reference(pair.accepted)
        .unwrap();
    assert_eq!(
        pair.retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        pair.accepted
    );
}

fn wait_for_guest_reset(
    process: &BrokerProcess,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
) {
    let readiness = ReadinessFlags::READ | ReadinessFlags::ERROR | ReadinessFlags::HANGUP;
    wait_for_readiness_publication(publications, handle, readiness);
    assert!(process.check_readiness(handle).unwrap().contains(readiness));
}

#[test]
fn reactor_drives_a_loopback_tcp_socket() {
    assert_eq!(
        socket_operation_error_from_errno(Errno::NOMEM),
        Err(BrokerError::OutOfMemory)
    );
    assert_eq!(
        socket_operation_error_from_errno(Errno::NOBUFS),
        Err(BrokerError::ResourceExhausted)
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (allow_response, response_allowed) = channel();
    let (allow_end_of_stream, end_of_stream_allowed) = channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        response_allowed.recv_timeout(TEST_TIMEOUT).unwrap();
        stream.write_all(b"pong").unwrap();
        end_of_stream_allowed.recv_timeout(TEST_TIMEOUT).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let read_shutdown_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let read_shutdown_address = read_shutdown_listener.local_addr().unwrap();
    let (allow_read_shutdown_data, read_shutdown_data_allowed) = channel();
    let (read_shutdown_data_sent, read_shutdown_data_received) = channel();
    let (release_read_shutdown_server, read_shutdown_server_released) = channel();
    let read_shutdown_server = thread::spawn(move || {
        let (mut stream, _) = read_shutdown_listener.accept().unwrap();
        read_shutdown_data_allowed
            .recv_timeout(TEST_TIMEOUT)
            .unwrap();
        stream.write_all(b"x").unwrap();
        read_shutdown_data_sent.send(()).unwrap();
        read_shutdown_server_released
            .recv_timeout(TEST_TIMEOUT)
            .unwrap();
    });
    let abort_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let abort_address = abort_listener.local_addr().unwrap();
    let (abort_accepted, wait_for_abort_accept) = channel();
    let abort_server = thread::spawn(move || {
        let (mut stream, _) = abort_listener.accept().unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        abort_accepted.send(()).unwrap();
        let error = stream.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    });

    let provider = Arc::new(LinuxSocketProvider::new(8, 8).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(16, 0, 8, 8),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let handle = create_socket(&process, readiness.clone());
    assert_eq!(provider.reactor.tcp_descriptor_counts(), (1, 0, 0));
    let connect = litebox_broker_core::socket::connect(
        &process,
        handle,
        gateway_address(socket_address_v4(address)),
    )
    .unwrap();
    assert!(matches!(
        connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    wait_until_connected(&process, handle, &publications);
    assert_eq!(provider.reactor.tcp_descriptor_counts(), (0, 1, 0));
    let status = litebox_broker_core::socket::status(&process, handle).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connected);
    let local_address = status
        .local_address
        .expect("connected socket must expose its local address");
    assert_eq!(*local_address.ip(), GUEST_IPV4_ADDRESS);
    assert_ne!(local_address.port(), 0);
    assert_eq!(status.pending_error, None);
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&process, handle, TcpOptionName::NoDelay,),
        Ok(TcpOptionValue::NoDelay(false))
    );
    litebox_broker_core::socket::set_tcp_option(&process, handle, TcpOptionValue::NoDelay(true))
        .unwrap();
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&process, handle, TcpOptionName::NoDelay,),
        Ok(TcpOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&process, handle, TcpOptionName::KeepAlive,),
        Ok(TcpOptionValue::KeepAlive(false))
    );
    litebox_broker_core::socket::set_tcp_option(&process, handle, TcpOptionValue::KeepAlive(true))
        .unwrap();
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&process, handle, TcpOptionName::KeepAlive,),
        Ok(TcpOptionValue::KeepAlive(true))
    );

    let mut unavailable = [0_u8; 1];
    assert_eq!(
        receive_into(&process, handle, &mut unavailable, ReceiveFlags::NONE, 0, 0,),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        send_bytes(&process, handle, b"ping", SendFlags::NONE,),
        Ok(SocketOutcome::Completed(4))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, handle, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        send_bytes(&process, handle, b"after shutdown", SendFlags::NONE),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );
    allow_response.send(()).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    let current_readiness = process.check_readiness(handle).unwrap();
    assert!(!current_readiness.contains(ReadinessFlags::WRITE));
    assert!(!current_readiness.contains(ReadinessFlags::ERROR));

    let mut first = [0_u8; 1];
    assert_eq!(
        receive_into(&process, handle, &mut first, ReceiveFlags::NONE, 0, 0,),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    assert_eq!(&first, b"p");
    assert!(
        process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    let mut peeked = [0_u8; 3];
    assert_eq!(
        receive_into(&process, handle, &mut peeked, ReceiveFlags::PEEK, 0, 3,),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
    );
    assert_eq!(&peeked, b"ong");
    let mut received = [0_u8; 3];
    assert_eq!(
        receive_into(&process, handle, &mut received, ReceiveFlags::NONE, 0, 0,),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
    );
    assert_eq!(&received, b"ong");
    assert!(
        !process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert_eq!(
        receive_into(&process, handle, &mut unavailable, ReceiveFlags::NONE, 0, 0,),
        Err(BrokerError::WouldBlock)
    );
    assert!(
        !process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    allow_end_of_stream.send(()).unwrap();
    wait_for_end_of_stream(&process, handle, &publications);

    let read_shutdown_handle = create_socket(&process, readiness.clone());
    let read_shutdown_connect = litebox_broker_core::socket::connect(
        &process,
        read_shutdown_handle,
        gateway_address(socket_address_v4(read_shutdown_address)),
    )
    .unwrap();
    assert!(matches!(
        read_shutdown_connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    wait_until_connected(&process, read_shutdown_handle, &publications);
    allow_read_shutdown_data.send(()).unwrap();
    read_shutdown_data_received
        .recv_timeout(TEST_TIMEOUT)
        .unwrap();
    wait_for_readiness_publication(&publications, read_shutdown_handle, ReadinessFlags::READ);
    let mut read_shutdown_peek = [0_u8; 2];
    assert_eq!(
        receive_into(
            &process,
            read_shutdown_handle,
            &mut read_shutdown_peek,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            2,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, read_shutdown_handle, ShutdownMode::Read,),
        Ok(SocketOutcome::Completed(()))
    );
    wait_for_readiness_publication(&publications, read_shutdown_handle, ReadinessFlags::READ);
    assert_eq!(
        receive_into(
            &process,
            read_shutdown_handle,
            &mut read_shutdown_peek,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            2,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    assert_eq!(read_shutdown_peek[0], b'x');
    let mut queued_after_shutdown = [0_u8; 1];
    assert_eq!(
        receive_into(
            &process,
            read_shutdown_handle,
            &mut queued_after_shutdown,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    assert_eq!(queued_after_shutdown, [b'x']);
    assert!(
        process
            .check_readiness(read_shutdown_handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert_eq!(
        receive_into(
            &process,
            read_shutdown_handle,
            &mut queued_after_shutdown,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
    let read_shutdown_readiness = process.check_readiness(read_shutdown_handle).unwrap();
    assert!(read_shutdown_readiness.contains(ReadinessFlags::READ));
    assert!(!read_shutdown_readiness.contains(ReadinessFlags::HANGUP));
    assert!(!read_shutdown_readiness.contains(ReadinessFlags::ERROR));

    let unconnected_handle = create_socket(&process, readiness.clone());
    assert_eq!(
        receive_into(
            &process,
            unconnected_handle,
            &mut unavailable,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            1,
        ),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, unconnected_handle, ShutdownMode::Both,),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &process,
            unconnected_handle,
            ShutdownMode::StopListening,
        ),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert!(
        !process
            .check_readiness(unconnected_handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );

    let refused_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let refused_address = refused_listener.local_addr().unwrap();
    drop(refused_listener);
    let refused_handle = create_socket(&process, readiness.clone());
    let refused_connect = litebox_broker_core::socket::connect(
        &process,
        refused_handle,
        gateway_address(socket_address_v4(refused_address)),
    )
    .unwrap();
    assert!(matches!(
        refused_connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Failed(_)
        )
    ));
    assert_eq!(
        wait_until_failed(&process, refused_handle, &publications),
        SocketError::ConnectionRefused
    );
    assert!(
        process
            .check_readiness(refused_handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );

    let abort_handle = create_socket(&process, readiness);
    let abort_connect = litebox_broker_core::socket::connect(
        &process,
        abort_handle,
        gateway_address(socket_address_v4(abort_address)),
    )
    .unwrap();
    assert!(matches!(
        abort_connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    wait_until_connected(&process, abort_handle, &publications);
    wait_for_abort_accept.recv_timeout(TEST_TIMEOUT).unwrap();
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, abort_handle, ShutdownMode::Abort),
        Ok(SocketOutcome::Completed(()))
    );
    process.close_object_reference(abort_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        abort_handle
    );
    abort_server.join().unwrap();

    process.close_object_reference(handle).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
    process
        .close_object_reference(read_shutdown_handle)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        read_shutdown_handle
    );
    process.close_object_reference(unconnected_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        unconnected_handle
    );
    process.close_object_reference(refused_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        refused_handle
    );
    release_read_shutdown_server.send(()).unwrap();
    read_shutdown_server.join().unwrap();
    server.join().unwrap();
}

#[test]
fn external_tcp_deferred_abortive_close_resets_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = gateway_address(socket_address_v4(listener.local_addr().unwrap()));
    let (accepted, wait_for_accept) = channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        accepted.send(()).unwrap();
        let error = stream.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    });

    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let socket = create_socket(&process, readiness);

    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, socket, ShutdownMode::Abort),
        Ok(SocketOutcome::Completed(()))
    );
    assert!(matches!(
        litebox_broker_core::socket::connect(&process, socket, address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process, socket, &publications);
    wait_for_accept.recv_timeout(TEST_TIMEOUT).unwrap();
    process.close_object_reference(socket).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), socket);
    server.join().unwrap();
}

#[test]
fn external_tcp_gateway_uses_host_loopback_and_keeps_guest_identity() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let host_address = socket_address_v4(listener.local_addr().unwrap());
    let destination = gateway_address(host_address);
    let policy = SocketPolicy::deny()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(destination.port()), Port(destination.port())).unwrap(),
        )])
        .unwrap();
    let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(policy),
        BrokerCoreLimits::new_with_all_limits(3, 0, 2, 2),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let direct = create_socket(&process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&process, direct, host_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    process.close_object_reference(direct).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), direct);

    let socket = create_socket(&process, readiness);
    let SocketOutcome::Completed(binding) = litebox_broker_core::socket::bind(
        &process,
        socket,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard bind failed");
    };
    assert!(matches!(
        litebox_broker_core::socket::connect(&process, socket, destination),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process, socket, &publications);

    let status = litebox_broker_core::socket::status(&process, socket).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connected);
    assert_eq!(
        status.local_address,
        Some(SocketAddrV4::new(GUEST_IPV4_ADDRESS, binding.port()))
    );
    assert_eq!(
        litebox_broker_core::socket::status(&process, socket)
            .unwrap()
            .local_address,
        status.local_address
    );
}

#[test]
fn external_tcp_route_keeps_guest_private_identity() {
    let local_ip = non_loopback_local_ipv4();
    if std::env::var_os("CI").is_some() {
        assert!(
            local_ip.is_some(),
            "CI runner must provide a routable non-loopback IPv4 address"
        );
    }
    let Some(local_ip) = local_ip else {
        return;
    };
    let listener = TcpListener::bind((local_ip, 0)).unwrap();
    let destination = socket_address_v4(listener.local_addr().unwrap());
    let policy = SocketPolicy::deny()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(local_ip.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(destination.port()), Port(destination.port())).unwrap(),
        )])
        .unwrap();
    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(policy),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let socket = create_socket(&process, readiness);
    let SocketOutcome::Completed(binding) = litebox_broker_core::socket::bind(
        &process,
        socket,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard bind failed");
    };

    assert!(matches!(
        litebox_broker_core::socket::connect(&process, socket, destination),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process, socket, &publications);
    assert_eq!(
        litebox_broker_core::socket::status(&process, socket)
            .unwrap()
            .local_address,
        Some(SocketAddrV4::new(GUEST_IPV4_ADDRESS, binding.port()))
    );
}

#[test]
fn tcp_connect_to_zero_port_returns_an_ordinary_socket_outcome() {
    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_socket(&process, Arc::new(TestReadinessSink { published, retired }));

    assert_eq!(
        litebox_broker_core::socket::connect(
            &process,
            socket,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
}

#[test]
fn tcp_receive_survives_readiness_publication_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (send_data, wait_to_send_data) = channel();
    let (release_server, wait_to_release_server) = channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        wait_to_send_data.recv_timeout(TEST_TIMEOUT).unwrap();
        stream.write_all(b"reply").unwrap();
        wait_to_release_server.recv_timeout(TEST_TIMEOUT).unwrap();
    });

    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let handle = create_socket(&process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &process,
            handle,
            gateway_address(socket_address_v4(address)),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process, handle, &publications);

    send_data.send(()).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    readiness.fail_next_publish_matching(handle, ReadinessFlags::default(), ReadinessFlags::READ);
    let mut data = [0_u8; 5];
    assert_eq!(
        receive_into(&process, handle, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(5)))
    );
    assert_eq!(&data, b"reply");
    readiness.assert_no_pending_publish_failure();
    assert!(
        !process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    release_server.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn tcp_status_publication_failure_preserves_consumed_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (abort_connection, wait_to_abort_connection) = channel();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        wait_to_abort_connection.recv_timeout(TEST_TIMEOUT).unwrap();
        sockopt::set_socket_linger(&stream, Some(Duration::ZERO)).unwrap();
    });

    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let handle = create_socket(&process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &process,
            handle,
            gateway_address(socket_address_v4(address)),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process, handle, &publications);

    abort_connection.send(()).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::ERROR);
    readiness.fail_next_publish_matching(handle, ReadinessFlags::default(), ReadinessFlags::ERROR);
    let status = litebox_broker_core::socket::status(&process, handle).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connected);
    assert_eq!(status.pending_error, Some(SocketError::ConnectionReset));
    readiness.assert_no_pending_publish_failure();
    assert!(
        !process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    server.join().unwrap();
}

#[test]
fn external_tcp_readiness_failure_does_not_fail_shared_reactor() {
    // Process A owns the socket whose asynchronous reactor publication fails.
    let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
    let address_a = listener_a.local_addr().unwrap();
    let (send_reply_a, wait_to_send_reply_a) = channel();
    let (release_a, wait_to_release_a) = channel();
    let server_a = thread::spawn(move || {
        let (mut stream, _) = listener_a.accept().unwrap();
        wait_to_send_reply_a.recv_timeout(TEST_TIMEOUT).unwrap();
        stream.write_all(b"reply").unwrap();
        wait_to_release_a.recv_timeout(TEST_TIMEOUT).unwrap();
    });

    // Process B shares the same reactor. The original bug cleared every
    // process's sockets, so B is the cross-process isolation witness.
    let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
    let address_b = listener_b.local_addr().unwrap();
    let (send_beta_b, wait_to_send_beta_b) = channel();
    let (release_b, wait_to_release_b) = channel();
    let server_b = thread::spawn(move || {
        let (mut stream, _) = listener_b.accept().unwrap();
        wait_to_send_beta_b.recv_timeout(TEST_TIMEOUT).unwrap();
        stream.write_all(b"beta").unwrap();
        wait_to_release_b.recv_timeout(TEST_TIMEOUT).unwrap();
    });

    let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider,
    )
    .unwrap();

    let process_a = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published_a, publications_a) = channel();
    let (retired_a, _retirements_a) = channel();
    let readiness_a = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink {
            published: published_a,
            retired: retired_a,
        },
        fail_next_publish: Mutex::new(None),
    });
    let handle_a = create_socket(&process_a, readiness_a.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &process_a,
            handle_a,
            gateway_address(socket_address_v4(address_a)),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process_a, handle_a, &publications_a);

    // Process B gets its own readiness sink, mirroring production's
    // per-association sinks.
    let process_b = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published_b, publications_b) = channel();
    let (retired_b, _retirements_b) = channel();
    let readiness_b = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink {
            published: published_b,
            retired: retired_b,
        },
        fail_next_publish: Mutex::new(None),
    });
    let handle_b = create_socket(&process_b, readiness_b.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &process_b,
            handle_b,
            gateway_address(socket_address_v4(address_b)),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process_b, handle_b, &publications_b);

    // Fail process A's asynchronous readiness publication at the moment the
    // peer's data makes the socket readable. This exercises the shared-reactor
    // event path (`handle_socket_event`), not a synchronous command: the reactor
    // must absorb one association's publication failure and keep serving that
    // socket rather than tearing down every process's sockets.
    readiness_a.fail_next_publish_matching(
        handle_a,
        ReadinessFlags::READ,
        ReadinessFlags::default(),
    );
    send_reply_a.send(()).unwrap();
    readiness_a.wait_for_publish_failure_consumed();

    // `update_snapshot` commits the cached snapshot before publishing, so the
    // guest-visible readiness reflects READ even though the notification was
    // dropped.
    assert!(
        process_a
            .check_readiness(handle_a)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    // Process A's own socket is still serviceable through the reactor.
    let mut data_a = [0_u8; 5];
    assert_eq!(
        receive_into(&process_a, handle_a, &mut data_a, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(5)))
    );
    assert_eq!(&data_a, b"reply");
    readiness_a.assert_no_pending_publish_failure();

    // Cross-process isolation: process B still transacts after A's failure.
    // Under the original bug the reactor would have exited and cleared B's
    // socket, so this receive would fail.
    send_beta_b.send(()).unwrap();
    wait_until_ready(&process_b, &publications_b, handle_b, ReadinessFlags::READ);
    let mut data_b = [0_u8; 4];
    assert_eq!(
        receive_into(&process_b, handle_b, &mut data_b, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(4)))
    );
    assert_eq!(&data_b, b"beta");

    release_a.send(()).unwrap();
    release_b.send(()).unwrap();
    server_a.join().unwrap();
    server_b.join().unwrap();
}

#[test]
fn external_tcp_connect_completion_readiness_failure_does_not_fail_shared_reactor() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (send_data, wait_to_send_data) = channel();
    let (release_server, wait_to_release_server) = channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        wait_to_send_data.recv_timeout(TEST_TIMEOUT).unwrap();
        stream.write_all(b"reply").unwrap();
        wait_to_release_server.recv_timeout(TEST_TIMEOUT).unwrap();
    });

    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let handle = create_socket(&process, readiness.clone());

    // Arm the failure before connecting. A non-blocking loopback connect
    // returns EINPROGRESS, so the reactor publishes empty readiness
    // synchronously (no WRITE, no match) and completes the connection
    // asynchronously through `complete_connect`, whose best-effort WRITE
    // publication is the site under test. Forbidding ERROR keeps a
    // failed-connect publication from matching instead.
    readiness.fail_next_publish_matching(handle, ReadinessFlags::WRITE, ReadinessFlags::ERROR);
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &process,
            handle,
            gateway_address(socket_address_v4(address)),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    readiness.wait_for_publish_failure_consumed();

    // The cached snapshot committed the connected, writable state before the
    // dropped notification, so the guest still observes a usable socket.
    assert_eq!(
        litebox_broker_core::socket::status(&process, handle)
            .unwrap()
            .status,
        SocketConnectionStatus::Connected
    );
    assert!(
        process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );

    // The connection is fully usable despite the dropped connect-completion
    // notification.
    send_data.send(()).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    let mut data = [0_u8; 5];
    assert_eq!(
        receive_into(&process, handle, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(5)))
    );
    assert_eq!(&data, b"reply");
    readiness.assert_no_pending_publish_failure();

    release_server.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn exhausted_tcp_peek_cache_refreshes_before_terminal_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let chunk = MAX_SOCKET_TRANSFER_SIZE as usize;
    let (first_chunk_sent, wait_for_first_chunk) = channel();
    let (send_second_chunk, wait_to_send_second_chunk) = channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(&vec![0x41; chunk]).unwrap();
        first_chunk_sent.send(()).unwrap();
        wait_to_send_second_chunk
            .recv_timeout(TEST_TIMEOUT)
            .unwrap();
        stream.write_all(&vec![0x42; chunk]).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let handle = create_socket(&process, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &process,
            handle,
            gateway_address(socket_address_v4(address)),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process, handle, &publications);
    wait_for_first_chunk.recv_timeout(TEST_TIMEOUT).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);

    let peek_length = MAX_SOCKET_TRANSFER_SIZE * 2;
    let mut first = vec![0_u8; chunk];
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        match receive_into(
            &process,
            handle,
            &mut first,
            ReceiveFlags::PEEK,
            0,
            peek_length,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
                MAX_SOCKET_TRANSFER_SIZE,
            ))) => break,
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(_)))
            | Err(BrokerError::WouldBlock) => {
                deadline
                    .checked_duration_since(Instant::now())
                    .expect("timed out waiting for the first TCP peek chunk");
                thread::yield_now();
            }
            outcome => panic!("unexpected first peek outcome: {outcome:?}"),
        }
    }
    assert!(first.iter().all(|byte| *byte == 0x41));

    send_second_chunk.send(()).unwrap();
    wait_until_ready(
        &process,
        &publications,
        handle,
        ReadinessFlags::READ | ReadinessFlags::HANGUP,
    );
    let mut second = vec![0_u8; chunk];
    assert_eq!(
        receive_into(
            &process,
            handle,
            &mut second,
            ReceiveFlags::PEEK,
            MAX_SOCKET_TRANSFER_SIZE,
            peek_length,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
            MAX_SOCKET_TRANSFER_SIZE
        )))
    );
    assert!(second.iter().all(|byte| *byte == 0x42));
    server.join().unwrap();
}

#[test]
fn accepted_guest_tcp_close_with_unread_data_preserves_reset() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(6, 0, 3, 3),
        provider,
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8091);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, connector, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, connector, &publications);
    wait_until_ready(
        &listener_process,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    let accepted =
        match litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone())
            .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted.handle,
            SocketOutcome::Failed(error) => panic!("guest accept failed: {error:?}"),
        };
    assert_eq!(
        send_bytes(&listener_process, accepted, b"unread", SendFlags::NONE,),
        Ok(SocketOutcome::Completed(6))
    );
    wait_until_ready(
        &connector_process,
        &publications,
        connector,
        ReadinessFlags::READ,
    );

    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    wait_for_guest_reset(&listener_process, &publications, accepted);
    let mut byte = [0_u8; 1];
    assert_eq!(
        receive_into(
            &listener_process,
            accepted,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    listener_process.close_object_reference(accepted).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), accepted);

    let aborting = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, aborting, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let abort_peer =
        litebox_broker_core::socket::accept(&listener_process, listener, readiness).unwrap();
    let SocketOutcome::Completed(abort_peer) = abort_peer else {
        panic!("second guest accept failed");
    };
    assert_eq!(
        litebox_broker_core::socket::shutdown(&connector_process, aborting, ShutdownMode::Abort,),
        Ok(SocketOutcome::Completed(()))
    );
    connector_process.close_object_reference(aborting).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), aborting);
    wait_for_guest_reset(&listener_process, &publications, abort_peer.handle);
    assert_eq!(
        receive_into(
            &listener_process,
            abort_peer.handle,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
}

#[test]
fn guest_tcp_direct_receive_reports_reset_once_then_eof() {
    let pair = connected_guest_tcp_pair(8101);
    abort_and_close_accepted_peer(&pair);
    wait_for_guest_reset(&pair.connector_process, &pair.publications, pair.connector);

    let mut byte = [0_u8; 1];
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    loop {
        let (handle, readiness) = pair.publications.recv_timeout(TEST_TIMEOUT).unwrap();
        if handle == pair.connector
            && readiness.contains(ReadinessFlags::READ | ReadinessFlags::HANGUP)
            && !readiness.contains(ReadinessFlags::ERROR)
        {
            break;
        }
    }
    let readiness = pair
        .connector_process
        .check_readiness(pair.connector)
        .unwrap();
    assert!(readiness.contains(ReadinessFlags::READ));
    assert!(readiness.contains(ReadinessFlags::HANGUP));
    assert!(!readiness.contains(ReadinessFlags::ERROR));
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
    assert_eq!(
        litebox_broker_core::socket::status(&pair.connector_process, pair.connector)
            .unwrap()
            .pending_error,
        None
    );
    assert!(matches!(
        send_bytes(
            &pair.connector_process,
            pair.connector,
            b"after reset",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Failed(_))
    ));
}

#[test]
fn guest_tcp_status_consumes_reset_before_buffered_data() {
    let pair = connected_guest_tcp_pair(8102);
    assert_eq!(
        send_bytes(
            &pair.listener_process,
            pair.accepted,
            b"buffered",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(8))
    );
    wait_until_ready(
        &pair.connector_process,
        &pair.publications,
        pair.connector,
        ReadinessFlags::READ,
    );
    abort_and_close_accepted_peer(&pair);
    wait_for_guest_reset(&pair.connector_process, &pair.publications, pair.connector);

    let status =
        litebox_broker_core::socket::status(&pair.connector_process, pair.connector).unwrap();
    assert_eq!(status.pending_error, Some(SocketError::ConnectionReset));
    let readiness = pair
        .connector_process
        .check_readiness(pair.connector)
        .unwrap();
    assert!(readiness.contains(ReadinessFlags::READ));
    assert!(readiness.contains(ReadinessFlags::HANGUP));
    assert!(!readiness.contains(ReadinessFlags::ERROR));
    let mut buffered = [0_u8; 8];
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut buffered,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(8)))
    );
    assert_eq!(&buffered, b"buffered");
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut buffered,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
    assert_eq!(
        litebox_broker_core::socket::status(&pair.connector_process, pair.connector)
            .unwrap()
            .pending_error,
        None
    );
}

#[test]
fn guest_tcp_buffered_data_precedes_direct_reset_and_eof() {
    let pair = connected_guest_tcp_pair(8103);
    assert_eq!(
        send_bytes(
            &pair.listener_process,
            pair.accepted,
            b"buffered",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(8))
    );
    wait_until_ready(
        &pair.connector_process,
        &pair.publications,
        pair.connector,
        ReadinessFlags::READ,
    );
    abort_and_close_accepted_peer(&pair);

    let mut buffered = [0_u8; 8];
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut buffered,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(8)))
    );
    assert_eq!(&buffered, b"buffered");
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut buffered,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut buffered,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
}

#[test]
fn guest_read_shutdown_buffer_precedes_reset_and_eof() {
    let pair = connected_guest_tcp_pair(8108);
    assert_eq!(
        send_bytes(
            &pair.listener_process,
            pair.accepted,
            b"queued",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(6))
    );
    wait_until_ready(
        &pair.connector_process,
        &pair.publications,
        pair.connector,
        ReadinessFlags::READ,
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &pair.connector_process,
            pair.connector,
            ShutdownMode::Read,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    abort_and_close_accepted_peer(&pair);
    wait_for_guest_reset(&pair.connector_process, &pair.publications, pair.connector);

    let mut data = [0_u8; 6];
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(6)))
    );
    assert_eq!(&data, b"queued");
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
}

#[test]
fn guest_tcp_namespace_routes_across_processs_and_hides_private_backend() {
    let provider = Arc::new(LinuxSocketProvider::new(5, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 5, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let client_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let shadowed_host_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    shadowed_host_listener.set_nonblocking(true).unwrap();
    let guest_port = shadowed_host_listener.local_addr().unwrap().port();
    let guest_address = SocketAddrV4::new(GUEST_IPV4_ADDRESS, guest_port);
    let claimed_port_miss = SocketAddrV4::new(Ipv4Addr::LOCALHOST, guest_port);
    let guest_destination = guest_address;
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    let early_client = create_socket(&client_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&client_process, early_client, claimed_port_miss,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    assert_eq!(
        shadowed_host_listener.accept().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    client_process.close_object_reference(early_client).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        early_client
    );
    let unbound_private_port = if guest_port == u16::MAX {
        guest_port - 1
    } else {
        guest_port + 1
    };
    let unbound_private_client = create_socket(&client_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(
            &client_process,
            unbound_private_client,
            SocketAddrV4::new(GUEST_IPV4_ADDRESS, unbound_private_port),
        ),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    client_process
        .close_object_reference(unbound_private_client)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        unbound_private_client
    );

    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 3),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(provider.reactor.tcp_descriptor_counts(), (1, 0, 0));
    let client = create_socket(&client_process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&client_process, client, guest_destination),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&client_process, client, &publications);
    assert_eq!(provider.reactor.tcp_descriptor_counts(), (1, 0, 1));
    let client_address = litebox_broker_core::socket::status(&client_process, client)
        .unwrap()
        .local_address
        .unwrap();
    assert_eq!(*client_address.ip(), GUEST_IPV4_ADDRESS);
    wait_until_ready(
        &listener_process,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    let accepted =
        match litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone())
            .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("accept failed: {error:?}"),
        };
    assert_eq!(accepted.local_address, guest_address);
    assert_eq!(accepted.remote_address, client_address);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    assert_eq!(provider.reactor.tcp_descriptor_counts(), (1, 0, 2));

    assert_eq!(
        send_bytes(&client_process, client, b"x", SendFlags::NONE),
        Ok(SocketOutcome::Completed(1))
    );
    wait_until_ready(
        &listener_process,
        &publications,
        accepted.handle,
        ReadinessFlags::READ,
    );
    let mut byte = [0];
    assert_eq!(
        receive_into(
            &listener_process,
            accepted.handle,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    assert_eq!(byte, *b"x");
    assert_eq!(
        shadowed_host_listener.accept().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn tcp_exact_bindings_coexist_and_wildcard_accepts_concrete_destinations() {
    let provider = Arc::new(LinuxSocketProvider::new(12, 8).unwrap());
    let policy = SocketPolicy::deny()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address([0, 0, 0, 0]), 0).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        )])
        .unwrap();
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(policy),
        BrokerCoreLimits::new_with_all_limits(20, 0, 12, 12),
        provider,
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });

    let first_listener = create_socket(&listener_process, readiness.clone());
    let SocketOutcome::Completed(first_address) = litebox_broker_core::socket::bind(
        &listener_process,
        first_listener,
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0),
    )
    .unwrap() else {
        panic!("first exact bind failed");
    };
    let second_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), first_address.port());
    let second_listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, second_listener, second_address,),
        Ok(SocketOutcome::Completed(second_address))
    );
    let wildcard_competitor = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(
            &listener_process,
            wildcard_competitor,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, first_address.port()),
        ),
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, first_listener, 1),
        Ok(SocketOutcome::Completed(first_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, second_listener, 1),
        Ok(SocketOutcome::Completed(second_address))
    );

    for (listener, destination) in [
        (first_listener, first_address),
        (second_listener, second_address),
    ] {
        let connector = create_socket(&connector_process, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_process, connector, destination,),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&connector_process, connector, &publications);
        let connector_address = litebox_broker_core::socket::status(&connector_process, connector)
            .unwrap()
            .local_address
            .unwrap();
        assert_eq!(*connector_address.ip(), Ipv4Addr::LOCALHOST);
        wait_until_ready(
            &listener_process,
            &publications,
            listener,
            ReadinessFlags::READ,
        );
        let accepted = match litebox_broker_core::socket::accept(
            &listener_process,
            listener,
            readiness.clone(),
        )
        .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("exact accept failed: {error:?}"),
        };
        assert_eq!(accepted.local_address, destination);
        assert_eq!(accepted.remote_address, connector_address);
    }

    let wildcard_listener = create_socket(&listener_process, readiness.clone());
    let SocketOutcome::Completed(wildcard_address) = litebox_broker_core::socket::bind(
        &listener_process,
        wildcard_listener,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard bind failed");
    };
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, wildcard_listener, 2),
        Ok(SocketOutcome::Completed(wildcard_address))
    );
    let concrete_destination = SocketAddrV4::new(GUEST_IPV4_ADDRESS, wildcard_address.port());
    let connector = create_socket(&connector_process, readiness.clone());
    let SocketOutcome::Completed(connector_binding) = litebox_broker_core::socket::bind(
        &connector_process,
        connector,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard connector bind failed");
    };
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, connector, concrete_destination,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, connector, &publications);
    assert_eq!(
        litebox_broker_core::socket::status(&connector_process, connector)
            .unwrap()
            .local_address,
        Some(SocketAddrV4::new(
            GUEST_IPV4_ADDRESS,
            connector_binding.port(),
        ))
    );
    wait_until_ready(
        &listener_process,
        &publications,
        wildcard_listener,
        ReadinessFlags::READ,
    );
    let accepted = match litebox_broker_core::socket::accept(
        &listener_process,
        wildcard_listener,
        readiness.clone(),
    )
    .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted,
        SocketOutcome::Failed(error) => panic!("wildcard accept failed: {error:?}"),
    };
    assert_eq!(accepted.local_address, concrete_destination);
    assert_eq!(
        accepted.remote_address,
        SocketAddrV4::new(GUEST_IPV4_ADDRESS, connector_binding.port())
    );
}

#[test]
fn connector_and_process_teardown_clean_bounded_pending_state() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8082);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 2),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, connector, &publications);
    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
    let capacity = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::create(
            &connector_process,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            },
            readiness.clone(),
        ),
        Err(BrokerError::ResourceExhausted)
    );
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), capacity);
    connector_process.close_object_reference(capacity).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), capacity);

    drop(connector_process);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    assert!(
        !listener_process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone(),),
        Err(BrokerError::WouldBlock)
    ));
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    let final_connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let final_connector = create_socket(&final_connector_process, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &final_connector_process,
            final_connector,
            guest_address,
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&final_connector_process, final_connector, &publications);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
    listener_process.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    wait_for_guest_reset(&final_connector_process, &publications, final_connector);
    let mut byte = [0_u8; 1];
    assert_eq!(
        receive_into(
            &final_connector_process,
            final_connector,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
}

#[test]
fn graceful_connector_close_preserves_late_accept_and_eof() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8089);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, connector, &publications);
    let connector_address = litebox_broker_core::socket::status(&connector_process, connector)
        .unwrap()
        .local_address
        .unwrap();
    assert_eq!(
        send_bytes(&connector_process, connector, b"queued", SendFlags::NONE,),
        Ok(SocketOutcome::Completed(6))
    );

    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
    wait_until_ready(
        &listener_process,
        &publications,
        listener,
        ReadinessFlags::READ,
    );

    let accepted = match litebox_broker_core::socket::accept(&listener_process, listener, readiness)
        .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted,
        SocketOutcome::Failed(error) => panic!("late accept failed: {error:?}"),
    };
    assert_eq!(accepted.remote_address, connector_address);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    wait_until_ready(
        &listener_process,
        &publications,
        accepted.handle,
        ReadinessFlags::READ,
    );
    let mut queued = [0_u8; 6];
    assert_eq!(
        receive_into(
            &listener_process,
            accepted.handle,
            &mut queued,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(6)))
    );
    assert_eq!(&queued, b"queued");
    wait_for_end_of_stream(&listener_process, accepted.handle, &publications);
}

#[test]
fn guest_tcp_zero_backlog_accepts_one_unspecified_destination() {
    let port = 8104;
    let policy = SocketPolicy::guest_network()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(Ipv4Addr::UNSPECIFIED.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(port), Port(port)).unwrap(),
        )])
        .unwrap();
    let provider = Arc::new(LinuxSocketProvider::new(6, 4).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(policy),
        BrokerCoreLimits::new_with_all_limits(10, 0, 6, 6),
        provider,
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let wildcard_listener = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let concrete_listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, wildcard_listener),
        Ok(SocketOutcome::Completed(wildcard_listener))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 0),
        Ok(SocketOutcome::Completed(wildcard_listener))
    );

    let connector = create_socket(&connector_process, readiness.clone());
    let SocketOutcome::Completed(connector_binding) = litebox_broker_core::socket::bind(
        &connector_process,
        connector,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard connector bind failed");
    };
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, wildcard_listener,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let concrete_connector = SocketAddrV4::new(Ipv4Addr::LOCALHOST, connector_binding.port());
    assert_eq!(
        litebox_broker_core::socket::status(&connector_process, connector)
            .unwrap()
            .local_address,
        Some(concrete_connector)
    );

    let full = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, full, wildcard_listener),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    let SocketOutcome::Completed(accepted) =
        litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone())
            .unwrap()
    else {
        panic!("zero-backlog listener did not accept its queued connection");
    };
    assert_eq!(accepted.local_address, concrete_listener);
    assert_eq!(accepted.remote_address, concrete_connector);

    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    let contender = create_socket(&connector_process, readiness);
    assert_eq!(
        litebox_broker_core::socket::bind(&connector_process, contender, concrete_connector,),
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    );
    listener_process
        .close_object_reference(accepted.handle)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        accepted.handle
    );
    assert_eq!(
        litebox_broker_core::socket::bind(&connector_process, contender, concrete_connector,),
        Ok(SocketOutcome::Completed(concrete_connector))
    );
}

#[test]
fn guest_tcp_backlog_relisten_and_fifo_are_bounded() {
    let provider = Arc::new(LinuxSocketProvider::new(10, 8).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(16, 0, 10, 10),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8092);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 2),
        Ok(SocketOutcome::Completed(address))
    );

    let first = create_socket(&connector_process, readiness.clone());
    let second = create_socket(&connector_process, readiness.clone());
    let mut expected = VecDeque::new();
    for connector in [first, second] {
        assert_eq!(
            litebox_broker_core::socket::connect(&connector_process, connector, address),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        expected.push_back(
            litebox_broker_core::socket::status(&connector_process, connector)
                .unwrap()
                .local_address
                .unwrap(),
        );
    }
    assert_eq!(provider.reactor.queued_guest_connection_count(), 2);
    let full = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, full, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(provider.reactor.queued_guest_connection_count(), 2);

    wait_until_ready(
        &listener_process,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    let accepted =
        litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone())
            .unwrap();
    let SocketOutcome::Completed(accepted) = accepted else {
        panic!("first FIFO accept failed");
    };
    assert_eq!(accepted.remote_address, expected.pop_front().unwrap());
    assert!(
        listener_process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    let still_full = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, still_full, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 3),
        Ok(SocketOutcome::Completed(address))
    );
    let third = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, third, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    expected.push_back(
        litebox_broker_core::socket::status(&connector_process, third)
            .unwrap()
            .local_address
            .unwrap(),
    );
    for expected_remote in expected {
        let accepted =
            litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone())
                .unwrap();
        let SocketOutcome::Completed(accepted) = accepted else {
            panic!("later FIFO accept failed");
        };
        assert_eq!(accepted.remote_address, expected_remote);
    }
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    assert!(
        !listener_process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
}

#[test]
fn guest_tcp_stream_preserves_options_peek_waitall_and_half_close() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 4).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(12, 0, 6, 6),
        provider,
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8093);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    litebox_broker_core::socket::set_tcp_option(
        &listener_process,
        listener,
        TcpOptionValue::NoDelay(true),
    )
    .unwrap();
    litebox_broker_core::socket::set_tcp_option(
        &listener_process,
        listener,
        TcpOptionValue::KeepAlive(true),
    )
    .unwrap();
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    let connector = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let accepted =
        litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone())
            .unwrap();
    let SocketOutcome::Completed(accepted) = accepted else {
        panic!("guest accept failed");
    };
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(
            &listener_process,
            accepted.handle,
            TcpOptionName::NoDelay,
        ),
        Ok(TcpOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(
            &listener_process,
            accepted.handle,
            TcpOptionName::KeepAlive,
        ),
        Ok(TcpOptionValue::KeepAlive(true))
    );
    listener_process.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    assert_eq!(
        send_bytes(&connector_process, connector, b"a", SendFlags::NONE),
        Ok(SocketOutcome::Completed(1))
    );
    wait_for_readiness_publication(&publications, accepted.handle, ReadinessFlags::READ);
    let mut peeked = [0_u8; 2];
    assert_eq!(
        receive_into(
            &listener_process,
            accepted.handle,
            &mut peeked,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            2,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        send_bytes(&connector_process, connector, b"b", SendFlags::NONE),
        Ok(SocketOutcome::Completed(1))
    );
    wait_for_readiness_publication(&publications, accepted.handle, ReadinessFlags::READ);
    assert_eq!(
        receive_into(
            &listener_process,
            accepted.handle,
            &mut peeked,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            2,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(2)))
    );
    assert_eq!(&peeked, b"ab");
    let mut received = [0_u8; 2];
    assert_eq!(
        receive_into(
            &listener_process,
            accepted.handle,
            &mut received,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(2)))
    );
    assert_eq!(&received, b"ab");
    assert_eq!(
        litebox_broker_core::socket::shutdown(&connector_process, connector, ShutdownMode::Write,),
        Ok(SocketOutcome::Completed(()))
    );
    wait_for_end_of_stream(&listener_process, accepted.handle, &publications);
    assert_eq!(
        send_bytes(
            &listener_process,
            accepted.handle,
            b"response",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(8))
    );
    let mut response = [0_u8; 8];
    loop {
        match receive_into(
            &connector_process,
            connector,
            &mut response,
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(8))) => break,
            Err(BrokerError::WouldBlock) => wait_until_ready(
                &connector_process,
                &publications,
                connector,
                ReadinessFlags::READ,
            ),
            outcome => panic!("unexpected half-close receive outcome: {outcome:?}"),
        }
    }
    assert_eq!(&response, b"response");
}

#[test]
fn guest_tcp_read_shutdown_is_logical_and_unread_close_resets_peer() {
    let pair = connected_guest_tcp_pair(8105);
    assert_eq!(
        send_bytes(
            &pair.listener_process,
            pair.accepted,
            b"queued",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(6))
    );
    wait_until_ready(
        &pair.connector_process,
        &pair.publications,
        pair.connector,
        ReadinessFlags::READ,
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &pair.connector_process,
            pair.connector,
            ShutdownMode::Read,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        send_bytes(
            &pair.connector_process,
            pair.connector,
            b"write remains open",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(18))
    );
    wait_until_ready(
        &pair.listener_process,
        &pair.publications,
        pair.accepted,
        ReadinessFlags::READ,
    );
    let mut write_response = [0_u8; 18];
    assert_eq!(
        receive_into(
            &pair.listener_process,
            pair.accepted,
            &mut write_response,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
            18
        )))
    );
    assert_eq!(&write_response, b"write remains open");
    assert_eq!(
        send_bytes(
            &pair.listener_process,
            pair.accepted,
            b"unread",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(6))
    );
    let payload = vec![0_u8; MAX_SOCKET_TRANSFER_SIZE as usize];
    let mut sent = 0;
    let send_deadline = Instant::now() + TEST_TIMEOUT;
    while sent < 2 * 1024 * 1024 {
        match send_bytes(
            &pair.listener_process,
            pair.accepted,
            &payload,
            SendFlags::NONE,
        ) {
            Ok(SocketOutcome::Completed(count)) if count != 0 => sent += count,
            Err(BrokerError::WouldBlock) => wait_until_ready_until(
                &pair.listener_process,
                &pair.publications,
                pair.accepted,
                ReadinessFlags::WRITE,
                send_deadline,
            ),
            outcome => panic!("post-shutdown send stopped making progress: {outcome:?}"),
        }
    }
    let mut data = [0_u8; 12];
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            12,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(6)))
    );
    assert_eq!(&data[..6], b"queued");
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(6)))
    );
    assert_eq!(&data[..6], b"queued");
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );

    pair.connector_process
        .close_object_reference(pair.connector)
        .unwrap();
    assert_eq!(
        pair.retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        pair.connector
    );
    wait_for_guest_reset(&pair.listener_process, &pair.publications, pair.accepted);
    assert_eq!(
        receive_into(
            &pair.listener_process,
            pair.accepted,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
}

#[test]
fn guest_read_shutdown_detects_data_awaiting_discard() {
    let (socket, peer) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .unwrap();
    let SocketTransportState::Tcp(mut tcp) = create_tcp_transport() else {
        unreachable!();
    };
    tcp.descriptor = TcpDescriptor::InternalUnix(socket);
    tcp.install_empty_guest_read_shutdown_for_test();

    assert_eq!(
        rustix::net::send(&peer, b"x", rustix::net::SendFlags::NOSIGNAL).unwrap(),
        1
    );
    assert!(tcp.has_guest_unread_data_for_test());
}

#[test]
fn guest_tcp_both_shutdown_keeps_peer_send_open_and_closes_write_half() {
    let pair = connected_guest_tcp_pair(8106);
    assert_eq!(
        send_bytes(
            &pair.listener_process,
            pair.accepted,
            b"queued",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(6))
    );
    wait_until_ready(
        &pair.connector_process,
        &pair.publications,
        pair.connector,
        ReadinessFlags::READ,
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &pair.connector_process,
            pair.connector,
            ShutdownMode::Both,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    wait_for_end_of_stream(&pair.listener_process, pair.accepted, &pair.publications);
    assert_eq!(
        send_bytes(
            &pair.listener_process,
            pair.accepted,
            b"unread",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(6))
    );
    let mut data = [0_u8; 12];
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(6)))
    );
    assert_eq!(&data[..6], b"queued");
    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );

    pair.connector_process
        .close_object_reference(pair.connector)
        .unwrap();
    assert_eq!(
        pair.retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        pair.connector
    );
    wait_for_guest_reset(&pair.listener_process, &pair.publications, pair.accepted);
    assert_eq!(
        receive_into(
            &pair.listener_process,
            pair.accepted,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
}

#[test]
fn drained_guest_read_shutdown_close_delivers_end_of_stream() {
    let pair = connected_guest_tcp_pair(8107);
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &pair.connector_process,
            pair.connector,
            ShutdownMode::Read,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        send_bytes(
            &pair.connector_process,
            pair.connector,
            b"drained",
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(7))
    );
    wait_until_ready(
        &pair.listener_process,
        &pair.publications,
        pair.accepted,
        ReadinessFlags::READ,
    );
    let mut data = [0_u8; 7];
    assert_eq!(
        receive_into(
            &pair.listener_process,
            pair.accepted,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(7)))
    );
    assert_eq!(&data, b"drained");

    pair.connector_process
        .close_object_reference(pair.connector)
        .unwrap();
    assert_eq!(
        pair.retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        pair.connector
    );
    wait_for_end_of_stream(&pair.listener_process, pair.accepted, &pair.publications);
    assert!(
        !pair
            .listener_process
            .check_readiness(pair.accepted)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
}

#[test]
fn guest_tcp_connect_publication_failure_purges_committed_queue() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8094);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    let connector = create_socket(&connector_process, readiness.clone());
    readiness.fail_next_publish_matching(listener, ReadinessFlags::READ, ReadinessFlags::default());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, address),
        Err(BrokerError::ResourceExhausted)
    );
    readiness.assert_no_pending_publish_failure();
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    assert!(
        !listener_process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_process, listener, readiness),
        Err(BrokerError::WouldBlock)
    ));
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
}

#[test]
fn guest_tcp_accept_publication_failure_purges_registered_endpoint() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8096);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    let connector = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    readiness.fail_next_publish_matching_any(ReadinessFlags::WRITE, ReadinessFlags::READ);
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone()),
        Err(BrokerError::ResourceExhausted)
    ));
    readiness.assert_no_pending_publish_failure();
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    assert!(
        !listener_process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    wait_for_guest_reset(&connector_process, &publications, connector);
    let mut byte = [0_u8; 1];
    assert_eq!(
        receive_into(
            &connector_process,
            connector,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
}

#[test]
fn queued_guest_accept_transfers_capacity_without_global_growth() {
    let provider = Arc::new(LinuxSocketProvider::new(5, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(10, 0, 5, 5),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8095);
    let listener = create_socket(&listener_process, readiness.clone());
    let _listener_capacity = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    let connector = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
    let capacity_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let _global_capacity = create_socket(&capacity_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::create(
            &capacity_process,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            },
            readiness.clone(),
        ),
        Err(BrokerError::ResourceExhausted)
    );
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    let accepted =
        litebox_broker_core::socket::accept(&listener_process, listener, readiness).unwrap();
    assert!(matches!(accepted, SocketOutcome::Completed(_)));
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
}

#[test]
fn queued_guest_accept_rejects_exhausted_listener_process_capacity() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(10, 0, 6, 6),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8097);
    let listener = create_socket(&listener_process, readiness.clone());
    let listener_capacity = create_socket(&listener_process, readiness.clone());
    let _second_listener_capacity = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, address),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    let connector = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone(),),
        Err(BrokerError::ResourceExhausted)
    ));
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    listener_process
        .close_object_reference(listener_capacity)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        listener_capacity
    );
    let accepted =
        litebox_broker_core::socket::accept(&listener_process, listener, readiness).unwrap();
    assert!(matches!(accepted, SocketOutcome::Completed(_)));
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
}

#[test]
fn abortive_connector_close_releases_descriptor_capacity() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8086);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, connector, &publications);
    assert_eq!(
        litebox_broker_core::socket::shutdown(&connector_process, connector, ShutdownMode::Abort,),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
    let accepted =
        match litebox_broker_core::socket::accept(&listener_process, listener, readiness.clone())
            .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted.handle,
            SocketOutcome::Failed(error) => panic!("accept after Abort failed: {error:?}"),
        };
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    wait_for_guest_reset(&listener_process, &publications, accepted);
    let mut byte = [0_u8; 1];
    assert_eq!(
        receive_into(
            &listener_process,
            accepted,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    listener_process.close_object_reference(accepted).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), accepted);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);

    let replacement = create_socket(&connector_process, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, replacement, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, replacement, &publications);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);
}

#[test]
fn stop_listening_cleanup_survives_readiness_failure() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
        provider.clone(),
    )
    .unwrap();
    let listener_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let connector_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088);
    let listener = create_socket(&listener_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_process, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );
    let connector = create_socket(&connector_process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, connector, &publications);
    wait_until_ready(
        &listener_process,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 1);

    readiness.fail_next_publish_matching(listener, ReadinessFlags::HANGUP, ReadinessFlags::READ);
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &listener_process,
            listener,
            ShutdownMode::StopListening,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    readiness.assert_no_pending_publish_failure();
    let listener_readiness = listener_process.check_readiness(listener).unwrap();
    assert!(listener_readiness.contains(ReadinessFlags::WRITE));
    assert!(listener_readiness.contains(ReadinessFlags::HANGUP));
    assert!(!listener_readiness.contains(ReadinessFlags::READ));
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );

    let refused = create_socket(&connector_process, readiness);
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, refused, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    connector_process.close_object_reference(refused).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), refused);
    listener_process.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    assert_eq!(provider.reactor.queued_guest_connection_count(), 0);
}

#[test]
fn reactor_drives_a_loopback_tcp_listener() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 6).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 6, 6),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let listener = create_socket(&process, readiness.clone());
    let local_address = match litebox_broker_core::socket::listen(&process, listener, 8)
        .expect("listen request must succeed")
    {
        SocketOutcome::Completed(address) => address,
        SocketOutcome::Failed(error) => panic!("listen failed: {error:?}"),
    };
    assert!(local_address.ip().is_loopback());
    assert_ne!(local_address.port(), 0);
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, listener, ShutdownMode::Write),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&process, listener, readiness.clone()),
        Err(BrokerError::WouldBlock)
    ));
    let failed_accept_handle = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
    assert_ne!(failed_accept_handle, listener);
    assert!(
        !process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    let first_client = create_socket(&process, readiness.clone());
    let second_client = create_socket(&process, readiness.clone());
    for client in [first_client, second_client] {
        assert!(matches!(
            litebox_broker_core::socket::connect(&process, client, local_address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&process, client, &publications);
    }
    let first_client_address = litebox_broker_core::socket::status(&process, first_client)
        .unwrap()
        .local_address
        .unwrap();
    let second_client_address = litebox_broker_core::socket::status(&process, second_client)
        .unwrap()
        .local_address
        .unwrap();
    wait_until_ready(&process, &publications, listener, ReadinessFlags::READ);
    assert_eq!(
        litebox_broker_core::socket::listen(&process, listener, 4),
        Ok(SocketOutcome::Completed(local_address))
    );

    let first =
        match litebox_broker_core::socket::accept(&process, listener, readiness.clone()).unwrap() {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("first accept failed: {error:?}"),
        };
    assert_eq!(first.local_address, local_address);
    assert_eq!(first.remote_address, first_client_address);
    assert!(
        process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ),
        "accept must preserve listener readiness until the queue is observed empty"
    );

    let second =
        match litebox_broker_core::socket::accept(&process, listener, readiness.clone()).unwrap() {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("second accept failed: {error:?}"),
        };
    assert_eq!(second.local_address, local_address);
    assert_eq!(second.remote_address, second_client_address);
    assert!(
        !process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ),
        "accept must clear listener readiness after draining the queue"
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&process, listener, readiness.clone()),
        Err(BrokerError::WouldBlock)
    ));
    assert!(
        !process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    assert_eq!(
        send_bytes(&process, first_client, b"request", SendFlags::NONE),
        Ok(SocketOutcome::Completed(7))
    );
    let mut request = [0_u8; 7];
    loop {
        match receive_into(
            &process,
            first.handle,
            &mut request,
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(7))) => break,
            Err(BrokerError::WouldBlock) => {
                wait_until_ready(&process, &publications, first.handle, ReadinessFlags::READ);
            }
            outcome => panic!("unexpected accepted receive outcome: {outcome:?}"),
        }
    }
    assert_eq!(&request, b"request");
    assert_eq!(
        send_bytes(&process, first.handle, b"response", SendFlags::NONE,),
        Ok(SocketOutcome::Completed(8))
    );
    let mut response = [0_u8; 8];
    loop {
        match receive_into(
            &process,
            first_client,
            &mut response,
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(8))) => break,
            Err(BrokerError::WouldBlock) => {
                wait_until_ready(&process, &publications, first_client, ReadinessFlags::READ);
            }
            outcome => panic!("unexpected client receive outcome: {outcome:?}"),
        }
    }
    assert_eq!(&response, b"response");
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, listener, ShutdownMode::StopListening,),
        Ok(SocketOutcome::Completed(()))
    );
    wait_until_ready(&process, &publications, listener, ReadinessFlags::HANGUP);
    assert!(
        process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::HANGUP)
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&process, listener, readiness.clone()),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    ));
    process.close_object_reference(first.handle).unwrap();
    drop(process);
    let expected = [first.handle, second.handle, listener];
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut observed = std::vec::Vec::new();
    while expected.iter().any(|handle| !observed.contains(handle)) {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out waiting for listener retirements");
        observed.push(retirements.recv_timeout(remaining).unwrap());
    }
}
