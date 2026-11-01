// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use std::collections::VecDeque;

struct GuestTcpPair {
    provider: Arc<UserlandSocketProvider>,
    listener_process: Arc<BrokerProcess>,
    connector_process: Arc<BrokerProcess>,
    connector: ObjectHandle,
    accepted: ObjectHandle,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
    retirements: Receiver<ObjectHandle>,
}

fn connected_guest_tcp_pair(port: u16) -> GuestTcpPair {
    let provider = Arc::new(UserlandSocketProvider::new(4, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    connect_guest_tcp_pair(&broker, provider, port)
}

/// Connects a guest TCP pair on `broker`, whose sockets `provider` hosts.
fn connect_guest_tcp_pair(
    broker: &BrokerCore,
    provider: Arc<UserlandSocketProvider>,
    port: u16,
) -> GuestTcpPair {
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
    let SocketOutcome::Completed(accepted) = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness,
    )
    .expect("guest accept failed") else {
        panic!("guest accept returned a socket failure");
    };
    GuestTcpPair {
        provider,
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
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    handle: ObjectHandle,
) {
    // Checking readiness would queue the reset, so wait for its publication
    // to leave it for the next operation to report.
    let readiness = ReadinessFlags::READ | ReadinessFlags::ERROR | ReadinessFlags::HANGUP;
    wait_for_readiness_publication(publications, handle, readiness);
}

#[test]
fn provider_drives_a_loopback_tcp_socket() {
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

    let provider = Arc::new(UserlandSocketProvider::new(8, 8).unwrap());
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
    assert_eq!(provider.core.tcp_descriptor_counts(), (1, 0, 0));
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
    assert_eq!(provider.core.tcp_descriptor_counts(), (0, 1, 0));
    let status = litebox_broker_core::socket::status(&process, handle).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connected);
    let local_address = status
        .local_address
        .expect("connected socket must expose its local address");
    assert_eq!(*local_address.ip(), GUEST_IPV4_ADDRESS);
    assert_ne!(local_address.port(), 0);
    assert_eq!(status.pending_error, None);
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, handle, SocketOptionName::NoDelay,),
        Ok(SocketOptionValue::NoDelay(false))
    );
    litebox_broker_core::socket::set_option(&process, handle, SocketOptionValue::NoDelay(true))
        .unwrap();
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, handle, SocketOptionName::NoDelay,),
        Ok(SocketOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, handle, SocketOptionName::KeepAlive,),
        Ok(SocketOptionValue::KeepAlive(false))
    );
    litebox_broker_core::socket::set_option(&process, handle, SocketOptionValue::KeepAlive(true))
        .unwrap();
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, handle, SocketOptionName::KeepAlive,),
        Ok(SocketOptionValue::KeepAlive(true))
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
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    allow_response.send(()).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    let current_readiness = process.check_readiness(handle).unwrap();
    // A socket shut down for writing is writable.
    assert!(current_readiness.contains(ReadinessFlags::WRITE));
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
    assert!(read_shutdown_readiness.contains(ReadinessFlags::HANGUP));
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

    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
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
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
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
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
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
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
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
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
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

    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
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
fn tcp_peek_continues_only_for_its_reader() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let chunk = MAX_SOCKET_TRANSFER_SIZE as usize;
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(&vec![0x41; chunk]).unwrap();
        stream.write_all(&vec![0x42; chunk]).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(3, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let sharer = broker
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
    wait_until_ready(
        &process,
        &publications,
        handle,
        ReadinessFlags::READ | ReadinessFlags::HANGUP,
    );
    server.join().unwrap();
    let duplicate = process
        .duplicate_object_reference_to(handle, &sharer, ObjectRights::all())
        .unwrap();

    let peek_length = MAX_SOCKET_TRANSFER_SIZE * 2;
    let mut data = vec![0_u8; chunk];
    let peek = |process: &BrokerProcess, handle, data: &mut [u8], peek_offset| {
        receive_into(
            process,
            handle,
            data,
            ReceiveFlags::PEEK,
            peek_offset,
            peek_length,
        )
    };
    let received = Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
        MAX_SOCKET_TRANSFER_SIZE,
    )));
    assert_eq!(peek(&process, handle, &mut data, 0), received);
    assert!(data.iter().all(|byte| *byte == 0x41));
    assert_eq!(
        peek(&sharer, duplicate, &mut data, MAX_SOCKET_TRANSFER_SIZE),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        peek(&process, handle, &mut data, MAX_SOCKET_TRANSFER_SIZE),
        received
    );
    assert!(data.iter().all(|byte| *byte == 0x42));

    // A receive by another reader interrupts the peek, even when it does not
    // consume anything.
    assert_eq!(peek(&process, handle, &mut data, 0), received);
    assert_eq!(peek(&sharer, duplicate, &mut data, 0), received);
    assert_eq!(
        peek(&process, handle, &mut data, MAX_SOCKET_TRANSFER_SIZE),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        receive_into(&sharer, duplicate, &mut data, ReceiveFlags::NONE, 0, 0),
        received
    );
    assert_eq!(
        peek(&sharer, duplicate, &mut data, MAX_SOCKET_TRANSFER_SIZE),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(peek(&process, handle, &mut data, 0), received);
    assert!(data.iter().all(|byte| *byte == 0x42));
}

#[test]
fn accepted_guest_tcp_close_with_unread_data_preserves_reset() {
    let provider = Arc::new(UserlandSocketProvider::new(3, 2).unwrap());
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
    let accepted = match litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
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
    wait_for_guest_reset(&publications, accepted);
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
    let abort_peer = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness,
    )
    .unwrap();
    let SocketOutcome::Completed(abort_peer) = abort_peer else {
        panic!("second guest accept failed");
    };
    assert_eq!(
        litebox_broker_core::socket::shutdown(&connector_process, aborting, ShutdownMode::Abort,),
        Ok(SocketOutcome::Completed(()))
    );
    connector_process.close_object_reference(aborting).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), aborting);
    wait_for_guest_reset(&publications, abort_peer.handle);
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
    wait_for_guest_reset(&pair.publications, pair.connector);

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

/// Checking readiness queues a reset, which is then reported once after the
/// buffered data in place of the end of stream that a receive reports.
#[test]
fn guest_tcp_polled_reset_is_queued_behind_buffered_data() {
    let pair = connected_guest_tcp_pair(8109);
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
    wait_for_guest_reset(&pair.publications, pair.connector);

    assert!(
        pair.connector_process
            .check_readiness(pair.connector)
            .unwrap()
            .contains(ReadinessFlags::READ | ReadinessFlags::ERROR | ReadinessFlags::HANGUP)
    );
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
        litebox_broker_core::socket::take_error(&pair.connector_process, pair.connector),
        Ok(Some(SocketError::ConnectionReset))
    );
    assert_eq!(
        litebox_broker_core::socket::take_error(&pair.connector_process, pair.connector),
        Ok(None)
    );
    assert!(
        !pair
            .connector_process
            .check_readiness(pair.connector)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
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
    wait_for_guest_reset(&pair.publications, pair.connector);

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
    wait_for_guest_reset(&pair.publications, pair.connector);

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
    let provider = Arc::new(UserlandSocketProvider::new(5, 3).unwrap());
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
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
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
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
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
    assert_eq!(provider.core.tcp_descriptor_counts(), (1, 0, 0));
    let client = create_socket(&client_process, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&client_process, client, guest_destination),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&client_process, client, &publications);
    assert_eq!(provider.core.tcp_descriptor_counts(), (1, 0, 1));
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
    let accepted = match litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
    .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted,
        SocketOutcome::Failed(error) => panic!("accept failed: {error:?}"),
    };
    assert_eq!(accepted.local_address, guest_address);
    assert_eq!(accepted.remote_address, client_address);
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
    assert_eq!(provider.core.tcp_descriptor_counts(), (1, 0, 2));

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
    let provider = Arc::new(UserlandSocketProvider::new(12, 8).unwrap());
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
            FileOpenFlags::NONE,
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
        FileOpenFlags::NONE,
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
    let provider = Arc::new(UserlandSocketProvider::new(4, 2).unwrap());
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
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
    let capacity = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::create(
            &connector_process,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
                flags: FileOpenFlags::NONE,
            },
            readiness.clone(),
        ),
        Err(BrokerError::ResourceExhausted)
    );
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), capacity);
    connector_process.close_object_reference(capacity).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), capacity);

    drop(connector_process);
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
    assert!(
        !listener_process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(
            &listener_process,
            listener,
            FileOpenFlags::NONE,
            readiness.clone(),
        ),
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
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
    listener_process.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
    wait_for_guest_reset(&publications, final_connector);
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
    let provider = Arc::new(UserlandSocketProvider::new(4, 2).unwrap());
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
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
    wait_until_ready(
        &listener_process,
        &publications,
        listener,
        ReadinessFlags::READ,
    );

    let accepted = match litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness,
    )
    .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted,
        SocketOutcome::Failed(error) => panic!("late accept failed: {error:?}"),
    };
    assert_eq!(accepted.remote_address, connector_address);
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
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

/// A connection accepted while its queued connector is closing gracefully
/// cannot send into the closing end, whose data would vanish without a reset.
#[test]
fn accept_during_graceful_queued_connector_close_cannot_send() {
    let provider = Arc::new(UserlandSocketProvider::new(4, 2).unwrap());
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
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8208);
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
    let connector_id = *provider.core.socket_ids().last().unwrap();

    let hook = TestHook::install(&provider);
    let acceptor = Arc::new(Mutex::new(Some((Arc::clone(&listener_process), readiness))));
    let sent = Arc::new(Mutex::new(None));
    let pending_accept = Arc::clone(&acceptor);
    let accepted_send = Arc::clone(&sent);
    hook.act(move |_, _, point| {
        if point != HookPoint::Unlinked(connector_id) {
            return;
        }
        let acceptor = pending_accept.lock().unwrap().take();
        if let Some((process, readiness)) = acceptor {
            let accepted_send = Arc::clone(&accepted_send);
            run_on_thread(move || {
                let accepted = match litebox_broker_core::socket::accept(
                    &process,
                    listener,
                    FileOpenFlags::NONE,
                    readiness,
                ) {
                    Ok(SocketOutcome::Completed(accepted)) => accepted,
                    Ok(SocketOutcome::Failed(error)) => panic!("accept failed: {error:?}"),
                    Err(error) => panic!("accept failed: {error:?}"),
                };
                *accepted_send.lock().unwrap() =
                    Some(send_bytes(&process, accepted.handle, b"x", SendFlags::NONE));
            });
        }
    });

    connector_process.close_object_reference(connector).unwrap();
    hook.stop();
    assert!(acceptor.lock().unwrap().is_none());
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(
        sent.lock().unwrap().take(),
        Some(Ok(SocketOutcome::Failed(SocketError::NotConnected)))
    );
}

#[test]
fn guest_tcp_zero_backlog_wildcard_listener_accepts_one_connection() {
    let port = 8104;
    let policy = SocketPolicy::guest_network()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(Ipv4Addr::UNSPECIFIED.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(port), Port(port)).unwrap(),
        )])
        .unwrap();
    let provider = Arc::new(UserlandSocketProvider::new(6, 4).unwrap());
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
    // Like a refused connection, an unspecified destination leaves the socket
    // free to connect again.
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, wildcard_listener),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, connector, concrete_listener),
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
        litebox_broker_core::socket::connect(&connector_process, full, concrete_listener),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    let SocketOutcome::Completed(accepted) = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
    .unwrap() else {
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
    let provider = Arc::new(UserlandSocketProvider::new(10, 8).unwrap());
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
    assert_eq!(provider.core.queued_guest_connection_count(), 2);
    let full = create_socket(&connector_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_process, full, address),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_process, listener, 1),
        Ok(SocketOutcome::Completed(address))
    );
    assert_eq!(provider.core.queued_guest_connection_count(), 2);

    wait_until_ready(
        &listener_process,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    let accepted = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
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
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
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
        let accepted = litebox_broker_core::socket::accept(
            &listener_process,
            listener,
            FileOpenFlags::NONE,
            readiness.clone(),
        )
        .unwrap();
        let SocketOutcome::Completed(accepted) = accepted else {
            panic!("later FIFO accept failed");
        };
        assert_eq!(accepted.remote_address, expected_remote);
    }
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
    assert!(
        !listener_process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
}

#[test]
fn guest_tcp_stream_preserves_options_peek_waitall_and_half_close() {
    let provider = Arc::new(UserlandSocketProvider::new(6, 4).unwrap());
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
    litebox_broker_core::socket::set_option(
        &listener_process,
        listener,
        SocketOptionValue::NoDelay(true),
    )
    .unwrap();
    litebox_broker_core::socket::set_option(
        &listener_process,
        listener,
        SocketOptionValue::KeepAlive(true),
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
    let accepted = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
    .unwrap();
    let SocketOutcome::Completed(accepted) = accepted else {
        panic!("guest accept failed");
    };
    assert_eq!(
        litebox_broker_core::socket::get_option(
            &listener_process,
            accepted.handle,
            SocketOptionName::NoDelay,
        ),
        Ok(SocketOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_option(
            &listener_process,
            accepted.handle,
            SocketOptionName::KeepAlive,
        ),
        Ok(SocketOptionValue::KeepAlive(true))
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
    wait_for_guest_reset(&pair.publications, pair.accepted);
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
    wait_for_guest_reset(&pair.publications, pair.accepted);
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
fn queued_guest_accept_transfers_capacity_without_global_growth() {
    let provider = Arc::new(UserlandSocketProvider::new(5, 3).unwrap());
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
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
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
                flags: FileOpenFlags::NONE,
            },
            readiness.clone(),
        ),
        Err(BrokerError::ResourceExhausted)
    );
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    let accepted = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness,
    )
    .unwrap();
    assert!(matches!(accepted, SocketOutcome::Completed(_)));
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
}

#[test]
fn queued_guest_accept_rejects_exhausted_listener_process_capacity() {
    let provider = Arc::new(UserlandSocketProvider::new(6, 3).unwrap());
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
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
    assert!(matches!(
        litebox_broker_core::socket::accept(
            &listener_process,
            listener,
            FileOpenFlags::NONE,
            readiness.clone(),
        ),
        Err(BrokerError::ResourceExhausted)
    ));
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    listener_process
        .close_object_reference(listener_capacity)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        listener_capacity
    );
    let accepted = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness,
    )
    .unwrap();
    assert!(matches!(accepted, SocketOutcome::Completed(_)));
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
}

#[test]
fn abortive_connector_close_releases_descriptor_capacity() {
    let provider = Arc::new(UserlandSocketProvider::new(3, 2).unwrap());
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
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
    let accepted = match litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
    .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted.handle,
        SocketOutcome::Failed(error) => panic!("accept after Abort failed: {error:?}"),
    };
    assert_eq!(provider.core.queued_guest_connection_count(), 0);
    connector_process.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    wait_for_guest_reset(&publications, accepted);
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
    assert_eq!(provider.core.queued_guest_connection_count(), 0);

    let replacement = create_socket(&connector_process, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_process, replacement, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_process, replacement, &publications);
    assert_eq!(provider.core.queued_guest_connection_count(), 1);
}

#[test]
fn provider_drives_a_loopback_tcp_listener() {
    let provider = Arc::new(UserlandSocketProvider::new(6, 6).unwrap());
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
        Ok(SocketOutcome::Failed(SocketError::Listening))
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(
            &process,
            listener,
            FileOpenFlags::NONE,
            readiness.clone()
        ),
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

    let first = match litebox_broker_core::socket::accept(
        &process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
    .unwrap()
    {
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

    let second = match litebox_broker_core::socket::accept(
        &process,
        listener,
        FileOpenFlags::NONE,
        readiness.clone(),
    )
    .unwrap()
    {
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
        litebox_broker_core::socket::accept(
            &process,
            listener,
            FileOpenFlags::NONE,
            readiness.clone()
        ),
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
    wait_until_ready(&process, &publications, listener, ReadinessFlags::CLOSED);
    assert!(
        process
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::CLOSED)
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(
            &process,
            listener,
            FileOpenFlags::NONE,
            readiness.clone()
        ),
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

/// A provider and broker for external TCP to host loopback, with one process
/// and its socket.
struct ExternalTcpSocket {
    provider: Arc<UserlandSocketProvider>,
    process: Arc<BrokerProcess>,
    socket: ObjectHandle,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
    retirements: Receiver<ObjectHandle>,
    readiness: Arc<TestReadinessSink>,
}

fn external_tcp_socket() -> ExternalTcpSocket {
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let socket = create_socket(&process, readiness.clone());
    ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        retirements,
        readiness,
    }
}

fn connect_to_host(
    process: &BrokerProcess,
    socket: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    listener: &TcpListener,
) -> std::net::TcpStream {
    let destination = gateway_address(socket_address_v4(listener.local_addr().unwrap()));
    assert!(matches!(
        litebox_broker_core::socket::connect(process, socket, destination),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(process, socket, publications);
    listener.accept().unwrap().0
}

/// A host listener that leaves connects to it pending until admitted.
#[cfg(target_os = "linux")]
struct UnresponsiveListener {
    listener: TcpListener,
    _queued: Vec<std::net::TcpStream>,
}

#[cfg(target_os = "linux")]
impl UnresponsiveListener {
    /// Lets a pending connect complete.
    fn admit_pending_connect(&mut self) {
        // Room in the accept queue lets the connect's next SYN through.
        rustix::net::listen(&self.listener, 64).unwrap();
    }
}

/// Returns a host listener that leaves connects to it pending, and its
/// address.
#[cfg(target_os = "linux")]
fn unresponsive_listener() -> (UnresponsiveListener, SocketAddrV4) {
    // Once its accept queue is full, this listener drops connection requests.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    rustix::net::listen(&listener, 0).unwrap();
    let address = listener.local_addr().unwrap();
    let mut queued = Vec::new();
    while let Ok(stream) =
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200))
    {
        queued.push(stream);
        assert!(queued.len() < 8, "listener accept queue did not fill");
    }
    (
        UnresponsiveListener {
            listener,
            _queued: queued,
        },
        socket_address_v4(address),
    )
}

/// A host listener that leaves connects to it pending until admitted.
#[cfg(windows)]
struct UnresponsiveListener {
    listener: socket2::Socket,
    admitted: Vec<socket2::Socket>,
}

#[cfg(windows)]
impl UnresponsiveListener {
    /// Lets a pending connect complete.
    fn admit_pending_connect(&mut self) {
        self.admitted.push(self.listener.accept().unwrap().0);
    }
}

/// Returns a host listener that leaves connects to it pending, and its
/// address.
#[cfg(windows)]
fn unresponsive_listener() -> (UnresponsiveListener, SocketAddrV4) {
    use std::os::windows::io::AsRawSocket as _;
    use windows_sys::Win32::Networking::WinSock::{SO_CONDITIONAL_ACCEPT, SOL_SOCKET, setsockopt};

    // Winsock refuses connection requests once a listener's accept queue is
    // full, so this listener instead leaves each request to the application,
    // which never accepts it.
    let listener =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    let enable = 1_i32;
    // SAFETY: `listener` owns a live socket, and `enable` outlives the call,
    // which reads only the given length from it.
    assert_eq!(
        unsafe {
            setsockopt(
                usize::try_from(listener.as_raw_socket()).unwrap(),
                SOL_SOCKET,
                SO_CONDITIONAL_ACCEPT,
                std::ptr::from_ref(&enable).cast(),
                i32::try_from(size_of_val(&enable)).unwrap(),
            )
        },
        0
    );
    listener
        .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    listener.listen(16).unwrap();
    let address = listener.local_addr().unwrap().as_socket_ipv4().unwrap();
    (
        UnresponsiveListener {
            listener,
            admitted: Vec::new(),
        },
        address,
    )
}

/// Receives exactly `data.len()` bytes, waiting for READ when none are queued.
fn receive_exact(
    process: &BrokerProcess,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    data: &mut [u8],
) {
    let mut received = 0;
    while received < data.len() {
        match receive_into(
            process,
            handle,
            &mut data[received..],
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(length))) => {
                received += length as usize;
            }
            Err(BrokerError::WouldBlock) => {
                wait_until_ready(process, publications, handle, ReadinessFlags::READ);
            }
            outcome => panic!("unexpected receive outcome: {outcome:?}"),
        }
    }
}

/// A TCP socket sends from and receives and peeks into a buffer's own raw
/// parts.
#[test]
fn tcp_transfers_use_raw_parts() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let mut host = connect_to_host(&process, socket, &publications, &listener);
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let mut data = TEST_MESSAGE;
    assert_eq!(
        litebox_broker_core::socket::send(
            &process,
            socket,
            &TestBuffer::new(&mut data, Some(TEST_PART_LENGTH)),
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(TEST_MESSAGE.len()))
    );
    let mut sent = [0; TEST_MESSAGE.len()];
    host.read_exact(&mut sent).unwrap();
    assert_eq!(sent, TEST_MESSAGE);

    host.write_all(&TEST_MESSAGE).unwrap();
    for (flags, peek_length) in [
        (
            ReceiveFlags::PEEK,
            u32::try_from(TEST_MESSAGE.len()).unwrap(),
        ),
        (ReceiveFlags::NONE, 0),
    ] {
        let mut received = [0; TEST_MESSAGE.len()];
        loop {
            match litebox_broker_core::socket::receive(
                &process,
                socket,
                &mut TestBuffer::new(&mut received, Some(TEST_PART_LENGTH)),
                flags,
                0,
                peek_length,
            ) {
                Err(BrokerError::WouldBlock) => {
                    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
                }
                outcome => {
                    assert_eq!(
                        outcome,
                        Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                            TEST_MESSAGE.len()
                        )))
                    );
                    break;
                }
            }
        }
        assert_eq!(received, TEST_MESSAGE);
    }
}

/// A shutdown of an external TCP connection that its peer reset fails as not
/// connected, and leaves the reset pending.
#[test]
fn external_tcp_shutdown_after_reset_is_not_connected() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let host = connect_to_host(&process, socket, &publications, &listener);
    let mut data = *b"x";
    assert_eq!(
        litebox_broker_core::socket::send(
            &process,
            socket,
            &TestBuffer::new(&mut data, None),
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(data.len()))
    );
    // Closing a stream with unread data resets the connection.
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    assert_eq!(host.peek(&mut [0]).unwrap(), 1);
    drop(host);
    wait_until_ready(&process, &publications, socket, ReadinessFlags::ERROR);
    for mode in [ShutdownMode::Write, ShutdownMode::Read] {
        assert_eq!(
            litebox_broker_core::socket::shutdown(&process, socket, mode),
            Ok(SocketOutcome::Failed(SocketError::NotConnected))
        );
    }
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, socket),
        Ok(Some(SocketError::ConnectionReset))
    );
}

/// A reset that follows the peer's end of stream is reported once as a
/// reset, after which sends and shutdowns fail as not connected and receives
/// end the stream.
#[test]
fn external_tcp_reset_after_peer_end_of_stream_is_reported_as_a_reset() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    drop(connect_to_host(&process, socket, &publications, &listener));
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    // The peer closed its stream, so it resets the connection on this data.
    let mut data = *b"x";
    assert_eq!(
        litebox_broker_core::socket::send(
            &process,
            socket,
            &TestBuffer::new(&mut data, None),
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(data.len()))
    );
    wait_until_ready(&process, &publications, socket, ReadinessFlags::ERROR);
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, socket),
        Ok(Some(SocketError::ConnectionReset))
    );
    assert_eq!(
        litebox_broker_core::socket::send(
            &process,
            socket,
            &TestBuffer::new(&mut data, None),
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, socket, ShutdownMode::Write),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        receive_into(&process, socket, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
}

/// Closes a host stream with a reset.
fn reset_host_stream(stream: std::net::TcpStream) {
    #[cfg(target_os = "linux")]
    rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO)).unwrap();
    #[cfg(windows)]
    socket2::SockRef::from(&stream)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
}

/// A reset that a send reports before the broker sees its connect complete
/// leaves the data before the reset readable where the host keeps it, and no
/// error pending.
#[test]
fn external_tcp_reset_a_send_reports_before_connect_completion_keeps_the_data() {
    assert_send_reset_before_connect_completion_keeps_the_data(false);
}

/// A reset that follows the peer's end of stream, which a Linux host's send
/// reports as a broken pipe before the broker sees its connect complete,
/// leaves the data before the reset readable, and no error pending.
///
/// A Windows peer that ended its stream closes without a reset.
#[cfg(target_os = "linux")]
#[test]
fn external_tcp_broken_pipe_a_send_reports_before_connect_completion_keeps_the_data() {
    assert_send_reset_before_connect_completion_keeps_the_data(true);
}

/// Resets an external TCP connection after the host sends data, and then
/// ends its stream if `end_of_stream`, while the event thread holds the event
/// that completes the connect, and checks that the guest's send reports the
/// reset and leaves the data readable where the host keeps it.
fn assert_send_reset_before_connect_completion_keeps_the_data(end_of_stream: bool) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications: _publications,
        ..
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    let hook = TestHook::install(&provider);
    let (held, holding) = channel();
    let (release, released) = channel::<()>();
    let gate = Mutex::new(Some((held, released)));
    // The event thread holds the first event, which is what completes the
    // connect, until the guest's calls have taken the reset.
    hook.act(move |_, _, point| {
        if point != HookPoint::Harvested(id) {
            return;
        }
        let gate = gate.lock().unwrap().take();
        if let Some((held, released)) = gate {
            held.send(()).unwrap();
            let _ = released.recv_timeout(TEST_TIMEOUT);
        }
    });
    assert_eq!(
        litebox_broker_core::socket::connect(
            &process,
            socket,
            gateway_address(socket_address_v4(listener.local_addr().unwrap())),
        ),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    holding.recv_timeout(TEST_TIMEOUT).unwrap();
    let (mut host, _) = listener.accept().unwrap();
    host.write_all(b"data").unwrap();
    if end_of_stream {
        host.shutdown(Shutdown::Write).unwrap();
    }
    reset_host_stream(host);
    wait_until(
        || provider.core.host_error_pending(id),
        "the host socket has the reset",
    );
    // A send reports a reset that follows the peer's end of stream as a
    // broken pipe.
    let error = if end_of_stream {
        SocketError::NotConnected
    } else {
        SocketError::ConnectionReset
    };
    let mut byte = *b"x";
    assert_eq!(
        litebox_broker_core::socket::send(
            &process,
            socket,
            &TestBuffer::new(&mut byte, None),
            SendFlags::NONE,
        ),
        Ok(SocketOutcome::Failed(error))
    );
    let mut data = [0_u8; 8];
    // Winsock discards the data before a reset.
    #[cfg(target_os = "linux")]
    {
        assert_eq!(
            receive_into(&process, socket, &mut data, ReceiveFlags::NONE, 0, 0),
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(4)))
        );
        assert_eq!(&data[..4], b"data");
    }
    assert_eq!(
        receive_into(&process, socket, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
    drop(release);
    hook.wait_for_harvest_handled(0, |token| token == id);
    hook.stop();
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, socket),
        Ok(None)
    );
}

/// The data queued before an external TCP connection is shut down in both
/// directions stays readable, after which receives end the stream.
#[test]
fn external_tcp_data_queued_before_both_shutdown_stays_readable() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let mut host = connect_to_host(&process, socket, &publications, &listener);
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    host.write_all(b"queued").unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, socket, ShutdownMode::Both),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(host.read(&mut [0]).unwrap(), 0);
    let mut data = [0_u8; 8];
    assert_eq!(
        receive_into(&process, socket, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(6)))
    );
    assert_eq!(&data[..6], b"queued");
    assert_eq!(
        receive_into(&process, socket, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
}

/// Shutting down a pending connect, which aborts it, closes its host socket,
/// so the host cannot complete the connection the guest saw abort.
#[test]
fn pending_connect_shutdown_closes_the_host_socket() {
    let (_listener, address) = unresponsive_listener();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        ..
    } = external_tcp_socket();
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway_address(address)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    assert_eq!(provider.core.tcp_descriptor_counts(), (0, 1, 0));
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, socket, ShutdownMode::Both),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(provider.core.tcp_descriptor_counts(), (1, 0, 0));
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, socket),
        Ok(Some(SocketError::ConnectionReset))
    );
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, socket),
        Ok(None)
    );
}

/// Options set while a connect is pending succeed, read back, and reach the
/// host socket once it connects, though Winsock refuses them until the
/// connect completes.
#[test]
fn tcp_options_set_during_a_pending_connect_read_back() {
    let (mut listener, address) = unresponsive_listener();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway_address(address)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    for value in [
        SocketOptionValue::NoDelay(true),
        SocketOptionValue::KeepAlive(true),
    ] {
        assert_eq!(
            litebox_broker_core::socket::set_option(&process, socket, value),
            Ok(())
        );
    }
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, socket, SocketOptionName::NoDelay),
        Ok(SocketOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, socket, SocketOptionName::KeepAlive),
        Ok(SocketOptionValue::KeepAlive(true))
    );
    listener.admit_pending_connect();
    wait_until_connected(&process, socket, &publications);
    assert_eq!(provider.core.host_tcp_options(id), (true, true));
}

/// Options set on a connected socket whose host socket may refuse them
/// succeed and read back, and the host socket takes them all with the next
/// set once it can. A forced connection over a pending host connect, which a
/// host may refuse them on, stands in for a failed one.
#[test]
fn tcp_options_refused_by_a_connected_host_socket_read_back() {
    let (mut listener, address) = unresponsive_listener();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway_address(address)),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    provider.core.force_tcp_connected(id);
    for value in [
        SocketOptionValue::NoDelay(true),
        SocketOptionValue::KeepAlive(true),
    ] {
        assert_eq!(
            litebox_broker_core::socket::set_option(&process, socket, value),
            Ok(())
        );
    }
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, socket, SocketOptionName::NoDelay),
        Ok(SocketOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_option(&process, socket, SocketOptionName::KeepAlive),
        Ok(SocketOptionValue::KeepAlive(true))
    );
    listener.admit_pending_connect();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::WRITE);
    assert_eq!(
        litebox_broker_core::socket::set_option(&process, socket, SocketOptionValue::NoDelay(true)),
        Ok(())
    );
    assert_eq!(provider.core.host_tcp_options(id), (true, true));
}

/// Options set while the broker still sees a connect as pending reach the
/// host socket once it connects.
#[test]
fn tcp_options_set_during_a_pending_connect_reach_the_host() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    let hook = TestHook::install(&provider);
    let setter = Arc::new(Mutex::new(Some(Arc::clone(&process))));
    let pending_setter = Arc::clone(&setter);
    // The options are set before the event thread handles the first event,
    // which is what completes the connect.
    hook.act(move |_, _, point| {
        if point != HookPoint::Harvested(id) {
            return;
        }
        let setter = pending_setter.lock().unwrap().take();
        if let Some(process) = setter {
            run_on_thread(move || {
                for value in [
                    SocketOptionValue::NoDelay(true),
                    SocketOptionValue::KeepAlive(true),
                ] {
                    assert_eq!(
                        litebox_broker_core::socket::set_option(&process, socket, value),
                        Ok(())
                    );
                }
            });
        }
    });
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &process,
            socket,
            gateway_address(socket_address_v4(listener.local_addr().unwrap())),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&process, socket, &publications);
    hook.stop();
    assert!(setter.lock().unwrap().is_none());
    assert_eq!(provider.core.host_tcp_options(id), (true, true));
}

/// Data that arrives between a receive's EAGAIN and its READ clear raises an
/// edge that is deferred while the receive holds the socket and applied after,
/// so READ survives the clear.
#[test]
fn tcp_edge_during_eagain_is_applied_after_the_read_clear() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    let host = connect_to_host(&process, socket, &publications, &listener);
    // The action writes through a clone, so stopping it does not close the
    // connection, whose end of stream would raise READ on its own.
    let writer = Mutex::new(host.try_clone().unwrap());
    let hook = TestHook::install(&provider);
    let deferred_at = AtomicUsize::new(usize::MAX);
    hook.act(move |hook, index, point| match point {
        HookPoint::Eagain(socket) if socket == id => {
            writer.lock().unwrap().write_all(b"data").unwrap();
            let (deferred, _) = hook.wait_for(index, |point| {
                point == HookPoint::Handled(id, Dispatch::Deferred)
            });
            deferred_at.store(deferred, Ordering::Relaxed);
        }
        HookPoint::Unlocked(socket) if socket == id => {
            let deferred = deferred_at.swap(usize::MAX, Ordering::Relaxed);
            if deferred != usize::MAX {
                hook.wait_for(deferred, |point| {
                    point == HookPoint::Handled(id, Dispatch::Applied)
                });
            }
        }
        _ => {}
    });

    let mut data = [0; 4];
    assert_eq!(
        receive_into(&process, socket, &mut data, ReceiveFlags::NONE, 0, 0),
        Err(BrokerError::WouldBlock)
    );
    hook.stop();
    assert!(
        process
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert_eq!(
        receive_into(&process, socket, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(4)))
    );
    assert_eq!(&data, b"data");
    drop(host);
}

/// An accepted socket's descriptor joins the poller only once the socket is set
/// up, so the first edge, for data sent before the accept, is deferred and
/// then applied rather than dropped.
#[test]
fn accepted_tcp_socket_applies_the_edge_for_data_sent_before_accept() {
    let provider = Arc::new(UserlandSocketProvider::new(4, 3).unwrap());
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
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8201);
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
    assert_eq!(
        send_bytes(&connector_process, connector, b"early", SendFlags::NONE),
        Ok(SocketOutcome::Completed(5))
    );
    let hook = TestHook::install(&provider);
    hook.act(|hook, index, point| {
        if let HookPoint::Watched(token) = point {
            let (_, handled) = hook.wait_for(
                index,
                |point| matches!(point, HookPoint::Handled(handled, _) if handled == token),
            );
            assert_eq!(handled, HookPoint::Handled(token, Dispatch::Deferred));
        }
    });

    let SocketOutcome::Completed(accepted) = litebox_broker_core::socket::accept(
        &listener_process,
        listener,
        FileOpenFlags::NONE,
        readiness,
    )
    .unwrap() else {
        panic!("guest accept returned a socket failure");
    };
    let token = *provider.core.socket_ids().last().unwrap();
    hook.wait_for(0, |point| {
        point == HookPoint::Handled(token, Dispatch::Applied)
    });
    hook.stop();
    assert!(
        listener_process
            .check_readiness(accepted.handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    let mut data = [0; 5];
    receive_exact(&listener_process, accepted.handle, &publications, &mut data);
    assert_eq!(&data, b"early");
}

/// An external connect adds its descriptor to the poller only after `connect()`,
/// so the fresh socket's OUT|HUP never marks it hung up.
#[test]
fn external_tcp_connect_applies_only_events_after_connect() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    let hook = TestHook::install(&provider);
    hook.act(move |hook, index, point| {
        if point == HookPoint::Watched(id) {
            let (_, handled) = hook.wait_for(
                index,
                |point| matches!(point, HookPoint::Handled(handled, _) if handled == id),
            );
            assert_eq!(handled, HookPoint::Handled(id, Dispatch::Deferred));
        }
    });

    let _host = connect_to_host(&process, socket, &publications, &listener);
    hook.wait_for(0, |point| {
        point == HookPoint::Handled(id, Dispatch::Applied)
    });
    hook.stop();
    let readiness = process.check_readiness(socket).unwrap();
    assert!(!readiness.contains(ReadinessFlags::HANGUP));
    assert!(!readiness.contains(ReadinessFlags::CLOSED));
    assert_eq!(
        litebox_broker_core::socket::status(&process, socket)
            .unwrap()
            .status,
        SocketConnectionStatus::Connected
    );
}

/// The IDs of a pair's connector and accepted sockets.
fn guest_tcp_pair_ids(pair: &GuestTcpPair) -> (u64, u64) {
    let ids = pair.provider.core.socket_ids();
    let [_listener, connector, accepted] = ids[..] else {
        panic!("unexpected sockets: {ids:?}");
    };
    (connector, accepted)
}

/// An abortive close that completes after the peer's receive checked for a
/// reset, just before its `recv`, still reports a reset, not the end of stream
/// its syscall sees.
#[test]
fn guest_tcp_abortive_close_during_peer_receive_reports_reset() {
    let pair = connected_guest_tcp_pair(8202);
    let (connector_id, accepted_id) = guest_tcp_pair_ids(&pair);
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &pair.listener_process,
            pair.accepted,
            ShutdownMode::Abort,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    let hook = TestHook::install(&pair.provider);
    let closer = Arc::new(Mutex::new(Some((
        Arc::clone(&pair.listener_process),
        pair.accepted,
    ))));
    let pending_close = Arc::clone(&closer);
    hook.act(move |hook, index, point| {
        if point != HookPoint::Receiving(connector_id) {
            return;
        }
        let closer = pending_close.lock().unwrap().take();
        if let Some((process, accepted)) = closer {
            run_on_thread(move || process.close_object_reference(accepted).unwrap());
            hook.wait_for(index, |point| {
                point == HookPoint::EndpointClosed(accepted_id)
            });
        }
    });

    assert_eq!(
        receive_into(
            &pair.connector_process,
            pair.connector,
            &mut [0; 1],
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    hook.stop();
    assert!(closer.lock().unwrap().is_none());
}

/// A receive that runs once an abortive close has closed its descriptor
/// reports the reset, which the close posted first.
#[test]
fn guest_tcp_receive_after_abortive_close_closes_descriptor_reports_reset() {
    let pair = connected_guest_tcp_pair(8203);
    let (_, accepted_id) = guest_tcp_pair_ids(&pair);
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &pair.listener_process,
            pair.accepted,
            ShutdownMode::Abort,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    let hook = TestHook::install(&pair.provider);
    let receiver = Arc::new(Mutex::new(Some((
        Arc::clone(&pair.connector_process),
        pair.connector,
    ))));
    let pending_receive = Arc::clone(&receiver);
    hook.act(move |_, _, point| {
        if point != HookPoint::EndpointClosed(accepted_id) {
            return;
        }
        let receiver = pending_receive.lock().unwrap().take();
        if let Some((process, connector)) = receiver {
            run_on_thread(move || {
                assert_eq!(
                    receive_into(&process, connector, &mut [0; 1], ReceiveFlags::NONE, 0, 0,),
                    Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
                );
            });
        }
    });

    pair.listener_process
        .close_object_reference(pair.accepted)
        .unwrap();
    hook.stop();
    assert!(receiver.lock().unwrap().is_none());
    assert_eq!(
        pair.retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        pair.accepted
    );
}

/// An event harvested for a socket that closes before the event is handled
/// is dropped, and the provider keeps working.
#[test]
fn tcp_event_for_a_socket_closed_after_harvest_is_dropped() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        retirements,
        readiness,
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    let mut host = connect_to_host(&process, socket, &publications, &listener);
    let hook = TestHook::install(&provider);
    let closer = Arc::new(Mutex::new(Some((Arc::clone(&process), socket))));
    let pending_close = Arc::clone(&closer);
    hook.act(move |_, _, point| {
        if point != HookPoint::Harvested(id) {
            return;
        }
        let closer = pending_close.lock().unwrap().take();
        if let Some((process, socket)) = closer {
            run_on_thread(move || process.close_object_reference(socket).unwrap());
        }
    });

    let start = hook.len();
    host.write_all(b"data").unwrap();
    assert_eq!(
        hook.wait_for_harvest_handled(start, |token| token == id),
        Dispatch::Dropped
    );
    hook.stop();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), socket);

    let socket = create_socket(&process, readiness);
    let mut host = connect_to_host(&process, socket, &publications, &listener);
    host.write_all(b"next").unwrap();
    let mut data = [0; 4];
    receive_exact(&process, socket, &publications, &mut data);
    assert_eq!(&data, b"next");
}

/// A `MSG_PEEK | MSG_WAITALL` peek the guest stops waiting for, as when its
/// wait times out and it peeks what is queued instead, no longer keeps the
/// event thread checking for its data, and readiness is republished for a
/// peek another thread may still wait in.
#[test]
fn abandoned_waitall_peek_stops_waiting_for_its_data() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        provider,
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let id = *provider.core.socket_ids().last().unwrap();
    let mut host = connect_to_host(&process, socket, &publications, &listener);
    host.write_all(b"x").unwrap();
    wait_for_readiness_publication(&publications, socket, ReadinessFlags::READ);
    let hook = TestHook::install(&provider);
    let mut peeked = [0_u8; 4];
    assert_eq!(
        receive_into(
            &process,
            socket,
            &mut peeked,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            4,
        ),
        Err(BrokerError::WouldBlock)
    );
    while publications.try_recv().is_ok() {}

    // While the peek waits, the event thread only polls, so it applies an
    // event only once the plain peek abandons it.
    let start = hook.len();
    assert_eq!(
        receive_into(&process, socket, &mut peeked, ReceiveFlags::PEEK, 0, 4),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    wait_for_readiness_publication(&publications, socket, ReadinessFlags::READ);
    // Too little data for the abandoned peek, so an event thread still
    // checking for it would keep polling rather than apply the event. Linux
    // reports this arrival; Windows does not, but applies a pending poll.
    host.write_all(b"y").unwrap();
    hook.wait_for(start, |point| {
        point == HookPoint::Handled(id, Dispatch::Applied)
    });
    hook.stop();
}

/// The data of a `MSG_PEEK | MSG_WAITALL` peek that no one retries, as when
/// the thread waiting in it exits, stops being watched once its interest
/// lapses, and readiness is republished.
#[test]
fn unretried_waitall_peek_stops_being_watched() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let mut host = connect_to_host(&process, socket, &publications, &listener);
    host.write_all(b"x").unwrap();
    wait_for_readiness_publication(&publications, socket, ReadinessFlags::READ);
    let mut peeked = [0_u8; 4];
    assert_eq!(
        receive_into(
            &process,
            socket,
            &mut peeked,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            4,
        ),
        Err(BrokerError::WouldBlock)
    );
    while publications.try_recv().is_ok() {}

    std::thread::sleep(PEEK_WAITALL_INTEREST);
    // Too little data for the peek, and readiness is unchanged, so only a
    // lapsed interest republishes it. Linux reports this arrival; Windows
    // does not, but polls for the peek until its interest lapses.
    host.write_all(b"y").unwrap();
    wait_for_readiness_publication(&publications, socket, ReadinessFlags::READ);
}

/// A `MSG_PEEK | MSG_WAITALL` peek on a nonblocking socket does not wait, so
/// it peeks what is queued.
#[test]
fn nonblocking_waitall_peek_peeks_what_is_queued() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ExternalTcpSocket {
        process,
        socket,
        publications,
        ..
    } = external_tcp_socket();
    let mut host = connect_to_host(&process, socket, &publications, &listener);
    host.write_all(b"x").unwrap();
    wait_for_readiness_publication(&publications, socket, ReadinessFlags::READ);
    process
        .set_status_flags(litebox_broker_protocol::fs::SetStatusFlagsRequest {
            handle: socket,
            mask: FileOpenFlags::NONBLOCKING,
            flags: FileOpenFlags::NONBLOCKING,
        })
        .unwrap();
    let mut peeked = [0_u8; 4];
    assert_eq!(
        receive_into(
            &process,
            socket,
            &mut peeked,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            4,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    assert_eq!(peeked[0], b'x');
}

/// Sends a byte on `pair`'s connector while waking the event thread fails,
/// once the event thread has finished its last batch, so the event the send
/// posts for the accepted socket waits with no wake to report it.
fn send_with_failed_wake(provider: &UserlandSocketProvider, pair: &GuestTcpPair) {
    let hook = TestHook::install(provider);
    // An event the thread has harvested leaves no wake pending once it waits.
    let trigger = *provider.core.socket_ids().last().unwrap();
    let triggered = AtomicBool::new(false);
    let (sent, sends) = channel();
    let sender = Mutex::new(Some((
        Arc::clone(&provider.core.posted),
        Arc::clone(&pair.connector_process),
        pair.connector,
        sent,
    )));
    hook.act(move |_, _, point| match point {
        HookPoint::Harvested(token) if token == trigger => {
            triggered.store(true, Ordering::Relaxed);
        }
        HookPoint::Waiting if triggered.load(Ordering::Relaxed) => {
            let Some((posted, process, connector, sent)) = sender.lock().unwrap().take() else {
                return;
            };
            posted.fail_wakes.store(true, Ordering::Relaxed);
            run_on_thread(move || {
                assert_eq!(
                    send_bytes(&process, connector, b"x", SendFlags::NONE),
                    Ok(SocketOutcome::Completed(1))
                );
            });
            posted.fail_wakes.store(false, Ordering::Relaxed);
            sent.send(()).unwrap();
        }
        _ => {}
    });
    provider.core.posted.post(trigger);
    sends.recv_timeout(TEST_TIMEOUT).unwrap();
    hook.stop();
}

/// An event an internal endpoint posts while waking the event thread fails
/// is applied once a later post wakes it.
#[test]
fn posted_events_survive_a_failed_wake_once_another_post_wakes() {
    let provider = Arc::new(UserlandSocketProvider::new(6, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(16, 0, 6, 3),
        provider.clone(),
    )
    .unwrap();
    let first = connect_guest_tcp_pair(&broker, provider.clone(), 8206);
    let second = connect_guest_tcp_pair(&broker, provider.clone(), 8207);
    wait_for_settled_readiness(&provider);

    send_with_failed_wake(&provider, &first);
    // The first pair's event is still posted, so this post would not wake
    // the event thread had no wake failed.
    assert_eq!(
        send_bytes(
            &second.connector_process,
            second.connector,
            b"y",
            SendFlags::NONE
        ),
        Ok(SocketOutcome::Completed(1))
    );
    for pair in [&first, &second] {
        wait_until_ready(
            &pair.listener_process,
            &pair.publications,
            pair.accepted,
            ReadinessFlags::READ,
        );
    }
}

/// An event an internal endpoint posts while waking the event thread fails
/// is applied once a host event wakes the thread, even with no later post.
#[test]
fn posted_events_survive_a_failed_wake_once_a_host_event_arrives() {
    let provider = Arc::new(UserlandSocketProvider::new(6, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_tcp_policy()),
        BrokerCoreLimits::new_with_all_limits(16, 0, 6, 3),
        provider.clone(),
    )
    .unwrap();
    let pair = connect_guest_tcp_pair(&broker, provider.clone(), 8208);
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let external = create_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut host = connect_to_host(&process, external, &publications, &listener);
    wait_for_settled_readiness(&provider);

    send_with_failed_wake(&provider, &pair);
    host.write_all(b"z").unwrap();
    wait_until_ready(&process, &publications, external, ReadinessFlags::READ);
    wait_until_ready(
        &pair.listener_process,
        &pair.publications,
        pair.accepted,
        ReadinessFlags::READ,
    );
}

/// A peer flooding an endpoint after its guest read shutdown does not stall
/// the event thread: another socket's readiness still arrives.
#[test]
fn guest_read_shutdown_flood_does_not_stall_other_sockets() {
    let provider = Arc::new(UserlandSocketProvider::new(6, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(16, 0, 6, 3),
        provider.clone(),
    )
    .unwrap();
    let flooded = connect_guest_tcp_pair(&broker, provider.clone(), 8204);
    let quiet = connect_guest_tcp_pair(&broker, provider.clone(), 8205);
    let quiet_accepted_id = *provider.core.socket_ids().last().unwrap();
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &flooded.listener_process,
            flooded.accepted,
            ShutdownMode::Read,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let flood = {
        let stop = Arc::clone(&stop);
        let sent = Arc::clone(&sent);
        let process = Arc::clone(&flooded.connector_process);
        let connector = flooded.connector;
        thread::spawn(move || {
            let data = vec![0; MAX_SOCKET_TRANSFER_SIZE as usize];
            while !stop.load(Ordering::Relaxed) {
                match send_bytes(&process, connector, &data, SendFlags::NONE) {
                    Ok(SocketOutcome::Completed(length)) => {
                        sent.fetch_add(length, Ordering::Relaxed);
                    }
                    Err(BrokerError::WouldBlock) => thread::yield_now(),
                    outcome => panic!("unexpected send outcome: {outcome:?}"),
                }
            }
        })
    };
    // Far more than a stream's capacity, so the stream is discarding.
    let flooding = 64 * MAX_SOCKET_TRANSFER_SIZE as usize;
    wait_until(
        || sent.load(Ordering::Relaxed) >= flooding,
        "the flood starts",
    );

    // A receive would find the data without the event thread, so wait for
    // the event thread to apply an event for the quiet socket during the
    // flood.
    let hook = TestHook::install(&provider);
    let start = hook.len();
    assert_eq!(
        send_bytes(
            &quiet.connector_process,
            quiet.connector,
            b"ping",
            SendFlags::NONE
        ),
        Ok(SocketOutcome::Completed(4))
    );
    assert_eq!(
        hook.wait_for_harvest_handled(start, |token| token == quiet_accepted_id),
        Dispatch::Applied
    );
    hook.stop();
    let flooded_before = sent.load(Ordering::Relaxed);
    wait_until(
        || sent.load(Ordering::Relaxed) > flooded_before,
        "the flood continues",
    );
    let mut data = [0; 4];
    receive_exact(
        &quiet.listener_process,
        quiet.accepted,
        &quiet.publications,
        &mut data,
    );
    assert_eq!(&data, b"ping");
    stop.store(true, Ordering::Relaxed);
    flood.join().unwrap();
}

/// Many connections exchange data in parallel, and every socket's readiness
/// then settles.
#[test]
fn many_guest_tcp_pairs_exchange_data_in_parallel() {
    const PAIRS: u16 = 8;
    const ROUNDS: u8 = 64;
    let provider = Arc::new(UserlandSocketProvider::new(3 * usize::from(PAIRS), 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8 * usize::from(PAIRS), 0, 3 * usize::from(PAIRS), 2),
        provider.clone(),
    )
    .unwrap();
    let workers: Vec<_> = (0..PAIRS)
        .map(|index| {
            let pair = connect_guest_tcp_pair(&broker, provider.clone(), 8300 + index);
            thread::spawn(move || {
                for round in 0..ROUNDS {
                    let message = [round; 256];
                    let mut data = [0; 256];
                    assert_eq!(
                        send_bytes(
                            &pair.connector_process,
                            pair.connector,
                            &message,
                            SendFlags::NONE,
                        ),
                        Ok(SocketOutcome::Completed(message.len()))
                    );
                    receive_exact(
                        &pair.listener_process,
                        pair.accepted,
                        &pair.publications,
                        &mut data,
                    );
                    assert_eq!(data, message);
                    assert_eq!(
                        send_bytes(
                            &pair.listener_process,
                            pair.accepted,
                            &data,
                            SendFlags::NONE,
                        ),
                        Ok(SocketOutcome::Completed(data.len()))
                    );
                    receive_exact(
                        &pair.connector_process,
                        pair.connector,
                        &pair.publications,
                        &mut data,
                    );
                    assert_eq!(data, message);
                }
                pair
            })
        })
        .collect();
    let pairs: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    wait_for_settled_readiness(&provider);
    drop(pairs);
}
