// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;

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

    let refused_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let refused_address = refused_listener.local_addr().unwrap();
    drop(refused_listener);

    let provider = Arc::new(LinuxSocketProvider::new(8, 8).unwrap());
    let broker = BrokerCore::new_with_limits(
        policy_with_gateway(
            &[
                address.port(),
                read_shutdown_address.port(),
                abort_address.port(),
                refused_address.port(),
            ],
            &[],
        ),
        BrokerCoreLimits::new_with_all_limits(16, 0, 8, 8),
        provider,
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let handle = create_socket(&session, readiness.clone());
    let connect =
        litebox_broker_core::socket::connect(&session, handle, gateway_address(address.port()))
            .unwrap();
    assert!(matches!(
        connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    wait_until_connected(&session, handle, &publications);
    let status = litebox_broker_core::socket::status(&session, handle).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connected);
    let local_address = status
        .local_address
        .expect("connected socket must expose its local address");
    assert_eq!(*local_address.ip(), guest_ipv4_address());
    assert_ne!(local_address.port(), 0);
    assert_eq!(status.pending_error, None);
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::NoDelay,),
        Ok(TcpOptionValue::NoDelay(false))
    );
    litebox_broker_core::socket::set_tcp_option(&session, handle, TcpOptionValue::NoDelay(true))
        .unwrap();
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::NoDelay,),
        Ok(TcpOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::KeepAlive,),
        Ok(TcpOptionValue::KeepAlive(false))
    );
    litebox_broker_core::socket::set_tcp_option(&session, handle, TcpOptionValue::KeepAlive(true))
        .unwrap();
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, handle, TcpOptionName::KeepAlive,),
        Ok(TcpOptionValue::KeepAlive(true))
    );

    let mut unavailable = [0_u8; 1];
    assert_eq!(
        receive_into(&session, handle, &mut unavailable, ReceiveFlags::NONE, 0, 0,),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        send_bytes(&session, handle, b"ping", SendFlags::NONE,),
        Ok(SocketOutcome::Completed(4))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, handle, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        send_bytes(&session, handle, b"after shutdown", SendFlags::NONE),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );
    allow_response.send(()).unwrap();
    wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
    let current_readiness = session.check_readiness(handle).unwrap();
    assert!(!current_readiness.contains(ReadinessFlags::WRITE));
    assert!(!current_readiness.contains(ReadinessFlags::ERROR));

    let mut first = [0_u8; 1];
    assert_eq!(
        receive_into(&session, handle, &mut first, ReceiveFlags::NONE, 0, 0,),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    assert_eq!(&first, b"p");
    assert!(
        session
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    let mut peeked = [0_u8; 3];
    assert_eq!(
        receive_into(&session, handle, &mut peeked, ReceiveFlags::PEEK, 0, 3,),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
    );
    assert_eq!(&peeked, b"ong");
    let mut received = [0_u8; 3];
    assert_eq!(
        receive_into(&session, handle, &mut received, ReceiveFlags::NONE, 0, 0,),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(3)))
    );
    assert_eq!(&received, b"ong");
    assert!(
        !session
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert_eq!(
        receive_into(&session, handle, &mut unavailable, ReceiveFlags::NONE, 0, 0,),
        Err(BrokerError::WouldBlock)
    );
    assert!(
        !session
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    allow_end_of_stream.send(()).unwrap();
    wait_for_end_of_stream(&session, handle, &publications);

    let read_shutdown_handle = create_socket(&session, readiness.clone());
    let read_shutdown_connect = litebox_broker_core::socket::connect(
        &session,
        read_shutdown_handle,
        gateway_address(read_shutdown_address.port()),
    )
    .unwrap();
    assert!(matches!(
        read_shutdown_connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    wait_until_connected(&session, read_shutdown_handle, &publications);
    allow_read_shutdown_data.send(()).unwrap();
    read_shutdown_data_received
        .recv_timeout(TEST_TIMEOUT)
        .unwrap();
    wait_until_ready(
        &session,
        &publications,
        read_shutdown_handle,
        ReadinessFlags::READ,
    );
    let mut read_shutdown_peek = [0_u8; 2];
    assert_eq!(
        receive_into(
            &session,
            read_shutdown_handle,
            &mut read_shutdown_peek,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            2,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, read_shutdown_handle, ShutdownMode::Read,),
        Ok(SocketOutcome::Completed(()))
    );
    wait_until_ready(
        &session,
        &publications,
        read_shutdown_handle,
        ReadinessFlags::READ,
    );
    assert_eq!(
        receive_into(
            &session,
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
            &session,
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
        session
            .check_readiness(read_shutdown_handle)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert_eq!(
        receive_into(
            &session,
            read_shutdown_handle,
            &mut queued_after_shutdown,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream))
    );
    let read_shutdown_readiness = session.check_readiness(read_shutdown_handle).unwrap();
    assert!(read_shutdown_readiness.contains(ReadinessFlags::READ));
    assert!(!read_shutdown_readiness.contains(ReadinessFlags::HANGUP));
    assert!(!read_shutdown_readiness.contains(ReadinessFlags::ERROR));

    let unconnected_handle = create_socket(&session, readiness.clone());
    assert_eq!(
        receive_into(
            &session,
            unconnected_handle,
            &mut unavailable,
            ReceiveFlags(ReceiveFlags::PEEK.0 | ReceiveFlags::WAITALL.0),
            0,
            1,
        ),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, unconnected_handle, ShutdownMode::Both,),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &session,
            unconnected_handle,
            ShutdownMode::StopListening,
        ),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert!(
        !session
            .check_readiness(unconnected_handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );

    let refused_handle = create_socket(&session, readiness.clone());
    let refused_connect = litebox_broker_core::socket::connect(
        &session,
        refused_handle,
        gateway_address(refused_address.port()),
    )
    .unwrap();
    assert!(matches!(
        refused_connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Failed(_)
        )
    ));
    assert_eq!(
        wait_until_failed(&session, refused_handle, &publications),
        SocketError::ConnectionRefused
    );
    assert!(
        session
            .check_readiness(refused_handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );

    let abort_handle = create_socket(&session, readiness);
    let abort_connect = litebox_broker_core::socket::connect(
        &session,
        abort_handle,
        gateway_address(abort_address.port()),
    )
    .unwrap();
    assert!(matches!(
        abort_connect,
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    wait_until_connected(&session, abort_handle, &publications);
    wait_for_abort_accept.recv_timeout(TEST_TIMEOUT).unwrap();
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, abort_handle, ShutdownMode::Abort),
        Ok(SocketOutcome::Completed(()))
    );
    session.close_object_reference(abort_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        abort_handle
    );
    abort_server.join().unwrap();

    session.close_object_reference(handle).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
    session
        .close_object_reference(read_shutdown_handle)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        read_shutdown_handle
    );
    session.close_object_reference(unconnected_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        unconnected_handle
    );
    session.close_object_reference(refused_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        refused_handle
    );
    release_read_shutdown_server.send(()).unwrap();
    read_shutdown_server.join().unwrap();
    server.join().unwrap();
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
    let broker = BrokerCore::new_with_limits(
        policy_with_gateway(&[address.port()], &[]),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
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
    let handle = create_socket(&session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&session, handle, gateway_address(address.port())),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&session, handle, &publications);

    send_data.send(()).unwrap();
    wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
    readiness.fail_next_publish_matching(handle, ReadinessFlags::default(), ReadinessFlags::READ);
    let mut data = [0_u8; 5];
    assert_eq!(
        receive_into(&session, handle, &mut data, ReceiveFlags::NONE, 0, 0),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(5)))
    );
    assert_eq!(&data, b"reply");
    readiness.assert_no_pending_publish_failure();
    assert!(
        !session
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
    let broker = BrokerCore::new_with_limits(
        policy_with_gateway(&[address.port()], &[]),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
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
    let handle = create_socket(&session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&session, handle, gateway_address(address.port())),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&session, handle, &publications);

    abort_connection.send(()).unwrap();
    wait_until_ready(&session, &publications, handle, ReadinessFlags::ERROR);
    readiness.fail_next_publish_matching(handle, ReadinessFlags::default(), ReadinessFlags::ERROR);
    let status = litebox_broker_core::socket::status(&session, handle).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connected);
    assert_eq!(status.pending_error, Some(SocketError::ConnectionReset));
    readiness.assert_no_pending_publish_failure();
    assert!(
        !session
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
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
    let broker = BrokerCore::new_with_limits(
        policy_with_gateway(&[address.port()], &[]),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let handle = create_socket(&session, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(&session, handle, gateway_address(address.port())),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&session, handle, &publications);
    wait_for_first_chunk.recv_timeout(TEST_TIMEOUT).unwrap();
    wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);

    let peek_length = MAX_SOCKET_TRANSFER_SIZE * 2;
    let mut first = vec![0_u8; chunk];
    assert_eq!(
        receive_into(
            &session,
            handle,
            &mut first,
            ReceiveFlags::PEEK,
            0,
            peek_length,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(
            MAX_SOCKET_TRANSFER_SIZE
        )))
    );
    assert!(first.iter().all(|byte| *byte == 0x41));

    send_second_chunk.send(()).unwrap();
    wait_until_ready(
        &session,
        &publications,
        handle,
        ReadinessFlags::READ | ReadinessFlags::HANGUP,
    );
    let mut second = vec![0_u8; chunk];
    assert_eq!(
        receive_into(
            &session,
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
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(6, 0, 3, 3),
        provider,
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8091);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, connector, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, connector, &publications);
    wait_until_ready(
        &listener_session,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    let accepted = match litebox_broker_core::socket::accept(&listener_session, listener, readiness)
        .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted.handle,
        SocketOutcome::Failed(error) => panic!("guest accept failed: {error:?}"),
    };
    assert_eq!(
        send_bytes(&listener_session, accepted, b"unread", SendFlags::NONE,),
        Ok(SocketOutcome::Completed(6))
    );
    wait_until_ready(
        &connector_session,
        &publications,
        connector,
        ReadinessFlags::READ,
    );

    connector_session.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    wait_until_ready(
        &listener_session,
        &publications,
        accepted,
        ReadinessFlags::READ | ReadinessFlags::ERROR | ReadinessFlags::HANGUP,
    );
    let mut byte = [0_u8; 1];
    assert_eq!(
        receive_into(
            &listener_session,
            accepted,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
}

#[test]
fn guest_tcp_namespace_routes_across_sessions_without_host_endpoints() {
    let provider = Arc::new(LinuxSocketProvider::new(5, 3).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 5, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let client_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    // The host keeps its own listener on the numerically identical port to
    // prove that the guest namespace never borrows a host endpoint.
    let shadowed_host_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    shadowed_host_listener.set_nonblocking(true).unwrap();
    let guest_port = shadowed_host_listener.local_addr().unwrap().port();
    let guest_address = guest_address(guest_port);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        provider.reactor.tcp_transport_kind(guest_address),
        Some(TcpTransportKind::NoDescriptor)
    );

    let early_client = create_socket(&client_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&client_session, early_client, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((0, 0)),
        "a connect refused before listen must not queue anything"
    );
    assert_eq!(
        shadowed_host_listener.accept().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    client_session.close_object_reference(early_client).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        early_client
    );

    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 3),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        provider.reactor.tcp_transport_kind(guest_address),
        Some(TcpTransportKind::NoDescriptor),
        "a guest listener must never own a host descriptor"
    );
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((0, 0))
    );

    let client = create_socket(&client_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&client_session, client, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&client_session, client, &publications);
    let client_address = litebox_broker_core::socket::status(&client_session, client)
        .unwrap()
        .local_address
        .unwrap();
    assert_eq!(
        provider.reactor.tcp_transport_kind(client_address),
        Some(TcpTransportKind::Virtual),
        "a guest connection must use only a broker-local stream"
    );
    assert_eq!(*client_address.ip(), guest_ipv4_address());
    assert_eq!(provider.reactor.queued_accept_count(), 1);
    wait_until_ready(
        &listener_session,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    let accepted =
        match litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone())
            .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("accept failed: {error:?}"),
        };
    assert_eq!(accepted.local_address, guest_address);
    assert_eq!(accepted.remote_address, client_address);
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((0, 0))
    );

    assert_eq!(
        send_bytes(&client_session, client, b"x", SendFlags::NONE),
        Ok(SocketOutcome::Completed(1))
    );
    wait_until_ready(
        &listener_session,
        &publications,
        accepted.handle,
        ReadinessFlags::READ,
    );
    let mut byte = [0];
    assert_eq!(
        receive_into(
            &listener_session,
            accepted.handle,
            &mut byte,
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(1)))
    );
    assert_eq!(byte, *b"x");
    // The host listener on the same port number stays untouched by every
    // guest-namespace connection.
    assert_eq!(
        shadowed_host_listener.accept().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );

    listener_session
        .close_object_reference(accepted.handle)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        accepted.handle
    );
    client_session.close_object_reference(client).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), client);
    listener_session.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
}

#[test]
fn guest_tcp_options_are_cached_without_a_host_socket() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 3).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
        provider.clone(),
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8094);
    let listener = create_socket(&session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );
    // A logical listener owns no descriptor, so its options are pure cache.
    for value in [
        TcpOptionValue::NoDelay(true),
        TcpOptionValue::KeepAlive(true),
    ] {
        assert_eq!(
            litebox_broker_core::socket::set_tcp_option(&session, listener, value),
            Ok(())
        );
    }
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, listener, TcpOptionName::NoDelay),
        Ok(TcpOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, listener, TcpOptionName::KeepAlive),
        Ok(TcpOptionValue::KeepAlive(true))
    );

    let connector = create_socket(&session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::set_tcp_option(
            &session,
            connector,
            TcpOptionValue::NoDelay(true),
        ),
        Ok(())
    );
    assert!(matches!(
        litebox_broker_core::socket::connect(&session, connector, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&session, connector, &publications);
    // The virtual stream rejects TCP-level options natively, so the cached
    // value must survive the connection.
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, connector, TcpOptionName::NoDelay),
        Ok(TcpOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::set_tcp_option(
            &session,
            connector,
            TcpOptionValue::KeepAlive(true),
        ),
        Ok(())
    );
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(&session, connector, TcpOptionName::KeepAlive),
        Ok(TcpOptionValue::KeepAlive(true))
    );
    wait_until_ready(&session, &publications, listener, ReadinessFlags::READ);
    let accepted =
        match litebox_broker_core::socket::accept(&session, listener, readiness.clone()).unwrap() {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("accept failed: {error:?}"),
        };
    // An accepted socket inherits the listener options like a native accept.
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(
            &session,
            accepted.handle,
            TcpOptionName::NoDelay,
        ),
        Ok(TcpOptionValue::NoDelay(true))
    );
    assert_eq!(
        litebox_broker_core::socket::get_tcp_option(
            &session,
            accepted.handle,
            TcpOptionName::KeepAlive,
        ),
        Ok(TcpOptionValue::KeepAlive(true))
    );
    drop(session);
    let _ = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
}

#[test]
fn saturated_guest_backlog_parks_connectors_until_accept() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 6).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 6, 6),
        provider.clone(),
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8095);
    let listener = create_socket(&session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let first = create_socket(&session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&session, first, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&session, first, &publications);
    let second = create_socket(&session, readiness.clone());
    // The backlog is full, so this connect must park instead of failing.
    assert_eq!(
        litebox_broker_core::socket::connect(&session, second, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((1, 1))
    );
    assert_eq!(provider.reactor.queued_accept_count(), 2);
    let second_address = litebox_broker_core::socket::status(&session, second)
        .unwrap()
        .local_address
        .unwrap();
    assert!(matches!(
        receive_into(&session, second, &mut [0_u8; 1], ReceiveFlags::NONE, 0, 0),
        Err(BrokerError::WouldBlock)
    ));

    wait_until_ready(&session, &publications, listener, ReadinessFlags::READ);
    let accepted =
        match litebox_broker_core::socket::accept(&session, listener, readiness.clone()).unwrap() {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("first accept failed: {error:?}"),
        };
    assert_ne!(accepted.remote_address, second_address);
    // Accepting frees one backlog slot, which promotes the parked connector.
    wait_until_connected(&session, second, &publications);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((1, 0))
    );
    assert_eq!(provider.reactor.queued_accept_count(), 1);

    wait_until_ready(&session, &publications, listener, ReadinessFlags::READ);
    let promoted =
        match litebox_broker_core::socket::accept(&session, listener, readiness.clone()).unwrap() {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("promoted accept failed: {error:?}"),
        };
    assert_eq!(promoted.remote_address, second_address);
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        send_bytes(&session, second, b"promoted", SendFlags::NONE),
        Ok(SocketOutcome::Completed(8))
    );
    let mut data = [0_u8; 8];
    loop {
        match receive_into(
            &session,
            promoted.handle,
            &mut data,
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(8))) => break,
            Err(BrokerError::WouldBlock) => {
                wait_until_ready(
                    &session,
                    &publications,
                    promoted.handle,
                    ReadinessFlags::READ,
                );
            }
            outcome => panic!("unexpected promoted receive outcome: {outcome:?}"),
        }
    }
    assert_eq!(&data, b"promoted");
    drop(session);
    let _ = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
}

#[test]
fn growing_guest_backlog_promotes_all_parked_connectors() {
    let provider = Arc::new(LinuxSocketProvider::new(10, 10).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 10, 10),
        provider.clone(),
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8097);
    let listener = create_socket(&session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&session, listener, 2),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connectors = [
        create_socket(&session, readiness.clone()),
        create_socket(&session, readiness.clone()),
        create_socket(&session, readiness.clone()),
        create_socket(&session, readiness.clone()),
    ];
    for connector in connectors {
        assert!(matches!(
            litebox_broker_core::socket::connect(&session, connector, guest_address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
    }
    wait_until_connected(&session, connectors[0], &publications);
    wait_until_connected(&session, connectors[1], &publications);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((2, 2))
    );

    assert_eq!(
        litebox_broker_core::socket::listen(&session, listener, 4),
        Ok(SocketOutcome::Completed(guest_address))
    );
    wait_until_connected(&session, connectors[2], &publications);
    wait_until_connected(&session, connectors[3], &publications);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((4, 0))
    );
    drop(session);
    let _ = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
}

#[test]
fn listener_close_resets_queued_and_refuses_parked_connectors() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 6).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 6, 6),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8096);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let queued = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, queued, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, queued, &publications);
    let parked = create_socket(&connector_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_session, parked, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    assert_eq!(provider.reactor.queued_accept_count(), 2);

    listener_session.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        None
    );

    // A connection that was never accepted is aborted, exactly as a native
    // listener close would reset its unaccepted backlog.
    wait_until_ready(
        &connector_session,
        &publications,
        queued,
        ReadinessFlags::ERROR,
    );
    assert_eq!(
        receive_into(
            &connector_session,
            queued,
            &mut [0_u8; 1],
            ReceiveFlags::NONE,
            0,
            0,
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    assert_eq!(
        send_bytes(&connector_session, queued, b"x", SendFlags::NONE),
        Ok(SocketOutcome::Failed(SocketError::ConnectionReset))
    );
    assert_eq!(
        wait_until_failed(&connector_session, parked, &publications),
        SocketError::ConnectionRefused
    );
    drop(connector_session);
    drop(listener_session);
    let _ = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
}

#[test]
fn connector_and_session_teardown_release_queued_accepts() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 3).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8082);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 2),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let first = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, first, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, first, &publications);
    connector_session.close_object_reference(first).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), first);
    // A graceful close keeps the queued connection acceptable, so its slot
    // stays charged to the connector session.
    assert_eq!(provider.reactor.queued_accept_count(), 1);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((1, 0))
    );

    let second = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, second, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, second, &publications);
    assert_eq!(provider.reactor.queued_accept_count(), 2);
    // Queued accepts are charged like live sockets, so the session budget is
    // exhausted even though only one of its sockets is still open.
    assert_eq!(
        litebox_broker_core::socket::create(
            &connector_session,
            CreateSocketRequest {
                address_family: AddressFamily::Ipv4,
                socket_type: SocketType::Stream,
                protocol: IpProtocol::Tcp,
            },
            readiness.clone(),
        ),
        Err(BrokerError::ResourceExhausted)
    );
    // The rejected create still retires the handle it reserved.
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), second);

    drop(connector_session);
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), second);
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((0, 0))
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone()),
        Err(BrokerError::WouldBlock)
    ));
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    listener_session.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    drop(listener_session);
}

#[test]
fn guest_connect_budget_counts_live_and_queued_resources_together() {
    let provider = Arc::new(LinuxSocketProvider::new(5, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 5, 5),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8098);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let first = create_socket(&connector_session, readiness.clone());
    let second = create_socket(&connector_session, readiness);
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_session, first, guest_address),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((0, 0))
    );
    let first_address = litebox_broker_core::socket::status(&connector_session, first)
        .unwrap()
        .local_address
        .unwrap();
    assert_eq!(
        provider.reactor.tcp_transport_kind(first_address),
        Some(TcpTransportKind::NoDescriptor)
    );

    connector_session.close_object_reference(first).unwrap();
    connector_session.close_object_reference(second).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), first);
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), second);
}

#[test]
fn guest_connect_capacity_failure_leaves_external_retry_unbound() {
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
    let external_listener = TcpListener::bind((local_ip, 0)).unwrap();
    let external_address = socket_address_v4(external_listener.local_addr().unwrap());
    let socket_policy = SocketPolicy::from_tcp_destination_rules(&[DestinationRule::new(
        CallerCredential::Unauthenticated,
        Ipv4Cidr::new(Ipv4Address(local_ip.octets()), 32).unwrap(),
        DestinationPortRange::new(Port(external_address.port()), Port(external_address.port()))
            .unwrap(),
    )])
    .unwrap();
    let provider = Arc::new(LinuxSocketProvider::new(4, 4).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let retry_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8083);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 2),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let retry = create_socket(&retry_session, readiness.clone());
    // Another session consumes the last reactor slot with a queued accept
    // before this socket connects anywhere.
    let connector = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, connector, guest_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, connector, &publications);
    assert_eq!(provider.reactor.queued_accept_count(), 1);

    assert_eq!(
        litebox_broker_core::socket::connect(&retry_session, retry, guest_address),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((1, 0)),
        "a refused connect must not add itself to the listener queue"
    );
    assert_eq!(provider.reactor.queued_accept_count(), 1);

    // The external route needs no accept slot, so the same socket stays
    // usable after the guest route was refused.
    assert!(matches!(
        litebox_broker_core::socket::connect(&retry_session, retry, external_address),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&retry_session, retry, &publications);
    let (_, peer_address) = external_listener.accept().unwrap();
    assert_eq!(peer_address.ip(), local_ip);
    drop(retry_session);
    let _ = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
}

#[test]
fn graceful_connector_close_preserves_late_accept_and_eof() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 4),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8089);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, connector, &publications);
    let connector_address = litebox_broker_core::socket::status(&connector_session, connector)
        .unwrap()
        .local_address
        .unwrap();

    connector_session.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(provider.reactor.queued_accept_count(), 1);
    wait_until_ready(
        &listener_session,
        &publications,
        listener,
        ReadinessFlags::READ,
    );

    let accepted = match litebox_broker_core::socket::accept(&listener_session, listener, readiness)
        .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted,
        SocketOutcome::Failed(error) => panic!("late accept failed: {error:?}"),
    };
    assert_eq!(accepted.remote_address, connector_address);
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    wait_for_end_of_stream(&listener_session, accepted.handle, &publications);
}

#[test]
fn abortive_connector_close_releases_queued_capacity() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = guest_address(8086);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, connector, &publications);
    assert_eq!(provider.reactor.queued_accept_count(), 1);
    assert_eq!(
        litebox_broker_core::socket::shutdown(&connector_session, connector, ShutdownMode::Abort,),
        Ok(SocketOutcome::Completed(()))
    );
    connector_session.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    // An abortive close discards the queued connection immediately, so the
    // listener never observes it and the accept slot is released.
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((0, 0))
    );
    assert!(
        !listener_session
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone()),
        Err(BrokerError::WouldBlock)
    ));
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    let replacement = create_socket(&connector_session, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, replacement, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, replacement, &publications);
    assert_eq!(provider.reactor.queued_accept_count(), 1);
}

#[test]
fn stop_listening_cleanup_survives_readiness_failure() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 3, 3),
        provider.clone(),
    )
    .unwrap();
    let listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let guest_address = guest_address(8088);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );

    let connector = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, connector, &publications);
    wait_until_ready(
        &listener_session,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    connector_session.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(provider.reactor.queued_accept_count(), 1);

    readiness.fail_next_publish_matching(listener, ReadinessFlags::HANGUP, ReadinessFlags::READ);
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &listener_session,
            listener,
            ShutdownMode::StopListening,
        ),
        Ok(SocketOutcome::Completed(()))
    );
    readiness.assert_no_pending_publish_failure();
    let listener_readiness = listener_session.check_readiness(listener).unwrap();
    assert!(listener_readiness.contains(ReadinessFlags::WRITE));
    assert!(listener_readiness.contains(ReadinessFlags::HANGUP));
    assert!(!listener_readiness.contains(ReadinessFlags::READ));
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        Some((0, 0))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );

    let refused = create_socket(&connector_session, readiness);
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_session, refused, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    connector_session.close_object_reference(refused).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), refused);
    listener_session.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    assert_eq!(provider.reactor.queued_accept_count(), 0);
    assert_eq!(
        provider.reactor.listener_queue_state(guest_address.port()),
        None
    );
}

#[test]
fn reactor_drives_a_loopback_tcp_listener() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 6).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 6, 6),
        provider.clone(),
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let listener = create_socket(&session, readiness.clone());
    let local_address = match litebox_broker_core::socket::listen(&session, listener, 8)
        .expect("listen request must succeed")
    {
        SocketOutcome::Completed(address) => address,
        SocketOutcome::Failed(error) => panic!("listen failed: {error:?}"),
    };
    assert!(local_address.ip().is_unspecified());
    assert_ne!(local_address.port(), 0);
    let listener_guest_address = guest_address(local_address.port());
    assert_eq!(
        provider.reactor.tcp_transport_kind(local_address),
        Some(TcpTransportKind::NoDescriptor),
        "a guest listener must never own a host descriptor"
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, listener, ShutdownMode::Write),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&session, listener, readiness.clone()),
        Err(BrokerError::WouldBlock)
    ));
    let failed_accept_handle = retirements.recv_timeout(TEST_TIMEOUT).unwrap();
    assert_ne!(failed_accept_handle, listener);
    assert!(
        !session
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    let first_client = create_socket(&session, readiness.clone());
    let second_client = create_socket(&session, readiness.clone());
    for client in [first_client, second_client] {
        assert!(matches!(
            litebox_broker_core::socket::connect(&session, client, listener_guest_address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(&session, client, &publications);
    }
    let first_client_address = litebox_broker_core::socket::status(&session, first_client)
        .unwrap()
        .local_address
        .unwrap();
    let second_client_address = litebox_broker_core::socket::status(&session, second_client)
        .unwrap()
        .local_address
        .unwrap();
    wait_until_ready(&session, &publications, listener, ReadinessFlags::READ);
    assert_eq!(
        litebox_broker_core::socket::listen(&session, listener, 4),
        Ok(SocketOutcome::Completed(local_address))
    );

    let first =
        match litebox_broker_core::socket::accept(&session, listener, readiness.clone()).unwrap() {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("first accept failed: {error:?}"),
        };
    assert_eq!(first.local_address, listener_guest_address);
    assert_eq!(first.remote_address, first_client_address);
    assert!(
        session
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ),
        "accept must preserve listener readiness until the queue is observed empty"
    );

    let second =
        match litebox_broker_core::socket::accept(&session, listener, readiness.clone()).unwrap() {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("second accept failed: {error:?}"),
        };
    assert_eq!(second.local_address, listener_guest_address);
    assert_eq!(second.remote_address, second_client_address);
    assert!(
        !session
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ),
        "accept must clear listener readiness after draining the queue"
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&session, listener, readiness.clone()),
        Err(BrokerError::WouldBlock)
    ));
    assert!(
        !session
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    assert_eq!(
        send_bytes(&session, first_client, b"request", SendFlags::NONE),
        Ok(SocketOutcome::Completed(7))
    );
    let mut request = [0_u8; 7];
    loop {
        match receive_into(
            &session,
            first.handle,
            &mut request,
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(7))) => break,
            Err(BrokerError::WouldBlock) => {
                wait_until_ready(&session, &publications, first.handle, ReadinessFlags::READ);
            }
            outcome => panic!("unexpected accepted receive outcome: {outcome:?}"),
        }
    }
    assert_eq!(&request, b"request");
    assert_eq!(
        send_bytes(&session, first.handle, b"response", SendFlags::NONE,),
        Ok(SocketOutcome::Completed(8))
    );
    let mut response = [0_u8; 8];
    loop {
        match receive_into(
            &session,
            first_client,
            &mut response,
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(8))) => break,
            Err(BrokerError::WouldBlock) => {
                wait_until_ready(&session, &publications, first_client, ReadinessFlags::READ);
            }
            outcome => panic!("unexpected client receive outcome: {outcome:?}"),
        }
    }
    assert_eq!(&response, b"response");
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, listener, ShutdownMode::StopListening,),
        Ok(SocketOutcome::Completed(()))
    );
    wait_until_ready(&session, &publications, listener, ReadinessFlags::HANGUP);
    assert!(
        session
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::HANGUP)
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&session, listener, readiness.clone()),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    ));
    session.close_object_reference(first.handle).unwrap();
    drop(session);
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
