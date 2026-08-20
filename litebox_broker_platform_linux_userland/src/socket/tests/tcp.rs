// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;

#[test]
fn pending_guest_connections_are_keyed_by_complete_host_tuple() {
    let remote_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
    let first_listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000);
    let second_listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5001);
    let first_guest = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1000);
    let second_guest = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001);
    let mut tcp = ReactorTcpState::default();
    for (listener, guest) in [
        (first_listener, first_guest),
        (second_listener, second_guest),
    ] {
        tcp.insert_pending_guest_connection(
            (remote_address, listener),
            PendingGuestTcpConnection {
                session_id: SessionId(7),
                guest_address: guest,
                local_address: listener,
                listener_id: 1,
                discard_on_accept: false,
                discard_until_deadline: false,
                discard_deadline: None,
                retained_connector: None,
            },
        )
        .unwrap();
    }
    assert_eq!(
        tcp.insert_pending_guest_connection(
            (remote_address, first_listener),
            PendingGuestTcpConnection {
                session_id: SessionId(8),
                guest_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1002),
                local_address: first_listener,
                listener_id: 1,
                discard_on_accept: false,
                discard_until_deadline: false,
                discard_deadline: None,
                retained_connector: None,
            },
        ),
        Err(BrokerError::ResourceExhausted)
    );

    assert_eq!(
        match tcp
            .take_pending_guest_connection(remote_address, second_listener)
            .unwrap()
        {
            PendingGuestConnectionMatch::Take(connection) => connection.guest_address,
            PendingGuestConnectionMatch::PersistentDiscard => {
                panic!("deliverable connection became a discard marker")
            }
        },
        second_guest
    );
    assert_eq!(
        match tcp
            .take_pending_guest_connection(remote_address, first_listener)
            .unwrap()
        {
            PendingGuestConnectionMatch::Take(connection) => connection.guest_address,
            PendingGuestConnectionMatch::PersistentDiscard => {
                panic!("deliverable connection became a discard marker")
            }
        },
        first_guest
    );
    assert!(tcp.pending_guest_connections.is_empty());
}

#[test]
fn tuple_collision_persists_its_discard_marker() {
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000);
    let remote_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
    let host_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41000);
    let connection = (remote_address, host_address);
    let deadline = Instant::now() + PENDING_CONNECT_DISCARD_LIFETIME;
    let mut tcp = ReactorTcpState::default();
    assert!(!tcp.persist_discard_marker_for_collision(connection, 1, deadline));
    tcp.insert_pending_guest_connection(
        connection,
        PendingGuestTcpConnection {
            session_id: SessionId(7),
            guest_address,
            local_address: guest_address,
            listener_id: 1,
            discard_on_accept: false,
            discard_until_deadline: false,
            discard_deadline: Some(Instant::now()),
            retained_connector: None,
        },
    )
    .unwrap();
    assert!(!tcp.persist_discard_marker_for_collision(connection, 1, deadline));
    tcp.pending_guest_connections
        .get_mut(&connection)
        .unwrap()
        .discard_on_accept = true;

    assert!(tcp.persist_discard_marker_for_collision(connection, 1, deadline));
    let marker = tcp.pending_guest_connections.get(&connection).unwrap();
    assert!(marker.discard_until_deadline);
    assert_eq!(marker.discard_deadline, Some(deadline));
    assert!(matches!(
        tcp.take_pending_guest_connection(remote_address, host_address),
        Some(PendingGuestConnectionMatch::PersistentDiscard)
    ));
    assert!(tcp.pending_guest_connections.contains_key(&connection));
}

#[test]
fn untracked_guest_connection_cleanup_is_bounded_and_drains_backlog() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 3).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(12, 0, 6, 6),
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
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8090);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 4),
        Ok(SocketOutcome::Completed(guest_address))
    );

    provider
        .reactor
        .defer_untracked_guest_connection(guest_address.port());
    let blocked = create_socket(&connector_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_session, blocked, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused
        )))
    );
    connector_session.close_object_reference(blocked).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), blocked);

    provider.reactor.expire_pending_guest_connections();
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
    let accepted =
        match litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone())
            .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted.handle,
            SocketOutcome::Failed(error) => panic!("guest accept failed: {error:?}"),
        };
    listener_session.close_object_reference(accepted).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), accepted);
    connector_session.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);

    let private_address = provider.reactor.host_address(guest_address.port()).unwrap();
    let _unmatched = TcpStream::connect(private_address).unwrap();
    provider
        .reactor
        .defer_untracked_guest_connection(guest_address.port());
    provider.reactor.expire_pending_guest_connections();

    let gated = create_socket(&connector_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_session, gated, guest_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused
        )))
    );
    connector_session.close_object_reference(gated).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), gated);
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone(),),
        Err(BrokerError::WouldBlock)
    ));

    let final_connector = create_socket(&connector_session, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, final_connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
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
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
        litebox_broker_core::socket::connect(&session, handle, socket_address_v4(address)).unwrap();
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
    assert_eq!(*local_address.ip(), Ipv4Addr::LOCALHOST);
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
        socket_address_v4(read_shutdown_address),
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

    let refused_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let refused_address = refused_listener.local_addr().unwrap();
    drop(refused_listener);
    let refused_handle = create_socket(&session, readiness.clone());
    let refused_connect = litebox_broker_core::socket::connect(
        &session,
        refused_handle,
        socket_address_v4(refused_address),
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
        socket_address_v4(abort_address),
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
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
        litebox_broker_core::socket::connect(&session, handle, socket_address_v4(address),),
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
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
        litebox_broker_core::socket::connect(&session, handle, socket_address_v4(address),),
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
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
        litebox_broker_core::socket::connect(&session, handle, socket_address_v4(address),),
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
            .with_socket_policy(SocketPolicy::guest_network()),
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
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8091);
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
fn guest_tcp_namespace_routes_across_sessions_and_hides_private_backend() {
    let provider = Arc::new(LinuxSocketProvider::new(5, 3).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
    let shadowed_host_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    shadowed_host_listener.set_nonblocking(true).unwrap();
    let guest_port = shadowed_host_listener.local_addr().unwrap().port();
    let guest_address = SocketAddrV4::new(GUEST_IPV4_ADDRESS, guest_port);
    let claimed_port_miss = SocketAddrV4::new(Ipv4Addr::LOCALHOST, guest_port);
    let guest_destination = guest_address;
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(provider.reactor.host_address(guest_address.port()), None);

    let early_client = create_socket(&client_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&client_session, early_client, claimed_port_miss,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
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
    let unbound_private_port = if guest_port == u16::MAX {
        guest_port - 1
    } else {
        guest_port + 1
    };
    let unbound_private_client = create_socket(&client_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(
            &client_session,
            unbound_private_client,
            SocketAddrV4::new(GUEST_IPV4_ADDRESS, unbound_private_port),
        ),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    client_session
        .close_object_reference(unbound_private_client)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        unbound_private_client
    );

    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 3),
        Ok(SocketOutcome::Completed(guest_address))
    );
    let private_address = provider
        .reactor
        .host_address(guest_address.port())
        .expect("listener backend must be realized");
    assert!(private_address.ip().is_loopback());
    assert_ne!(private_address, guest_address);

    let direct_client = create_socket(&client_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&client_session, direct_client, private_address,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    client_session
        .close_object_reference(direct_client)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        direct_client
    );

    let native_client = TcpStream::connect(private_address).unwrap();
    wait_for_readiness(&publications, listener, ReadinessFlags::READ);
    let client = create_socket(&client_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(&client_session, client, guest_destination),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&client_session, client, &publications);
    let client_address = litebox_broker_core::socket::status(&client_session, client)
        .unwrap()
        .local_address
        .unwrap();
    assert_eq!(*client_address.ip(), GUEST_IPV4_ADDRESS);
    let connector_private_address = provider
        .reactor
        .host_address(client_address.port())
        .expect("connector backend must be realized");
    assert_ne!(connector_private_address, client_address);
    let connector_probe = create_socket(&client_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(
            &client_session,
            connector_probe,
            connector_private_address,
        ),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused,
        )))
    );
    client_session
        .close_object_reference(connector_probe)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        connector_probe
    );
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
    assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
    assert_eq!(provider.reactor.retained_connector_count(), 0);

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
    assert_eq!(
        shadowed_host_listener.accept().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    drop(native_client);
}

#[test]
fn tcp_exact_bindings_coexist_and_wildcard_accepts_concrete_destinations() {
    let provider = Arc::new(LinuxSocketProvider::new(12, 8).unwrap());
    let policy = SocketPolicy::from_tcp_destination_rules(&[DestinationRule::new(
        CallerCredential::Unauthenticated,
        Ipv4Cidr::new(Ipv4Address([0, 0, 0, 0]), 0).unwrap(),
        DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
    )])
    .unwrap();
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(policy),
        BrokerCoreLimits::new_with_all_limits(20, 0, 12, 12),
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
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });

    let first_listener = create_socket(&listener_session, readiness.clone());
    let SocketOutcome::Completed(first_address) = litebox_broker_core::socket::bind(
        &listener_session,
        first_listener,
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0),
    )
    .unwrap() else {
        panic!("first exact bind failed");
    };
    let second_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), first_address.port());
    let second_listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, second_listener, second_address,),
        Ok(SocketOutcome::Completed(second_address))
    );
    let wildcard_competitor = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(
            &listener_session,
            wildcard_competitor,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, first_address.port()),
        ),
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, first_listener, 1),
        Ok(SocketOutcome::Completed(first_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, second_listener, 1),
        Ok(SocketOutcome::Completed(second_address))
    );

    for (listener, destination) in [
        (first_listener, first_address),
        (second_listener, second_address),
    ] {
        let connector = create_socket(&connector_session, readiness.clone());
        assert!(matches!(
            litebox_broker_core::socket::connect(&connector_session, connector, destination,),
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
        let accepted = match litebox_broker_core::socket::accept(
            &listener_session,
            listener,
            readiness.clone(),
        )
        .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("exact accept failed: {error:?}"),
        };
        assert_eq!(accepted.local_address, destination);
    }

    let wildcard_listener = create_socket(&listener_session, readiness.clone());
    let SocketOutcome::Completed(wildcard_address) = litebox_broker_core::socket::bind(
        &listener_session,
        wildcard_listener,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard bind failed");
    };
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, wildcard_listener, 2),
        Ok(SocketOutcome::Completed(wildcard_address))
    );
    let concrete_destination = SocketAddrV4::new(GUEST_IPV4_ADDRESS, wildcard_address.port());
    let connector = create_socket(&connector_session, readiness.clone());
    let SocketOutcome::Completed(connector_binding) = litebox_broker_core::socket::bind(
        &connector_session,
        connector,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard connector bind failed");
    };
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, connector, concrete_destination,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, connector, &publications);
    assert_eq!(
        litebox_broker_core::socket::status(&connector_session, connector)
            .unwrap()
            .local_address,
        Some(SocketAddrV4::new(
            GUEST_IPV4_ADDRESS,
            connector_binding.port(),
        ))
    );
    wait_until_ready(
        &listener_session,
        &publications,
        wildcard_listener,
        ReadinessFlags::READ,
    );
    let accepted = match litebox_broker_core::socket::accept(
        &listener_session,
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

    let unspecified_connector = create_socket(&connector_session, readiness.clone());
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &connector_session,
            unspecified_connector,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, wildcard_address.port()),
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, unspecified_connector, &publications);
    wait_until_ready(
        &listener_session,
        &publications,
        wildcard_listener,
        ReadinessFlags::READ,
    );
    let accepted =
        match litebox_broker_core::socket::accept(&listener_session, wildcard_listener, readiness)
            .unwrap()
        {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("unspecified accept failed: {error:?}"),
        };
    assert_eq!(
        accepted.local_address,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, wildcard_address.port())
    );
}

#[test]
fn connector_and_session_teardown_clean_bounded_pending_state() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8082);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 2),
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
    connector_session.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
    assert_eq!(provider.reactor.retained_connector_count(), 1);
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
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    drop(connector_session);
    assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
    assert_eq!(provider.reactor.retained_connector_count(), 0);
    provider.reactor.expire_pending_guest_connections();
    assert_eq!(provider.reactor.pending_guest_connection_count(), 0);

    let blocked_connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let blocked_connector = create_socket(&blocked_connector_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(
            &blocked_connector_session,
            blocked_connector,
            guest_address,
        ),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused
        )))
    );
    blocked_connector_session
        .close_object_reference(blocked_connector)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        blocked_connector
    );

    wait_until_ready(
        &listener_session,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone(),),
        Err(BrokerError::WouldBlock)
    ));
    assert_ne!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);

    let final_connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let final_connector = create_socket(&final_connector_session, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(
            &final_connector_session,
            final_connector,
            guest_address,
        ),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&final_connector_session, final_connector, &publications);
    assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
    listener_session.close_object_reference(listener).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), listener);
    assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
    assert_eq!(provider.reactor.retained_connector_count(), 0);
}

#[test]
fn graceful_connector_close_preserves_late_accept_and_eof() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8089);
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
    assert_eq!(provider.reactor.retained_connector_count(), 1);
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
    assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
    assert_eq!(provider.reactor.retained_connector_count(), 0);
    wait_for_end_of_stream(&listener_session, accepted.handle, &publications);
}

#[test]
fn abortive_connector_close_releases_descriptor_capacity() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8086);
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
    assert_eq!(
        litebox_broker_core::socket::shutdown(&connector_session, connector, ShutdownMode::Abort,),
        Ok(SocketOutcome::Completed(()))
    );
    connector_session.close_object_reference(connector).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), connector);
    assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
    assert_eq!(provider.reactor.retained_connector_count(), 0);

    provider.reactor.expire_pending_guest_connections();
    assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
    assert_eq!(provider.reactor.retained_connector_count(), 0);

    let replacement = create_socket(&connector_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::connect(&connector_session, replacement, guest_address,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Failed(
            SocketError::ConnectionRefused
        )))
    );
    connector_session
        .close_object_reference(replacement)
        .unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), replacement);

    loop {
        match litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone()) {
            Err(BrokerError::WouldBlock) => break,
            Ok(SocketOutcome::Failed(
                SocketError::ConnectionAborted | SocketError::ConnectionReset,
            )) => {}
            _ => panic!("unexpected stale accept outcome"),
        }
    }

    let final_connector = create_socket(&connector_session, readiness);
    assert!(matches!(
        litebox_broker_core::socket::connect(&connector_session, final_connector, guest_address,),
        Ok(SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        ))
    ));
    wait_until_connected(&connector_session, final_connector, &publications);
}

#[test]
fn accept_bounds_unmatched_private_connections_per_command() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8087);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    let unmatched_connection_count = MAX_UNMATCHED_ACCEPTS_PER_COMMAND;
    assert_eq!(
        litebox_broker_core::socket::listen(
            &listener_session,
            listener,
            u32::try_from(unmatched_connection_count + 2).unwrap(),
        ),
        Ok(SocketOutcome::Completed(guest_address))
    );
    let private_address = provider.reactor.host_address(guest_address.port()).unwrap();
    let _unmatched_connections = (0..unmatched_connection_count)
        .map(|_| TcpStream::connect(private_address).unwrap())
        .collect::<Vec<_>>();

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
    wait_until_ready(
        &listener_session,
        &publications,
        listener,
        ReadinessFlags::READ,
    );
    assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
    while publications.try_recv().is_ok() {}

    assert!(matches!(
        litebox_broker_core::socket::accept(&listener_session, listener, readiness.clone(),),
        Err(BrokerError::WouldBlock)
    ));
    assert!(
        listener_session
            .check_readiness(listener)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    wait_for_readiness(&publications, listener, ReadinessFlags::READ);
    let accepted = match litebox_broker_core::socket::accept(&listener_session, listener, readiness)
        .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted,
        SocketOutcome::Failed(error) => panic!("guest accept failed: {error:?}"),
    };
    assert_eq!(accepted.remote_address, connector_address);
}

#[test]
fn accept_preserves_a_queued_connection_when_retained_capacity_is_unrelated() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 4).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 5, 5),
        provider.clone(),
    )
    .unwrap();
    let target_listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let target_connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let other_listener_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let other_connector_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let target_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8084);
    let other_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8085);

    let target_listener = create_socket(&target_listener_session, readiness.clone());
    let other_listener = create_socket(&other_listener_session, readiness.clone());
    for (session, listener, address) in [
        (&target_listener_session, target_listener, target_address),
        (&other_listener_session, other_listener, other_address),
    ] {
        assert_eq!(
            litebox_broker_core::socket::bind(session, listener, address),
            Ok(SocketOutcome::Completed(address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(session, listener, 1),
            Ok(SocketOutcome::Completed(address))
        );
    }

    let target_connector = create_socket(&target_connector_session, readiness.clone());
    let other_connector = create_socket(&other_connector_session, readiness.clone());
    for (session, connector, address) in [
        (&target_connector_session, target_connector, target_address),
        (&other_connector_session, other_connector, other_address),
    ] {
        assert!(matches!(
            litebox_broker_core::socket::connect(session, connector, address),
            Ok(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            ))
        ));
        wait_until_connected(session, connector, &publications);
    }
    let target_connector_address =
        litebox_broker_core::socket::status(&target_connector_session, target_connector)
            .unwrap()
            .local_address
            .unwrap();
    other_connector_session
        .close_object_reference(other_connector)
        .unwrap();
    assert_eq!(provider.reactor.pending_guest_connection_count(), 2);
    assert_eq!(provider.reactor.retained_connector_count(), 1);

    let deadline = Instant::now() + TEST_TIMEOUT;
    while !target_listener_session
        .check_readiness(target_listener)
        .unwrap()
        .contains(ReadinessFlags::READ)
    {
        assert!(
            Instant::now() < deadline,
            "target listener did not become ready"
        );
        std::thread::yield_now();
    }
    assert!(matches!(
        litebox_broker_core::socket::accept(
            &target_listener_session,
            target_listener,
            readiness.clone(),
        ),
        Err(BrokerError::ResourceExhausted)
    ));
    assert_eq!(provider.reactor.pending_guest_connection_count(), 2);

    other_listener_session
        .close_object_reference(other_listener)
        .unwrap();
    assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
    assert_eq!(provider.reactor.retained_connector_count(), 0);
    let accepted = match litebox_broker_core::socket::accept(
        &target_listener_session,
        target_listener,
        readiness,
    )
    .unwrap()
    {
        SocketOutcome::Completed(accepted) => accepted,
        SocketOutcome::Failed(error) => panic!("target accept failed: {error:?}"),
    };
    assert_eq!(accepted.remote_address, target_connector_address);
}

#[test]
fn stop_listening_cleanup_survives_readiness_failure() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
    let guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8088);
    let listener = create_socket(&listener_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&listener_session, listener, guest_address),
        Ok(SocketOutcome::Completed(guest_address))
    );
    assert_eq!(
        litebox_broker_core::socket::listen(&listener_session, listener, 1),
        Ok(SocketOutcome::Completed(guest_address))
    );
    let private_address = provider.reactor.host_address(guest_address.port()).unwrap();

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
    assert_eq!(provider.reactor.pending_guest_connection_count(), 1);
    assert_eq!(provider.reactor.retained_connector_count(), 1);

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
    assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
    assert_eq!(provider.reactor.retained_connector_count(), 0);
    assert_eq!(
        provider.reactor.host_address(guest_address.port()),
        Some(private_address)
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
    assert_eq!(provider.reactor.pending_guest_connection_count(), 0);
    assert_eq!(provider.reactor.retained_connector_count(), 0);
    assert_eq!(provider.reactor.host_address(guest_address.port()), None);
}

#[test]
fn reactor_drives_a_loopback_tcp_listener() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 6).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
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
    assert!(local_address.ip().is_loopback());
    assert_ne!(local_address.port(), 0);
    let private_address = provider
        .reactor
        .host_address(local_address.port())
        .expect("listening socket must have a private host endpoint");
    assert!(private_address.ip().is_loopback());
    assert_ne!(private_address.port(), 0);
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
            litebox_broker_core::socket::connect(&session, client, local_address),
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
    assert_eq!(first.local_address, local_address);
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
    assert_eq!(second.local_address, local_address);
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
