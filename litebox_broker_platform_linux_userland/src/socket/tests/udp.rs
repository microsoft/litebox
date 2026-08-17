// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;

#[test]
fn udp_send_to_revalidates_trusted_destination_classification() {
    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&session, Arc::new(TestReadinessSink { published, retired }));
    let socket_id = provider
        .reactor
        .next_socket_id
        .load(Ordering::Relaxed)
        .checked_sub(1)
        .unwrap();

    assert_eq!(
        provider.reactor.request(|response| ReactorCommand::SendTo {
            id: socket_id,
            data: b"forged".to_vec(),
            destination: Some(SocketDestination::Guest {
                requested: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
            }),
            response,
        }),
        Err(BrokerError::Internal)
    );
    session.close_object_reference(socket).unwrap();
}

#[test]
fn guest_udp_readiness_failure_rolls_back_enqueue() {
    let provider = Arc::new(LinuxSocketProvider::new(2, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 1),
        provider.clone(),
    )
    .unwrap();
    let receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let sender_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(FailingReadinessSink {
        inner: TestReadinessSink { published, retired },
        fail_next_publish: Mutex::new(None),
    });
    let receiver = create_udp_socket(&receiver_session, readiness.clone());
    let receiver_address = guest_address(18100);
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let sender = create_udp_socket(&sender_session, readiness.clone());

    readiness.fail_next_publish_for(receiver);
    assert_eq!(
        send_datagram(
            &sender_session,
            sender,
            b"dropped",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    let mut data = [0; 7];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut data,
            ReceiveFromFlags::NONE,
        ),
        Err(BrokerError::WouldBlock)
    );
    readiness.assert_no_pending_publish_failure();

    assert_eq!(
        send_datagram(
            &sender_session,
            sender,
            b"queued",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(6))
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
    let sender_address = litebox_broker_core::socket::status(&sender_session, sender)
        .unwrap()
        .local_address
        .map(|address| guest_address(address.port()))
        .unwrap();

    readiness.fail_next_publish_for(receiver);
    let mut data = [0; 6];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut data,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 6,
            datagram_length: 6,
            source_address: sender_address,
        }))
    );
    assert_eq!(&data, b"queued");
    readiness.assert_no_pending_publish_failure();
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    assert!(
        !receiver_session
            .check_readiness(receiver)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
}

#[test]
fn native_udp_readiness_failure_does_not_fail_shared_reactor() {
    let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
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
    let socket = create_udp_socket(&session, readiness.clone());
    let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    external.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let external_address = socket_address_v4(external.local_addr().unwrap());
    assert_eq!(
        send_datagram(
            &session,
            socket,
            b"contact",
            SendFlags::NONE,
            Some(external_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    let mut contact = [0; 7];
    let (_, native_address) = external.recv_from(&mut contact).unwrap();
    assert_eq!(&contact, b"contact");

    readiness.fail_next_publish_matching(socket, ReadinessFlags::READ, ReadinessFlags::default());
    external.send_to(b"reply", native_address).unwrap();
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !session
        .check_readiness(socket)
        .unwrap()
        .contains(ReadinessFlags::READ)
    {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for cached native UDP readiness"
        );
        thread::sleep(Duration::from_millis(1));
    }
    readiness.wait_for_publish_failure_consumed();
    readiness.fail_next_publish_matching(socket, ReadinessFlags::default(), ReadinessFlags::READ);
    let mut reply = [0; 5];
    assert_eq!(
        receive_datagram_into(&session, socket, &mut reply, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address: external_address,
        }))
    );
    assert_eq!(&reply, b"reply");
    readiness.assert_no_pending_publish_failure();
    assert!(
        !session
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );

    external.send_to(b"first", native_address).unwrap();
    external.send_to(b"second", native_address).unwrap();
    wait_until_ready(&session, &publications, socket, ReadinessFlags::READ);
    readiness.fail_next_publish_matching(socket, ReadinessFlags::default(), ReadinessFlags::READ);
    for (index, expected) in [b"first".as_slice(), b"second".as_slice()]
        .into_iter()
        .enumerate()
    {
        let mut data = [0; 6];
        assert_eq!(
            receive_datagram_into(
                &session,
                socket,
                &mut data[..expected.len()],
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: expected.len(),
                datagram_length: expected.len(),
                source_address: external_address,
            }))
        );
        assert_eq!(&data[..expected.len()], expected);
        if index == 0 {
            assert!(
                session
                    .check_readiness(socket)
                    .unwrap()
                    .contains(ReadinessFlags::READ)
            );
        }
    }
    assert!(
        !session
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::READ)
    );
    readiness.assert_no_pending_publish_failure();
}

#[test]
fn udp_status_publication_failure_still_rearms_native_endpoint() {
    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
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
    let socket = create_udp_socket(&session, readiness.clone());
    let refused = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let refused_address = socket_address_v4(refused.local_addr().unwrap());
    drop(refused);
    assert_eq!(
        litebox_broker_core::socket::connect(&session, socket, refused_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let local_address = litebox_broker_core::socket::status(&session, socket)
        .unwrap()
        .local_address;
    assert_eq!(
        send_datagram(&session, socket, b"first", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(5))
    );
    wait_until_ready(&session, &publications, socket, ReadinessFlags::ERROR);

    readiness.fail_next_publish_matching(socket, ReadinessFlags::default(), ReadinessFlags::ERROR);
    assert_eq!(
        litebox_broker_core::socket::status(&session, socket),
        Ok(SocketStatusResponse {
            status: SocketConnectionStatus::Connected,
            local_address,
            pending_error: Some(SocketError::ConnectionRefused),
        })
    );
    assert!(
        !session
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    readiness.assert_no_pending_publish_failure();

    readiness.fail_next_publish_matching(socket, ReadinessFlags::ERROR, ReadinessFlags::default());
    assert_eq!(
        send_datagram(&session, socket, b"second", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(6))
    );
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !session
        .check_readiness(socket)
        .unwrap()
        .contains(ReadinessFlags::ERROR)
    {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the rearmed UDP error"
        );
        thread::sleep(Duration::from_millis(1));
    }
    readiness.wait_for_publish_failure_consumed();
}

#[test]
fn guest_udp_queue_pressure_drops_new_datagrams_successfully() {
    let provider = Arc::new(LinuxSocketProvider::new(2, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 1),
        provider.clone(),
    )
    .unwrap();
    let receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let sender_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let receiver = create_udp_socket(&receiver_session, readiness.clone());
    let receiver_address = guest_address(18102);
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let sender = create_udp_socket(&sender_session, readiness);
    assert_eq!(
        send_datagram(
            &sender_session,
            sender,
            &[],
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(0))
    );
    for _ in 0..MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE {
        assert_eq!(
            send_datagram(
                &sender_session,
                sender,
                b"x",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(1))
        );
    }
    assert_eq!(
        provider.reactor.udp_queued_datagram_count(),
        MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE
    );

    let mut empty = [];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut empty,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 0,
            datagram_length: 0,
            source_address: litebox_broker_core::socket::status(&sender_session, sender)
                .unwrap()
                .local_address
                .map(|address| guest_address(address.port()))
                .unwrap(),
        }))
    );
    for _ in 1..MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE {
        let mut byte = [0];
        assert!(matches!(
            receive_datagram_into(
                &receiver_session,
                receiver,
                &mut byte,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
                received: 1,
                datagram_length: 1,
                ..
            }))
        ));
        assert_eq!(byte, *b"x");
    }
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
}

#[test]
fn udp_external_peer_authorization_is_bounded_without_eviction() {
    let provider = Arc::new(LinuxSocketProvider::new(1, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
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
    let handle = create_udp_socket(&session, readiness);

    let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    first.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let first_address = socket_address_v4(first.local_addr().unwrap());
    assert_eq!(
        send_datagram(&session, handle, b"x", SendFlags::NONE, Some(first_address),),
        Ok(SocketOutcome::Completed(1))
    );
    let mut byte = [0];
    let (_, native_source) = first.recv_from(&mut byte).unwrap();
    let native_source = socket_address_v4(native_source);

    let mut peers = Vec::new();
    while peers.len() < MAX_UDP_EXTERNAL_PEERS_PER_SOCKET - 1 {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = socket_address_v4(peer.local_addr().unwrap());
        if address.port() == native_source.port() {
            continue;
        }
        assert_eq!(
            send_datagram(&session, handle, b"x", SendFlags::NONE, Some(address),),
            Ok(SocketOutcome::Completed(1))
        );
        peers.push(peer);
    }
    let overflow = loop {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        if socket.local_addr().unwrap().port() != native_source.port() {
            break socket;
        }
    };
    assert_eq!(
        send_datagram(
            &session,
            handle,
            b"overflow",
            SendFlags::NONE,
            Some(socket_address_v4(overflow.local_addr().unwrap())),
        ),
        Err(BrokerError::ResourceExhausted)
    );

    first.send_to(b"reply", native_source).unwrap();
    wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
    let mut reply = [0; 5];
    assert_eq!(
        receive_datagram_into(&session, handle, &mut reply, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address: first_address,
        }))
    );
    assert_eq!(&reply, b"reply");
}

#[test]
fn reactor_preserves_udp_datagram_semantics() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let server_address = socket_address_v4(server.local_addr().unwrap());
    let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
    let socket_policy = SocketPolicy::from_udp_destination_rules(&[
        DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address([127, 0, 0, 0]), 8).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        ),
        DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address([255, 255, 255, 255]), 32).unwrap(),
            DestinationPortRange::new(Port(9), Port(9)).unwrap(),
        ),
    ])
    .unwrap();
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider.clone(),
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let handle = litebox_broker_core::socket::create(
        &session,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
        },
        readiness.clone(),
    )
    .unwrap();

    wait_until_ready(&session, &publications, handle, ReadinessFlags::WRITE);
    let shutdown_handle = litebox_broker_core::socket::create(
        &session,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
        },
        readiness.clone(),
    )
    .unwrap();
    wait_until_ready(
        &session,
        &publications,
        shutdown_handle,
        ReadinessFlags::WRITE,
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, shutdown_handle, ShutdownMode::Both,),
        Ok(SocketOutcome::Completed(()))
    );
    let shutdown_readiness = session.check_readiness(shutdown_handle).unwrap();
    assert!(shutdown_readiness.contains(ReadinessFlags::READ));
    assert!(!shutdown_readiness.contains(ReadinessFlags::WRITE));
    assert_eq!(
        send_datagram(
            &session,
            shutdown_handle,
            b"after shutdown",
            SendFlags::NONE,
            Some(server_address),
        ),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );
    let mut shutdown_data = [0; 1];
    assert_eq!(
        receive_datagram_into(
            &session,
            shutdown_handle,
            &mut shutdown_data,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    session.close_object_reference(shutdown_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        shutdown_handle
    );
    let read_shutdown_handle = create_udp_socket(&session, readiness);
    assert_eq!(
        send_datagram(
            &session,
            read_shutdown_handle,
            b"before shutdown",
            SendFlags::NONE,
            Some(server_address),
        ),
        Ok(SocketOutcome::Completed(15))
    );
    let mut before_shutdown = [0; 15];
    let (_, read_shutdown_source) = server.recv_from(&mut before_shutdown).unwrap();
    assert_eq!(&before_shutdown, b"before shutdown");
    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, read_shutdown_handle, ShutdownMode::Read,),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        send_datagram(
            &session,
            read_shutdown_handle,
            b"write only",
            SendFlags::NONE,
            Some(server_address),
        ),
        Ok(SocketOutcome::Completed(10))
    );
    let mut write_only = [0; 10];
    let (received, source_after_read_shutdown) = server.recv_from(&mut write_only).unwrap();
    assert_eq!(received, write_only.len());
    assert_eq!(&write_only, b"write only");
    assert_eq!(source_after_read_shutdown, read_shutdown_source);
    assert_eq!(
        receive_datagram_into(
            &session,
            read_shutdown_handle,
            &mut shutdown_data,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    session
        .close_object_reference(read_shutdown_handle)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        read_shutdown_handle
    );

    assert_eq!(
        send_datagram(
            &session,
            handle,
            b"denied",
            SendFlags::NONE,
            Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53)),
        ),
        Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
    );
    assert_eq!(
        send_datagram(
            &session,
            handle,
            b"implicit bind",
            SendFlags::NONE,
            Some(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9)),
        ),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );
    let implicitly_bound = litebox_broker_core::socket::status(&session, handle)
        .unwrap()
        .local_address
        .unwrap();
    assert!(implicitly_bound.ip().is_unspecified());
    assert_ne!(implicitly_bound.port(), 0);
    let mut no_data = [0; 1];
    assert_eq!(
        receive_datagram_into(&session, handle, &mut no_data, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        send_datagram(
            &session,
            handle,
            b"ping",
            SendFlags::NONE,
            Some(server_address),
        ),
        Ok(SocketOutcome::Completed(4))
    );
    let mut packet = vec![0; MAX_UDP_DATAGRAM_SIZE as usize];
    let (received, source) = server.recv_from(&mut packet).unwrap();
    assert_eq!(&packet[..received], b"ping");
    let source = socket_address_v4(source);
    let status = litebox_broker_core::socket::status(&session, handle).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Unconnected);
    let local_address = status.local_address.unwrap();
    assert!(local_address.ip().is_unspecified());
    assert_eq!(local_address, implicitly_bound);
    assert!(source.ip().is_loopback());

    server.send_to(&[], source).unwrap();
    wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
    let mut zero = [];
    assert_eq!(
        receive_datagram_into(&session, handle, &mut zero, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 0,
            datagram_length: 0,
            source_address: server_address,
        }))
    );
    assert_eq!(
        receive_datagram_into(&session, handle, &mut zero, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );

    server.send_to(b"abcdef", source).unwrap();
    wait_until_ready(&session, &publications, handle, ReadinessFlags::READ);
    let mut peeked = [0; 3];
    assert_eq!(
        receive_datagram_into(&session, handle, &mut peeked, ReceiveFromFlags::PEEK,),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 3,
            datagram_length: 6,
            source_address: server_address,
        }))
    );
    assert_eq!(&peeked, b"abc");
    peeked.fill(0);
    assert_eq!(
        receive_datagram_into(&session, handle, &mut peeked, ReceiveFromFlags::PEEK,),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 3,
            datagram_length: 6,
            source_address: server_address,
        }))
    );
    assert_eq!(&peeked, b"abc");
    let mut truncated = [0; 4];
    assert_eq!(
        receive_datagram_into(&session, handle, &mut truncated, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 4,
            datagram_length: 6,
            source_address: server_address,
        }))
    );
    assert_eq!(&truncated, b"abcd");
    assert_eq!(
        receive_datagram_into(&session, handle, &mut no_data, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );

    assert_eq!(
        litebox_broker_core::socket::connect(&session, handle, server_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let connected_status = litebox_broker_core::socket::status(&session, handle).unwrap();
    assert_eq!(connected_status.status, SocketConnectionStatus::Connected);
    assert_eq!(
        connected_status.local_address,
        Some(guest_address(local_address.port()))
    );
    let maximum = vec![0x5a; MAX_UDP_DATAGRAM_SIZE as usize];
    assert_eq!(
        send_datagram(&session, handle, &maximum, SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(maximum.len()))
    );
    let (received, connected_source) = server.recv_from(&mut packet).unwrap();
    assert_eq!(received, maximum.len());
    assert_eq!(&packet[..received], maximum.as_slice());
    let connected_source = socket_address_v4(connected_source);
    assert!(connected_source.ip().is_loopback());
    assert_eq!(connected_source, source);
    assert_eq!(provider.reactor.udp_native_endpoint_count(), 1);
    assert_eq!(
        litebox_broker_core::socket::connect(
            &session,
            handle,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 9),
        ),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );
    assert_eq!(
        send_datagram(&session, handle, b"old peer", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(8))
    );
    let (received, preserved_source) = server.recv_from(&mut packet).unwrap();
    assert_eq!(&packet[..received], b"old peer");
    assert_eq!(socket_address_v4(preserved_source), source);

    let refused_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let refused_address = socket_address_v4(refused_socket.local_addr().unwrap());
    drop(refused_socket);
    assert_eq!(
        litebox_broker_core::socket::connect(&session, handle, refused_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&session, handle, b"refused", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(7))
    );
    wait_until_ready(&session, &publications, handle, ReadinessFlags::ERROR);
    assert_eq!(
        send_datagram(
            &session,
            handle,
            b"broadcast",
            SendFlags::NONE,
            Some(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9)),
        ),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );
    let send_error_status = litebox_broker_core::socket::status(&session, handle).unwrap();
    assert_eq!(
        send_error_status.pending_error,
        Some(SocketError::ConnectionRefused)
    );
    assert!(
        !session
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    assert_eq!(
        send_datagram(&session, handle, b"refused again", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(13))
    );
    wait_until_ready(&session, &publications, handle, ReadinessFlags::ERROR);
    assert_eq!(
        litebox_broker_core::socket::connect(
            &session,
            handle,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 9),
        ),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );
    let refused_status = litebox_broker_core::socket::status(&session, handle).unwrap();
    assert_eq!(
        refused_status.pending_error,
        Some(SocketError::ConnectionRefused)
    );
    assert!(
        !session
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    assert_eq!(
        litebox_broker_core::socket::connect(&session, handle, server_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );

    assert_eq!(
        litebox_broker_core::socket::shutdown(&session, handle, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        litebox_broker_core::socket::connect(&session, handle, server_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert!(
        !session
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    assert_eq!(
        send_datagram(&session, handle, b"after shutdown", SendFlags::NONE, None,),
        Ok(SocketOutcome::Failed(SocketError::Other))
    );

    session.close_object_reference(handle).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
}

#[test]
fn guest_udp_namespace_routes_across_sessions_and_filters_private_endpoints() {
    let provider = Arc::new(LinuxSocketProvider::new(6, 3).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 6, 3),
        provider.clone(),
    )
    .unwrap();
    let receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let sender_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });

    let shadowed_host_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    shadowed_host_socket
        .set_nonblocking(true)
        .expect("failed to make shadow socket nonblocking");
    let guest_port = shadowed_host_socket.local_addr().unwrap().port();
    let receiver_guest_address = guest_address(guest_port);
    let receiver = create_udp_socket(&receiver_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_guest_address,),
        Ok(SocketOutcome::Completed(receiver_guest_address))
    );
    assert_eq!(
        provider.reactor.host_address(receiver_guest_address.port()),
        None
    );
    assert_eq!(provider.reactor.udp_native_endpoint_count(), 0);
    let tcp_same_port = create_socket(&sender_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&sender_session, tcp_same_port, receiver_guest_address,),
        Ok(SocketOutcome::Completed(receiver_guest_address))
    );

    let sender = create_udp_socket(&sender_session, readiness.clone());
    assert_eq!(
        send_datagram(
            &sender_session,
            sender,
            b"request",
            SendFlags::NONE,
            Some(receiver_guest_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    let sender_guest_address = litebox_broker_core::socket::status(&sender_session, sender)
        .unwrap()
        .local_address
        .expect("implicit UDP bind missing");
    let sender_source_address = guest_address(sender_guest_address.port());
    wait_until_ready(
        &receiver_session,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    let mut request = [0; 7];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut request,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 7,
            datagram_length: 7,
            source_address: sender_source_address,
        }))
    );
    assert_eq!(&request, b"request");

    assert_eq!(
        send_datagram(
            &receiver_session,
            receiver,
            b"response",
            SendFlags::NONE,
            Some(sender_source_address),
        ),
        Ok(SocketOutcome::Completed(8))
    );
    wait_until_ready(&sender_session, &publications, sender, ReadinessFlags::READ);
    let mut response = [0; 8];
    assert_eq!(
        receive_datagram_into(
            &sender_session,
            sender,
            &mut response,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 8,
            datagram_length: 8,
            source_address: receiver_guest_address,
        }))
    );
    assert_eq!(&response, b"response");
    sender_session.close_object_reference(sender).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), sender);

    assert_eq!(
        shadowed_host_socket
            .recv_from(&mut [0; 1])
            .unwrap_err()
            .kind(),
        ErrorKind::WouldBlock
    );

    let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    external.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let external_address = socket_address_v4(external.local_addr().unwrap());
    assert_eq!(
        send_datagram(
            &receiver_session,
            receiver,
            b"contact",
            SendFlags::NONE,
            Some(external_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    let mut external_packet = [0; 7];
    let (_, receiver_source) = external.recv_from(&mut external_packet).unwrap();
    assert_eq!(&external_packet, b"contact");
    assert_eq!(provider.reactor.udp_native_endpoint_count(), 1);
    assert!(
        provider
            .reactor
            .udp_native_receive_buffer_size(receiver_guest_address.port())
            .is_some_and(|size| size <= MAX_UDP_NATIVE_RECEIVE_BUFFER)
    );
    let receiver_private_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_source.port());
    let probe = create_udp_socket(&sender_session, readiness);
    let probe_guest_port = (1_u16..=u16::MAX)
        .find(|port| *port != receiver_guest_address.port() && *port != receiver_source.port())
        .unwrap();
    let probe_guest_address = guest_address(probe_guest_port);
    assert_eq!(
        litebox_broker_core::socket::bind(&sender_session, probe, probe_guest_address,),
        Ok(SocketOutcome::Completed(probe_guest_address))
    );
    assert_eq!(
        send_datagram(
            &sender_session,
            probe,
            b"private",
            SendFlags::NONE,
            Some(receiver_private_address),
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    let receiver_private_alias =
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), receiver_source.port());
    assert_eq!(
        send_datagram(
            &sender_session,
            probe,
            b"private alias",
            SendFlags::NONE,
            Some(receiver_private_alias),
        ),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    external.send_to(b"reply", receiver_source).unwrap();
    wait_until_ready(
        &receiver_session,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    assert_eq!(
        send_datagram(
            &sender_session,
            probe,
            b"guest",
            SendFlags::NONE,
            Some(receiver_guest_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let mut reply = [0; 5];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut reply,
            ReceiveFromFlags::PEEK,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address: external_address,
        }))
    );
    assert_eq!(&reply, b"reply");
    reply.fill(0);
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut reply,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address: external_address,
        }))
    );
    assert_eq!(&reply, b"reply");
    reply.fill(0);
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut reply,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address: probe_guest_address,
        }))
    );
    assert_eq!(&reply, b"guest");
}

#[test]
fn udp_endpoint_staging_error_rolls_back_external_peer_reservation() {
    let provider = Arc::new(LinuxSocketProvider::new(2, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider.clone(),
    )
    .unwrap();
    let session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let socket = create_udp_socket(&session, readiness);
    let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let external_address = socket_address_v4(external.local_addr().unwrap());

    provider.reactor.exhaust_udp_endpoint_generation();
    assert_eq!(
        send_datagram(
            &session,
            socket,
            b"not sent",
            SendFlags::NONE,
            Some(external_address),
        ),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(provider.reactor.udp_external_peer_count(), 0);
    assert_eq!(provider.reactor.udp_native_endpoint_count(), 0);

    session.close_object_reference(socket).unwrap();
}

#[test]
fn stale_udp_datagrams_are_not_relabelled_after_guest_port_reuse() {
    let provider = Arc::new(LinuxSocketProvider::new(5, 3).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 5, 3),
        provider.clone(),
    )
    .unwrap();
    let receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let source_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let receiver_port_guard = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let source_port_guard = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let receiver_port = receiver_port_guard.local_addr().unwrap().port();
    let source_port = source_port_guard.local_addr().unwrap().port();
    let receiver_address = guest_address(receiver_port);
    let source_address = guest_address(source_port);

    let receiver = create_udp_socket(&receiver_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let source = create_udp_socket(&source_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&source_session, source, source_address),
        Ok(SocketOutcome::Completed(source_address))
    );
    assert_eq!(provider.reactor.udp_native_endpoint_count(), 0);
    assert_eq!(
        send_datagram(
            &source_session,
            source,
            b"old",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(3))
    );
    wait_until_ready(
        &receiver_session,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);

    source_session.close_object_reference(source).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), source);

    let replacement = create_udp_socket(&source_session, readiness);
    let replacement_address = source_address;
    assert_eq!(
        litebox_broker_core::socket::bind(&source_session, replacement, replacement_address,),
        Ok(SocketOutcome::Completed(replacement_address))
    );
    assert_eq!(
        send_datagram(
            &source_session,
            replacement,
            b"fresh",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );

    let mut payload = [0; 5];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 3,
            datagram_length: 3,
            source_address,
        }))
    );
    assert_eq!(&payload[..3], b"old");
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address: replacement_address,
        }))
    );
    assert_eq!(&payload, b"fresh");
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
}

#[test]
fn udp_queued_datagrams_survive_source_session_teardown() {
    let provider = Arc::new(LinuxSocketProvider::new(3, 1).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(6, 0, 3, 1),
        provider.clone(),
    )
    .unwrap();
    let source_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let first_receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let second_receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let replacement_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let first_address = guest_address(18082);
    let second_address = guest_address(18083);
    let first_receiver = create_udp_socket(&first_receiver_session, readiness.clone());
    let second_receiver = create_udp_socket(&second_receiver_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&first_receiver_session, first_receiver, first_address,),
        Ok(SocketOutcome::Completed(first_address))
    );
    assert_eq!(
        litebox_broker_core::socket::bind(
            &second_receiver_session,
            second_receiver,
            second_address,
        ),
        Ok(SocketOutcome::Completed(second_address))
    );
    let source = create_udp_socket(&source_session, readiness.clone());

    assert_eq!(
        send_datagram(
            &source_session,
            source,
            b"first",
            SendFlags::NONE,
            Some(first_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let source_address = litebox_broker_core::socket::status(&source_session, source)
        .unwrap()
        .local_address
        .map(|address| guest_address(address.port()))
        .expect("implicit UDP source bind missing");
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
    assert_eq!(
        send_datagram(
            &source_session,
            source,
            b"second",
            SendFlags::NONE,
            Some(second_address),
        ),
        Ok(SocketOutcome::Completed(6))
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 2);
    wait_until_ready(
        &first_receiver_session,
        &publications,
        first_receiver,
        ReadinessFlags::READ,
    );
    let mut payload = [0; 6];
    assert_eq!(
        receive_datagram_into(
            &first_receiver_session,
            first_receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address,
        }))
    );
    assert_eq!(&payload[..5], b"first");
    assert_eq!(
        receive_datagram_into(
            &first_receiver_session,
            first_receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
    wait_until_ready(
        &second_receiver_session,
        &publications,
        second_receiver,
        ReadinessFlags::READ,
    );
    drop(source_session);
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), source);
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);

    let replacement = create_udp_socket(&replacement_session, readiness);
    assert_eq!(
        receive_datagram_into(
            &second_receiver_session,
            second_receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 6,
            datagram_length: 6,
            source_address,
        }))
    );
    assert_eq!(&payload, b"second");
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);

    replacement_session
        .close_object_reference(replacement)
        .unwrap();
}

#[test]
fn connected_guest_udp_enforces_barriers_peek_and_peer_generations() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 2),
        provider.clone(),
    )
    .unwrap();
    let first_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let second_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let expected_first_address = guest_address(18080);
    let second_address = guest_address(18081);
    let second = create_udp_socket(&second_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&second_session, second, second_address),
        Ok(SocketOutcome::Completed(second_address))
    );

    let first = create_udp_socket(&first_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&first_session, first, expected_first_address,),
        Ok(SocketOutcome::Completed(expected_first_address))
    );
    assert_eq!(
        send_datagram(
            &second_session,
            second,
            b"stale",
            SendFlags::NONE,
            Some(expected_first_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    wait_until_ready(&first_session, &publications, first, ReadinessFlags::READ);
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 1);
    assert_eq!(
        litebox_broker_core::socket::connect(&first_session, first, second_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    let mut stale = [0; 5];
    assert_eq!(
        receive_datagram_into(&first_session, first, &mut stale, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );
    let first_address = litebox_broker_core::socket::status(&first_session, first)
        .unwrap()
        .local_address
        .expect("connected UDP socket lost its local address");
    assert_eq!(first_address, expected_first_address);
    assert_eq!(
        send_datagram(&first_session, first, b"one", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(3))
    );
    wait_until_ready(&second_session, &publications, second, ReadinessFlags::READ);
    let mut first_payload = [0; 3];
    assert_eq!(
        receive_datagram_into(
            &second_session,
            second,
            &mut first_payload,
            ReceiveFromFlags::PEEK,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 3,
            datagram_length: 3,
            source_address: first_address,
        }))
    );
    assert_eq!(&first_payload, b"one");
    first_payload.fill(0);
    assert_eq!(
        receive_datagram_into(
            &second_session,
            second,
            &mut first_payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 3,
            datagram_length: 3,
            source_address: first_address,
        }))
    );
    assert_eq!(&first_payload, b"one");

    assert_eq!(
        litebox_broker_core::socket::connect(&second_session, second, first_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&second_session, second, b"two", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(3))
    );
    wait_until_ready(&first_session, &publications, first, ReadinessFlags::READ);
    let mut second_payload = [0; 3];
    assert_eq!(
        receive_datagram_into(
            &first_session,
            first,
            &mut second_payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 3,
            datagram_length: 3,
            source_address: second_address,
        }))
    );
    assert_eq!(&second_payload, b"two");

    second_session.close_object_reference(second).unwrap();
    let replacement = create_udp_socket(&second_session, readiness);
    assert_eq!(
        litebox_broker_core::socket::bind(&second_session, replacement, second_address),
        Ok(SocketOutcome::Completed(second_address))
    );
    assert_eq!(
        send_datagram(&first_session, first, b"stale peer", SendFlags::NONE, None),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
}

#[test]
fn externally_connected_udp_preserves_guest_routing_identity() {
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
    let external = UdpSocket::bind((local_ip, 0)).unwrap();
    external.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let external_address = socket_address_v4(external.local_addr().unwrap());
    let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
    let policy = SocketPolicy::from_udp_destination_rules(&[
        DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address([127, 0, 0, 0]), 8).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        ),
        DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(guest_ipv4_address().octets()), 32).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        ),
        DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(local_ip.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        ),
    ])
    .unwrap();
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(policy),
        BrokerCoreLimits::new_with_all_limits(6, 0, 4, 2),
        provider.clone(),
    )
    .unwrap();
    let source_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let receiver_address = guest_address(18084);
    let receiver = create_udp_socket(&receiver_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let source = create_udp_socket(&source_session, readiness);
    assert_eq!(
        litebox_broker_core::socket::connect(&source_session, source, external_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let source_address = litebox_broker_core::socket::status(&source_session, source)
        .unwrap()
        .local_address
        .expect("connected UDP source address missing");
    assert_eq!(source_address.ip(), &guest_ipv4_address());
    let internal_source_address = source_address;

    assert_eq!(
        send_datagram(&source_session, source, b"external", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(8))
    );
    let mut external_payload = [0; 8];
    let (external_received, _) = external.recv_from(&mut external_payload).unwrap();
    assert_eq!(external_received, external_payload.len());
    assert_eq!(&external_payload, b"external");

    assert_eq!(
        send_datagram(
            &source_session,
            source,
            b"guest",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    wait_until_ready(
        &receiver_session,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    let mut guest_payload = [0; 5];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut guest_payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 5,
            datagram_length: 5,
            source_address: internal_source_address,
        }))
    );
    assert_eq!(&guest_payload, b"guest");
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut guest_payload,
            ReceiveFromFlags::NONE,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    assert_eq!(
        send_datagram(
            &receiver_session,
            receiver,
            b"reply",
            SendFlags::NONE,
            Some(internal_source_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
    assert_eq!(
        receive_datagram_into(
            &source_session,
            source,
            &mut guest_payload,
            ReceiveFromFlags::NONE,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(provider.reactor.udp_queued_datagram_count(), 0);
}

#[test]
fn guest_connected_udp_drains_native_ingress_without_delivering_it() {
    let provider = Arc::new(LinuxSocketProvider::new(4, 2).unwrap());
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::Ipv4Loopback),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 2),
        provider.clone(),
    )
    .unwrap();
    let receiver_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let sender_session = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let receiver_address = guest_address(guest_port);
    let receiver = create_udp_socket(&receiver_session, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_session, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let sender = create_udp_socket(&sender_session, readiness);
    assert_eq!(
        send_datagram(
            &sender_session,
            sender,
            b"warmup",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(6))
    );
    wait_for_readiness(&publications, receiver, ReadinessFlags::READ);
    let source_address = litebox_broker_core::socket::status(&sender_session, sender)
        .unwrap()
        .local_address
        .map(|address| guest_address(address.port()))
        .unwrap();
    let mut warmup = [0; 6];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut warmup,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 6,
            datagram_length: 6,
            source_address,
        }))
    );
    assert_eq!(&warmup, b"warmup");
    assert_eq!(
        litebox_broker_core::socket::connect(&receiver_session, receiver, source_address,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );

    let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    attacker.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let attacker_address = socket_address_v4(attacker.local_addr().unwrap());
    assert_eq!(
        send_datagram(
            &receiver_session,
            receiver,
            b"contact",
            SendFlags::NONE,
            Some(attacker_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    let mut contact = [0; 7];
    let (_, receiver_native_address) = attacker.recv_from(&mut contact).unwrap();
    assert_eq!(&contact, b"contact");
    assert_eq!(provider.reactor.udp_native_endpoint_count(), 1);
    let (ready, wait_until_ready) = sync_channel(1);
    let (proceed, wait_to_proceed) = sync_channel(1);
    let (response, receive_response) = sync_channel(1);
    provider
        .reactor
        .commands
        .send(ReactorCommand::ExerciseUdpReceiveRejectionCap {
            guest_port,
            ready,
            proceed: wait_to_proceed,
            response,
        })
        .unwrap();
    provider.reactor.signal().unwrap();
    wait_until_ready.recv_timeout(TEST_TIMEOUT).unwrap();
    for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
        attacker.send_to(b"x", receiver_native_address).unwrap();
    }
    let sentinel = b"sentinel";
    attacker.send_to(sentinel, receiver_native_address).unwrap();
    proceed.send(()).unwrap();
    assert_eq!(
        receive_response.recv_timeout(TEST_TIMEOUT).unwrap(),
        Ok((false, sentinel.len()))
    );
    let deadline = Instant::now() + TEST_TIMEOUT;
    while provider.reactor.udp_native_head_datagram_bytes(guest_port) != 0 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the rearmed native UDP drain"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        send_datagram(
            &sender_session,
            sender,
            b"ok",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(2))
    );
    wait_for_readiness(&publications, receiver, ReadinessFlags::READ);
    let mut payload = [0; 2];
    assert_eq!(
        receive_datagram_into(
            &receiver_session,
            receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(ReceivedPlatformDatagram {
            received: 2,
            datagram_length: 2,
            source_address,
        }))
    );
    assert_eq!(&payload, b"ok");
}
