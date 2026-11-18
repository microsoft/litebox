// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_broker_core::socket as core_socket;

const REQUEST: [u8; 11] = [8, 0, 0, 0, 0xaa, 0xaa, 0, 1, 2, 3, 4];
const REPLY: [u8; 11] = [0, 0, 0xe7, 0xc7, 0x12, 0x34, 0, 1, 2, 3, 4];

fn with_echo(
    policy: &SocketPolicy,
    run: impl FnOnce(&BrokerProcess, ObjectHandle, &Receiver<(ObjectHandle, ReadinessFlags)>),
) {
    with_echo_provider(
        policy,
        Arc::new(UserlandSocketProvider::new(1, 1).unwrap()),
        run,
    );
}

fn with_echo_provider(
    policy: &SocketPolicy,
    provider: Arc<UserlandSocketProvider>,
    run: impl FnOnce(&BrokerProcess, ObjectHandle, &Receiver<(ObjectHandle, ReadinessFlags)>),
) {
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(*policy),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let handle = core_socket::create(
        &process,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::IcmpEcho,
            flags: FileOpenFlags::NONBLOCKING,
        },
        Arc::new(TestReadinessSink { published, retired }),
    )
    .unwrap();
    run(&process, handle, &publications);
}

#[cfg(target_os = "linux")]
#[test]
fn echo_filtered_batch_posts_continuation_without_publishing_read() {
    use crate::socket::echo::HOST_SCAN_BUDGET;

    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    with_echo_provider(
        &SocketPolicy::guest_network(),
        Arc::clone(&provider),
        |process, handle, publications| {
            let local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0x1234);
            assert_eq!(
                core_socket::bind(process, handle, local),
                Ok(SocketOutcome::Completed(local))
            );

            // Stand in for a ping socket with an ordinary loopback UDP socket;
            // do not watch it, so no host event can mask a lost continuation.
            let host = Socket::udp().unwrap();
            host.bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .unwrap();
            let address = host.local_address().unwrap();
            let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut unsolicited = REPLY;
            unsolicited[7] = 9;
            for _ in 0..HOST_SCAN_BUDGET {
                sender.send_to(&unsolicited, address).unwrap();
            }
            sender.send_to(&REPLY, address).unwrap();

            let peer = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 0);
            let socket = read_lock(&provider.core.registry)
                .sockets
                .values()
                .next()
                .unwrap()
                .upgrade()
                .unwrap();
            socket
                .call(|entry| {
                    entry.install_echo_test_host(host, peer, [0, 1]);
                    entry.refresh_echo().unwrap();
                    assert_eq!(entry.inbox().own, ReadinessFlags::WRITE);
                    Ok(())
                })
                .unwrap();
            // Wait for publication, not a status or receive call that could itself
            // rescan. The valid reply is immediately behind the unmatched batch.
            wait_for_readiness(publications, handle, ReadinessFlags::READ);
            let mut reply = [0; REPLY.len()];
            assert_eq!(
                receive_datagram_into(process, handle, &mut reply, ReceiveFromFlags::NONE),
                Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                    received: REPLY.len(),
                    datagram_length: REPLY.len(),
                    source_address: peer,
                }))
            );
            assert_eq!(reply, REPLY);
            assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
        },
    );
}

#[test]
fn echo_loopback_peek_truncation_and_connect() {
    with_echo(&SocketPolicy::guest_network(), |process, handle, _| {
        let local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0x1234);
        assert_eq!(
            core_socket::bind(process, handle, local),
            Ok(SocketOutcome::Completed(local))
        );
        assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
        for (ip, connected) in [(Ipv4Addr::LOCALHOST, false), (GUEST_IPV4_ADDRESS, true)] {
            let peer = SocketAddrV4::new(ip, 0);
            if connected {
                assert_eq!(
                    core_socket::connect(process, handle, peer),
                    Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
                );
            }
            let mut second = REQUEST;
            second[7] = 2;
            for request in [&REQUEST, &second] {
                assert_eq!(
                    send_datagram(
                        process,
                        handle,
                        request,
                        SendFlags::NONE,
                        (!connected).then_some(peer)
                    ),
                    Ok(SocketOutcome::Completed(request.len()))
                );
            }
            assert!(
                process
                    .check_readiness(handle)
                    .unwrap()
                    .contains(ReadinessFlags::READ)
            );
            for flags in [ReceiveFromFlags::PEEK, ReceiveFromFlags::NONE] {
                let mut short = [0xff; 8];
                assert_eq!(
                    receive_datagram_into(process, handle, &mut short, flags),
                    Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                        received: short.len(),
                        datagram_length: REPLY.len(),
                        source_address: peer,
                    }))
                );
                assert_eq!(short, REPLY[..8]);
            }
            assert!(
                process
                    .check_readiness(handle)
                    .unwrap()
                    .contains(ReadinessFlags::READ)
            );
            let mut full = [0; REPLY.len()];
            assert_eq!(
                receive_datagram_into(process, handle, &mut full, ReceiveFromFlags::NONE),
                Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                    received: REPLY.len(),
                    datagram_length: REPLY.len(),
                    source_address: peer,
                }))
            );
            let mut second_reply = REPLY;
            second_reply[7] = 2;
            second_reply[3] -= 1; // one's-complement checksum for the incremented sequence
            assert_eq!(full, second_reply);
            assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
            assert_eq!(
                receive_datagram_into(process, handle, &mut full, ReceiveFromFlags::NONE),
                Err(BrokerError::NonBlockingWouldBlock)
            );
        }
    });
}

#[test]
fn echo_drops_loopback_replies_beyond_its_queue_but_not_requests() {
    use crate::socket::echo::MAX_REPLIES;

    with_echo(&SocketPolicy::guest_network(), |process, handle, _| {
        let peer = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let mut request = REQUEST;
        for sequence in 0..=MAX_REPLIES {
            request[7] = u8::try_from(sequence).unwrap();
            assert_eq!(
                send_datagram(process, handle, &request, SendFlags::NONE, Some(peer)),
                Ok(SocketOutcome::Completed(request.len()))
            );
        }
        let mut reply = [0; REPLY.len()];
        for sequence in 0..MAX_REPLIES {
            assert_eq!(
                receive_datagram_into(process, handle, &mut reply, ReceiveFromFlags::NONE),
                Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                    received: REPLY.len(),
                    datagram_length: REPLY.len(),
                    source_address: peer,
                }))
            );
            assert_eq!(usize::from(reply[7]), sequence);
        }
        assert_eq!(
            receive_datagram_into(process, handle, &mut reply, ReceiveFromFlags::NONE),
            Err(BrokerError::NonBlockingWouldBlock)
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn echo_reports_a_host_error_once() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    with_echo_provider(
        &SocketPolicy::guest_network(),
        Arc::clone(&provider),
        |process, handle, publications| {
            let local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0x1234);
            assert_eq!(
                core_socket::bind(process, handle, local),
                Ok(SocketOutcome::Completed(local))
            );

            // Stand in for a ping socket that an ICMP error reached with a
            // UDP socket whose datagram a closed loopback port refused.
            let closed = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let std::net::SocketAddr::V4(closed_address) = closed.local_addr().unwrap() else {
                unreachable!()
            };
            drop(closed);
            let host = Socket::udp().unwrap();
            host.connect(closed_address).unwrap();
            let mut probe = REQUEST;
            let parts = [litebox_platform::buffer::RawBytes::from(
                probe.as_mut_slice(),
            )];
            host.send(RawParts::from(&parts), None).unwrap();
            let deadline = std::time::Instant::now() + TEST_TIMEOUT;
            while !host.events().unwrap().contains(SocketEvents::ERROR) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no ICMP error arrived"
                );
                std::thread::sleep(Duration::from_millis(1));
            }

            let peer = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 0);
            let socket = read_lock(&provider.core.registry)
                .sockets
                .values()
                .next()
                .unwrap()
                .upgrade()
                .unwrap();
            socket
                .call(|entry| {
                    entry.install_echo_test_host(host, peer, [0, 1]);
                    entry.refresh_echo().unwrap();
                    Ok(())
                })
                .unwrap();
            wait_for_readiness(
                publications,
                handle,
                ReadinessFlags::WRITE | ReadinessFlags::ERROR,
            );
            let mut reply = [0; REPLY.len()];
            assert_eq!(
                receive_datagram_into(process, handle, &mut reply, ReceiveFromFlags::NONE),
                Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
            );
            assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
            assert_eq!(
                receive_datagram_into(process, handle, &mut reply, ReceiveFromFlags::NONE),
                Err(BrokerError::NonBlockingWouldBlock)
            );
        },
    );
}

#[test]
fn echo_rejects_non_requests_and_unauthorized_external_destinations() {
    with_echo(&SocketPolicy::guest_network(), |process, handle, _| {
        let peer = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        for invalid in [&REQUEST[..7], &[3; 8], &[8, 1, 0, 0, 0, 0, 0, 0]] {
            assert_eq!(
                send_datagram(process, handle, invalid, SendFlags::NONE, Some(peer)),
                Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
            );
        }
        assert_eq!(
            send_datagram(
                process,
                handle,
                &REQUEST,
                SendFlags::NONE,
                Some(SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 0))
            ),
            Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
        );
        assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
    });
}

#[cfg(target_os = "linux")]
fn probe_native_loopback_echo() -> std::io::Result<()> {
    // Independent of the provider: opening a ping socket alone doesn't mean
    // the host will actually answer. Bound both directions of the probe.
    let socket: UdpSocket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::ICMPV4),
    )?
    .into();
    socket.set_write_timeout(Some(TEST_TIMEOUT))?;
    socket.set_read_timeout(Some(TEST_TIMEOUT))?;
    socket.connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    if socket.send(&REQUEST)? == REQUEST.len() {
        let mut reply = [0; 64];
        if socket.recv(&mut reply)? == REQUEST.len()
            && reply[..2] == [0, 0]
            && reply[6..REQUEST.len()] == REQUEST[6..]
        {
            return Ok(());
        }
    }
    Err(std::io::Error::other(
        "unexpected native ICMP loopback roundtrip",
    ))
}

/// Exercises a real host ping socket, which a namespace of the test's own
/// can permit without changing the host.
#[cfg(target_os = "linux")]
#[test]
fn echo_gateway_roundtrip_and_connected_reconnect() {
    in_network_namespace(
        "echo::echo_gateway_roundtrip_and_connected_reconnect",
        || {
            ip("link set lo up");
            // A new network namespace denies ping sockets to every group.
            std::fs::write("/proc/sys/net/ipv4/ping_group_range", "0 0").unwrap();
            probe_native_loopback_echo().unwrap();
            echo_gateway_roundtrip_and_connected_reconnect_with_ping_sockets();
        },
    );
}

#[cfg(target_os = "linux")]
fn echo_gateway_roundtrip_and_connected_reconnect_with_ping_sockets() {
    let rule = litebox_broker_core::IcmpEchoDestinationRule::new(
        CallerCredential::Unauthenticated,
        Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
    );
    let policy = SocketPolicy::guest_network()
        .with_icmp_echo_destination_rules(&[rule])
        .unwrap();
    with_echo(&policy, |process, handle, publications| {
        let peer = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 0);
        let local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0x1234);
        assert_eq!(
            core_socket::bind(process, handle, local),
            Ok(SocketOutcome::Completed(local))
        );
        // First send unconnected; then connect and send without a destination.
        // Neither a same-peer reconnect nor a denied reconnect may lose the unread reply.
        for connected in [false, true] {
            if connected {
                assert_eq!(
                    core_socket::connect(process, handle, peer),
                    Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
                );
            }
            assert_eq!(
                send_datagram(
                    process,
                    handle,
                    &REQUEST,
                    SendFlags::NONE,
                    (!connected).then_some(peer)
                ),
                Ok(SocketOutcome::Completed(REQUEST.len()))
            );
            wait_until_ready(process, publications, handle, ReadinessFlags::READ);
            if connected {
                assert_eq!(
                    core_socket::connect(process, handle, peer),
                    Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
                );
                let denied = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 0);
                assert_eq!(
                    core_socket::connect(process, handle, denied),
                    Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
                );
                assert_eq!(core_socket::get_name(process, handle, true), Ok(Some(peer)));
            }
            let mut reply = [0; REPLY.len()];
            assert_eq!(
                receive_datagram_into(process, handle, &mut reply, ReceiveFromFlags::NONE),
                Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                    received: REPLY.len(),
                    datagram_length: REPLY.len(),
                    source_address: peer,
                }))
            );
            assert_eq!(reply, REPLY);
        }
    });
}

/// Like a Linux ping socket, an echo socket keeps its host replies, queued
/// or still to come, when it connects elsewhere.
#[cfg(target_os = "linux")]
#[test]
fn echo_reconnect_keeps_host_replies() {
    in_network_namespace("echo::echo_reconnect_keeps_host_replies", || {
        ip("link set lo up");
        let other = Ipv4Addr::new(198, 51, 100, 1);
        ip(&format!("addr add {other}/32 dev lo"));
        std::fs::write("/proc/sys/net/ipv4/ping_group_range", "0 0").unwrap();
        let rules = [HOST_GATEWAY_IPV4_ADDRESS, other].map(|ip| {
            litebox_broker_core::IcmpEchoDestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(ip.octets()), 32).unwrap(),
            )
        });
        let policy = SocketPolicy::guest_network()
            .with_icmp_echo_destination_rules(&rules)
            .unwrap();
        with_echo(&policy, |process, handle, publications| {
            let gateway = SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, 0);
            let local = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0x1234);
            assert_eq!(
                core_socket::bind(process, handle, local),
                Ok(SocketOutcome::Completed(local))
            );
            // The provider stages one host reply at a time, so the second
            // stays queued in the host socket across the connect.
            let mut request = REQUEST;
            for sequence in 1..=2 {
                request[7] = sequence;
                assert_eq!(
                    send_datagram(process, handle, &request, SendFlags::NONE, Some(gateway)),
                    Ok(SocketOutcome::Completed(request.len()))
                );
            }
            wait_until_ready(process, publications, handle, ReadinessFlags::READ);
            assert_eq!(
                core_socket::connect(process, handle, SocketAddrV4::new(other, 0)),
                Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
            );
            for sequence in 1..=2 {
                wait_until_ready(process, publications, handle, ReadinessFlags::READ);
                let mut reply = [0; REPLY.len()];
                assert_eq!(
                    receive_datagram_into(process, handle, &mut reply, ReceiveFromFlags::NONE),
                    Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                        received: REPLY.len(),
                        datagram_length: REPLY.len(),
                        source_address: gateway,
                    }))
                );
                assert_eq!(reply[7], sequence);
            }
        });
    });
}
