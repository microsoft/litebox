// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;

fn gateway_udp_policy() -> SocketPolicy {
    SocketPolicy::guest_network()
        .with_udp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        )])
        .unwrap()
}

/// A reserved documentation address, to which a connect or send only selects
/// a route.
const REMOTE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9);

/// Allows UDP to the gateway and to [`REMOTE`].
fn gateway_and_remote_udp_policy() -> SocketPolicy {
    SocketPolicy::guest_network()
        .with_udp_destination_rules(&[
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(REMOTE.ip().octets()), 32).unwrap(),
                DestinationPortRange::new(Port(REMOTE.port()), Port(REMOTE.port())).unwrap(),
            ),
        ])
        .unwrap()
}

/// Reports whether the host routes to other hosts, as CI runners must.
fn routes_to_other_hosts() -> bool {
    let routable = non_loopback_local_ipv4().is_some();
    if std::env::var_os("CI").is_some() {
        assert!(
            routable,
            "CI runner must provide a routable non-loopback IPv4 address"
        );
    }
    routable
}

/// Runs this module's test `name` again in a network namespace of its own,
/// where it runs `child`, which may change the host's addresses and
/// settings. Skips the test where unprivileged namespaces are unavailable,
/// except on CI runners, which must provide them.
#[cfg(target_os = "linux")]
fn in_network_namespace(name: &str, child: impl FnOnce()) {
    const CHILD_ENV: &str = "LITEBOX_TEST_NETWORK_NAMESPACE";
    if std::env::var_os(CHILD_ENV).is_some() {
        child();
        return;
    }
    let output = std::process::Command::new("unshare")
        .args(["--map-root-user", "--net"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("socket::tests::udp::{name}"),
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output();
    let output = match output {
        // A test that ran exits with 0 or, failing, 101.
        Ok(output) if matches!(output.status.code(), Some(0 | 101)) => output,
        result => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI runner must provide unprivileged network namespaces \
                 (see kernel.apparmor_restrict_unprivileged_userns): {result:?}"
            );
            eprintln!("skipped: no unprivileged network namespace: {result:?}");
            return;
        }
    };
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{output:?}"
    );
}

/// Runs `ip` with the space-separated `args`.
#[cfg(target_os = "linux")]
fn ip(args: &str) {
    let status = std::process::Command::new("ip")
        .args(args.split(' '))
        .status()
        .unwrap();
    assert!(status.success(), "ip {args}: {status}");
}

/// A host address is local though its route selects another source, as
/// Linux's route to a secondary address does, and a remote address stays
/// remote though `ip_nonlocal_bind` lets a socket bind it.
#[cfg(target_os = "linux")]
#[test]
fn host_addresses_are_local_by_ownership() {
    in_network_namespace("host_addresses_are_local_by_ownership", || {
        use crate::socket::udp::is_local_ipv4_address;

        let secondary = Ipv4Addr::new(198, 51, 100, 2);
        ip("link set lo up");
        ip("addr add 198.51.100.1/24 dev lo");
        ip("addr add 198.51.100.2/24 dev lo");
        std::fs::write("/proc/sys/net/ipv4/ip_nonlocal_bind", "1").unwrap();
        HostSocket::udp()
            .unwrap()
            .bind(SocketAddrV4::new(*REMOTE.ip(), 0))
            .unwrap();
        assert!(is_local_ipv4_address(secondary));
        assert!(!is_local_ipv4_address(*REMOTE.ip()));
    });
}

/// A reconnect to a destination whose route selects another source address
/// moves the native endpoint to that source, to which a host service bound to
/// the wildcard address replies from the connected peer.
#[cfg(target_os = "linux")]
#[test]
fn udp_reconnect_sends_from_the_route_source() {
    in_network_namespace("udp_reconnect_sends_from_the_route_source", || {
        ip("link set lo up");
        ip("addr add 198.51.100.1/24 dev lo");
        ip("addr add 203.0.113.1/24 dev lo");
        let rule = |network| {
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(network), 24).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            )
        };
        let socket_policy = SocketPolicy::guest_network()
            .with_udp_destination_rules(&[rule([198, 51, 100, 0]), rule([203, 0, 113, 0])])
            .unwrap();
        let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
        let broker = test_broker_core(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(socket_policy),
            BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
            provider,
        )
        .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let (published, publications) = channel();
        let (retired, _retirements) = channel();
        let socket =
            create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
        let host = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let service = SocketAddrV4::new(
            Ipv4Addr::new(203, 0, 113, 1),
            host.local_addr().unwrap().port(),
        );

        // Linux fixes the endpoint's source address to 198.51.100.1 here.
        assert_eq!(
            litebox_broker_core::socket::connect(
                &process,
                socket,
                SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 9),
            ),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert_eq!(
            litebox_broker_core::socket::connect(&process, socket, service),
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
        );
        assert_eq!(
            send_datagram(&process, socket, b"request", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(7))
        );
        let mut payload = [0; 7];
        let (_, host_source) = host.recv_from(&mut payload).unwrap();
        assert_eq!(&payload, b"request");
        assert_eq!(socket_address_v4(host_source).ip(), service.ip());
        host.send_to(b"reply", host_source).unwrap();
        wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
        let mut reply = [0; 5];
        assert_eq!(
            receive_datagram_into(&process, socket, &mut reply, ReceiveFromFlags::NONE),
            Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                received: 5,
                datagram_length: 5,
                source_address: service,
            }))
        );
        assert_eq!(&reply, b"reply");
    });
}

#[test]
fn udp_gateway_translates_sources_filters_spoofing_and_reuses_endpoint() {
    let native_ip = non_loopback_local_ipv4();
    if std::env::var_os("CI").is_some() {
        assert!(
            native_ip.is_some(),
            "CI runner must provide a routable non-loopback IPv4 address"
        );
    }
    let Some(native_ip) = native_ip else {
        return;
    };
    // Both peers are host-local, and each needs an allowed socket.
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let socket_policy = SocketPolicy::guest_network()
        .with_udp_destination_rules(&[
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(native_ip.octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
        ])
        .unwrap();
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = UdpSocket::bind((native_ip, 0)).unwrap();
    let first_host_address = socket_address_v4(first.local_addr().unwrap());
    let unauthorized =
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), first_host_address.port())).unwrap();
    first.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    second.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let first_gateway = gateway_address(first_host_address);
    let second_native = socket_address_v4(second.local_addr().unwrap());

    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"first",
            SendFlags::NONE,
            Some(first_gateway),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let mut payload = [0; 6];
    let (_, host_source) = first.recv_from(&mut payload).unwrap();
    assert_eq!(&payload[..5], b"first");
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);

    unauthorized.send_to(b"spoof", host_source).unwrap();
    first.send_to(b"reply", host_source).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    payload.fill(0);
    assert_eq!(
        receive_datagram_into(&process, socket, &mut payload[..5], ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: first_gateway,
        }))
    );
    assert_eq!(&payload[..5], b"reply");

    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"second",
            SendFlags::NONE,
            Some(second_native),
        ),
        Ok(SocketOutcome::Completed(6))
    );
    payload.fill(0);
    let (_, reused_source) = second.recv_from(&mut payload).unwrap();
    assert_eq!(&payload, b"second");
    assert_eq!(reused_source.port(), host_source.port());
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);

    second.send_to(b"native", reused_source).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    payload.fill(0);
    assert_eq!(
        receive_datagram_into(&process, socket, &mut payload[..6], ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 6,
            datagram_length: 6,
            source_address: second_native,
        }))
    );
    assert_eq!(&payload, b"native");
}

#[test]
fn connected_udp_gateway_preserves_guest_visible_mapping() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let host = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let gateway = gateway_address(socket_address_v4(host.local_addr().unwrap()));

    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        *litebox_broker_core::socket::status(&process, socket)
            .unwrap()
            .local_address
            .unwrap()
            .ip(),
        GUEST_IPV4_ADDRESS
    );
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
    assert_eq!(
        send_datagram(&process, socket, b"request", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    let mut payload = [0; 7];
    let (_, host_source) = host.recv_from(&mut payload).unwrap();
    assert_eq!(&payload, b"request");

    host.send_to(b"response", host_source).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    let mut response = [0; 8];
    assert_eq!(
        receive_datagram_into(&process, socket, &mut response, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 8,
            datagram_length: 8,
            source_address: gateway,
        }))
    );
    assert_eq!(&response, b"response");
}

#[test]
fn udp_reconnects_between_the_gateway_and_another_host_keep_gateway_replies() {
    if !routes_to_other_hosts() {
        return;
    }
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_and_remote_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    // A service bound to the wildcard address replies from the address the
    // route to the endpoint's source selects.
    let host = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let gateway = gateway_address(socket_address_v4(host.local_addr().unwrap()));

    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // Linux fixes the endpoint's source address to loopback at this connect.
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, REMOTE),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // And to a non-loopback address at the previous one.
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
    assert_eq!(
        send_datagram(&process, socket, b"request", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    let mut payload = [0; 7];
    let (_, host_source) = host.recv_from(&mut payload).unwrap();
    assert_eq!(&payload, b"request");
    assert!(host_source.ip().is_loopback(), "{host_source}");
    host.send_to(b"reply", host_source).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    let mut reply = [0; 5];
    assert_eq!(
        receive_datagram_into(&process, socket, &mut reply, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: gateway,
        }))
    );
    assert_eq!(&reply, b"reply");

    process.close_object_reference(socket).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), socket);
    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
}

#[test]
fn udp_sends_past_a_connected_gateway_reach_another_host() {
    if !routes_to_other_hosts() {
        return;
    }
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_and_remote_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let host = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let gateway = gateway_address(socket_address_v4(host.local_addr().unwrap()));

    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // Linux fixes the endpoint's source address to loopback at this connect.
    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"elsewhere",
            SendFlags::NONE,
            Some(REMOTE)
        ),
        Ok(SocketOutcome::Completed(9))
    );
    assert_eq!(
        send_datagram(&process, socket, b"request", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    let mut payload = [0; 7];
    let (_, host_source) = host.recv_from(&mut payload).unwrap();
    assert_eq!(&payload, b"request");
    assert!(host_source.ip().is_loopback(), "{host_source}");
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
}

/// A connected socket reports no ICMP error that a send past its peer
/// causes.
#[test]
fn connected_udp_ignores_errors_of_sends_past_its_peer() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let host = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let gateway = gateway_address(socket_address_v4(host.local_addr().unwrap()));
    let closed = gateway_address(socket_address_v4(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap(),
    ));

    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&process, socket, b"request", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    let mut payload = [0; 7];
    let (_, host_source) = host.recv_from(&mut payload).unwrap();
    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"elsewhere",
            SendFlags::NONE,
            Some(closed)
        ),
        Ok(SocketOutcome::Completed(9))
    );
    host.send_to(b"reply", host_source).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    let mut reply = [0; 5];
    assert_eq!(
        receive_datagram_into(&process, socket, &mut reply, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: gateway,
        }))
    );
    assert_eq!(&reply, b"reply");
    assert_eq!(
        send_datagram(&process, socket, b"request", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    assert_eq!(host.recv_from(&mut payload).unwrap().1, host_source);
}

/// A reconnect discards the datagrams queued before it, even behind more
/// ICMP errors of sends past the peer than one receive drops.
#[test]
fn udp_reconnect_discards_datagrams_behind_errors_of_sends_past_its_peer() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let host = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let gateway = gateway_address(socket_address_v4(host.local_addr().unwrap()));
    let closed = gateway_address(socket_address_v4(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap(),
    ));

    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&process, socket, b"request", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    let (_, host_source) = host.recv_from(&mut [0; 7]).unwrap();
    // An unread datagram leaves the endpoint unwatched for input, so the
    // event thread drops none of the errors queued behind it.
    host.send_to(b"early", host_source).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    for _ in 0..16 {
        assert_eq!(
            send_datagram(
                &process,
                socket,
                b"elsewhere",
                SendFlags::NONE,
                Some(closed)
            ),
            Ok(SocketOutcome::Completed(9))
        );
    }
    host.send_to(b"stale", host_source).unwrap();
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );

    host.send_to(b"fresh", host_source).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    let mut reply = [0; 5];
    assert_eq!(
        receive_datagram_into(&process, socket, &mut reply, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: gateway,
        }))
    );
    assert_eq!(&reply, b"fresh");
}

/// An external UDP socket sends from and receives and peeks into a buffer's
/// own raw parts, keeping datagrams whole.
#[test]
fn external_udp_transfers_use_raw_parts() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let host = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let gateway = gateway_address(socket_address_v4(host.local_addr().unwrap()));
    let mut data = TEST_MESSAGE;
    assert_eq!(
        litebox_broker_core::socket::send_to(
            &process,
            socket,
            &TestBuffer::new(&mut data, Some(TEST_PART_LENGTH)),
            SendFlags::NONE,
            Some(gateway),
        ),
        Ok(SocketOutcome::Completed(TEST_MESSAGE.len()))
    );
    let mut sent = [0; TEST_MESSAGE.len() + 1];
    let (length, host_source) = host.recv_from(&mut sent).unwrap();
    assert_eq!(sent[..length], TEST_MESSAGE);

    host.send_to(&TEST_MESSAGE, host_source).unwrap();
    receive_test_message(&process, socket, &publications, gateway);
}

/// An internal UDP socket sends from and receives and peeks into a buffer's
/// own raw parts, keeping datagrams whole.
#[test]
fn internal_udp_transfers_use_raw_parts() {
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let addresses = [18110, 18111].map(|port| SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let [sender, receiver] = addresses.map(|address| {
        let socket = create_udp_socket(&process, readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&process, socket, address),
            Ok(SocketOutcome::Completed(address))
        );
        socket
    });
    let mut data = TEST_MESSAGE;
    assert_eq!(
        litebox_broker_core::socket::send_to(
            &process,
            sender,
            &TestBuffer::new(&mut data, Some(TEST_PART_LENGTH)),
            SendFlags::NONE,
            Some(addresses[1]),
        ),
        Ok(SocketOutcome::Completed(TEST_MESSAGE.len()))
    );
    receive_test_message(&process, receiver, &publications, addresses[0]);
}

#[test]
fn unmatched_guest_udp_destinations_are_port_unreachable() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let host = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_nonblocking(true).unwrap();
    let loopback_miss = socket_address_v4(host.local_addr().unwrap());
    let private_miss = SocketAddrV4::new(GUEST_IPV4_ADDRESS, loopback_miss.port());

    for destination in [loopback_miss, private_miss] {
        assert_eq!(
            send_datagram(
                &process,
                socket,
                b"blocked",
                SendFlags::NONE,
                Some(destination),
            ),
            Ok(SocketOutcome::Completed(7))
        );
    }
    let has_error = || {
        process
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    };
    assert!(!has_error(), "unconnected senders must not see refusals");
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, loopback_miss),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&process, socket, b"blocked", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    assert!(has_error());
    assert_eq!(
        send_datagram(&process, socket, b"blocked", SendFlags::NONE, None),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    assert!(!has_error());
    assert_eq!(
        send_datagram(&process, socket, b"blocked", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    assert_eq!(
        receive_datagram_into(&process, socket, &mut [0; 7], ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    assert!(!has_error());
    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"blocked",
            SendFlags::NONE,
            Some(private_miss),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    assert!(
        !has_error(),
        "only datagrams to the connected peer report refusals"
    );
    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
    assert_eq!(
        host.recv_from(&mut [0; 7]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn udp_status_republishes_when_another_error_remains_pending() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let socket = create_udp_socket(&process, readiness);
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_address = gateway_address(socket_address_v4(peer.local_addr().unwrap()));
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, peer_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let local_address = litebox_broker_core::socket::status(&process, socket)
        .unwrap()
        .local_address
        .unwrap();
    while publications.try_recv().is_ok() {}

    provider.core.inject_udp_status_errors(
        local_address.port(),
        SocketError::ConnectionRefused,
        SocketError::Other,
    );
    assert_eq!(
        litebox_broker_core::socket::status(&process, socket)
            .unwrap()
            .pending_error,
        Some(SocketError::ConnectionRefused)
    );
    let (published_socket, published_readiness) = publications.recv_timeout(TEST_TIMEOUT).unwrap();
    assert_eq!(published_socket, socket);
    assert!(published_readiness.contains(ReadinessFlags::ERROR));

    assert_eq!(
        litebox_broker_core::socket::status(&process, socket)
            .unwrap()
            .pending_error,
        Some(SocketError::Other)
    );
}

#[test]
fn guest_udp_queue_pressure_drops_new_datagrams_successfully() {
    let provider = Arc::new(UserlandSocketProvider::new(2, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 1),
        provider.clone(),
    )
    .unwrap();
    let receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let sender_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let receiver = create_udp_socket(&receiver_process, readiness.clone());
    let receiver_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18102);
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_process, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let sender = create_udp_socket(&sender_process, readiness);
    assert_eq!(
        send_datagram(
            &sender_process,
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
                &sender_process,
                sender,
                b"x",
                SendFlags::NONE,
                Some(receiver_address),
            ),
            Ok(SocketOutcome::Completed(1))
        );
    }
    assert_eq!(
        provider.core.udp_queued_datagram_count(),
        MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE
    );

    let mut empty = [];
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut empty,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 0,
            datagram_length: 0,
            source_address: litebox_broker_core::socket::status(&sender_process, sender)
                .unwrap()
                .local_address
                .map(|address| SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port()))
                .unwrap(),
        }))
    );
    for _ in 1..MAX_UDP_QUEUE_DATAGRAMS_PER_SOURCE {
        let mut byte = [0];
        assert!(matches!(
            receive_datagram_into(
                &receiver_process,
                receiver,
                &mut byte,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                received: 1,
                datagram_length: 1,
                ..
            }))
        ));
        assert_eq!(byte, *b"x");
    }
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);
}

#[test]
fn udp_external_peer_authorization_is_bounded_without_eviction() {
    // Allow a host-local peer for each of the socket's reply peers.
    let provider = Arc::new(
        UserlandSocketProvider::new(
            MAX_UDP_EXTERNAL_PEERS_PER_SOCKET,
            MAX_UDP_EXTERNAL_PEERS_PER_SOCKET,
        )
        .unwrap(),
    );
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
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
    let handle = create_udp_socket(&process, readiness);

    let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    first.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let first_address = gateway_address(socket_address_v4(first.local_addr().unwrap()));
    assert_eq!(
        send_datagram(&process, handle, b"x", SendFlags::NONE, Some(first_address),),
        Ok(SocketOutcome::Completed(1))
    );
    let mut byte = [0];
    let (_, host_source) = first.recv_from(&mut byte).unwrap();
    let host_source = socket_address_v4(host_source);

    let mut peers = Vec::new();
    while peers.len() < MAX_UDP_EXTERNAL_PEERS_PER_SOCKET - 1 {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = gateway_address(socket_address_v4(peer.local_addr().unwrap()));
        if address.port() == host_source.port() {
            continue;
        }
        assert_eq!(
            send_datagram(&process, handle, b"x", SendFlags::NONE, Some(address),),
            Ok(SocketOutcome::Completed(1))
        );
        peers.push(peer);
    }
    let overflow = loop {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        if socket.local_addr().unwrap().port() != host_source.port() {
            break socket;
        }
    };
    assert_eq!(
        send_datagram(
            &process,
            handle,
            b"overflow",
            SendFlags::NONE,
            Some(gateway_address(socket_address_v4(
                overflow.local_addr().unwrap(),
            ))),
        ),
        Err(BrokerError::ResourceExhausted)
    );

    first.send_to(b"reply", host_source).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    let mut reply = [0; 5];
    assert_eq!(
        receive_datagram_into(&process, handle, &mut reply, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: first_address,
        }))
    );
    assert_eq!(&reply, b"reply");
}

#[test]
fn udp_host_local_reply_peers_are_limited_to_one_per_allowed_socket() {
    let provider = Arc::new(UserlandSocketProvider::new(3, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 3, 2),
        provider.clone(),
    )
    .unwrap();
    let first_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let second_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let first = create_udp_socket(&first_process, readiness.clone());
    let second = create_udp_socket(&second_process, readiness);
    let hosts: Vec<_> = (0..3)
        .map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect();
    let peers: Vec<_> = hosts
        .iter()
        .map(|host| gateway_address(socket_address_v4(host.local_addr().unwrap())))
        .collect();
    let send =
        |process, handle, peer| send_datagram(process, handle, b"x", SendFlags::NONE, Some(peer));

    assert_eq!(
        send(&first_process, first, peers[0]),
        Ok(SocketOutcome::Completed(1))
    );
    assert_eq!(
        send(&first_process, first, peers[1]),
        Ok(SocketOutcome::Completed(1))
    );
    // The process has used its share of host-local peers.
    assert_eq!(
        send(&first_process, first, peers[2]),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(
        send(&second_process, second, peers[2]),
        Ok(SocketOutcome::Completed(1))
    );
    // All processes have used the global share.
    assert_eq!(
        send(&second_process, second, peers[0]),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(provider.core.udp_external_peer_count(), 3);

    first_process.close_object_reference(first).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), first);
    assert_eq!(
        send(&second_process, second, peers[0]),
        Ok(SocketOutcome::Completed(1))
    );
    second_process.close_object_reference(second).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), second);
    assert_eq!(provider.core.udp_external_peer_count(), 0);
}

#[test]
fn provider_preserves_udp_datagram_semantics() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let server_address = gateway_address(socket_address_v4(server.local_addr().unwrap()));
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let socket_policy = SocketPolicy::deny()
        .with_udp_destination_rules(&[
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address([255, 255, 255, 255]), 32).unwrap(),
                DestinationPortRange::new(Port(9), Port(9)).unwrap(),
            ),
        ])
        .unwrap();
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy),
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
    let handle = litebox_broker_core::socket::create(
        &process,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
            flags: FileOpenFlags::NONE,
        },
        readiness.clone(),
    )
    .unwrap();

    wait_until_ready(&process, &publications, handle, ReadinessFlags::WRITE);
    let shutdown_handle = litebox_broker_core::socket::create(
        &process,
        CreateSocketRequest {
            address_family: AddressFamily::Ipv4,
            socket_type: SocketType::Datagram,
            protocol: IpProtocol::Udp,
            flags: FileOpenFlags::NONE,
        },
        readiness.clone(),
    )
    .unwrap();
    wait_until_ready(
        &process,
        &publications,
        shutdown_handle,
        ReadinessFlags::WRITE,
    );
    // An unconnected socket records a shutdown that fails.
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, shutdown_handle, ShutdownMode::Both,),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    let shutdown_readiness = process.check_readiness(shutdown_handle).unwrap();
    assert!(shutdown_readiness.contains(ReadinessFlags::READ | ReadinessFlags::WRITE));
    assert_eq!(
        send_datagram(
            &process,
            shutdown_handle,
            b"after shutdown",
            SendFlags::NONE,
            Some(server_address),
        ),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    let mut shutdown_data = [0; 1];
    assert_eq!(
        receive_datagram_into(
            &process,
            shutdown_handle,
            &mut shutdown_data,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    process.close_object_reference(shutdown_handle).unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        shutdown_handle
    );
    let read_shutdown_handle = create_udp_socket(&process, readiness);
    assert_eq!(
        send_datagram(
            &process,
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
        litebox_broker_core::socket::shutdown(&process, read_shutdown_handle, ShutdownMode::Read,),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        send_datagram(
            &process,
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
            &process,
            read_shutdown_handle,
            &mut shutdown_data,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    process
        .close_object_reference(read_shutdown_handle)
        .unwrap();
    assert_eq!(
        retirements.recv_timeout(TEST_TIMEOUT).unwrap(),
        read_shutdown_handle
    );

    assert_eq!(
        send_datagram(
            &process,
            handle,
            b"denied",
            SendFlags::NONE,
            Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 53)),
        ),
        Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
    );
    assert_eq!(
        send_datagram(
            &process,
            handle,
            b"invalid",
            SendFlags::NONE,
            Some(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9)),
        ),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );
    assert_eq!(
        litebox_broker_core::socket::status(&process, handle)
            .unwrap()
            .local_address,
        None
    );
    let mut no_data = [0; 1];
    assert_eq!(
        receive_datagram_into(&process, handle, &mut no_data, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        send_datagram(
            &process,
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
    let status = litebox_broker_core::socket::status(&process, handle).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Unconnected);
    let local_address = status.local_address.unwrap();
    assert!(local_address.ip().is_unspecified());
    assert_ne!(local_address.port(), 0);
    assert!(source.ip().is_loopback());

    server.send_to(&[], source).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    let mut zero = [];
    assert_eq!(
        receive_datagram_into(&process, handle, &mut zero, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 0,
            datagram_length: 0,
            source_address: server_address,
        }))
    );
    assert_eq!(
        receive_datagram_into(&process, handle, &mut zero, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );

    server.send_to(b"abcdef", source).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    let mut peeked = [0; 3];
    assert_eq!(
        receive_datagram_into(&process, handle, &mut peeked, ReceiveFromFlags::PEEK,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 3,
            datagram_length: 6,
            source_address: server_address,
        }))
    );
    assert_eq!(&peeked, b"abc");
    peeked.fill(0);
    assert_eq!(
        receive_datagram_into(&process, handle, &mut peeked, ReceiveFromFlags::PEEK,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 3,
            datagram_length: 6,
            source_address: server_address,
        }))
    );
    assert_eq!(&peeked, b"abc");
    let mut truncated = [0; 4];
    assert_eq!(
        receive_datagram_into(&process, handle, &mut truncated, ReceiveFromFlags::NONE,),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 4,
            datagram_length: 6,
            source_address: server_address,
        }))
    );
    assert_eq!(&truncated, b"abcd");
    assert_eq!(
        receive_datagram_into(&process, handle, &mut no_data, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );

    assert_eq!(
        litebox_broker_core::socket::connect(&process, handle, server_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let connected_status = litebox_broker_core::socket::status(&process, handle).unwrap();
    assert_eq!(connected_status.status, SocketConnectionStatus::Connected);
    assert_eq!(
        connected_status.local_address,
        Some(SocketAddrV4::new(GUEST_IPV4_ADDRESS, local_address.port()))
    );
    let maximum = vec![0x5a; MAX_UDP_DATAGRAM_SIZE as usize];
    assert_eq!(
        send_datagram(&process, handle, &maximum, SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(maximum.len()))
    );
    let (received, connected_source) = server.recv_from(&mut packet).unwrap();
    assert_eq!(received, maximum.len());
    assert_eq!(&packet[..received], maximum.as_slice());
    let connected_source = socket_address_v4(connected_source);
    assert!(connected_source.ip().is_loopback());
    assert_eq!(connected_source, source);
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
    assert_eq!(
        litebox_broker_core::socket::connect(
            &process,
            handle,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 9),
        ),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );
    assert_eq!(
        send_datagram(&process, handle, b"old peer", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(8))
    );
    let (received, preserved_source) = server.recv_from(&mut packet).unwrap();
    assert_eq!(&packet[..received], b"old peer");
    assert_eq!(socket_address_v4(preserved_source), source);

    let refused_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let refused_address = gateway_address(socket_address_v4(refused_socket.local_addr().unwrap()));
    drop(refused_socket);
    assert_eq!(
        litebox_broker_core::socket::connect(&process, handle, refused_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&process, handle, b"refused", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(7))
    );
    // Leave the error with the transport so that the failed send queues it.
    wait_for_readiness_publication(&publications, handle, ReadinessFlags::ERROR);
    assert_eq!(
        send_datagram(
            &process,
            handle,
            b"broadcast",
            SendFlags::NONE,
            Some(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9)),
        ),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, handle),
        Ok(Some(SocketError::ConnectionRefused))
    );
    assert!(
        !process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    assert_eq!(
        send_datagram(&process, handle, b"refused again", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(13))
    );
    wait_until_ready(&process, &publications, handle, ReadinessFlags::ERROR);
    assert_eq!(
        litebox_broker_core::socket::connect(
            &process,
            handle,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 9),
        ),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, handle),
        Ok(Some(SocketError::ConnectionRefused))
    );
    assert!(
        !process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    assert_eq!(
        litebox_broker_core::socket::connect(&process, handle, server_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );

    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, handle, ShutdownMode::Write),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        litebox_broker_core::socket::connect(&process, handle, server_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    // A socket shut down for writing is writable.
    assert!(
        process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    assert_eq!(
        send_datagram(&process, handle, b"after shutdown", SendFlags::NONE, None,),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );

    process.close_object_reference(handle).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
}

/// A connected socket shut for reading still reports the ICMP errors its
/// datagrams cause.
#[test]
fn read_shutdown_udp_socket_reports_icmp_errors() {
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let socket_policy = SocketPolicy::deny()
        .with_udp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
            DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
        )])
        .unwrap();
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy),
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
    let handle = create_udp_socket(&process, readiness);
    wait_until_ready(&process, &publications, handle, ReadinessFlags::WRITE);
    let refused_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let refused_address = gateway_address(socket_address_v4(refused_socket.local_addr().unwrap()));
    drop(refused_socket);
    assert_eq!(
        litebox_broker_core::socket::connect(&process, handle, refused_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        litebox_broker_core::socket::shutdown(&process, handle, ShutdownMode::Read),
        Ok(SocketOutcome::Completed(()))
    );

    // The second error shows that taking the first keeps the socket watched.
    for _ in 0..2 {
        assert_eq!(
            send_datagram(&process, handle, b"refused", SendFlags::NONE, None),
            Ok(SocketOutcome::Completed(7))
        );
        wait_until_ready(&process, &publications, handle, ReadinessFlags::ERROR);
        assert_eq!(
            litebox_broker_core::socket::take_error(&process, handle),
            Ok(Some(SocketError::ConnectionRefused))
        );
        assert!(
            !process
                .check_readiness(handle)
                .unwrap()
                .contains(ReadinessFlags::ERROR)
        );
    }

    process.close_object_reference(handle).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
}

/// A send that reports a connected socket's pending ICMP error takes it, and
/// the socket keeps reporting the errors that follow.
#[test]
fn udp_send_takes_a_pending_icmp_error() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let handle = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let refused_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let refused_address = gateway_address(socket_address_v4(refused_socket.local_addr().unwrap()));
    drop(refused_socket);
    assert_eq!(
        litebox_broker_core::socket::connect(&process, handle, refused_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&process, handle, b"refused", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    wait_until_ready(&process, &publications, handle, ReadinessFlags::ERROR);
    assert_eq!(
        send_datagram(&process, handle, b"refused", SendFlags::NONE, None),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    assert!(
        !process
            .check_readiness(handle)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, handle),
        Ok(None)
    );
    assert_eq!(
        send_datagram(&process, handle, b"refused", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    wait_until_ready(&process, &publications, handle, ReadinessFlags::ERROR);
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, handle),
        Ok(Some(SocketError::ConnectionRefused))
    );
}

/// A connect that Winsock fails leaves an unconnected socket, which reports
/// no ICMP errors.
#[cfg(windows)]
#[test]
fn failed_udp_connect_keeps_icmp_errors_unreported() {
    // Windows routes a link-local address only over a link with one, and
    // Linux connects through its default route.
    let unroutable = SocketAddrV4::new(Ipv4Addr::new(169, 254, 0, 1), 9);
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let socket_policy = SocketPolicy::guest_network()
        .with_udp_destination_rules(&[
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(unroutable.ip().octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
        ])
        .unwrap();
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(socket_policy),
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
    let handle = create_udp_socket(&process, readiness);
    wait_until_ready(&process, &publications, handle, ReadinessFlags::WRITE);
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    server.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let server_address = gateway_address(socket_address_v4(server.local_addr().unwrap()));
    let refused_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let refused_address = gateway_address(socket_address_v4(refused_socket.local_addr().unwrap()));
    drop(refused_socket);

    assert_eq!(
        send_datagram(
            &process,
            handle,
            b"stage",
            SendFlags::NONE,
            Some(server_address)
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let mut payload = [0; 5];
    let (_, host_source) = server.recv_from(&mut payload).unwrap();
    match litebox_broker_core::socket::connect(&process, handle, unroutable) {
        Ok(SocketOutcome::Failed(_)) => {}
        // A host with a link-local address connects.
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected)) => return,
        other => panic!("unexpected connect result {other:?}"),
    }
    assert_eq!(
        send_datagram(
            &process,
            handle,
            b"refused",
            SendFlags::NONE,
            Some(refused_address)
        ),
        Ok(SocketOutcome::Completed(7))
    );
    // The reply queues behind any ICMP error the refused datagram caused.
    server.send_to(b"reply", host_source).unwrap();
    wait_until_ready(&process, &publications, handle, ReadinessFlags::READ);
    assert_eq!(
        receive_datagram_into(&process, handle, &mut payload, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: server_address,
        }))
    );
    assert_eq!(&payload, b"reply");
    assert_eq!(
        litebox_broker_core::socket::take_error(&process, handle),
        Ok(None)
    );

    process.close_object_reference(handle).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), handle);
}

#[test]
fn guest_udp_namespace_routes_across_processes_and_filters_private_endpoints() {
    let provider = Arc::new(UserlandSocketProvider::new(6, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 6, 3),
        provider.clone(),
    )
    .unwrap();
    let receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let sender_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });

    let shadowed_host_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    shadowed_host_socket
        .set_nonblocking(true)
        .expect("failed to make shadow socket nonblocking");
    let guest_port = shadowed_host_socket.local_addr().unwrap().port();
    let receiver_guest_address = SocketAddrV4::new(GUEST_IPV4_ADDRESS, guest_port);
    let receiver = create_udp_socket(&receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_process, receiver, receiver_guest_address,),
        Ok(SocketOutcome::Completed(receiver_guest_address))
    );
    assert_eq!(
        provider
            .core
            .udp_guest_local_address(receiver_guest_address.port()),
        None
    );
    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
    let tcp_same_port = create_socket(&sender_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&sender_process, tcp_same_port, receiver_guest_address,),
        Ok(SocketOutcome::Completed(receiver_guest_address))
    );

    let sender = create_udp_socket(&sender_process, readiness.clone());
    assert_eq!(
        send_datagram(
            &sender_process,
            sender,
            b"claimed miss",
            SendFlags::NONE,
            Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, guest_port)),
        ),
        Ok(SocketOutcome::Completed(12))
    );
    let unbound_private_port = if guest_port == u16::MAX {
        guest_port - 1
    } else {
        guest_port + 1
    };
    assert_eq!(
        send_datagram(
            &sender_process,
            sender,
            b"private miss",
            SendFlags::NONE,
            Some(SocketAddrV4::new(GUEST_IPV4_ADDRESS, unbound_private_port,)),
        ),
        Ok(SocketOutcome::Completed(12))
    );
    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
    assert_eq!(
        send_datagram(
            &sender_process,
            sender,
            b"request",
            SendFlags::NONE,
            Some(receiver_guest_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    let sender_guest_address = litebox_broker_core::socket::status(&sender_process, sender)
        .unwrap()
        .local_address
        .expect("implicit UDP bind missing");
    let sender_source_address = SocketAddrV4::new(GUEST_IPV4_ADDRESS, sender_guest_address.port());
    wait_until_ready(
        &receiver_process,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    let mut request = [0; 7];
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut request,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 7,
            datagram_length: 7,
            source_address: sender_source_address,
        }))
    );
    assert_eq!(&request, b"request");

    assert_eq!(
        send_datagram(
            &receiver_process,
            receiver,
            b"response",
            SendFlags::NONE,
            Some(sender_source_address),
        ),
        Ok(SocketOutcome::Completed(8))
    );
    wait_until_ready(&sender_process, &publications, sender, ReadinessFlags::READ);
    let mut response = [0; 8];
    assert_eq!(
        receive_datagram_into(
            &sender_process,
            sender,
            &mut response,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 8,
            datagram_length: 8,
            source_address: receiver_guest_address,
        }))
    );
    assert_eq!(&response, b"response");
    sender_process.close_object_reference(sender).unwrap();
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
    let external_address = gateway_address(socket_address_v4(external.local_addr().unwrap()));
    assert_eq!(
        send_datagram(
            &receiver_process,
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
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
    assert!(
        provider
            .core
            .udp_native_receive_buffer_size(receiver_guest_address.port())
            .is_some_and(|size| size <= MAX_UDP_NATIVE_RECEIVE_BUFFER)
    );
    let receiver_private_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_source.port());
    let probe = create_udp_socket(&sender_process, readiness);
    let probe_guest_port = (1_u16..=u16::MAX)
        .find(|port| *port != receiver_guest_address.port() && *port != receiver_source.port())
        .unwrap();
    let probe_guest_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, probe_guest_port);
    assert_eq!(
        litebox_broker_core::socket::bind(&sender_process, probe, probe_guest_address,),
        Ok(SocketOutcome::Completed(probe_guest_address))
    );
    assert_eq!(
        send_datagram(
            &sender_process,
            probe,
            b"private",
            SendFlags::NONE,
            Some(receiver_private_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    let receiver_private_alias =
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), receiver_source.port());
    assert_eq!(
        send_datagram(
            &sender_process,
            probe,
            b"private alias",
            SendFlags::NONE,
            Some(receiver_private_alias),
        ),
        Ok(SocketOutcome::Completed(13))
    );
    external.send_to(b"reply", receiver_source).unwrap();
    wait_until_ready(
        &receiver_process,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    assert_eq!(
        send_datagram(
            &sender_process,
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
            &receiver_process,
            receiver,
            &mut reply,
            ReceiveFromFlags::PEEK,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: external_address,
        }))
    );
    assert_eq!(&reply, b"reply");
    reply.fill(0);
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut reply,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: external_address,
        }))
    );
    assert_eq!(&reply, b"reply");
    reply.fill(0);
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut reply,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: probe_guest_address,
        }))
    );
    assert_eq!(&reply, b"guest");
}

#[test]
fn udp_exact_bindings_coexist_and_wildcard_covers_guest_addresses() {
    let provider = Arc::new(UserlandSocketProvider::new(8, 5).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(12, 0, 8, 8),
        provider,
    )
    .unwrap();
    let receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let sender_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });

    let first = create_udp_socket(&receiver_process, readiness.clone());
    let SocketOutcome::Completed(first_address) = litebox_broker_core::socket::bind(
        &receiver_process,
        first,
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0),
    )
    .unwrap() else {
        panic!("first exact UDP bind failed");
    };
    let second_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), first_address.port());
    let second = create_udp_socket(&receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_process, second, second_address),
        Ok(SocketOutcome::Completed(second_address))
    );
    let wildcard_competitor = create_udp_socket(&receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(
            &receiver_process,
            wildcard_competitor,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, first_address.port()),
        ),
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    );

    let sender = create_udp_socket(&sender_process, readiness.clone());
    for (receiver, destination, payload) in [
        (first, first_address, b"first".as_slice()),
        (second, second_address, b"second".as_slice()),
    ] {
        assert_eq!(
            send_datagram(
                &sender_process,
                sender,
                payload,
                SendFlags::NONE,
                Some(destination),
            ),
            Ok(SocketOutcome::Completed(payload.len()))
        );
        wait_until_ready(
            &receiver_process,
            &publications,
            receiver,
            ReadinessFlags::READ,
        );
        let mut received = [0; 6];
        assert_eq!(
            receive_datagram_into(
                &receiver_process,
                receiver,
                &mut received,
                ReceiveFromFlags::NONE,
            ),
            Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                received: payload.len(),
                datagram_length: payload.len(),
                source_address: SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    litebox_broker_core::socket::status(&sender_process, sender)
                        .unwrap()
                        .local_address
                        .unwrap()
                        .port(),
                ),
            }))
        );
        assert_eq!(&received[..payload.len()], payload);
    }

    let wildcard = create_udp_socket(&receiver_process, readiness.clone());
    let SocketOutcome::Completed(wildcard_address) = litebox_broker_core::socket::bind(
        &receiver_process,
        wildcard,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    )
    .unwrap() else {
        panic!("wildcard UDP bind failed");
    };
    let concrete_destination = SocketAddrV4::new(GUEST_IPV4_ADDRESS, wildcard_address.port());
    assert_eq!(
        send_datagram(
            &sender_process,
            sender,
            b"wild",
            SendFlags::NONE,
            Some(concrete_destination),
        ),
        Ok(SocketOutcome::Completed(4))
    );
    wait_until_ready(
        &receiver_process,
        &publications,
        wildcard,
        ReadinessFlags::READ,
    );
    let mut received = [0; 4];
    assert!(matches!(
        receive_datagram_into(
            &receiver_process,
            wildcard,
            &mut received,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 4,
            datagram_length: 4,
            ..
        }))
    ));
    assert_eq!(&received, b"wild");

    assert_eq!(
        litebox_broker_core::socket::connect(&sender_process, sender, concrete_destination,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&sender_process, sender, b"ping", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(4))
    );
    wait_until_ready(
        &receiver_process,
        &publications,
        wildcard,
        ReadinessFlags::READ,
    );
    let mut request = [0; 4];
    let source_address = match receive_datagram_into(
        &receiver_process,
        wildcard,
        &mut request,
        ReceiveFromFlags::NONE,
    ) {
        Ok(SocketOutcome::Completed(datagram)) => datagram.source_address,
        result => panic!("connected wildcard receive failed: {result:?}"),
    };
    assert_eq!(&request, b"ping");
    assert_eq!(
        send_datagram(
            &receiver_process,
            wildcard,
            b"pong",
            SendFlags::NONE,
            Some(source_address),
        ),
        Ok(SocketOutcome::Completed(4))
    );
    wait_until_ready(&sender_process, &publications, sender, ReadinessFlags::READ);
    let mut reply = [0; 4];
    assert!(matches!(
        receive_datagram_into(
            &sender_process,
            sender,
            &mut reply,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 4,
            datagram_length: 4,
            source_address,
        })) if source_address == SocketAddrV4::new(
            GUEST_IPV4_ADDRESS,
            wildcard_address.port(),
        )
    ));
    assert_eq!(&reply, b"pong");
}

#[test]
fn udp_native_endpoint_is_reused_and_retired() {
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let socket = create_udp_socket(&process, readiness);
    let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    first.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    second.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let first_address = gateway_address(socket_address_v4(first.local_addr().unwrap()));
    let second_address = gateway_address(socket_address_v4(second.local_addr().unwrap()));

    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
    assert_eq!(provider.core.udp_native_event_token_count(), 0);
    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"first",
            SendFlags::NONE,
            Some(first_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let mut first_payload = [0; 5];
    let (_, first_source) = first.recv_from(&mut first_payload).unwrap();
    assert_eq!(&first_payload, b"first");
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
    assert_eq!(provider.core.udp_native_event_token_count(), 1);

    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"second",
            SendFlags::NONE,
            Some(second_address),
        ),
        Ok(SocketOutcome::Completed(6))
    );
    let mut second_payload = [0; 6];
    let (_, second_source) = second.recv_from(&mut second_payload).unwrap();
    assert_eq!(&second_payload, b"second");
    assert_eq!(second_source, first_source);
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
    assert_eq!(provider.core.udp_native_event_token_count(), 1);

    process.close_object_reference(socket).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), socket);
    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
    assert_eq!(provider.core.udp_native_event_token_count(), 0);
}

#[test]
fn udp_endpoint_staging_error_rolls_back_external_peer_reservation() {
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let socket = create_udp_socket(&process, readiness);
    let external = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let external_address = gateway_address(socket_address_v4(external.local_addr().unwrap()));

    provider.core.exhaust_udp_event_tokens();
    assert_eq!(
        send_datagram(
            &process,
            socket,
            b"not sent",
            SendFlags::NONE,
            Some(external_address),
        ),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(provider.core.udp_external_peer_count(), 0);
    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
    assert_eq!(provider.core.udp_native_event_token_count(), 0);

    process.close_object_reference(socket).unwrap();
}

#[test]
fn stale_udp_datagrams_are_not_relabelled_after_guest_port_reuse() {
    let provider = Arc::new(UserlandSocketProvider::new(5, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 5, 3),
        provider.clone(),
    )
    .unwrap();
    let receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let source_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let receiver_port_guard = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let source_port_guard = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let receiver_port = receiver_port_guard.local_addr().unwrap().port();
    let source_port = source_port_guard.local_addr().unwrap().port();
    let receiver_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), receiver_port);
    let source_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), source_port);

    let receiver = create_udp_socket(&receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_process, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let source = create_udp_socket(&source_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&source_process, source, source_address),
        Ok(SocketOutcome::Completed(source_address))
    );
    assert_eq!(provider.core.udp_native_endpoint_count(), 0);
    assert_eq!(
        send_datagram(
            &source_process,
            source,
            b"old",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(3))
    );
    wait_until_ready(
        &receiver_process,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    assert_eq!(provider.core.udp_queued_datagram_count(), 1);

    source_process.close_object_reference(source).unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), source);

    let replacement = create_udp_socket(&source_process, readiness);
    let replacement_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 4), source_address.port());
    assert_eq!(
        litebox_broker_core::socket::bind(&source_process, replacement, replacement_address,),
        Ok(SocketOutcome::Completed(replacement_address))
    );
    assert_eq!(
        send_datagram(
            &source_process,
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
            &receiver_process,
            receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 3,
            datagram_length: 3,
            source_address,
        }))
    );
    assert_eq!(&payload[..3], b"old");
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: replacement_address,
        }))
    );
    assert_eq!(&payload, b"fresh");
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);
}

#[test]
fn udp_queued_datagrams_survive_source_process_teardown() {
    let provider = Arc::new(UserlandSocketProvider::new(3, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(6, 0, 3, 1),
        provider.clone(),
    )
    .unwrap();
    let source_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let first_receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let second_receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let replacement_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let first_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18082);
    let second_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18083);
    let first_receiver = create_udp_socket(&first_receiver_process, readiness.clone());
    let second_receiver = create_udp_socket(&second_receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&first_receiver_process, first_receiver, first_address,),
        Ok(SocketOutcome::Completed(first_address))
    );
    assert_eq!(
        litebox_broker_core::socket::bind(
            &second_receiver_process,
            second_receiver,
            second_address,
        ),
        Ok(SocketOutcome::Completed(second_address))
    );
    let source = create_udp_socket(&source_process, readiness.clone());
    let source_process_id = source_process.id();

    assert_eq!(
        send_datagram(
            &source_process,
            source,
            b"first",
            SendFlags::NONE,
            Some(first_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    let source_address = litebox_broker_core::socket::status(&source_process, source)
        .unwrap()
        .local_address
        .map(|address| SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port()))
        .expect("implicit UDP source bind missing");
    assert_eq!(provider.core.udp_queued_datagram_count(), 1);
    assert_eq!(
        send_datagram(
            &source_process,
            source,
            b"second",
            SendFlags::NONE,
            Some(second_address),
        ),
        Ok(SocketOutcome::Completed(6))
    );
    assert_eq!(provider.core.udp_queued_datagram_count(), 2);
    wait_until_ready(
        &first_receiver_process,
        &publications,
        first_receiver,
        ReadinessFlags::READ,
    );
    let mut payload = [0; 6];
    assert_eq!(
        receive_datagram_into(
            &first_receiver_process,
            first_receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address,
        }))
    );
    assert_eq!(&payload[..5], b"first");
    assert_eq!(
        receive_datagram_into(
            &first_receiver_process,
            first_receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(provider.core.udp_queued_datagram_count(), 1);
    assert!(provider.core.has_udp_source_accounting(source_process_id));
    wait_until_ready(
        &second_receiver_process,
        &publications,
        second_receiver,
        ReadinessFlags::READ,
    );
    source_process.cleanup(true);
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), source);
    assert_eq!(provider.core.udp_queued_datagram_count(), 1);
    assert!(!provider.core.has_udp_source_accounting(source_process_id));
    assert_eq!(provider.core.process_state_count(), 2);

    let replacement = create_udp_socket(&replacement_process, readiness);
    assert_eq!(
        receive_datagram_into(
            &second_receiver_process,
            second_receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 6,
            datagram_length: 6,
            source_address,
        }))
    );
    assert_eq!(&payload, b"second");
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);

    replacement_process
        .close_object_reference(replacement)
        .unwrap();
}

#[test]
fn connected_guest_udp_enforces_barriers_peek_and_peer_addresses() {
    let provider = Arc::new(UserlandSocketProvider::new(4, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 2),
        provider.clone(),
    )
    .unwrap();
    let first_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let second_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let expected_first_address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 18080);
    let second_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18081);
    let second = create_udp_socket(&second_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&second_process, second, second_address),
        Ok(SocketOutcome::Completed(second_address))
    );

    let first = create_udp_socket(&first_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&first_process, first, expected_first_address,),
        Ok(SocketOutcome::Completed(expected_first_address))
    );
    assert_eq!(
        send_datagram(
            &second_process,
            second,
            b"stale",
            SendFlags::NONE,
            Some(expected_first_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    wait_until_ready(&first_process, &publications, first, ReadinessFlags::READ);
    assert_eq!(provider.core.udp_queued_datagram_count(), 1);
    assert_eq!(
        litebox_broker_core::socket::connect(&first_process, first, second_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);
    let mut stale = [0; 5];
    assert_eq!(
        receive_datagram_into(&first_process, first, &mut stale, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );
    let first_address = litebox_broker_core::socket::status(&first_process, first)
        .unwrap()
        .local_address
        .expect("connected UDP socket lost its local address");
    assert_eq!(first_address, expected_first_address);
    assert_eq!(
        send_datagram(&first_process, first, b"one", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(3))
    );
    wait_until_ready(&second_process, &publications, second, ReadinessFlags::READ);
    let mut first_payload = [0; 3];
    assert_eq!(
        receive_datagram_into(
            &second_process,
            second,
            &mut first_payload,
            ReceiveFromFlags::PEEK,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 3,
            datagram_length: 3,
            source_address: first_address,
        }))
    );
    assert_eq!(&first_payload, b"one");
    first_payload.fill(0);
    assert_eq!(
        receive_datagram_into(
            &second_process,
            second,
            &mut first_payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 3,
            datagram_length: 3,
            source_address: first_address,
        }))
    );
    assert_eq!(&first_payload, b"one");

    assert_eq!(
        litebox_broker_core::socket::connect(&second_process, second, first_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&second_process, second, b"two", SendFlags::NONE, None,),
        Ok(SocketOutcome::Completed(3))
    );
    wait_until_ready(&first_process, &publications, first, ReadinessFlags::READ);
    let mut second_payload = [0; 3];
    assert_eq!(
        receive_datagram_into(
            &first_process,
            first,
            &mut second_payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 3,
            datagram_length: 3,
            source_address: second_address,
        }))
    );
    assert_eq!(&second_payload, b"two");

    second_process.close_object_reference(second).unwrap();
    assert_eq!(
        send_datagram(&first_process, first, b"lost", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(4))
    );
    assert_eq!(
        send_datagram(&first_process, first, b"refused", SendFlags::NONE, None),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
    let replacement = create_udp_socket(&second_process, readiness);
    assert_eq!(
        litebox_broker_core::socket::bind(&second_process, replacement, second_address),
        Ok(SocketOutcome::Completed(second_address))
    );
    // The peer is an address, so its new owner receives the connected traffic.
    assert_eq!(
        send_datagram(&first_process, first, b"new owner", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(9))
    );
    wait_until_ready(
        &second_process,
        &publications,
        replacement,
        ReadinessFlags::READ,
    );
    let mut new_owner_payload = [0; 9];
    assert_eq!(
        receive_datagram_into(
            &second_process,
            replacement,
            &mut new_owner_payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 9,
            datagram_length: 9,
            source_address: first_address,
        }))
    );
    assert_eq!(&new_owner_payload, b"new owner");
}

#[test]
fn connected_guest_udp_filters_other_wildcard_peer_aliases() {
    let provider = Arc::new(UserlandSocketProvider::new(2, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 2),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let sender_binding = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 18082);
    let receiver_binding = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 18083);
    let sender = create_udp_socket(&process, readiness.clone());
    let receiver = create_udp_socket(&process, readiness);
    assert_eq!(
        litebox_broker_core::socket::bind(&process, sender, sender_binding),
        Ok(SocketOutcome::Completed(sender_binding))
    );
    assert_eq!(
        litebox_broker_core::socket::bind(&process, receiver, receiver_binding),
        Ok(SocketOutcome::Completed(receiver_binding))
    );
    let connected_peer = SocketAddrV4::new(Ipv4Addr::LOCALHOST, sender_binding.port());
    assert_eq!(
        litebox_broker_core::socket::connect(&process, receiver, connected_peer),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );

    let private_receiver = SocketAddrV4::new(GUEST_IPV4_ADDRESS, receiver_binding.port());
    assert_eq!(
        send_datagram(
            &process,
            sender,
            b"wrong alias",
            SendFlags::NONE,
            Some(private_receiver),
        ),
        Ok(SocketOutcome::Completed(11))
    );
    let mut payload = [0_u8; 11];
    assert_eq!(
        receive_datagram_into(&process, receiver, &mut payload, ReceiveFromFlags::NONE,),
        Err(BrokerError::WouldBlock)
    );

    let loopback_receiver = SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver_binding.port());
    assert_eq!(
        send_datagram(
            &process,
            sender,
            b"connected",
            SendFlags::NONE,
            Some(loopback_receiver),
        ),
        Ok(SocketOutcome::Completed(9))
    );
    wait_until_ready(&process, &publications, receiver, ReadinessFlags::READ);
    assert_eq!(
        receive_datagram_into(
            &process,
            receiver,
            &mut payload[..9],
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 9,
            datagram_length: 9,
            source_address: connected_peer,
        }))
    );
    assert_eq!(&payload[..9], b"connected");

    // A bound port whose socket rejects the source is still unreachable.
    assert_eq!(
        litebox_broker_core::socket::connect(&process, sender, private_receiver),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&process, sender, b"wrong alias", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(11))
    );
    assert_eq!(
        send_datagram(&process, sender, b"wrong alias", SendFlags::NONE, None),
        Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
    );
}

#[test]
fn wildcard_udp_reconnect_updates_guest_source_identity() {
    let provider = Arc::new(UserlandSocketProvider::new(3, 3).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(6, 0, 3, 3),
        provider,
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });

    let private_receiver = create_udp_socket(&process, readiness.clone());
    let SocketOutcome::Completed(private_address) = litebox_broker_core::socket::bind(
        &process,
        private_receiver,
        SocketAddrV4::new(GUEST_IPV4_ADDRESS, 0),
    )
    .unwrap() else {
        panic!("private UDP bind failed");
    };
    let loopback_receiver = create_udp_socket(&process, readiness.clone());
    let SocketOutcome::Completed(loopback_address) = litebox_broker_core::socket::bind(
        &process,
        loopback_receiver,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    )
    .unwrap() else {
        panic!("loopback UDP bind failed");
    };

    let sender = create_udp_socket(&process, readiness);
    assert_eq!(
        litebox_broker_core::socket::connect(&process, sender, private_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let private_source = litebox_broker_core::socket::status(&process, sender)
        .unwrap()
        .local_address
        .expect("private UDP connect lost its local address");
    assert_eq!(*private_source.ip(), GUEST_IPV4_ADDRESS);

    assert_eq!(
        litebox_broker_core::socket::connect(&process, sender, loopback_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let loopback_source = litebox_broker_core::socket::status(&process, sender)
        .unwrap()
        .local_address
        .expect("loopback UDP reconnect lost its local address");
    assert_eq!(
        loopback_source,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, private_source.port())
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
    let provider = Arc::new(UserlandSocketProvider::new(4, 2).unwrap());
    let policy = SocketPolicy::deny()
        .with_udp_destination_rules(&[
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address([127, 0, 0, 0]), 8).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                Ipv4Cidr::new(Ipv4Address(local_ip.octets()), 32).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            ),
        ])
        .unwrap();
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(policy),
        BrokerCoreLimits::new_with_all_limits(6, 0, 4, 2),
        provider.clone(),
    )
    .unwrap();
    let source_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let receiver_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18084);
    let receiver = create_udp_socket(&receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_process, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let source = create_udp_socket(&source_process, readiness);
    assert_eq!(
        litebox_broker_core::socket::connect(&source_process, source, external_address),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    let source_address = litebox_broker_core::socket::status(&source_process, source)
        .unwrap()
        .local_address
        .expect("connected UDP source address missing");
    assert_eq!(source_address.ip(), &GUEST_IPV4_ADDRESS);
    let internal_source_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, source_address.port());

    assert_eq!(
        send_datagram(&source_process, source, b"external", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(8))
    );
    let mut external_payload = [0; 8];
    let (external_received, _) = external.recv_from(&mut external_payload).unwrap();
    assert_eq!(external_received, external_payload.len());
    assert_eq!(&external_payload, b"external");

    assert_eq!(
        send_datagram(
            &source_process,
            source,
            b"guest",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    wait_until_ready(
        &receiver_process,
        &publications,
        receiver,
        ReadinessFlags::READ,
    );
    let mut guest_payload = [0; 5];
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut guest_payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: internal_source_address,
        }))
    );
    assert_eq!(&guest_payload, b"guest");
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut guest_payload,
            ReceiveFromFlags::NONE,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);
    assert_eq!(
        send_datagram(
            &receiver_process,
            receiver,
            b"reply",
            SendFlags::NONE,
            Some(internal_source_address),
        ),
        Ok(SocketOutcome::Completed(5))
    );
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);
    assert_eq!(
        receive_datagram_into(
            &source_process,
            source,
            &mut guest_payload,
            ReceiveFromFlags::NONE,
        ),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);
}

#[test]
fn internally_connected_udp_drains_external_datagrams_without_delivering_them() {
    let provider = Arc::new(UserlandSocketProvider::new(4, 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(8, 0, 4, 2),
        provider.clone(),
    )
    .unwrap();
    let receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let sender_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let guest_port = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let receiver_address = SocketAddrV4::new(GUEST_IPV4_ADDRESS, guest_port);
    let receiver = create_udp_socket(&receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_process, receiver, receiver_address,),
        Ok(SocketOutcome::Completed(receiver_address))
    );
    let sender = create_udp_socket(&sender_process, readiness);
    assert_eq!(
        send_datagram(
            &sender_process,
            sender,
            b"warmup",
            SendFlags::NONE,
            Some(receiver_address),
        ),
        Ok(SocketOutcome::Completed(6))
    );
    wait_for_readiness(&publications, receiver, ReadinessFlags::READ);
    let source_address = litebox_broker_core::socket::status(&sender_process, sender)
        .unwrap()
        .local_address
        .map(|address| SocketAddrV4::new(GUEST_IPV4_ADDRESS, address.port()))
        .unwrap();
    let mut warmup = [0; 6];
    assert_eq!(
        receive_datagram_into(
            &receiver_process,
            receiver,
            &mut warmup,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 6,
            datagram_length: 6,
            source_address,
        }))
    );
    assert_eq!(&warmup, b"warmup");
    assert_eq!(
        litebox_broker_core::socket::connect(&receiver_process, receiver, source_address,),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );

    let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    attacker.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let attacker_address = gateway_address(socket_address_v4(attacker.local_addr().unwrap()));
    assert_eq!(
        send_datagram(
            &receiver_process,
            receiver,
            b"contact",
            SendFlags::NONE,
            Some(attacker_address),
        ),
        Ok(SocketOutcome::Completed(7))
    );
    let mut contact = [0; 7];
    let (_, receiver_host_address) = attacker.recv_from(&mut contact).unwrap();
    assert_eq!(&contact, b"contact");
    assert_eq!(provider.core.udp_native_endpoint_count(), 1);
    let sentinel = b"sentinel";
    // Queue the datagrams while the call holds the socket, so the event
    // thread cannot drain them first.
    assert_eq!(
        provider
            .core
            .exercise_udp_receive_rejection_cap(guest_port, || {
                for _ in 0..MAX_REJECTED_UDP_DATAGRAMS_PER_COMMAND {
                    attacker.send_to(b"x", receiver_host_address).unwrap();
                }
                attacker.send_to(sentinel, receiver_host_address).unwrap();
            }),
        // No rejected datagram reached the output.
        Ok((false, sentinel.len(), 0))
    );
    let deadline = Instant::now() + TEST_TIMEOUT;
    while provider.core.udp_native_head_datagram_bytes(guest_port) != 0 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the rearmed native UDP drain"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        send_datagram(
            &sender_process,
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
            &receiver_process,
            receiver,
            &mut payload,
            ReceiveFromFlags::NONE,
        ),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 2,
            datagram_length: 2,
            source_address,
        }))
    );
    assert_eq!(&payload, b"ok");
}

/// A native error that a receive consumes after the event thread harvested
/// its event is not reported again, and the endpoint keeps rearming.
// Windows queues the ICMP error behind the queued datagram, so the receive
// this test races with the event returns the datagram instead.
#[cfg(target_os = "linux")]
#[test]
fn udp_error_consumed_before_its_event_is_applied_is_not_reported() {
    let provider = Arc::new(UserlandSocketProvider::new(1, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(gateway_udp_policy()),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, _retirements) = channel();
    let socket = create_udp_socket(&process, Arc::new(TestReadinessSink { published, retired }));
    let host = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let host_address = host.local_addr().unwrap();
    let gateway = gateway_address(socket_address_v4(host_address));
    assert_eq!(
        litebox_broker_core::socket::connect(&process, socket, gateway),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected))
    );
    assert_eq!(
        send_datagram(&process, socket, b"hello", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(5))
    );
    let (_, endpoint) = host.recv_from(&mut [0; 5]).unwrap();
    host.send_to(b"queued", endpoint).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    drop(host);

    // The queued datagram leaves the endpoint armed only for errors, so the
    // ICMP error is its next event.
    let hook = TestHook::install(&provider);
    let receiver = Arc::new(Mutex::new(Some(Arc::clone(&process))));
    let pending_receive = Arc::clone(&receiver);
    hook.act(move |_, _, point| {
        let HookPoint::Harvested(token) = point else {
            return;
        };
        if token & UDP_EVENT_TOKEN_FLAG == 0 {
            return;
        }
        let receiver = pending_receive.lock().unwrap().take();
        if let Some(process) = receiver {
            run_on_thread(move || {
                assert_eq!(
                    receive_datagram_into(&process, socket, &mut [0; 6], ReceiveFromFlags::NONE),
                    Ok(SocketOutcome::Failed(SocketError::ConnectionRefused))
                );
            });
        }
    });
    let start = hook.len();
    assert_eq!(
        send_datagram(&process, socket, b"refused", SendFlags::NONE, None),
        Ok(SocketOutcome::Completed(7))
    );
    let handled = hook.wait_for_harvest_handled(start, |token| token & UDP_EVENT_TOKEN_FLAG != 0);
    hook.stop();
    assert!(receiver.lock().unwrap().is_none());
    assert_eq!(handled, Dispatch::Applied);
    assert!(
        !process
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::ERROR)
    );

    // Consuming the error rearmed the endpoint for input, so the queued
    // datagram raises READ again.
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    let mut payload = [0; 6];
    assert_eq!(
        receive_datagram_into(&process, socket, &mut payload, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 6,
            datagram_length: 6,
            source_address: gateway,
        }))
    );
    assert_eq!(&payload, b"queued");
    let host = UdpSocket::bind(host_address).unwrap();
    host.send_to(b"later", endpoint).unwrap();
    wait_until_ready(&process, &publications, socket, ReadinessFlags::READ);
    let mut payload = [0; 5];
    assert_eq!(
        receive_datagram_into(&process, socket, &mut payload, ReceiveFromFlags::NONE),
        Ok(SocketOutcome::Completed(PlatformDatagramReceive {
            received: 5,
            datagram_length: 5,
            source_address: gateway,
        }))
    );
    assert_eq!(&payload, b"later");
}

/// Internal datagrams sent while their receiver receives and closes are
/// each delivered or dropped, and every queue and source counter returns to
/// zero.
#[test]
fn guest_udp_send_racing_receive_and_close_releases_all_accounting() {
    let provider = Arc::new(UserlandSocketProvider::new(2, 1).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(4, 0, 2, 1),
        provider.clone(),
    )
    .unwrap();
    let sender_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let receiver_process = broker
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, _publications) = channel();
    let (retired, retirements) = channel();
    let readiness = Arc::new(TestReadinessSink { published, retired });
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18090);
    let receiver = create_udp_socket(&receiver_process, readiness.clone());
    assert_eq!(
        litebox_broker_core::socket::bind(&receiver_process, receiver, address),
        Ok(SocketOutcome::Completed(address))
    );
    let sender = create_udp_socket(&sender_process, readiness);
    let sender_process_id = sender_process.id();
    let delivered = Arc::new(AtomicUsize::new(0));
    let sent = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // An unconnected sender's datagram to an unbound address is dropped, so
    // sends keep completing across the close.
    let sending = {
        let sent = Arc::clone(&sent);
        let stop = Arc::clone(&stop);
        let sender_process = Arc::clone(&sender_process);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                assert_eq!(
                    send_datagram(
                        &sender_process,
                        sender,
                        b"datagram",
                        SendFlags::NONE,
                        Some(address),
                    ),
                    Ok(SocketOutcome::Completed(8))
                );
                sent.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    let receiving = {
        let delivered = Arc::clone(&delivered);
        let receiver_process = Arc::clone(&receiver_process);
        thread::spawn(move || {
            loop {
                match receive_datagram_into(
                    &receiver_process,
                    receiver,
                    &mut [0; 8],
                    ReceiveFromFlags::NONE,
                ) {
                    Ok(SocketOutcome::Completed(datagram)) => {
                        assert_eq!(datagram.received, 8);
                        delivered.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(BrokerError::WouldBlock) => thread::yield_now(),
                    // The close removed the handle.
                    Err(_) => break,
                    outcome => panic!("unexpected receive outcome: {outcome:?}"),
                }
            }
        })
    };
    wait_until(
        || delivered.load(Ordering::Relaxed) > 0,
        "a datagram is delivered",
    );
    receiver_process.close_object_reference(receiver).unwrap();
    // The second send counted after the close started after it.
    let sent_at_close = sent.load(Ordering::Relaxed);
    wait_until(
        || sent.load(Ordering::Relaxed) > sent_at_close + 1,
        "sends continue after the close",
    );
    stop.store(true, Ordering::Relaxed);
    receiving.join().unwrap();
    sending.join().unwrap();
    assert_eq!(retirements.recv_timeout(TEST_TIMEOUT).unwrap(), receiver);
    assert!(delivered.load(Ordering::Relaxed) <= sent.load(Ordering::Relaxed));
    assert_eq!(provider.core.udp_queued_datagram_count(), 0);
    assert!(!provider.core.has_udp_source_accounting(sender_process_id));
}

/// Receives one datagram of `data.len()` bytes, waiting for READ when none is
/// queued.
fn receive_datagram(
    process: &BrokerProcess,
    handle: ObjectHandle,
    publications: &Receiver<(ObjectHandle, ReadinessFlags)>,
    data: &mut [u8],
) {
    loop {
        match receive_datagram_into(process, handle, data, ReceiveFromFlags::NONE) {
            Ok(SocketOutcome::Completed(datagram)) => {
                assert_eq!(datagram.datagram_length, data.len());
                return;
            }
            Err(BrokerError::WouldBlock) => {
                wait_until_ready(process, publications, handle, ReadinessFlags::READ);
            }
            outcome => panic!("unexpected receive outcome: {outcome:?}"),
        }
    }
}

/// Many internal UDP socket pairs exchange datagrams in parallel, and every
/// socket's readiness then settles, including with a datagram left queued.
#[test]
fn many_guest_udp_pairs_exchange_datagrams_in_parallel() {
    const PAIRS: u16 = 8;
    const ROUNDS: u8 = 64;
    let provider = Arc::new(UserlandSocketProvider::new(2 * usize::from(PAIRS), 2).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(4 * usize::from(PAIRS), 0, 2 * usize::from(PAIRS), 2),
        provider.clone(),
    )
    .unwrap();
    let workers: Vec<_> = (0..PAIRS)
        .map(|index| {
            let process = broker
                .create_process(CallerCredential::Unauthenticated, None)
                .unwrap();
            let (published, publications) = channel();
            let (retired, _retirements) = channel();
            let readiness = Arc::new(TestReadinessSink { published, retired });
            let addresses = [
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18100 + 2 * index),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18101 + 2 * index),
            ];
            let sockets = addresses.map(|address| {
                let socket = create_udp_socket(&process, readiness.clone());
                assert_eq!(
                    litebox_broker_core::socket::bind(&process, socket, address),
                    Ok(SocketOutcome::Completed(address))
                );
                socket
            });
            thread::spawn(move || {
                for round in 0..ROUNDS {
                    let message = [round; 256];
                    let mut data = [0; 256];
                    for (from, to) in [(0, 1), (1, 0)] {
                        assert_eq!(
                            send_datagram(
                                &process,
                                sockets[from],
                                &message,
                                SendFlags::NONE,
                                Some(addresses[to]),
                            ),
                            Ok(SocketOutcome::Completed(message.len()))
                        );
                        receive_datagram(&process, sockets[to], &publications, &mut data);
                        assert_eq!(data, message);
                    }
                }
                assert_eq!(
                    send_datagram(
                        &process,
                        sockets[0],
                        b"left",
                        SendFlags::NONE,
                        Some(addresses[1]),
                    ),
                    Ok(SocketOutcome::Completed(4))
                );
                (process, sockets, readiness)
            })
        })
        .collect();
    let pairs: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    wait_for_settled_readiness(&provider);
    for (process, sockets, _) in &pairs {
        assert!(
            process
                .check_readiness(sockets[1])
                .unwrap()
                .contains(ReadinessFlags::READ)
        );
    }
    assert_eq!(
        provider.core.udp_queued_datagram_count(),
        usize::from(PAIRS)
    );
    drop(pairs);
}
