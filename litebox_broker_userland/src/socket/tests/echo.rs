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
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(*policy),
        BrokerCoreLimits::new_with_all_limits(2, 0, 1, 1),
        Arc::new(UserlandSocketProvider::new(1, 1).unwrap()),
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
            assert!(
                process
                    .check_readiness(handle)
                    .unwrap()
                    .contains(ReadinessFlags::READ)
            );
            let mut short = [0; 5];
            assert_eq!(
                receive_datagram_into(process, handle, &mut short, ReceiveFromFlags::PEEK),
                Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                    received: 5,
                    datagram_length: REPLY.len(),
                    source_address: peer,
                }))
            );
            assert_eq!(short, REPLY[..5]);
            let mut full = [0; REPLY.len()];
            assert_eq!(
                receive_datagram_into(process, handle, &mut full, ReceiveFromFlags::NONE),
                Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                    received: REPLY.len(),
                    datagram_length: REPLY.len(),
                    source_address: peer,
                }))
            );
            assert_eq!(full, REPLY);
            assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
            assert_eq!(
                receive_datagram_into(process, handle, &mut full, ReceiveFromFlags::NONE),
                Err(BrokerError::NonBlockingWouldBlock)
            );
        }
    });
}

#[test]
fn echo_rejects_non_requests_and_does_not_answer_external_addresses() {
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
#[test]
fn echo_gateway_uses_linux_ping_socket_or_fails_without_a_reply() {
    let rule = litebox_broker_core::IcmpEchoDestinationRule {
        caller_credential: CallerCredential::Unauthenticated,
        destination: Ipv4Cidr::new(Ipv4Address(HOST_GATEWAY_IPV4_ADDRESS.octets()), 32).unwrap(),
    };
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
        let result = send_datagram(process, handle, &REQUEST, SendFlags::NONE, Some(peer));
        if Socket::ping().is_err_and(Errno::ping_unavailable) {
            assert_eq!(
                result,
                Ok(SocketOutcome::Failed(SocketError::UnsupportedOperation))
            );
            assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
            return;
        }
        assert_eq!(result, Ok(SocketOutcome::Completed(REQUEST.len())));
        // The authorized gateway maps to host loopback, not a public test service.
        if std::fs::read_to_string("/proc/sys/net/ipv4/icmp_echo_ignore_all")
            .is_ok_and(|s| s.trim() == "1")
        {
            return;
        }
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
    });
}
