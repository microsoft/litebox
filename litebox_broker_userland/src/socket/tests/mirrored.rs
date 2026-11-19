// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::publish::{Networking, parse_ipv4_cidr};
use litebox_broker_core::socket::AcceptedBrokerSocket;
use std::net::TcpStream;

/// A guest process whose provider mirrors its sockets on the host.
struct Guest {
    process: Arc<BrokerProcess>,
    readiness: Arc<TestReadinessSink>,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
}

/// Starts a guest whose TCP listeners admit host clients from `tcp_sources`, and whose connects
/// `policy` authorizes.
fn guest(tcp_sources: &[&str], policy: &SocketPolicy) -> Guest {
    let networking = Networking::Mirrored {
        tcp_sources: tcp_sources
            .iter()
            .map(|source| parse_ipv4_cidr(source).unwrap())
            .collect(),
        udp_sources: Vec::new(),
    };
    let provider = UserlandSocketProvider::with_networking(8, 8, networking).unwrap();
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(*policy),
        BrokerCoreLimits::new_with_all_limits(16, 0, 8, 8),
        Arc::new(provider),
    )
    .unwrap();
    let (published, publications) = channel();
    let (retired, _) = channel();
    Guest {
        process: broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap(),
        readiness: Arc::new(TestReadinessSink { published, retired }),
        publications,
    }
}

/// Permits TCP connects to `destination` alone.
fn permitting(destination: SocketAddrV4) -> SocketPolicy {
    let network = Ipv4Cidr::new(Ipv4Address(destination.ip().octets()), 32).unwrap();
    let port = Port(destination.port());
    SocketPolicy::guest_network()
        .with_tcp_destination_rules(&[DestinationRule::new(
            CallerCredential::Unauthenticated,
            network,
            DestinationPortRange::new(port, port).unwrap(),
        )])
        .unwrap()
}

/// A loopback port that no socket uses.
fn unused_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Guest {
    fn socket(&self) -> ObjectHandle {
        create_socket(&self.process, self.readiness.clone())
    }

    /// A new socket with the SO_REUSEADDR option, which Windows hosts ignore.
    #[cfg(target_os = "linux")]
    fn reusing_socket(&self) -> ObjectHandle {
        let socket = self.socket();
        let reuse = SocketOptionValue::ReuseAddress(true);
        litebox_broker_core::socket::set_option(&self.process, socket, reuse).unwrap();
        socket
    }

    fn bind(&self, socket: ObjectHandle, address: &str) -> SocketOutcome<SocketAddrV4> {
        litebox_broker_core::socket::bind(&self.process, socket, address.parse().unwrap()).unwrap()
    }

    /// Listens on a new socket, unbound, and returns it and the address it listens at.
    fn listen(&self) -> (ObjectHandle, SocketAddrV4) {
        let listener = self.socket();
        let listening = litebox_broker_core::socket::listen(&self.process, listener, 4);
        let Ok(SocketOutcome::Completed(address)) = listening else {
            panic!("the listen failed: {listening:?}");
        };
        (listener, address)
    }

    fn connect(
        &self,
        socket: ObjectHandle,
        destination: SocketAddrV4,
    ) -> SocketOutcome<SocketConnectionStatus> {
        litebox_broker_core::socket::connect(&self.process, socket, destination).unwrap()
    }

    /// Accepts a connection on `listener`, waiting for one.
    fn accept(&self, listener: ObjectHandle) -> AcceptedBrokerSocket {
        self.wait(listener);
        let (flags, readiness) = (FileOpenFlags::NONE, self.readiness.clone());
        match litebox_broker_core::socket::accept(&self.process, listener, flags, readiness) {
            Ok(SocketOutcome::Completed(accepted)) => accepted,
            Ok(SocketOutcome::Failed(error)) => panic!("the accept failed: {error:?}"),
            Err(error) => panic!("the accept failed: {error:?}"),
        }
    }

    fn wait(&self, socket: ObjectHandle) {
        let read = ReadinessFlags::READ;
        wait_until_ready(&self.process, &self.publications, socket, read);
    }

    fn name(&self, socket: ObjectHandle, peer: bool) -> Option<SocketAddrV4> {
        litebox_broker_core::socket::get_name(&self.process, socket, peer).unwrap()
    }
}

#[test]
fn a_mirrored_bind_is_the_host_s() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let socket = guest.socket();
    for address in ["224.0.0.1:0", "255.255.255.255:0"] {
        assert_eq!(
            guest.bind(socket, address),
            SocketOutcome::Failed(SocketError::AddressNotAvailable)
        );
    }
    // On Linux's usual loopback route this is a directed broadcast, not a local unicast alias.
    let directed = Ipv4Addr::new(127, 255, 255, 255);
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    if probe
        .connect((directed, 9))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
    {
        probe.set_broadcast(true).unwrap();
        if probe.connect((directed, 9)).is_ok() {
            assert_eq!(
                guest.bind(socket, "127.255.255.255:0"),
                SocketOutcome::Failed(SocketError::AddressNotAvailable)
            );
        }
    }
    let SocketOutcome::Completed(bound) = guest.bind(socket, "0.0.0.0:0") else {
        panic!("the bind failed");
    };
    assert_ne!(bound.port(), 0);
    assert_eq!(guest.name(socket, false), Some(bound));
    // The port is the guest's alone.
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, bound.port())).is_err());
    // A port a host socket holds is not the guest's, and a failed bind can be retried.
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let taken_address = socket_address_v4(taken.local_addr().unwrap()).to_string();
    let socket = guest.socket();
    assert_eq!(
        guest.bind(socket, &taken_address),
        SocketOutcome::Failed(SocketError::AddressInUse)
    );
    drop(taken);
    let bound = guest.bind(socket, &taken_address);
    assert_eq!(
        bound,
        SocketOutcome::Completed(taken_address.parse().unwrap())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn mirrored_binds_share_a_port_as_the_guest_s_reuse_address_option_says() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let SocketOutcome::Completed(bound) = guest.bind(guest.reusing_socket(), "127.0.0.1:0") else {
        panic!("the bind failed");
    };
    let address = bound.to_string();
    assert_eq!(
        guest.bind(guest.reusing_socket(), &address),
        SocketOutcome::Completed(bound)
    );
    assert_eq!(
        guest.bind(guest.socket(), &address),
        SocketOutcome::Failed(SocketError::AddressInUse)
    );
}

#[test]
fn a_mirrored_listener_accepts_admitted_host_clients_at_their_real_addresses() {
    let guest = guest(&["127.0.0.0/8"], &SocketPolicy::guest_network());
    // Unbound, the listener binds the wildcard address.
    let (listener, address) = guest.listen();
    assert_eq!(*address.ip(), Ipv4Addr::UNSPECIFIED);
    assert_ne!(address.port(), 0);
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, address.port())).unwrap();
    let accepted = guest.accept(listener);
    assert_eq!(
        (accepted.local_address, accepted.remote_address),
        (
            socket_address_v4(client.peer_addr().unwrap()),
            socket_address_v4(client.local_addr().unwrap()),
        )
    );
    let sent = send_bytes(&guest.process, accepted.handle, b"pong", SendFlags::NONE);
    assert_eq!(sent, Ok(SocketOutcome::Completed(4)));
    let mut answer = [0; 4];
    client.read_exact(&mut answer).unwrap();
    assert_eq!(&answer, b"pong");
}

#[cfg(target_os = "linux")]
#[test]
fn a_failed_mirrored_listen_leaves_the_socket_bound_for_another() {
    let guest = guest(&["127.0.0.0/8"], &SocketPolicy::guest_network());
    let socket = guest.reusing_socket();
    let SocketOutcome::Completed(bound) = guest.bind(socket, "127.0.0.1:0") else {
        panic!("the bind failed");
    };
    // The standard library reuses addresses too, so a host listener shares the guest's port.
    let host = TcpListener::bind(bound).unwrap();
    let listen = || litebox_broker_core::socket::listen(&guest.process, socket, 4);
    assert_eq!(
        listen(),
        Ok(SocketOutcome::Failed(SocketError::AddressInUse))
    );
    drop(host);
    let refused = TcpStream::connect(bound).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(listen(), Ok(SocketOutcome::Completed(bound)));
    let client = TcpStream::connect(bound).unwrap();
    let accepted = guest.accept(socket);
    assert_eq!(
        accepted.remote_address,
        socket_address_v4(client.local_addr().unwrap())
    );
}

#[test]
fn a_mirrored_listener_resets_host_clients_it_does_not_admit() {
    let guest = guest(&["192.0.2.0/24"], &SocketPolicy::guest_network());
    let (listener, address) = guest.listen();
    let client = TcpStream::connect((Ipv4Addr::LOCALHOST, address.port())).unwrap();
    guest.wait(listener);
    let (flags, readiness) = (FileOpenFlags::NONE, guest.readiness.clone());
    let accepted = litebox_broker_core::socket::accept(&guest.process, listener, flags, readiness);
    assert_eq!(accepted.err(), Some(BrokerError::WouldBlock));
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let reset = { &client }.read(&mut [0]).unwrap_err();
    assert_eq!(reset.kind(), std::io::ErrorKind::ConnectionReset);
}

#[test]
fn guest_connections_to_guest_listeners_stay_in_memory_and_hold_their_ports() {
    // No rule permits the connect, and no host client is admitted, so only memory carries it.
    let guest = guest(&[], &SocketPolicy::guest_network());
    let (listener, address) = guest.listen();
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port());
    let connector = guest.socket();
    assert_eq!(
        guest.connect(connector, destination),
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    let source = guest.name(connector, false).unwrap();
    assert_eq!(*source.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(guest.name(connector, true), Some(destination));
    let accepted = guest.accept(listener);
    assert_eq!(
        (accepted.local_address, accepted.remote_address),
        (destination, source)
    );
    let sent = send_bytes(&guest.process, connector, b"ping", SendFlags::NONE);
    assert_eq!(sent, Ok(SocketOutcome::Completed(4)));
    let mut buffer = [0; 4];
    let received = receive_into(
        &guest.process,
        accepted.handle,
        &mut buffer,
        ReceiveFlags::NONE,
        0,
        0,
    );
    assert_eq!(
        received,
        Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(4)))
    );
    // The connector's port stays the guest's until both ends close.
    let held = || TcpListener::bind(source).is_err();
    guest.process.close_object_reference(connector).unwrap();
    assert!(held());
    guest
        .process
        .close_object_reference(accepted.handle)
        .unwrap();
    wait_until(|| !held(), "the connector's port is released");
}

#[cfg(target_os = "linux")]
#[test]
fn guest_connections_sharing_a_port_need_distinct_destinations() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let (listener, address) = guest.listen();
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port());
    let first = guest.reusing_socket();
    let SocketOutcome::Completed(bound) = guest.bind(first, "127.0.0.1:0") else {
        panic!("the bind failed");
    };
    let second = guest.reusing_socket();
    assert_eq!(
        guest.bind(second, &bound.to_string()),
        SocketOutcome::Completed(bound)
    );
    let connected = SocketOutcome::Completed(SocketConnectionStatus::Connected);
    assert_eq!(guest.connect(first, destination), connected);
    // As on the host, the pair of addresses names one connection, and a connect that finds it
    // taken leaves the socket bound for another.
    assert_eq!(
        guest.connect(second, destination),
        SocketOutcome::Failed(SocketError::AddressNotAvailable)
    );
    guest.process.close_object_reference(first).unwrap();
    // The connection's end the listener has yet to accept still names the pair.
    assert_eq!(
        guest.connect(second, destination),
        SocketOutcome::Failed(SocketError::AddressNotAvailable)
    );
    let accepted = guest.accept(listener);
    guest
        .process
        .close_object_reference(accepted.handle)
        .unwrap();
    assert_eq!(guest.connect(second, destination), connected);
    assert_eq!(guest.name(second, false), Some(bound));
}

#[test]
fn mirrored_connects_elsewhere_need_a_rule() {
    let host = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let host_address = socket_address_v4(host.local_addr().unwrap());
    let guest = guest(&[], &permitting(host_address));
    // A host that is not this one is denied, and a port of this one is refused, without a rule.
    // A denial leaves the socket as it was.
    let connector = guest.socket();
    let remote = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), host_address.port());
    assert_eq!(
        guest.connect(connector, remote),
        SocketOutcome::Failed(SocketError::PolicyDenied)
    );
    assert_eq!(guest.name(connector, false), None);
    let SocketOutcome::Completed(source) = guest.bind(connector, "127.0.0.1:0") else {
        panic!("a denied connect kept its automatic bind");
    };
    assert_eq!(
        guest.connect(connector, remote),
        SocketOutcome::Failed(SocketError::PolicyDenied)
    );
    assert_eq!(guest.name(connector, false), Some(source));
    let unserved = SocketAddrV4::new(Ipv4Addr::LOCALHOST, unused_port());
    assert_eq!(
        guest.connect(guest.socket(), unserved),
        SocketOutcome::Failed(SocketError::ConnectionRefused)
    );
    // With one, the guest connects from its own host socket.
    assert!(matches!(
        guest.connect(connector, host_address),
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    wait_until_connected(&guest.process, connector, &guest.publications);
    let (_server, client) = host.accept().unwrap();
    assert_eq!(socket_address_v4(client), source);
    assert_eq!(
        guest.name(connector, false),
        Some(socket_address_v4(client))
    );
}

#[test]
fn address_ownership_not_policy_routing_selects_the_local_listener() {
    let path = "mirrored::address_ownership_not_policy_routing_selects_the_local_listener";
    in_network_namespace(path, || {
        ip("link set lo up");
        let destination_ip = Ipv4Addr::new(127, 0, 0, 2);
        // In this private namespace, blackhole native traffic to the alias before the local
        // routing rule. The alias still belongs to the namespace.
        ip("rule add priority 100 lookup local");
        ip("rule del priority 0 lookup local");
        ip("rule add priority 50 to 127.0.0.2/32 blackhole");
        ip("rule add priority 51 to 127.255.255.255/32 prohibit");
        let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        assert_eq!(
            probe.connect((destination_ip, 9)).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        let guest = guest(&[], &SocketPolicy::guest_network());
        let listener = guest.socket();
        // A flow-specific route hides neither local unicast ownership nor a directed broadcast.
        assert_eq!(
            guest.bind(listener, "127.255.255.255:0"),
            SocketOutcome::Failed(SocketError::AddressNotAvailable)
        );
        let SocketOutcome::Completed(destination) = guest.bind(listener, "127.0.0.2:0") else {
            panic!("a UDP route prevented the bind to a local unicast address");
        };
        assert_eq!(
            litebox_broker_core::socket::listen(&guest.process, listener, 4),
            Ok(SocketOutcome::Completed(destination))
        );
        let connector = guest.socket();
        assert_eq!(
            guest.connect(connector, destination),
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        );
        let accepted = guest.accept(listener);
        assert_eq!(accepted.local_address, destination);
        assert_eq!(*accepted.remote_address.ip(), destination_ip);
    });
}

#[test]
fn mirrored_tcp_does_not_need_a_free_udp_port() {
    let path = "mirrored::mirrored_tcp_does_not_need_a_free_udp_port";
    in_network_namespace(path, || {
        ip("link set lo up");
        std::fs::write("/proc/sys/net/ipv4/ip_local_port_range", "48000 48007").unwrap();
        let _udp_ports: Vec<_> = (48000..=48007)
            .map(|port| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap())
            .collect();
        let guest = guest(&[], &SocketPolicy::guest_network());
        let (listener, bound) = guest.listen();
        let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, bound.port());
        assert_eq!(
            guest.connect(guest.socket(), destination),
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        );
        assert_eq!(guest.accept(listener).local_address, destination);
    });
}

#[test]
fn mirrored_providers_refuse_udp_sockets() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let request = CreateSocketRequest {
        address_family: AddressFamily::Ipv4,
        socket_type: SocketType::Datagram,
        protocol: IpProtocol::Udp,
        flags: FileOpenFlags::NONE,
    };
    let created = litebox_broker_core::socket::create(&guest.process, request, guest.readiness);
    assert_eq!(created.err(), Some(BrokerError::PolicyDenied));
}
