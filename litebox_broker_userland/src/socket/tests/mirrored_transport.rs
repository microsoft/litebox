// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! How mirrored sockets meet the host: which addresses are its own, what its routes select, and
//! when its sockets listen.

use super::*;
#[cfg(target_os = "linux")]
use crate::publish::{Networking, parse_ipv4_cidr};
#[cfg(target_os = "linux")]
use litebox_broker_core::socket::AcceptedBrokerSocket;
#[cfg(target_os = "linux")]
use std::net::TcpStream;

/// A guest process whose provider mirrors its sockets on the host.
#[cfg(target_os = "linux")]
struct Guest {
    provider: Arc<UserlandSocketProvider>,
    process: Arc<BrokerProcess>,
    readiness: Arc<TestReadinessSink>,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
}

/// Starts a guest whose TCP listeners admit host clients from `tcp_sources`, and whose connects
/// `policy` authorizes.
#[cfg(target_os = "linux")]
fn guest(tcp_sources: &[&str], policy: &SocketPolicy) -> Guest {
    let networking = Networking::Mirrored {
        tcp_sources: tcp_sources
            .iter()
            .map(|source| parse_ipv4_cidr(source).unwrap())
            .collect(),
        udp_sources: Vec::new(),
    };
    let provider = Arc::new(UserlandSocketProvider::with_networking(8, 8, networking).unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()).with_socket_policy(*policy),
        BrokerCoreLimits::new_with_all_limits(16, 0, 8, 8),
        Arc::clone(&provider),
    )
    .unwrap();
    let (published, publications) = channel();
    let (retired, _) = channel();
    Guest {
        provider,
        process: broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap(),
        readiness: Arc::new(TestReadinessSink { published, retired }),
        publications,
    }
}

#[cfg(target_os = "linux")]
impl Guest {
    /// A new socket, with the SO_REUSEADDR option if `reuse`.
    fn socket(&self, reuse: bool) -> ObjectHandle {
        let socket = create_socket(&self.process, self.readiness.clone());
        let reuse = SocketOptionValue::ReuseAddress(reuse);
        litebox_broker_core::socket::set_option(&self.process, socket, reuse).unwrap();
        socket
    }

    fn bind(&self, socket: ObjectHandle, address: SocketAddrV4) -> SocketOutcome<SocketAddrV4> {
        litebox_broker_core::socket::bind(&self.process, socket, address).unwrap()
    }

    fn listen(&self, socket: ObjectHandle) -> SocketOutcome<SocketAddrV4> {
        litebox_broker_core::socket::listen(&self.process, socket, 4).unwrap()
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
        let read = ReadinessFlags::READ;
        wait_until_ready(&self.process, &self.publications, listener, read);
        let (flags, readiness) = (FileOpenFlags::NONE, self.readiness.clone());
        match litebox_broker_core::socket::accept(&self.process, listener, flags, readiness) {
            Ok(SocketOutcome::Completed(accepted)) => accepted,
            Ok(SocketOutcome::Failed(error)) => panic!("the accept failed: {error:?}"),
            Err(error) => panic!("the accept failed: {error:?}"),
        }
    }

    fn local_name(&self, socket: ObjectHandle) -> SocketAddrV4 {
        litebox_broker_core::socket::get_name(&self.process, socket, false)
            .unwrap()
            .unwrap()
    }
}

/// Whether `token` is a mirrored listener's.
#[cfg(target_os = "linux")]
fn listener_token(token: u64) -> bool {
    token & LISTENER_EVENT_TOKEN_FLAG != 0
}

#[test]
fn hosts_own_their_addresses_and_no_others() {
    let remote = Ipv4Addr::new(192, 0, 2, 1);
    assert_eq!(Socket::owns_address(remote), Ok(false));
    for group in [Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::BROADCAST] {
        assert_eq!(Socket::owns_address(group), Ok(false), "{group}");
    }
    if let Some(address) = non_loopback_local_ipv4() {
        assert_eq!(Socket::owns_address(address), Ok(true), "{address}");
    }
}

/// A listener at the wildcard address serves each of the host's addresses, including a secondary
/// one, to which the host's route selects the primary as the source; a guest socket connecting
/// from the wildcard address does so from that source, whichever listener serves it. An address
/// that a socket may bind but no route sends from is not the host's, so policy decides.
#[cfg(target_os = "linux")]
#[test]
fn mirrored_connects_reach_guest_listeners_at_every_host_address() {
    let path = "mirrored_transport::mirrored_connects_reach_guest_listeners_at_every_host_address";
    in_network_namespace(path, || {
        let (primary, secondary) = (
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(198, 51, 100, 2),
        );
        ip("link set lo up");
        ip("addr add 198.51.100.1/24 dev lo");
        ip("addr add 198.51.100.2/24 dev lo");
        std::fs::write("/proc/sys/net/ipv4/ip_nonlocal_bind", "1").unwrap();
        let guest = guest(&[], &SocketPolicy::guest_network());
        let wildcard = guest.socket(false);
        let SocketOutcome::Completed(wildcard_address) = guest.listen(wildcard) else {
            panic!("the listen failed");
        };
        let exact = guest.socket(false);
        let SocketOutcome::Completed(exact_address) =
            guest.bind(exact, SocketAddrV4::new(secondary, 0))
        else {
            panic!("the bind failed");
        };
        assert_eq!(guest.listen(exact), SocketOutcome::Completed(exact_address));
        let connected = SocketOutcome::Completed(SocketConnectionStatus::Connected);
        for (listener, destination) in [
            (
                wildcard,
                SocketAddrV4::new(secondary, wildcard_address.port()),
            ),
            (exact, exact_address),
        ] {
            let connector = guest.socket(false);
            assert_eq!(guest.connect(connector, destination), connected);
            let source = guest.local_name(connector);
            assert_eq!(*source.ip(), primary);
            let accepted = guest.accept(listener);
            assert_eq!(
                (accepted.local_address, accepted.remote_address),
                (destination, source)
            );
        }
        let remote = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), wildcard_address.port());
        assert_eq!(
            guest.connect(guest.socket(false), remote),
            SocketOutcome::Failed(SocketError::PolicyDenied)
        );
    });
}

/// The host withholds a privileged port from the broker, as policy would from the guest.
#[cfg(target_os = "linux")]
#[test]
fn mirrored_binds_of_ports_the_host_withholds_are_denied() {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    match TcpListener::bind(address) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        bound => {
            eprintln!("skipped: the host lets the broker bind {address}: {bound:?}");
            return;
        }
    }
    let guest = guest(&[], &SocketPolicy::guest_network());
    let socket = guest.socket(false);
    assert_eq!(
        guest.bind(socket, address),
        SocketOutcome::Failed(SocketError::PolicyDenied)
    );
    assert!(matches!(
        guest.bind(socket, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        SocketOutcome::Completed(_)
    ));
}

/// A mirrored listener's host socket is watched before it listens, so that no host client
/// reaches a listener that a failed watch would leave unwatched.
#[cfg(target_os = "linux")]
#[test]
fn mirrored_listeners_are_watched_before_they_listen() {
    let guest = guest(&["127.0.0.0/8"], &SocketPolicy::guest_network());
    let hook = TestHook::install(&guest.provider);
    let listener = guest.socket(false);
    let SocketOutcome::Completed(address) =
        guest.bind(listener, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    let refused = Arc::new(Mutex::new(None));
    hook.act({
        let refused = Arc::clone(&refused);
        move |_, _, point| {
            if matches!(point, HookPoint::Watched(token) if listener_token(token)) {
                let kind = TcpStream::connect(address).map_err(|error| error.kind());
                *refused.lock().unwrap() = Some(kind.err());
            }
        }
    });
    assert_eq!(guest.listen(listener), SocketOutcome::Completed(address));
    hook.stop();
    assert_eq!(
        *refused.lock().unwrap(),
        Some(Some(std::io::ErrorKind::ConnectionRefused))
    );
    let client = TcpStream::connect(address).unwrap();
    let accepted = guest.accept(listener);
    assert_eq!(
        accepted.remote_address,
        socket_address_v4(client.local_addr().unwrap())
    );
}

/// The events of a host socket watched for a listen that then failed describe a socket that does
/// not listen, which polls as writable and hung up; they do not complete the connect the socket
/// starts next.
#[cfg(target_os = "linux")]
#[test]
fn events_from_before_a_failed_mirrored_listen_do_not_complete_a_connect() {
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination = socket_address_v4(server.local_addr().unwrap());
    let guest = guest(&[], &policy_permitting(&[destination]));
    let hook = TestHook::install(&guest.provider);
    let socket = guest.socket(true);
    let SocketOutcome::Completed(bound) =
        guest.bind(socket, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    // The standard library reuses addresses too, so a host listener shares the guest's port, and
    // the guest's listen fails.
    let _host = TcpListener::bind(bound).unwrap();
    // The listen waits for the event thread to take its host socket's first event, which the
    // event thread then holds until the connect started, and holds again once it handled it.
    let released = Arc::new(AtomicUsize::new(0));
    hook.act({
        let released = Arc::clone(&released);
        move |hook, _, point| {
            let held = match point {
                HookPoint::Watched(token) if listener_token(token) => {
                    // The event thread can receive the event before the watch reports itself.
                    hook.wait_for(0, |point| point == HookPoint::Received(token));
                    return;
                }
                HookPoint::Received(token) if listener_token(token) => 1,
                HookPoint::Handled(token, _) if listener_token(token) => 2,
                _ => return,
            };
            let deadline = Instant::now() + TEST_TIMEOUT;
            while released.load(Ordering::Acquire) < held {
                assert!(
                    Instant::now() < deadline,
                    "the test did not release the event"
                );
                thread::yield_now();
            }
        }
    });
    assert_eq!(
        guest.listen(socket),
        SocketOutcome::Failed(SocketError::AddressInUse)
    );
    let start = hook.len();
    assert_eq!(
        guest.connect(socket, destination),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    released.store(1, Ordering::Release);
    hook.wait_for(
        start,
        |point| matches!(point, HookPoint::Handled(token, _) if listener_token(token)),
    );
    let status = litebox_broker_core::socket::status(&guest.process, socket).unwrap();
    assert_eq!(status.status, SocketConnectionStatus::Connecting);
    assert!(
        !guest
            .process
            .check_readiness(socket)
            .unwrap()
            .contains(ReadinessFlags::WRITE)
    );
    released.store(2, Ordering::Release);
    hook.stop();
    wait_until_connected(&guest.process, socket, &guest.publications);
    let (_server, client) = server.accept().unwrap();
    assert_eq!(socket_address_v4(client), bound);
}

/// A loopback address at a port that no socket uses.
#[cfg(target_os = "linux")]
fn unused_loopback_address() -> SocketAddrV4 {
    socket_address_v4(
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap(),
    )
}

#[cfg(target_os = "linux")]
impl Guest {
    fn close(&self, socket: ObjectHandle) {
        self.process.close_object_reference(socket).unwrap();
    }

    fn shutdown(&self, socket: ObjectHandle, mode: ShutdownMode) -> SocketOutcome<()> {
        litebox_broker_core::socket::shutdown(&self.process, socket, mode).unwrap()
    }
}

/// Whether a host socket can bind `address`, as one that reuses addresses.
#[cfg(target_os = "linux")]
fn host_can_bind(address: SocketAddrV4) -> bool {
    TcpListener::bind(address).is_ok()
}

/// The pair of addresses of an in-memory connection stays taken until both of its ends close,
/// whichever closes first once the listener accepted it.
#[cfg(target_os = "linux")]
#[test]
fn an_accepted_in_memory_connection_names_its_pair_until_both_ends_close() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let listener = guest.socket(false);
    let SocketOutcome::Completed(address) = guest.listen(listener) else {
        panic!("the listen failed");
    };
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port());
    let connected = SocketOutcome::Completed(SocketConnectionStatus::Connected);
    let taken = SocketOutcome::Failed(SocketError::AddressNotAvailable);
    for connector_closes_first in [true, false] {
        let first = guest.socket(true);
        let SocketOutcome::Completed(bound) =
            guest.bind(first, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        else {
            panic!("the bind failed");
        };
        let second = guest.socket(true);
        assert_eq!(guest.bind(second, bound), SocketOutcome::Completed(bound));
        assert_eq!(guest.connect(first, destination), connected);
        let accepted = guest.accept(listener).handle;
        let (earlier, later) = if connector_closes_first {
            (first, accepted)
        } else {
            (accepted, first)
        };
        guest.close(earlier);
        assert_eq!(guest.connect(second, destination), taken);
        guest.close(later);
        assert_eq!(guest.connect(second, destination), connected);
        guest.close(guest.accept(listener).handle);
        guest.close(second);
    }
}

/// `SO_REUSEADDR` set after a bind lets later binds share the port, whether the guest socket's
/// host socket holds it or its in-memory connection does.
#[cfg(target_os = "linux")]
#[test]
fn reuse_address_set_after_a_mirrored_bind_shares_the_port() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let listener = guest.socket(false);
    let SocketOutcome::Completed(address) = guest.listen(listener) else {
        panic!("the listen failed");
    };
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port());
    let reuse = SocketOptionValue::ReuseAddress(true);
    for connects in [false, true] {
        let socket = guest.socket(false);
        let SocketOutcome::Completed(bound) =
            guest.bind(socket, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        else {
            panic!("the bind failed");
        };
        if connects {
            assert_eq!(
                guest.connect(socket, destination),
                SocketOutcome::Completed(SocketConnectionStatus::Connected)
            );
        }
        let other = guest.socket(true);
        assert_eq!(
            guest.bind(other, bound),
            SocketOutcome::Failed(SocketError::AddressInUse)
        );
        litebox_broker_core::socket::set_option(&guest.process, socket, reuse).unwrap();
        let name = SocketOptionName::ReuseAddress;
        let value = litebox_broker_core::socket::get_option(&guest.process, socket, name);
        assert_eq!(value, Ok(reuse));
        assert_eq!(guest.bind(other, bound), SocketOutcome::Completed(bound));
        guest.close(other);
        guest.close(socket);
    }
}

/// A listener that stops listening refuses clients from then on, and keeps a port the guest
/// named until it closes, but not one the host chose.
#[cfg(target_os = "linux")]
#[test]
fn a_stopped_mirrored_listener_keeps_only_a_port_the_guest_named() {
    let guest = guest(&["127.0.0.0/8"], &SocketPolicy::guest_network());
    for named in [true, false] {
        let requested = if named {
            unused_loopback_address()
        } else {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
        };
        let listener = guest.socket(false);
        let SocketOutcome::Completed(address) = guest.bind(listener, requested) else {
            panic!("the bind failed");
        };
        assert_eq!(guest.listen(listener), SocketOutcome::Completed(address));
        assert_eq!(
            guest.shutdown(listener, ShutdownMode::StopListening),
            SocketOutcome::Completed(())
        );
        let refused = TcpStream::connect(address).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
        let connector = guest.socket(false);
        assert_eq!(
            guest.connect(connector, address),
            SocketOutcome::Failed(SocketError::ConnectionRefused)
        );
        guest.close(connector);
        assert_eq!(host_can_bind(address), !named, "{address}");
        guest.close(listener);
        wait_until(|| host_can_bind(address), "the listener's port is released");
    }
}

/// Once a listener closes, the connections it accepted in memory hold its port, at every host
/// address for a wildcard listener, though no client reaches it; their connectors do not.
#[cfg(target_os = "linux")]
#[test]
fn in_memory_connections_a_closed_listener_accepted_hold_its_port() {
    let guest = guest(&["127.0.0.0/8"], &SocketPolicy::guest_network());
    let listener = guest.socket(false);
    let SocketOutcome::Completed(address) = guest.listen(listener) else {
        panic!("the listen failed");
    };
    assert!(address.ip().is_unspecified());
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port());
    let mut connections = Vec::new();
    for _ in 0..2 {
        let connector = guest.socket(false);
        assert_eq!(
            guest.connect(connector, destination),
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        );
        connections.push((connector, guest.accept(listener).handle));
    }
    guest.close(listener);
    let refused = TcpStream::connect(destination).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(
        guest.connect(guest.socket(false), destination),
        SocketOutcome::Failed(SocketError::ConnectionRefused)
    );
    let [
        (first_connector, first_accepted),
        (_second_connector, second_accepted),
    ] = connections[..]
    else {
        unreachable!();
    };
    guest.close(first_connector);
    assert!(!host_can_bind(destination));
    guest.close(first_accepted);
    assert!(!host_can_bind(destination));
    guest.close(second_accepted);
    wait_until(
        || host_can_bind(destination),
        "the listener's port is released",
    );
}

/// Aborting a connect the host has yet to complete keeps the port the guest named until the
/// socket closes.
#[cfg(target_os = "linux")]
#[test]
fn an_aborted_mirrored_connect_keeps_a_port_the_guest_named() {
    // A listener whose queue is full drops further connects' first segments, so they stay
    // pending.
    let server = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        None,
    )
    .unwrap();
    rustix::net::bind(&server, &SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    rustix::net::listen(&server, 0).unwrap();
    let server = TcpListener::from(server);
    let destination = socket_address_v4(server.local_addr().unwrap());
    let _queued = TcpStream::connect(destination).unwrap();
    let mut queue = [rustix::event::PollFd::new(
        &server,
        rustix::event::PollFlags::IN,
    )];
    let timeout = rustix::event::Timespec {
        tv_sec: TEST_TIMEOUT.as_secs().try_into().unwrap(),
        tv_nsec: 0,
    };
    assert_eq!(rustix::event::poll(&mut queue, Some(&timeout)), Ok(1));
    let guest = guest(&[], &policy_permitting(&[destination]));
    let socket = guest.socket(false);
    let SocketOutcome::Completed(bound) = guest.bind(socket, unused_loopback_address()) else {
        panic!("the bind failed");
    };
    assert_eq!(
        guest.connect(socket, destination),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    assert_eq!(
        guest.shutdown(socket, ShutdownMode::Both),
        SocketOutcome::Completed(())
    );
    assert!(!host_can_bind(bound));
    guest.close(socket);
    wait_until(|| host_can_bind(bound), "the socket's port is released");
}

/// A policy whose rules let the guest connect through the host to `destinations`.
#[cfg(target_os = "linux")]
fn policy_permitting(destinations: &[SocketAddrV4]) -> SocketPolicy {
    let rules: Vec<_> = destinations
        .iter()
        .map(|destination| {
            let network = Ipv4Cidr::new(Ipv4Address(destination.ip().octets()), 32).unwrap();
            let port = Port(destination.port());
            DestinationRule::new(
                CallerCredential::Unauthenticated,
                network,
                DestinationPortRange::new(port, port).unwrap(),
            )
        })
        .collect();
    SocketPolicy::guest_network()
        .with_tcp_destination_rules(&rules)
        .unwrap()
}

/// A connection takes its pair of addresses in either direction: a socket at its destination
/// cannot connect back to its source while it lives.
#[cfg(target_os = "linux")]
#[test]
fn a_mirrored_connection_takes_its_pair_in_either_direction() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    // A listener, and a socket sharing its port that connects to the other listener.
    let ends = [(); 2].map(|()| {
        let listener = guest.socket(true);
        let SocketOutcome::Completed(address) =
            guest.bind(listener, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        else {
            panic!("the bind failed");
        };
        let connector = guest.socket(true);
        assert_eq!(
            guest.bind(connector, address),
            SocketOutcome::Completed(address)
        );
        assert_eq!(guest.listen(listener), SocketOutcome::Completed(address));
        (listener, connector, address)
    });
    let [
        (first_listener, first, first_address),
        (second_listener, second, second_address),
    ] = ends;
    let connected = SocketOutcome::Completed(SocketConnectionStatus::Connected);
    assert_eq!(guest.connect(first, second_address), connected);
    let accepted = guest.accept(second_listener).handle;
    assert_eq!(
        guest.connect(second, first_address),
        SocketOutcome::Failed(SocketError::AddressNotAvailable)
    );
    guest.close(first);
    guest.close(accepted);
    assert_eq!(guest.connect(second, first_address), connected);
    guest.close(guest.accept(first_listener).handle);
}

/// A connection through the host takes its pair of addresses from in-memory connections, and an
/// in-memory connection its pair from connections through the host.
#[cfg(target_os = "linux")]
#[test]
fn mirrored_connections_in_memory_and_through_the_host_take_distinct_pairs() {
    let taken = SocketOutcome::Failed(SocketError::AddressNotAvailable);
    // Through the host first: a host listener accepts the guest's connection, and then gives way
    // to a guest listener, which shares its port with the accepted connection, as both reuse it.
    let host = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination = socket_address_v4(host.local_addr().unwrap());
    let guest = guest(&[], &policy_permitting(&[destination]));
    let first = guest.socket(true);
    let SocketOutcome::Completed(source) =
        guest.bind(first, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    assert!(matches!(
        guest.connect(first, destination),
        SocketOutcome::Completed(
            SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
        )
    ));
    let (_accepted, peer) = host.accept().unwrap();
    assert_eq!(socket_address_v4(peer), source);
    drop(host);
    let listener = guest.socket(true);
    assert_eq!(
        guest.bind(listener, destination),
        SocketOutcome::Completed(destination)
    );
    assert_eq!(
        guest.listen(listener),
        SocketOutcome::Completed(destination)
    );
    let second = guest.socket(true);
    assert_eq!(guest.bind(second, source), SocketOutcome::Completed(source));
    assert_eq!(guest.connect(second, destination), taken);
    guest.close(first);
    guest.close(second);

    // In memory first: once its listener closed, a connect through the host from the wildcard
    // address finds the pair its route would name taken.
    let first = guest.socket(true);
    let SocketOutcome::Completed(source) =
        guest.bind(first, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    assert_eq!(
        guest.connect(first, destination),
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    let accepted = guest.accept(listener).handle;
    guest.close(listener);
    let second = guest.socket(true);
    let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, source.port());
    assert_eq!(
        guest.bind(second, wildcard),
        SocketOutcome::Completed(wildcard)
    );
    assert_eq!(guest.connect(second, destination), taken);
    guest.close(accepted);
    guest.close(first);
    guest.close(second);
}

/// A wildcard native connect takes its source from TCP, not from a UDP route that might name
/// the same pair as a draining in-memory connection.
#[cfg(target_os = "linux")]
#[test]
fn mirrored_wildcard_connect_checks_the_source_tcp_actually_chooses() {
    let path =
        "mirrored_transport::mirrored_wildcard_connect_checks_the_source_tcp_actually_chooses";
    in_network_namespace(path, || {
        ip("link set lo up");
        ip("addr add 127.0.0.2/32 dev lo");
        ip("route add local 127.0.0.3/32 dev lo src 127.0.0.2 table 100");
        ip("rule add priority 100 lookup local");
        ip("rule del priority 0 lookup local");
        ip("rule add priority 50 ipproto udp lookup 100");
        // The later wildcard bind must not also overlap the native listener. This namespace
        // belongs only to the test, so use two distinct ports.
        let destination = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), 40123);
        let guest = guest(&[], &policy_permitting(&[destination]));
        let listener = guest.socket(true);
        assert_eq!(
            guest.bind(listener, destination),
            SocketOutcome::Completed(destination)
        );
        assert_eq!(
            guest.listen(listener),
            SocketOutcome::Completed(destination)
        );
        let first = guest.socket(true);
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        udp.connect(destination).unwrap();
        let udp_ip = *socket_address_v4(udp.local_addr().unwrap()).ip();
        assert_eq!(udp_ip, Ipv4Addr::new(127, 0, 0, 2));
        let SocketOutcome::Completed(first_source) =
            guest.bind(first, SocketAddrV4::new(udp_ip, 40124))
        else {
            panic!("the bind failed");
        };
        assert_eq!(
            guest.connect(first, destination),
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        );
        let _child = guest.accept(listener);
        guest.close(listener);

        let host = TcpListener::bind(destination).unwrap();
        let second = guest.socket(true);
        let wildcard = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, first_source.port());
        assert_eq!(
            guest.bind(second, wildcard),
            SocketOutcome::Completed(wildcard)
        );
        assert!(matches!(
            guest.connect(second, destination),
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        ));
        let (_client, peer) = host.accept().unwrap();
        assert_eq!(
            socket_address_v4(peer),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, wildcard.port())
        );
    });
}

/// Only the guest sockets still open that name a port refuse to share it: once a listener that
/// refuses closes, a connection it accepted that shares lets other sockets share the port.
#[cfg(target_os = "linux")]
#[test]
fn a_closed_mirrored_listener_s_refusal_to_share_its_port_ends() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let listener = guest.socket(false);
    let SocketOutcome::Completed(address) =
        guest.bind(listener, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    assert_eq!(guest.listen(listener), SocketOutcome::Completed(address));
    let connector = guest.socket(false);
    assert_eq!(
        guest.connect(connector, address),
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    let accepted = guest.accept(listener).handle;
    let reuse = SocketOptionValue::ReuseAddress(true);
    litebox_broker_core::socket::set_option(&guest.process, accepted, reuse).unwrap();
    let other = guest.socket(true);
    assert_eq!(
        guest.bind(other, address),
        SocketOutcome::Failed(SocketError::AddressInUse)
    );
    guest.close(listener);
    assert_eq!(
        guest.bind(other, address),
        SocketOutcome::Completed(address)
    );
    guest.close(other);
    guest.close(connector);
    guest.close(accepted);
}

/// A directed broadcast address on the loopback interface is not the host's own, so no guest
/// listener serves it.
#[cfg(target_os = "linux")]
#[test]
fn guest_listeners_do_not_serve_a_directed_broadcast() {
    let directed = Ipv4Addr::new(127, 255, 255, 255);
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let refused = probe.connect((directed, 9));
    probe.set_broadcast(true).unwrap();
    if !refused.is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
        || probe.connect((directed, 9)).is_err()
    {
        eprintln!("skipped: {directed} is not a directed broadcast on this host");
        return;
    }
    assert_eq!(Socket::owns_address(directed), Ok(false));
    let guest = guest(&[], &SocketPolicy::guest_network());
    let listener = guest.socket(false);
    let SocketOutcome::Completed(address) = guest.listen(listener) else {
        panic!("the listen failed");
    };
    assert_eq!(
        guest.connect(
            guest.socket(false),
            SocketAddrV4::new(directed, address.port())
        ),
        SocketOutcome::Failed(SocketError::PolicyDenied)
    );
}

/// An address that a socket may bind but no route sends from is not the host's: a listener bound
/// to it serves no connect, and a socket bound to it connects to no listener.
#[cfg(target_os = "linux")]
#[test]
fn mirrored_sockets_at_addresses_the_host_does_not_own_meet_no_listener() {
    let path =
        "mirrored_transport::mirrored_sockets_at_addresses_the_host_does_not_own_meet_no_listener";
    in_network_namespace(path, || {
        ip("link set lo up");
        std::fs::write("/proc/sys/net/ipv4/ip_nonlocal_bind", "1").unwrap();
        let guest = guest(&[], &SocketPolicy::guest_network());
        let exact = guest.socket(false);
        let nonlocal = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 0);
        let SocketOutcome::Completed(exact_address) = guest.bind(exact, nonlocal) else {
            panic!("the bind failed");
        };
        assert_eq!(guest.listen(exact), SocketOutcome::Completed(exact_address));
        assert_eq!(
            guest.connect(guest.socket(false), exact_address),
            SocketOutcome::Failed(SocketError::PolicyDenied)
        );
        let wildcard = guest.socket(false);
        let SocketOutcome::Completed(wildcard_address) = guest.listen(wildcard) else {
            panic!("the listen failed");
        };
        let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, wildcard_address.port());
        let connector = guest.socket(false);
        let nonlocal = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 0);
        assert!(matches!(
            guest.bind(connector, nonlocal),
            SocketOutcome::Completed(_)
        ));
        for _ in 0..2 {
            assert_eq!(
                guest.connect(connector, destination),
                SocketOutcome::Failed(SocketError::NetworkUnreachable)
            );
        }
    });
}

/// A listener refuses a host client whose pair of addresses an in-memory connection holds, which
/// the host does not know of, and accepts the clients after it.
#[cfg(target_os = "linux")]
#[test]
fn mirrored_listeners_refuse_host_clients_at_the_pairs_of_in_memory_connections() {
    let guest = guest(&["127.0.0.0/8"], &SocketPolicy::guest_network());
    let listener = guest.socket(true);
    let SocketOutcome::Completed(destination) =
        guest.bind(listener, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    assert_eq!(
        guest.listen(listener),
        SocketOutcome::Completed(destination)
    );
    let connector = guest.socket(true);
    let SocketOutcome::Completed(source) =
        guest.bind(connector, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    assert_eq!(
        guest.connect(connector, destination),
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    let _accepted = guest.accept(listener);
    let colliding = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        None,
    )
    .unwrap();
    rustix::net::sockopt::set_socket_reuseaddr(&colliding, true).unwrap();
    rustix::net::bind(&colliding, &source).unwrap();
    rustix::net::connect(&colliding, &destination).unwrap();
    let mut colliding = TcpStream::from(colliding);
    // The colliding client is queued first, as the listener is ready once the host queues it.
    let ready = ReadinessFlags::READ;
    wait_until_ready(&guest.process, &guest.publications, listener, ready);
    let other = TcpStream::connect(destination).unwrap();
    let deadline = Instant::now() + TEST_TIMEOUT;
    let accepted = loop {
        wait_until_ready_until(
            &guest.process,
            &guest.publications,
            listener,
            ready,
            deadline,
        );
        let (flags, readiness) = (FileOpenFlags::NONE, guest.readiness.clone());
        match litebox_broker_core::socket::accept(&guest.process, listener, flags, readiness) {
            Ok(SocketOutcome::Completed(accepted)) => break accepted,
            Ok(SocketOutcome::Failed(error)) => panic!("the accept failed: {error:?}"),
            Err(BrokerError::WouldBlock) => {}
            Err(error) => panic!("the accept failed: {error:?}"),
        }
    };
    assert_eq!(
        accepted.remote_address,
        socket_address_v4(other.local_addr().unwrap())
    );
    colliding.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let reset = colliding.read(&mut [0; 1]).unwrap_err();
    assert_eq!(reset.kind(), std::io::ErrorKind::ConnectionReset);
}

/// A connect through the host whose pair of addresses another connection through the host holds
/// fails as the host fails it, leaving the socket bound for a connect elsewhere.
#[cfg(target_os = "linux")]
#[test]
fn a_mirrored_connect_to_a_taken_pair_leaves_the_socket_bound() {
    let servers = [(); 2].map(|()| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap());
    let destinations = servers
        .each_ref()
        .map(|server| socket_address_v4(server.local_addr().unwrap()));
    let guest = guest(&[], &policy_permitting(&destinations));
    let first = guest.socket(true);
    let SocketOutcome::Completed(source) =
        guest.bind(first, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    let second = guest.socket(true);
    assert_eq!(guest.bind(second, source), SocketOutcome::Completed(source));
    let started = |outcome| {
        matches!(
            outcome,
            SocketOutcome::Completed(
                SocketConnectionStatus::Connecting | SocketConnectionStatus::Connected
            )
        )
    };
    assert!(started(guest.connect(first, destinations[0])));
    assert_eq!(
        guest.connect(second, destinations[0]),
        SocketOutcome::Failed(SocketError::AddressNotAvailable)
    );
    assert!(started(guest.connect(second, destinations[1])));
    let (_accepted, peer) = servers[1].accept().unwrap();
    assert_eq!(socket_address_v4(peer), source);
    assert_eq!(guest.local_name(second), source);
}

/// A connection accepted in memory takes `SO_REUSEADDR` as its listener had it when the connect
/// reached it, as the host's connections take it at their handshake, and shares the listener's
/// port accordingly once the listener closes.
#[cfg(target_os = "linux")]
#[test]
fn in_memory_connections_take_reuse_address_as_their_listener_had_it_at_the_connect() {
    let guest = guest(&[], &SocketPolicy::guest_network());
    let listener = guest.socket(true);
    let SocketOutcome::Completed(address) =
        guest.bind(listener, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    else {
        panic!("the bind failed");
    };
    assert_eq!(guest.listen(listener), SocketOutcome::Completed(address));
    let connector = guest.socket(false);
    assert_eq!(
        guest.connect(connector, address),
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    let exclusive = SocketOptionValue::ReuseAddress(false);
    litebox_broker_core::socket::set_option(&guest.process, listener, exclusive).unwrap();
    let accepted = guest.accept(listener).handle;
    let name = SocketOptionName::ReuseAddress;
    assert_eq!(
        litebox_broker_core::socket::get_option(&guest.process, accepted, name),
        Ok(SocketOptionValue::ReuseAddress(true))
    );
    guest.close(listener);
    let other = guest.socket(true);
    assert_eq!(
        guest.bind(other, address),
        SocketOutcome::Completed(address)
    );
    guest.close(other);
    guest.close(accepted);
    guest.close(connector);
}
