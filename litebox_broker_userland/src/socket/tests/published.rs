// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use std::collections::HashSet;
use std::net::TcpStream;

use litebox_broker_core::socket::{AcceptedBrokerSocket, PublishedTcpPort};

use super::super::published::{MAX_ACCEPTS_PER_EVENT, MAX_QUEUED_PUBLISHED_CONNECTIONS};

const GUEST_PORT: u16 = 8080;

/// A broker whose provider publishes guest ports, and one guest process.
struct PublishedGuest {
    provider: Arc<UserlandSocketProvider>,
    process: Arc<BrokerProcess>,
    readiness: Arc<TestReadinessSink>,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
    retirements: Receiver<ObjectHandle>,
    hook: Arc<TestHook>,
    /// The guest port the host clients reach.
    guest_port: u16,
    /// The host address the clients connect to.
    host_address: SocketAddrV4,
}

/// A broker whose provider publishes [`GUEST_PORT`] on an ephemeral host
/// loopback port.
fn published_guest(max_sockets: usize, max_sockets_per_process: usize) -> PublishedGuest {
    let mut guest = guest_with(
        &HostNetworkOptions {
            published_tcp_ports: vec![PublishedTcpPort {
                host_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                guest_port: GUEST_PORT,
            }],
            ..HostNetworkOptions::default()
        },
        max_sockets,
        max_sockets_per_process,
    );
    guest.host_address = guest.provider.core.published_host_address(0);
    guest
}

/// A broker whose provider publishes each guest listener on the host's
/// loopback address.
fn listener_publishing_guest() -> PublishedGuest {
    guest_with(
        &HostNetworkOptions {
            published_listener_ip: Some(Ipv4Addr::LOCALHOST),
            ..HostNetworkOptions::default()
        },
        8,
        8,
    )
}

fn guest_with(
    options: &HostNetworkOptions,
    max_sockets: usize,
    max_sockets_per_process: usize,
) -> PublishedGuest {
    let provider = Arc::new(
        UserlandSocketProvider::with_host_network(max_sockets, max_sockets_per_process, options)
            .unwrap(),
    );
    let hook = TestHook::install(&provider);
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(
            2 * max_sockets,
            0,
            max_sockets,
            max_sockets_per_process,
        ),
        provider.clone(),
    )
    .unwrap();
    let process = broker
        .create_process(CallerCredential::Unauthenticated)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    PublishedGuest {
        provider,
        process,
        readiness: Arc::new(TestReadinessSink { published, retired }),
        publications,
        retirements,
        hook,
        guest_port: GUEST_PORT,
        host_address: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    }
}

impl PublishedGuest {
    /// Creates a guest TCP listener on `address` with `backlog`.
    fn listen(&self, address: SocketAddrV4, backlog: u32) -> ObjectHandle {
        let listener = create_socket(&self.process, self.readiness.clone());
        assert_eq!(
            litebox_broker_core::socket::bind(&self.process, listener, address),
            Ok(SocketOutcome::Completed(address))
        );
        assert_eq!(
            litebox_broker_core::socket::listen(&self.process, listener, backlog),
            Ok(SocketOutcome::Completed(address))
        );
        listener
    }

    /// Connects `count` host clients, and waits until the provider queued
    /// `queued` of them and reset `reset`; the rest wait in the host's
    /// backlog.
    fn connect_clients(&self, count: usize, queued: usize, reset: usize) -> Vec<TcpStream> {
        let start = self.hook.len();
        let clients = (0..count)
            .map(|_| {
                let client = TcpStream::connect(self.host_address).unwrap();
                client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
                client
            })
            .collect();
        self.wait_for_deliveries(start, queued, reset);
        clients
    }

    /// Waits for `queued` queued and `reset` reset host clients from hook
    /// point `start` on.
    fn wait_for_deliveries(&self, start: usize, queued: usize, reset: usize) {
        let mut next = start;
        let mut outcomes = Vec::new();
        while outcomes.len() < queued + reset {
            let (index, point) = self
                .hook
                .wait_for(next, |point| matches!(point, HookPoint::Published(..)));
            let HookPoint::Published(port, outcome) = point else {
                unreachable!()
            };
            assert_eq!(port, self.guest_port);
            outcomes.push(outcome);
            next = index + 1;
        }
        assert_eq!(
            outcomes.iter().filter(|queued| **queued).count(),
            queued,
            "queued connections"
        );
    }

    fn accept(&self, listener: ObjectHandle) -> BrokerResult<AcceptedBrokerSocket> {
        wait_until_ready(
            &self.process,
            &self.publications,
            listener,
            ReadinessFlags::READ,
        );
        match litebox_broker_core::socket::accept(
            &self.process,
            listener,
            FileOpenFlags::NONE,
            self.readiness.clone(),
        )? {
            SocketOutcome::Completed(accepted) => Ok(accepted),
            SocketOutcome::Failed(error) => panic!("accept failed: {error:?}"),
        }
    }

    fn close(&self, handle: ObjectHandle) {
        self.process.close_object_reference(handle).unwrap();
        wait_until(
            || {
                self.retirements
                    .try_recv()
                    .is_ok_and(|retired| retired == handle)
            },
            "the socket retires",
        );
    }
}

fn wildcard() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, GUEST_PORT)
}

/// Asserts that `client` has neither data nor an error yet: it waits.
fn assert_waiting(client: &TcpStream) {
    client.set_nonblocking(true).unwrap();
    let error = (&*client).read(&mut [0]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    client.set_nonblocking(false).unwrap();
}

fn assert_reset(client: &mut TcpStream) {
    let error = client.read(&mut [0]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

fn receive_exactly(guest: &PublishedGuest, handle: ObjectHandle, length: usize) -> Vec<u8> {
    let mut received = Vec::new();
    while received.len() < length {
        let mut buffer = vec![0; length - received.len()];
        match receive_into(
            &guest.process,
            handle,
            &mut buffer,
            ReceiveFlags::NONE,
            0,
            0,
        ) {
            Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(count))) => {
                received.extend_from_slice(&buffer[..count as usize]);
            }
            Err(BrokerError::WouldBlock) => wait_until_ready(
                &guest.process,
                &guest.publications,
                handle,
                ReadinessFlags::READ,
            ),
            outcome => panic!("unexpected receive outcome: {outcome:?}"),
        }
    }
    received
}

#[test]
fn published_port_reaches_a_wildcard_guest_listener_both_ways() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(wildcard(), 4);
    let mut client = guest.connect_clients(1, 1, 0).pop().unwrap();
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(
        accepted.local_address,
        SocketAddrV4::new(GUEST_IPV4_ADDRESS, GUEST_PORT)
    );
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
    assert!(accepted.remote_address.port() >= 49152);
    assert_eq!(guest.provider.core.gateway_peer_count(), 1);

    client.write_all(b"ping").unwrap();
    assert_eq!(receive_exactly(&guest, accepted.handle, 4), b"ping");
    assert_eq!(
        send_bytes(&guest.process, accepted.handle, b"pong", SendFlags::NONE),
        Ok(SocketOutcome::Completed(4))
    );
    let mut response = [0; 4];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"pong");

    client.shutdown(Shutdown::Write).unwrap();
    wait_for_end_of_stream(&guest.process, accepted.handle, &guest.publications);
    guest.close(accepted.handle);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    assert_eq!(guest.provider.core.gateway_peer_count(), 0);
    guest.close(listener);
}

#[test]
fn published_port_reaches_an_exact_private_guest_listener() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(SocketAddrV4::new(GUEST_IPV4_ADDRESS, GUEST_PORT), 4);
    let _client = guest.connect_clients(1, 1, 0);
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
}

#[test]
fn published_connections_without_a_covering_listener_are_reset() {
    let guest = published_guest(8, 8);
    for mut client in guest.connect_clients(1, 0, 1) {
        assert_reset(&mut client);
    }
    // A loopback listener stays private.
    let loopback = guest.listen(SocketAddrV4::new(Ipv4Addr::LOCALHOST, GUEST_PORT), 4);
    for mut client in guest.connect_clients(1, 0, 1) {
        assert_reset(&mut client);
    }
    guest.close(loopback);
    assert_eq!(guest.provider.core.gateway_peer_count(), 0);
}

#[test]
fn published_connections_beyond_the_backlog_wait_for_an_accept() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(wildcard(), 1);
    let mut clients = guest.connect_clients(2, 1, 0);
    assert_waiting(&clients[1]);
    assert_eq!(guest.provider.core.queued_external_connection_count(), 1);
    let start = guest.hook.len();
    let first = guest.accept(listener).unwrap();
    // The accept made room, which wakes the published listener.
    guest.wait_for_deliveries(start, 1, 0);
    let second = guest.accept(listener).unwrap();
    for (client, accepted, byte) in [(0, first, b"1"), (1, second, b"2")] {
        clients[client].write_all(byte).unwrap();
        assert_eq!(receive_exactly(&guest, accepted.handle, 1), byte);
    }
}

#[test]
fn closing_a_listener_resets_its_queued_published_connections() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(wildcard(), 4);
    let mut clients = guest.connect_clients(2, 2, 0);
    assert_eq!(guest.provider.core.queued_external_connection_count(), 2);
    assert_eq!(guest.provider.core.gateway_peer_count(), 2);
    guest.close(listener);
    for client in &mut clients {
        assert_reset(client);
    }
    assert_eq!(guest.provider.core.queued_external_connection_count(), 0);
    assert_eq!(guest.provider.core.gateway_peer_count(), 0);
}

#[test]
fn published_connections_beyond_one_events_accepts_all_arrive() {
    let count = MAX_ACCEPTS_PER_EVENT + 6;
    let guest = published_guest(256, 256);
    let listener = guest.listen(wildcard(), 256);
    let _clients = guest.connect_clients(count, count, 0);
    let mut peers = HashSet::new();
    for _ in 0..count {
        assert!(peers.insert(guest.accept(listener).unwrap().remote_address));
    }
}

#[test]
fn queued_published_connections_are_bounded_and_charged_to_no_process() {
    let extra = 2;
    let guest = published_guest(512, 2);
    let listener = guest.listen(wildcard(), 4096);
    let clients = guest.connect_clients(
        MAX_QUEUED_PUBLISHED_CONNECTIONS + extra,
        MAX_QUEUED_PUBLISHED_CONNECTIONS,
        0,
    );
    assert_eq!(
        guest.provider.core.queued_external_connection_count(),
        MAX_QUEUED_PUBLISHED_CONNECTIONS
    );
    // The listener's process can still open its second socket.
    let other = create_socket(&guest.process, guest.readiness.clone());
    assert_eq!(
        guest.accept(listener).map(|_| ()),
        Err(BrokerError::ResourceExhausted)
    );
    guest.close(other);
    let start = guest.hook.len();
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
    // The accept made room for one of the waiting clients.
    guest.wait_for_deliveries(start, 1, 0);
    assert_eq!(
        guest.provider.core.queued_external_connection_count(),
        MAX_QUEUED_PUBLISHED_CONNECTIONS
    );
    for client in &clients {
        assert_waiting(client);
    }
}

#[test]
fn publishing_a_taken_host_address_fails() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let Err(error) = UserlandSocketProvider::with_host_network(
        8,
        8,
        &HostNetworkOptions {
            published_tcp_ports: vec![PublishedTcpPort {
                host_address: socket_address_v4(taken.local_addr().unwrap()),
                guest_port: GUEST_PORT,
            }],
            ..HostNetworkOptions::default()
        },
    ) else {
        panic!("published a taken host address");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
}

impl PublishedGuest {
    /// Whether the last publication check of `port`, which the guest's
    /// listen or close ran before it returned, left it published.
    fn listener_published(&self, port: u16) -> bool {
        let points = self.hook.points.lock().unwrap();
        points
            .iter()
            .rev()
            .find_map(|point| match point {
                HookPoint::ListenerPublished(published_port, published)
                    if *published_port == port =>
                {
                    Some(*published)
                }
                _ => None,
            })
            .expect("the port's publication was not checked")
    }

    /// Listens on the guest's wildcard address on a port that the host's
    /// loopback address does not use, so that it is published there.
    fn listen_published(&mut self, backlog: u32) -> ObjectHandle {
        for _ in 0..16 {
            let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let listener = self.listen(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port), backlog);
            if self.listener_published(port) {
                self.guest_port = port;
                self.host_address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
                return listener;
            }
            // Another process took the port meanwhile.
            self.close(listener);
        }
        panic!("found no free host port to publish a guest listener on");
    }
}

/// A guest listener's port is published from its listen until it stops
/// listening, and again for the next listener on the port, until it closes;
/// clients then reach it as they reach a fixed published port.
#[test]
fn guest_listeners_are_published_while_they_listen() {
    let mut guest = listener_publishing_guest();
    let listener = guest.listen_published(4);
    assert_eq!(guest.provider.core.published_guest_listener_count(), 1);
    let mut client = guest.connect_clients(1, 1, 0).pop().unwrap();
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
    client.write_all(b"ping").unwrap();
    assert_eq!(receive_exactly(&guest, accepted.handle, 4), b"ping");
    guest.close(accepted.handle);

    let port = guest.guest_port;
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &guest.process,
            listener,
            ShutdownMode::StopListening
        ),
        Ok(SocketOutcome::Completed(()))
    );
    assert!(!guest.listener_published(port));
    assert_eq!(guest.provider.core.published_guest_listener_count(), 0);
    guest.close(listener);

    let listener = guest.listen(SocketAddrV4::new(GUEST_IPV4_ADDRESS, port), 4);
    assert!(guest.listener_published(port), "port {port} was taken");
    let _client = guest.connect_clients(1, 1, 0);
    guest.close(listener);
    assert!(!guest.listener_published(port));
    assert_eq!(guest.provider.core.published_guest_listener_count(), 0);
    assert_eq!(guest.provider.core.queued_external_connection_count(), 0);
}

/// A wake posted for a published listener that stops listening before the
/// event thread takes it is dropped with the listener, so listeners that come
/// and go leave no stale tokens in the posted set, whose room is reserved.
#[test]
fn a_closed_published_listener_leaves_no_pending_wake() {
    let mut guest = listener_publishing_guest();
    let listener = guest.listen_published(4);
    let token = guest
        .provider
        .core
        .published_guest_listener_token(guest.guest_port)
        .unwrap();
    // Park the event thread before it takes posted events.
    let (parked, parked_receiver) = channel();
    let (release, released) = channel::<()>();
    let (parked, released) = (Mutex::new(parked), Mutex::new(released));
    guest.hook.act(move |_, _, point| {
        if point == HookPoint::Waiting && parked.lock().unwrap().send(()).is_ok() {
            let _ = released.lock().unwrap().recv();
        }
    });
    parked_receiver.recv_timeout(TEST_TIMEOUT).unwrap();
    drop(parked_receiver);
    guest.provider.core.wake_published();
    assert!(guest.provider.core.posted_holds(token));
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &guest.process,
            listener,
            ShutdownMode::StopListening
        ),
        Ok(SocketOutcome::Completed(()))
    );
    assert!(!guest.provider.core.posted_holds(token));
    guest.hook.stop();
    drop(release);
}

/// Only listeners that host clients could reach are published, and a port
/// the host already uses stays unpublished without failing the listen.
#[test]
fn private_guest_listeners_and_taken_ports_stay_unpublished() {
    let guest = listener_publishing_guest();
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = taken.local_addr().unwrap().port();
    let loopback = guest.listen(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), 4);
    assert!(!guest.listener_published(port));
    guest.close(loopback);
    let wildcard = guest.listen(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port), 4);
    assert!(!guest.listener_published(port));
    assert_eq!(guest.provider.core.published_guest_listener_count(), 0);
    guest.close(wildcard);
}

/// A provider fails to start in a network it cannot enter: Linux selects no
/// network, and Windows has no compartment `u32::MAX`.
#[test]
fn a_network_that_cannot_be_entered_fails_the_provider() {
    let options = HostNetworkOptions {
        compartment: Some(u32::MAX),
        ..HostNetworkOptions::default()
    };
    let Err(error) = UserlandSocketProvider::with_host_network(8, 8, &options) else {
        panic!("entered network compartment {:?}", options.compartment);
    };
    if cfg!(target_os = "linux") {
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}
