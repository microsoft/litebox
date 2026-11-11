// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use std::collections::HashSet;
use std::net::TcpStream;

use litebox_broker_core::socket::{AcceptedBrokerSocket, PublishedTcpPort};

use super::super::published::{
    MAX_ACCEPTS_PER_EVENT, MAX_QUEUED_PUBLISHED_CONNECTIONS, PUBLISHED_EVENT_TOKEN_FLAG,
};
use super::super::tcp::RoomShortage;

const GUEST_PORT: u16 = 8080;

/// Ephemeral host ports a test tries, as another process may take one
/// between the test's choice and its use.
const PORT_ATTEMPTS: usize = 16;

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
    published_guest_on(Ipv4Addr::LOCALHOST, max_sockets, max_sockets_per_process)
}

/// A broker whose provider publishes [`GUEST_PORT`] on an ephemeral port of
/// `host_ip`, which its clients reach at the loopback address if it is the
/// wildcard.
fn published_guest_on(
    host_ip: Ipv4Addr,
    max_sockets: usize,
    max_sockets_per_process: usize,
) -> PublishedGuest {
    let mut guest = guest_with(
        &HostNetworkOptions {
            published_tcp_ports: vec![PublishedTcpPort {
                host_address: SocketAddrV4::new(host_ip, 0),
                guest_port: GUEST_PORT,
            }],
            ..HostNetworkOptions::default()
        },
        max_sockets,
        max_sockets_per_process,
    );
    let mut host_address = guest.provider.core.published_host_address(0);
    if host_address.ip().is_unspecified() {
        host_address.set_ip(Ipv4Addr::LOCALHOST);
    }
    guest.host_address = host_address;
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
        let clients = (0..count).map(|_| self.connect_client()).collect();
        self.wait_for_deliveries(start, queued, reset);
        clients
    }

    fn connect_client(&self) -> TcpStream {
        // A blocking connect returns once the handshake completes, where a
        // timed one may instead fail with the reset the provider sends a
        // client that no guest listener covers.
        let client = TcpStream::connect(self.host_address).unwrap();
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        client
    }

    /// Waits for `queued` queued and `reset` reset host clients from hook
    /// point `start` on.
    fn wait_for_deliveries(&self, start: usize, queued: usize, reset: usize) {
        let mut next = start;
        let mut outcomes = Vec::new();
        while outcomes.len() < queued + reset {
            let (index, point) = self.hook.wait_for(next, |point| {
                matches!(point, HookPoint::PublishedClient { .. })
            });
            let HookPoint::PublishedClient { guest_port, queued } = point else {
                unreachable!()
            };
            assert_eq!(guest_port, self.guest_port);
            outcomes.push(queued);
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

    /// Asserts that `client` waits in the host backlog of the published
    /// listener with `token`, with neither data nor an error, returning the
    /// shortage that the paused listener waits for to ease. A paused
    /// listener accepts no client, so none can reset `client` later.
    fn assert_client_waits(&self, client: &TcpStream, token: u64) -> RoomShortage {
        let mut shortage = None;
        wait_until(
            || {
                shortage = self.provider.core.published_shortage(token);
                shortage.is_some()
            },
            "the published listener waits for room",
        );
        client.set_nonblocking(true).unwrap();
        let error = (&*client).read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        client.set_nonblocking(false).unwrap();
        shortage.unwrap()
    }

    /// Holds the event thread at its next wait, before it takes posted
    /// events, until the returned guard drops.
    fn park_event_thread(&self) -> ParkedEventThread {
        let (parked, parked_receiver) = channel();
        let (release, released) = channel::<()>();
        let (parked, released) = (Mutex::new(parked), Mutex::new(released));
        self.hook.act(move |_, _, point| {
            if point == HookPoint::Waiting && parked.lock().unwrap().send(()).is_ok() {
                let _ = released.lock().unwrap().recv();
            }
        });
        // Brings the event thread to its next wait now, rather than after
        // its idle wait.
        self.provider.core.posted.wake().unwrap();
        parked_receiver.recv_timeout(TEST_TIMEOUT).unwrap();
        // Later waits do not park.
        drop(parked_receiver);
        ParkedEventThread {
            hook: Arc::clone(&self.hook),
            _release: release,
        }
    }
}

/// Releases the event thread that [`PublishedGuest::park_event_thread`]
/// parked when it drops.
struct ParkedEventThread {
    hook: Arc<TestHook>,
    _release: Sender<()>,
}

impl Drop for ParkedEventThread {
    fn drop(&mut self) {
        // The sender drops after this, which releases the thread.
        self.hook.stop();
    }
}

fn wildcard() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, GUEST_PORT)
}

fn assert_reset(client: &mut TcpStream) {
    let error = client.read(&mut [0]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
}

fn receive_exactly(guest: &PublishedGuest, handle: ObjectHandle, length: usize) -> Vec<u8> {
    let mut received = vec![0; length];
    receive_exact(&guest.process, handle, &guest.publications, &mut received);
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
    // A guest listener's backlog of N holds N connections, the broker's rule
    // for internal connections too (`published_room` applies the same
    // check). Linux holds N + 1: its `sk_acceptq_is_full` compares with `>`.
    let mut clients = guest.connect_clients(2, 1, 0);
    assert!(matches!(
        guest.assert_client_waits(&clients[1], PUBLISHED_EVENT_TOKEN_FLAG),
        RoomShortage::Backlog(_)
    ));
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
    assert_eq!(
        guest.assert_client_waits(clients.last().unwrap(), PUBLISHED_EVENT_TOKEN_FLAG),
        RoomShortage::PublishedQueue
    );
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

/// A published host address whose port another socket listens on at every
/// address is taken, though Winsock would let the published listener take
/// that socket's clients.
#[test]
fn publishing_a_port_a_wildcard_listener_holds_fails() {
    let wildcard_v4 = TcpListener::bind("0.0.0.0:0").unwrap();
    let dual_stack =
        socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None).unwrap();
    dual_stack.set_only_v6(false).unwrap();
    dual_stack
        .bind(&"[::]:0".parse::<std::net::SocketAddr>().unwrap().into())
        .unwrap();
    dual_stack.listen(1).unwrap();
    let dual_stack_port = dual_stack.local_addr().unwrap().as_socket().unwrap().port();
    for (host_ip, port) in [
        (
            Ipv4Addr::LOCALHOST,
            wildcard_v4.local_addr().unwrap().port(),
        ),
        (Ipv4Addr::LOCALHOST, dual_stack_port),
        (Ipv4Addr::UNSPECIFIED, dual_stack_port),
    ] {
        let Err(error) = UserlandSocketProvider::with_host_network(
            8,
            8,
            &HostNetworkOptions {
                published_tcp_ports: vec![PublishedTcpPort {
                    host_address: SocketAddrV4::new(host_ip, port),
                    guest_port: GUEST_PORT,
                }],
                ..HostNetworkOptions::default()
            },
        ) else {
            panic!("published {host_ip}:{port}, which a wildcard listener holds");
        };
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::AddrInUse,
            "{host_ip}:{port}"
        );
    }
}

/// While the broker publishes a host address, another socket cannot take
/// it over with `SO_REUSEADDR`, as it could on Windows if the published
/// listener allowed address reuse as Linux listeners do.
#[test]
fn a_published_host_address_cannot_be_taken_over() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(wildcard(), 4);
    let rival = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    rival.set_reuse_address(true).unwrap();
    let error = rival
        .bind(&std::net::SocketAddr::V4(guest.host_address).into())
        .unwrap_err();
    // Windows refuses an exclusive address with `WSAEACCES`.
    let expected = if cfg!(windows) {
        std::io::ErrorKind::PermissionDenied
    } else {
        std::io::ErrorKind::AddrInUse
    };
    assert_eq!(error.kind(), expected, "{error}");
    let _client = guest.connect_clients(1, 1, 0);
    assert_eq!(
        *guest.accept(listener).unwrap().remote_address.ip(),
        HOST_GATEWAY_IPV4_ADDRESS
    );
}

/// Host clients' queued connections count against the global socket limit,
/// as guests' queued connections do.
#[test]
fn queued_published_connections_count_against_the_global_limit() {
    let guest = published_guest(2, 8);
    let listener = guest.listen(wildcard(), 4);
    let _client = guest.connect_clients(1, 1, 0);
    let create = || try_create_socket(&guest.process, guest.readiness.clone());
    assert_eq!(create().map(|_| ()), Err(BrokerError::ResourceExhausted));
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(create().map(|_| ()), Err(BrokerError::ResourceExhausted));
    guest.close(accepted.handle);
    let socket = create().unwrap();
    guest.close(socket);
}

/// A listener whose accepts fail other than for one connection stops for
/// a while, then retries, until an accept delivers the waiting client.
#[test]
fn a_published_listener_retries_after_its_accepts_fail() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(wildcard(), 4);
    guest.provider.core.fail_published_accepts(2);
    let start = guest.hook.len();
    let mut client = guest.connect_clients(1, 1, 0).pop().unwrap();
    assert_eq!(guest.provider.core.published_accepts_left_to_fail(), 0);
    guest.hook.wait_for(start, |point| {
        point
            == HookPoint::PublishedBackOff {
                guest_port: GUEST_PORT,
            }
    });
    let accepted = guest.accept(listener).unwrap();
    client.write_all(b"ping").unwrap();
    assert_eq!(receive_exactly(&guest, accepted.handle, 4), b"ping");
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
                HookPoint::ListenerPublished {
                    guest_port,
                    published,
                } if *guest_port == port => Some(*published),
                _ => None,
            })
            .expect("the port's publication was not checked")
    }

    /// Listens on the guest's wildcard address on a port that the host's
    /// loopback address does not use, so that it is published there.
    fn listen_published(&mut self, backlog: u32) -> ObjectHandle {
        for _ in 0..PORT_ATTEMPTS {
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
    for _ in 0..PORT_ATTEMPTS {
        if try_publish_a_guest_port_twice(&mut guest) {
            return;
        }
    }
    panic!("no port was published again after its first listener stopped");
}

/// One attempt of [`guest_listeners_are_published_while_they_listen`] on a
/// fresh port, which returns false if the port was not published again,
/// as when another process took it between the listens.
fn try_publish_a_guest_port_twice(guest: &mut PublishedGuest) -> bool {
    let listener = guest.listen_published(4);
    assert_eq!(guest.provider.core.published_guest_listener_count(), 1);
    let mut client = guest.connect_clients(1, 1, 0).pop().unwrap();
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
    client.write_all(b"ping").unwrap();
    assert_eq!(receive_exactly(guest, accepted.handle, 4), b"ping");
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
    if !guest.listener_published(port) {
        guest.close(listener);
        return false;
    }
    let _client = guest.connect_clients(1, 1, 0);
    guest.close(listener);
    assert!(!guest.listener_published(port));
    assert_eq!(guest.provider.core.published_guest_listener_count(), 0);
    assert_eq!(guest.provider.core.queued_external_connection_count(), 0);
    true
}

/// A wake posted for a published listener waiting for room that stops
/// listening before the event thread takes it is dropped with the listener,
/// so listeners that come and go leave no stale tokens in the posted set,
/// whose room is reserved.
#[test]
fn a_closed_published_listener_leaves_no_pending_wake() {
    let mut guest = listener_publishing_guest();
    let listener = guest.listen_published(1);
    let token = guest
        .provider
        .core
        .published_guest_listener_token(guest.guest_port)
        .unwrap();
    // The first client fills the backlog, so the listener waits for room
    // within the same event, before the event thread waits again.
    let clients = guest.connect_clients(2, 1, 0);
    assert!(matches!(
        guest.assert_client_waits(&clients[1], token),
        RoomShortage::Backlog(_)
    ));
    let parked = guest.park_event_thread();
    // The accept makes room, which posts a wake for the waiting listener.
    let _accepted = guest.accept(listener).unwrap();
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
    drop(parked);
}

/// A listener waiting for room resumes when room comes from a socket
/// closing under the global limit, with no accept to wake it: the close
/// posts its wake at once, rather than leaving it to the room retry.
#[test]
fn published_connections_resume_when_room_comes_without_an_accept() {
    let guest = published_guest(2, 8);
    let listener = guest.listen(wildcard(), 4);
    // The listener and this socket fill the global limit.
    let other = create_socket(&guest.process, guest.readiness.clone());
    let client = guest.connect_client();
    let token = PUBLISHED_EVENT_TOKEN_FLAG;
    assert_eq!(
        guest.assert_client_waits(&client, token),
        RoomShortage::Sockets
    );
    assert_eq!(guest.provider.core.queued_external_connection_count(), 0);
    let parked = guest.park_event_thread();
    guest.close(other);
    assert!(guest.provider.core.posted_holds(token));
    let start = guest.hook.len();
    drop(parked);
    guest.wait_for_deliveries(start, 1, 0);
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
}

/// A socket closing wakes the published listeners waiting for room under
/// the global limit, but not one waiting for its guest listener's backlog,
/// which only changes to that backlog wake.
#[test]
fn room_wakes_only_the_published_listeners_waiting_for_it() {
    const OTHER_GUEST_PORT: u16 = GUEST_PORT + 1;
    // Two guest listeners, a socket, and a queued connection fill it.
    let mut guest = guest_with(
        &HostNetworkOptions {
            published_tcp_ports: [GUEST_PORT, OTHER_GUEST_PORT]
                .map(|guest_port| PublishedTcpPort {
                    host_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                    guest_port,
                })
                .to_vec(),
            ..HostNetworkOptions::default()
        },
        4,
        8,
    );
    guest.host_address = guest.provider.core.published_host_address(0);
    let backlog_listener = guest.listen(wildcard(), 1);
    let _other_listener = guest.listen(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, OTHER_GUEST_PORT),
        4,
    );
    let other = create_socket(&guest.process, guest.readiness.clone());
    let backlog_clients = guest.connect_clients(2, 1, 0);
    let backlog_token = PUBLISHED_EVENT_TOKEN_FLAG;
    assert!(matches!(
        guest.assert_client_waits(&backlog_clients[1], backlog_token),
        RoomShortage::Backlog(_)
    ));
    guest.host_address = guest.provider.core.published_host_address(1);
    let sockets_client = guest.connect_client();
    let sockets_token = PUBLISHED_EVENT_TOKEN_FLAG | 1;
    assert_eq!(
        guest.assert_client_waits(&sockets_client, sockets_token),
        RoomShortage::Sockets
    );
    let parked = guest.park_event_thread();
    guest.close(other);
    assert!(guest.provider.core.posted_holds(sockets_token));
    assert!(!guest.provider.core.posted_holds(backlog_token));
    let _accepted = guest.accept(backlog_listener).unwrap();
    assert!(guest.provider.core.posted_holds(backlog_token));
    drop(parked);
}

/// Growing a guest listener's backlog by listening again wakes the
/// published listener waiting for room in it at once.
#[test]
fn a_grown_backlog_wakes_the_published_listener_waiting_for_it() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(wildcard(), 1);
    let clients = guest.connect_clients(2, 1, 0);
    let token = PUBLISHED_EVENT_TOKEN_FLAG;
    assert!(matches!(
        guest.assert_client_waits(&clients[1], token),
        RoomShortage::Backlog(_)
    ));
    let parked = guest.park_event_thread();
    assert_eq!(
        litebox_broker_core::socket::listen(&guest.process, listener, 2),
        Ok(SocketOutcome::Completed(wildcard()))
    );
    assert!(guest.provider.core.posted_holds(token));
    let start = guest.hook.len();
    drop(parked);
    guest.wait_for_deliveries(start, 1, 0);
}

/// A guest listener that stops listening wakes the published listener
/// waiting for room in its backlog at once, which then resets the client
/// that no listener covers any more.
#[test]
fn a_full_listener_that_stops_wakes_and_resets_the_clients_waiting_for_it() {
    let guest = published_guest(8, 8);
    let listener = guest.listen(wildcard(), 1);
    let mut clients = guest.connect_clients(2, 1, 0);
    let token = PUBLISHED_EVENT_TOKEN_FLAG;
    assert!(matches!(
        guest.assert_client_waits(&clients[1], token),
        RoomShortage::Backlog(_)
    ));
    let parked = guest.park_event_thread();
    assert_eq!(
        litebox_broker_core::socket::shutdown(
            &guest.process,
            listener,
            ShutdownMode::StopListening
        ),
        Ok(SocketOutcome::Completed(()))
    );
    assert!(guest.provider.core.posted_holds(token));
    let start = guest.hook.len();
    drop(parked);
    guest.wait_for_deliveries(start, 0, 1);
    for client in &mut clients {
        assert_reset(client);
    }
}

/// A client that resets before the event thread accepts it fails only its
/// own accept, if any: the listener goes on to the next client rather than
/// back off. Windows fails that accept; Linux accepts the reset connection.
#[test]
fn a_client_reset_before_its_accept_leaves_the_listener_accepting() {
    let guest = published_guest(8, 8);
    let _listener = guest.listen(wildcard(), 4);
    let parked = guest.park_event_thread();
    let reset = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    reset
        .connect_timeout(
            &std::net::SocketAddr::V4(guest.host_address).into(),
            TEST_TIMEOUT,
        )
        .unwrap();
    reset.set_linger(Some(Duration::ZERO)).unwrap();
    drop(reset);
    let _client = guest.connect_client();
    let start = guest.hook.len();
    drop(parked);
    guest.wait_for_deliveries(start, if cfg!(windows) { 1 } else { 2 }, 0);
    assert!(
        !guest.hook.points.lock().unwrap()[start..]
            .iter()
            .any(|point| matches!(point, HookPoint::PublishedBackOff { .. }))
    );
}

/// A port published on the host's wildcard address reaches the guest, for
/// the published listener does not count itself as a wildcard listener
/// holding the port.
#[test]
fn a_port_published_on_every_host_address_reaches_the_guest() {
    let guest = published_guest_on(Ipv4Addr::UNSPECIFIED, 8, 8);
    let listener = guest.listen(wildcard(), 4);
    let _client = guest.connect_clients(1, 1, 0);
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
}

/// A listener on another specific address of a port leaves the port
/// publishable, unlike a wildcard listener.
#[test]
fn a_listener_on_another_host_address_leaves_its_port_publishable() {
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let host_address = SocketAddrV4::new(
        Ipv4Addr::new(127, 0, 0, 2),
        taken.local_addr().unwrap().port(),
    );
    let mut guest = guest_with(
        &HostNetworkOptions {
            published_tcp_ports: vec![PublishedTcpPort {
                host_address,
                guest_port: GUEST_PORT,
            }],
            ..HostNetworkOptions::default()
        },
        8,
        8,
    );
    guest.host_address = host_address;
    let listener = guest.listen(wildcard(), 4);
    let _client = guest.connect_clients(1, 1, 0);
    let accepted = guest.accept(listener).unwrap();
    assert_eq!(*accepted.remote_address.ip(), HOST_GATEWAY_IPV4_ADDRESS);
}

/// Host clients of one guest listener that is not accepting cannot stop
/// another published port: a listener with none queued may queue one past
/// the broker-wide bound.
#[test]
fn a_stalled_published_listener_leaves_room_for_others() {
    const OTHER_GUEST_PORT: u16 = GUEST_PORT + 1;
    let mut guest = guest_with(
        &HostNetworkOptions {
            published_tcp_ports: [GUEST_PORT, OTHER_GUEST_PORT]
                .map(|guest_port| PublishedTcpPort {
                    host_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                    guest_port,
                })
                .to_vec(),
            ..HostNetworkOptions::default()
        },
        512,
        512,
    );
    guest.host_address = guest.provider.core.published_host_address(0);
    let stalled = guest.listen(wildcard(), 4096);
    let _stalled_clients = guest.connect_clients(
        MAX_QUEUED_PUBLISHED_CONNECTIONS,
        MAX_QUEUED_PUBLISHED_CONNECTIONS,
        0,
    );

    guest.guest_port = OTHER_GUEST_PORT;
    guest.host_address = guest.provider.core.published_host_address(1);
    let other = guest.listen(
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, OTHER_GUEST_PORT),
        4,
    );
    let clients = guest.connect_clients(2, 1, 0);
    let other_token = PUBLISHED_EVENT_TOKEN_FLAG | 1;
    assert_eq!(
        guest.assert_client_waits(&clients[1], other_token),
        RoomShortage::PublishedQueue
    );
    assert_eq!(
        guest.provider.core.queued_external_connection_count(),
        MAX_QUEUED_PUBLISHED_CONNECTIONS + 1
    );
    // Discarding the stalled listener's queue makes room under the bound,
    // which wakes the waiting listener at once.
    let parked = guest.park_event_thread();
    assert_eq!(
        litebox_broker_core::socket::shutdown(&guest.process, stalled, ShutdownMode::StopListening),
        Ok(SocketOutcome::Completed(()))
    );
    assert!(guest.provider.core.posted_holds(other_token));
    let start = guest.hook.len();
    drop(parked);
    guest.wait_for_deliveries(start, 1, 0);
    assert_eq!(guest.provider.core.queued_external_connection_count(), 2);
    for _ in 0..2 {
        let accepted = guest.accept(other).unwrap();
        assert_eq!(accepted.local_address.port(), OTHER_GUEST_PORT);
    }
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
