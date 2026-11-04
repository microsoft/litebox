// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use std::collections::HashSet;
use std::net::TcpStream;

use litebox_broker_core::socket::AcceptedBrokerSocket;

use super::super::published::{MAX_ACCEPTS_PER_EVENT, MAX_QUEUED_PUBLISHED_CONNECTIONS};

const GUEST_PORT: u16 = 8080;

/// A broker whose provider publishes [`GUEST_PORT`] on an ephemeral host
/// loopback port, and one guest process.
struct PublishedGuest {
    provider: Arc<UserlandSocketProvider>,
    process: Arc<BrokerProcess>,
    readiness: Arc<TestReadinessSink>,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
    retirements: Receiver<ObjectHandle>,
    hook: Arc<TestHook>,
    host_address: SocketAddrV4,
}

fn published_guest(max_sockets: usize, max_sockets_per_process: usize) -> PublishedGuest {
    let provider = Arc::new(
        UserlandSocketProvider::with_published_tcp_ports(
            max_sockets,
            max_sockets_per_process,
            &[PublishedTcpPort {
                host_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                guest_port: GUEST_PORT,
            }],
        )
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
        .create_process(CallerCredential::Unauthenticated, None)
        .unwrap();
    let (published, publications) = channel();
    let (retired, retirements) = channel();
    let host_address = provider.core.published_host_address(0);
    PublishedGuest {
        provider,
        process,
        readiness: Arc::new(TestReadinessSink { published, retired }),
        publications,
        retirements,
        hook,
        host_address,
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
            assert_eq!(port, GUEST_PORT);
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
    let Err(error) = UserlandSocketProvider::with_published_tcp_ports(
        8,
        8,
        &[PublishedTcpPort {
            host_address: socket_address_v4(taken.local_addr().unwrap()),
            guest_port: GUEST_PORT,
        }],
    ) else {
        panic!("published a taken host address");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
}
