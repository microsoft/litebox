// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::publish::{Publish, Publishing, duplicate, parse_ipv4_cidr};
use litebox_broker_core::socket::AcceptedBrokerSocket;
use std::net::TcpStream;

#[cfg(target_os = "linux")]
mod linux;

/// A guest process whose provider publishes ports.
struct Guest {
    process: Arc<BrokerProcess>,
    readiness: Arc<TestReadinessSink>,
    publications: Receiver<(ObjectHandle, ReadinessFlags)>,
    host: SocketAddrV4,
}

/// Starts a guest that publishes `127.0.0.1:host_port` to port 80, with `max_sockets` sockets.
/// Each test's port is its own, below every ephemeral range, so no parallel test takes it.
fn guest(max_sockets: usize, host_port: u16) -> Guest {
    let host = SocketAddrV4::new(Ipv4Addr::LOCALHOST, host_port);
    guest_with(
        max_sockets,
        host,
        publishing(&[&format!("{host}:80")], "10.0.2.1/32"),
    )
}

/// Publishes `rules` to clients from `source`.
fn publishing(rules: &[&str], source: &str) -> Publishing {
    Publishing {
        rules: rules.iter().map(|rule| rule.parse().unwrap()).collect(),
        listener_ip: None,
        tcp_sources: vec![parse_ipv4_cidr(source).unwrap()],
    }
}

/// Starts a guest whose provider publishes as `publishing` says; `host` is the address its tests
/// reach.
fn guest_with(max_sockets: usize, host: SocketAddrV4, publishing: Publishing) -> Guest {
    let provider = UserlandSocketProvider::with_publishing(max_sockets, max_sockets, publishing);
    let provider = Arc::new(provider.unwrap());
    let broker = test_broker_core(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
            .with_socket_policy(SocketPolicy::guest_network()),
        BrokerCoreLimits::new_with_all_limits(16, 0, 8, 8),
        provider,
    )
    .unwrap();
    let (published, publications) = channel();
    let (retired, _) = channel();
    let process = broker.create_process(CallerCredential::Unauthenticated);
    let readiness = Arc::new(TestReadinessSink { published, retired });
    Guest {
        process: process.unwrap(),
        readiness,
        publications,
        host,
    }
}

impl Guest {
    /// Binds a new socket to `address` and listens on it.
    fn listen(&self, address: &str) -> (ObjectHandle, BrokerResult<SocketOutcome<SocketAddrV4>>) {
        let address = address.parse().unwrap();
        let listener = create_socket(&self.process, self.readiness.clone());
        let bound = litebox_broker_core::socket::bind(&self.process, listener, address);
        assert_eq!(bound, Ok(SocketOutcome::Completed(address)));
        let listening = litebox_broker_core::socket::listen(&self.process, listener, 4);
        (listener, listening)
    }

    /// Accepts a connection on `listener` without waiting.
    fn accept(&self, listener: ObjectHandle) -> BrokerResult<AcceptedBrokerSocket> {
        let (flags, readiness) = (FileOpenFlags::NONE, self.readiness.clone());
        match litebox_broker_core::socket::accept(&self.process, listener, flags, readiness)? {
            SocketOutcome::Completed(accepted) => Ok(accepted),
            SocketOutcome::Failed(error) => panic!("the accept failed: {error:?}"),
        }
    }

    fn wait(&self, socket: ObjectHandle) {
        wait_until_ready(
            &self.process,
            &self.publications,
            socket,
            ReadinessFlags::READ,
        );
    }

    /// Receives on `socket` until its stream ends.
    fn receive_all(&self, socket: ObjectHandle) -> Vec<u8> {
        let mut received = Vec::new();
        loop {
            let mut buffer = [0; 16];
            match receive_into(&self.process, socket, &mut buffer, ReceiveFlags::NONE, 0, 0) {
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::Received(count))) => {
                    received.extend_from_slice(&buffer[..count as usize]);
                }
                Ok(SocketOutcome::Completed(ReceiveSocketResponse::EndOfStream)) => {
                    return received;
                }
                Err(BrokerError::WouldBlock) => self.wait(socket),
                outcome => panic!("unexpected receive outcome: {outcome:?}"),
            }
        }
    }

    fn assert_refused(&self) {
        let refused = TcpStream::connect(self.host).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    }

    /// Asserts that a new client connects and is reset unaccepted.
    fn assert_reset(&self) {
        assert_reset(&TcpStream::connect(self.host).unwrap());
    }
}

fn assert_reset(client: &TcpStream) {
    client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let reset = { client }.read(&mut [0]).unwrap_err();
    assert_eq!(reset.kind(), std::io::ErrorKind::ConnectionReset);
}

#[test]
fn a_published_connection_carries_data_and_half_closes_both_ways() {
    let guest = guest(4, 20_801);
    let (listener, listening) = guest.listen("0.0.0.0:80");
    assert!(matches!(listening, Ok(SocketOutcome::Completed(_))));
    let mut client = TcpStream::connect(guest.host).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    guest.wait(listener);
    let accepted = guest.accept(listener).unwrap();
    // Its only connection taken, the listener is not readable.
    let readiness = guest.process.check_readiness(listener).unwrap();
    assert!(!readiness.contains(ReadinessFlags::READ));
    let client_port = client.local_addr().unwrap().port();
    assert_eq!(
        (accepted.local_address, accepted.remote_address),
        (
            SocketAddrV4::new(GUEST_IPV4_ADDRESS, 80),
            SocketAddrV4::new(HOST_GATEWAY_IPV4_ADDRESS, client_port),
        )
    );
    assert_eq!(guest.receive_all(accepted.handle), b"ping");
    let sent = send_bytes(&guest.process, accepted.handle, b"pong", SendFlags::NONE);
    assert_eq!(sent, Ok(SocketOutcome::Completed(4)));
    let (process, write) = (&guest.process, ShutdownMode::Write);
    let shut = litebox_broker_core::socket::shutdown(process, accepted.handle, write);
    assert_eq!(shut, Ok(SocketOutcome::Completed(())));
    let mut answer = String::new();
    client.read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "pong");
}

#[test]
fn the_host_port_is_held_and_served_while_the_guest_listens() {
    let guest = guest(4, 20_803);
    // Not listening, the port resets clients and stays the broker's.
    guest.assert_reset();
    assert!(TcpListener::bind(guest.host).is_err());
    let (listener, _) = guest.listen("0.0.0.0:80");
    let _client = TcpStream::connect(guest.host).unwrap();
    guest.wait(listener);
    let _accepted = guest.accept(listener).unwrap();
    // A client still waiting when the guest stops listening is reset.
    let waiting = TcpStream::connect(guest.host).unwrap();
    guest.process.close_object_reference(listener).unwrap();
    assert_reset(&waiting);
    assert!(TcpListener::bind(guest.host).is_err());
    // The accepted connection open, the guest listens again.
    let (listener, listening) = guest.listen("0.0.0.0:80");
    assert!(matches!(listening, Ok(SocketOutcome::Completed(_))));
    let _client = TcpStream::connect(guest.host).unwrap();
    guest.wait(listener);
    guest.accept(listener).unwrap();
}

#[test]
fn guest_listeners_are_mirrored_at_their_own_ports_while_they_listen() {
    let host = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_807);
    let mirroring = Publishing {
        listener_ip: Some(Ipv4Addr::LOCALHOST),
        ..publishing(&[], "10.0.2.1/32")
    };
    let guest = guest_with(4, host, mirroring);
    guest.assert_refused();
    // Unlike a published port, a mirrored one is the host's again once the guest stops listening
    // (on Windows, once the connections accepted on it end too).
    let (listener, _) = guest.listen("0.0.0.0:20807");
    guest.process.close_object_reference(listener).unwrap();
    guest.assert_refused();
    drop(TcpListener::bind(host).unwrap());
    let (listener, _) = guest.listen("0.0.0.0:20807");
    let _client = TcpStream::connect(host).unwrap();
    guest.wait(listener);
    guest.accept(listener).unwrap();
    // Loopback guest listeners are not mirrored, and a port the host uses stays unpublished.
    let taken = TcpListener::bind("127.0.0.1:20808").unwrap();
    for address in ["127.0.0.1:20809", "0.0.0.0:20808"] {
        let (_, listening) = guest.listen(address);
        assert!(matches!(listening, Ok(SocketOutcome::Completed(_))));
    }
    assert!(TcpStream::connect("127.0.0.1:20809").is_err());
    drop(taken);
}

#[test]
fn a_wildcard_publication_excludes_specific_addresses() {
    let start = || {
        let publishing = publishing(&["0.0.0.0:20820:80"], "10.0.2.1/32");
        UserlandSocketProvider::with_publishing(4, 4, publishing)
    };
    // A specific address taken before fails the start, and one taken after is refused.
    let taken = TcpListener::bind("127.0.0.1:20820").unwrap();
    assert!(start().is_err());
    drop(taken);
    let _provider = start().unwrap();
    assert!(TcpListener::bind("127.0.0.1:20820").is_err());
}

#[test]
fn a_client_from_outside_the_allowed_sources_is_reset_unaccepted() {
    // The sources exclude 10.0.2.1, as which the guest sees a local client.
    let host = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 20_821);
    let guest = guest_with(
        4,
        host,
        publishing(&[&format!("{host}:80")], "192.0.2.0/24"),
    );
    let (listener, _) = guest.listen("0.0.0.0:80");
    let client = TcpStream::connect(host).unwrap();
    guest.wait(listener);
    assert_eq!(guest.accept(listener).err(), Some(BrokerError::WouldBlock));
    assert_reset(&client);
}

#[test]
fn published_ports_parse_as_docker_s_and_are_unique() {
    let publish = |host: &str, guest_port| Publish {
        host: host.parse().unwrap(),
        guest_port,
    };
    assert_eq!("8080:80".parse(), Ok(publish("0.0.0.0:8080", 80)));
    assert_eq!("127.0.0.1:1:2".parse(), Ok(publish("127.0.0.1:1", 2)));
    for bad in ["80", "0:80", "80:65536", "x:80:80"] {
        assert!(bad.parse::<Publish>().is_err(), "{bad}");
    }
    let unique = [publish("127.0.0.1:80", 1), publish("127.0.0.2:80", 2)];
    assert_eq!(duplicate(&unique), None);
    // As in Docker, the unspecified IP overlaps every other.
    let host_twice = [unique[0], publish("0.0.0.0:80", 3)];
    assert_eq!(duplicate(&host_twice), Some(host_twice[1]));
    let guest_twice = [unique[0], publish("0.0.0.0:81", 1)];
    assert_eq!(duplicate(&guest_twice), Some(guest_twice[1]));
}
