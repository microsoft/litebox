// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use platform::mock::MockPlatform;

use super::*;

use core::net::SocketAddrV4;
use core::str::FromStr;

extern crate std;

fn bidi_tcp_comms(mut network: Network<MockPlatform>, comms: fn(&mut Network<MockPlatform>)) {
    // Create a listening socket
    let listener_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");
    let listen_addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());

    network
        .bind(&listener_fd, &listen_addr)
        .expect("Failed to bind TCP socket");
    network
        .listen(&listener_fd, 1)
        .expect("Failed to listen on TCP socket");

    // Create a connecting socket
    let client_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");
    let err = network
        .connect(&client_fd, &listen_addr, false)
        .unwrap_err();
    assert!(
        matches!(err, ConnectError::InProgress),
        "Expected InProgress error, got {err:?}",
    );

    comms(&mut network);

    // Accept the connection on the listening socket
    let server_fd = loop {
        match network.accept(&listener_fd, None) {
            Ok(fd) => break fd,
            Err(AcceptError::NoConnectionsReady) => {}
            Err(other) => panic!("Unexpected accept error: {other:?}"),
        }
    };

    // Send data from client to server
    let client_to_server_data = b"Hello from client!";
    let bytes_sent = network
        .send(&client_fd, client_to_server_data, SendFlags::empty(), None)
        .expect("Failed to send data");
    assert_eq!(bytes_sent, client_to_server_data.len());

    comms(&mut network);

    // Receive data on the server
    let mut server_buffer = [0u8; 1024];
    let bytes_received = network
        .receive(&server_fd, &mut server_buffer, ReceiveFlags::empty(), None)
        .expect("Failed to receive data");
    assert_eq!(&server_buffer[..bytes_received], client_to_server_data);

    // Send data from server to client
    let server_to_client_data = b"Hello from server!";
    let bytes_sent = network
        .send(&server_fd, server_to_client_data, SendFlags::empty(), None)
        .expect("Failed to send data");
    assert_eq!(bytes_sent, server_to_client_data.len());

    comms(&mut network);

    // Receive data on the client
    let mut client_buffer = [0u8; 1024];
    let bytes_received = network
        .receive(&client_fd, &mut client_buffer, ReceiveFlags::empty(), None)
        .expect("Failed to receive data");
    assert_eq!(&client_buffer[..bytes_received], server_to_client_data);

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network
        .close(&listener_fd, CloseBehavior::Immediate)
        .unwrap();
}

#[test]
fn test_bidirectional_tcp_communication_default() {
    let litebox = LiteBox::new(MockPlatform::new());
    let network = Network::new(&litebox);
    bidi_tcp_comms(network, |_| {});
}

#[test]
fn test_bidirectional_tcp_communication_manual() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    bidi_tcp_comms(network, |nw| {
        while nw.perform_platform_interaction().call_again_immediately() {}
    });
}

#[test]
fn test_bidirectional_tcp_communication_automatic() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Automatic);
    bidi_tcp_comms(network, |_| {});
}

/// Number of distinct remote (ip, port) destinations sent to from a single UDP fd in
/// [`test_udp_socket_table_does_not_grow_with_many_distinct_destinations`].
const DISTINCT_DESTINATIONS: u32 = 5000;

/// Real reproduction/regression test for the investigated "UDP flow table unbounded growth"
/// concern: a single guest UDP socket sending traffic to many thousands of distinct remote
/// destinations (varying both remote IP and remote port, i.e. what a real NAT/conntrack table
/// would key a "flow" on) must NOT cause `Network`'s own bookkeeping to grow per destination.
///
/// LiteBox's UDP socket lifecycle is one `smoltcp::socket::udp::Socket` entry in `socket_set`
/// per guest `socket()`/`close()` pair (see `Network::socket` and `Network::close_handle`), not
/// an implicit per-remote-peer table. `Network::send`'s UDP branch always operates on the
/// existing `SocketHandle`'s single smoltcp handle, regardless of how many distinct
/// `destination`s are passed across separate calls -- there is no separate NAT-style flow
/// created per peer to evict.
#[test]
fn test_udp_socket_table_does_not_grow_with_many_distinct_destinations() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Automatic);

    let fd = network
        .socket(Protocol::Udp)
        .expect("Failed to create UDP socket");

    // Baseline: exactly the one socket we explicitly created.
    assert_eq!(
        network.socket_set.iter().count(),
        1,
        "expected exactly one smoltcp socket for the one guest UDP fd"
    );

    // Send real UDP datagrams from the SAME fd to many thousands of distinct remote
    // (ip, port) pairs -- exactly the pattern that would grow an implicit NAT/conntrack-style
    // flow table keyed on remote peer, if one existed.
    let data = b"probe";
    for i in 0..DISTINCT_DESTINATIONS {
        let ip = Ipv4Addr::new(
            203,
            0,
            113,
            u8::try_from(1 + (i % 250)).expect("in range 1..=250"),
        );
        let port = u16::try_from(20000 + (i % 40000)).expect("in range 20000..60000");
        let destination = SocketAddr::V4(SocketAddrV4::new(ip, port));

        network
            .send(&fd, data, SendFlags::empty(), Some(destination))
            .unwrap_or_else(|e| panic!("send #{i} to {destination} failed: {e:?}"));
    }

    // The socket bookkeeping table must remain exactly one entry: LiteBox's UDP "flow" is the
    // guest's own socket fd, not a per-remote-peer entry.
    assert_eq!(
        network.socket_set.iter().count(),
        1,
        "socket_set grew while sending to distinct destinations from a single UDP fd -- \
         indicates an implicit per-remote-peer flow table with no eviction"
    );

    network.close(&fd, CloseBehavior::Immediate).unwrap();

    // After close, the table shrinks back to zero, confirming the one entry that did exist was
    // tied to the guest's own fd lifecycle (created at `socket()`, destroyed at `close()`) and
    // not to any of the many remote peers contacted along the way.
    assert_eq!(
        network.socket_set.iter().count(),
        0,
        "closing the fd should remove its socket_set entry"
    );
}
