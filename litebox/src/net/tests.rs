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
        .local_socket(Protocol::Tcp)
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
        .local_socket(Protocol::Tcp)
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

#[test]
fn attach_socket_proxy_is_idempotent() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    let fd = network
        .local_socket(Protocol::Tcp)
        .expect("failed to create TCP socket");

    let first = network
        .attach_socket_proxy(&fd)
        .expect("TCP socket must support a proxy");
    let second = network
        .attach_socket_proxy(&fd)
        .expect("TCP socket must retain its proxy");

    assert!(alloc::sync::Arc::ptr_eq(&first, &second));
}

#[test]
fn pinned_immediate_close_remains_abortive() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    let fd = network
        .local_socket(Protocol::Tcp)
        .expect("failed to create TCP socket");
    let entry = litebox
        .descriptor_table()
        .entry_handle(&fd)
        .expect("socket entry must exist");

    network
        .close(&fd, CloseBehavior::Immediate)
        .expect("close must be queued while the entry is pinned");
    assert!(
        entry.with_entry(|socket| socket.entry.tcp().immediate_close.load(Ordering::SeqCst)),
        "queued close must retain abortive semantics"
    );

    drop(entry);
    assert!(!network.finish_deferred_closes());
    assert!(network.queued_for_closure.is_empty());
}

#[test]
fn final_duplicate_close_updates_abortive_behavior() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    let fd = network
        .local_socket(Protocol::Tcp)
        .expect("failed to create TCP socket");
    let duplicate = litebox
        .descriptor_table_mut()
        .duplicate(&fd)
        .expect("socket duplication must succeed");
    let entry = litebox
        .descriptor_table()
        .entry_handle(&duplicate)
        .expect("socket entry must exist");

    network
        .close(&fd, CloseBehavior::Immediate)
        .expect("first duplicate close must be queued");
    assert!(entry.with_entry(|socket| socket.entry.tcp().immediate_close.load(Ordering::SeqCst)));

    network
        .close(&duplicate, CloseBehavior::Graceful)
        .expect("final duplicate close must be queued while the entry is pinned");
    assert!(
        !entry.with_entry(|socket| socket.entry.tcp().immediate_close.load(Ordering::SeqCst)),
        "the final descriptor close must determine abortive behavior"
    );

    drop(entry);
    assert!(!network.finish_deferred_closes());
    assert!(network.queued_for_closure.is_empty());
}

#[test]
fn final_duplicate_close_is_reaped_immediately() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    let fd = network
        .local_socket(Protocol::Tcp)
        .expect("failed to create TCP socket");
    let duplicate = litebox
        .descriptor_table_mut()
        .duplicate(&fd)
        .expect("socket duplication must succeed");

    network
        .close(&fd, CloseBehavior::Graceful)
        .expect("first duplicate close must be queued");
    assert_eq!(network.queued_for_closure.len(), 1);
    network
        .close(&duplicate, CloseBehavior::Graceful)
        .expect("final duplicate close must succeed");
    assert!(network.queued_for_closure.is_empty());
}

#[test]
fn unsupported_sockets_fail_cleanly_without_broker() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);

    assert!(matches!(
        network.socket(Protocol::Tcp),
        Err(SocketError::BrokerUnavailable)
    ));
    assert!(matches!(
        network.socket(Protocol::Udp),
        Err(SocketError::BrokerUnavailable)
    ));
    assert!(matches!(
        network.socket(Protocol::Icmp),
        Err(SocketError::UnsupportedProtocol(1))
    ));
}
