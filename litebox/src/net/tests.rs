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

fn wildcard_bound_udp_comms(
    mut network: Network<MockPlatform>,
    comms: fn(&mut Network<MockPlatform>),
) {
    let server_fd = network
        .socket(Protocol::Udp)
        .expect("Failed to create UDP server socket");
    let server_addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    network
        .bind(&server_fd, &server_addr)
        .expect("Failed to bind UDP server socket");

    let client_fd = network
        .socket(Protocol::Udp)
        .expect("Failed to create UDP client socket");
    let wildcard_addr = SocketAddr::V4(SocketAddrV4::from_str("0.0.0.0:0").unwrap());
    network
        .bind(&client_fd, &wildcard_addr)
        .expect("Failed to bind UDP client socket");

    let client_to_server_data = b"Hello from wildcard client!";
    let bytes_sent = network
        .send(
            &client_fd,
            client_to_server_data,
            SendFlags::empty(),
            Some(server_addr),
        )
        .expect("Failed to send UDP packet from wildcard-bound client");
    assert_eq!(bytes_sent, client_to_server_data.len());

    comms(&mut network);

    let mut server_buffer = [0u8; 1024];
    let mut source_addr = None;
    let bytes_received = network
        .receive(
            &server_fd,
            &mut server_buffer,
            ReceiveFlags::empty(),
            Some(&mut source_addr),
        )
        .expect("Failed to receive UDP packet on server");
    assert_eq!(&server_buffer[..bytes_received], client_to_server_data);
    let source_addr = source_addr.expect("Expected UDP source address");

    let server_to_client_data = b"Hello back from server!";
    let bytes_sent = network
        .send(
            &server_fd,
            server_to_client_data,
            SendFlags::empty(),
            Some(source_addr),
        )
        .expect("Failed to send UDP reply to wildcard-bound client");
    assert_eq!(bytes_sent, server_to_client_data.len());

    comms(&mut network);

    let mut client_buffer = [0u8; 1024];
    let bytes_received = network
        .receive(&client_fd, &mut client_buffer, ReceiveFlags::empty(), None)
        .expect("Failed to receive UDP reply on wildcard-bound client");
    assert_eq!(&client_buffer[..bytes_received], server_to_client_data);

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
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
fn test_wildcard_bound_udp_communication_manual() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    wildcard_bound_udp_comms(network, |nw| {
        while nw.perform_platform_interaction().call_again_immediately() {}
    });
}

#[test]
fn test_udp_bound_port_is_released_on_close() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);

    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let first_fd = network
        .socket(Protocol::Udp)
        .expect("Failed to create UDP socket");
    network
        .bind(&first_fd, &addr)
        .expect("Failed to bind first UDP socket");
    network
        .close(&first_fd, CloseBehavior::Immediate)
        .expect("Failed to close first UDP socket");

    let second_fd = network
        .socket(Protocol::Udp)
        .expect("Failed to create UDP socket");
    network
        .bind(&second_fd, &addr)
        .expect("UDP port should be reusable after close");
    network
        .close(&second_fd, CloseBehavior::Immediate)
        .expect("Failed to close second UDP socket");
}
