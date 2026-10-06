// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use platform::mock::MockPlatform;

use super::*;

use core::net::SocketAddrV4;
use core::str::FromStr;

use crate::event::IOPollable as _;
use errors::ShutdownError;
use socket_channel::{ChannelReadError, ChannelWriteError};

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

type TestProxy = alloc::sync::Arc<NetworkProxy<MockPlatform>>;

fn pump(network: &mut Network<MockPlatform>) {
    while network
        .perform_platform_interaction()
        .call_again_immediately()
    {}
}

fn stream_socket(network: &mut Network<MockPlatform>) -> (SocketFd<MockPlatform>, TestProxy) {
    let fd = network.socket(Protocol::Tcp).unwrap();
    let proxy = alloc::sync::Arc::new(NetworkProxy::Stream(
        socket_channel::StreamSocketChannel::new(),
    ));
    assert!(network.set_socket_proxy(&fd, proxy.clone()));
    (fd, proxy)
}

fn listening_socket(network: &mut Network<MockPlatform>) -> SocketFd<MockPlatform> {
    let (fd, _) = stream_socket(network);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    network.bind(&fd, &addr).unwrap();
    network.listen(&fd, 1).unwrap();
    fd
}

/// Connect a new socket to `listener` and accept it, returning `(client, server)` ends.
fn connect_and_accept(
    network: &mut Network<MockPlatform>,
    listener: &SocketFd<MockPlatform>,
) -> (
    (SocketFd<MockPlatform>, TestProxy),
    (SocketFd<MockPlatform>, TestProxy),
) {
    let (client_fd, client) = stream_socket(network);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    pump(network);
    let server_fd = network.accept(listener, None).unwrap();
    let server = alloc::sync::Arc::new(NetworkProxy::Stream(
        socket_channel::StreamSocketChannel::new(),
    ));
    assert!(network.set_socket_proxy(&server_fd, server.clone()));
    pump(network);
    ((client_fd, client), (server_fd, server))
}

fn read(proxy: &NetworkProxy<MockPlatform>) -> Result<alloc::vec::Vec<u8>, ChannelReadError> {
    let mut buf = [0u8; 64];
    let n = proxy.try_read(&mut buf, ReceiveFlags::empty(), None)?;
    Ok(buf[..n].to_vec())
}

fn write(proxy: &NetworkProxy<MockPlatform>, data: &[u8]) -> Result<usize, ChannelWriteError> {
    proxy.try_write(data, SendFlags::empty(), None)
}

#[test]
fn test_tcp_shutdown_write_half_close() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let ((client_fd, client), (server_fd, server)) = connect_and_accept(&mut network, &listener);

    // Data written before `SHUT_WR` is delivered before the FIN.
    assert_eq!(write(&client, b"hello").unwrap(), 5);
    network.shutdown(&client_fd, Shutdown::Write).unwrap();
    assert!(matches!(
        write(&client, b"late"),
        Err(ChannelWriteError::WriteShutdown)
    ));
    pump(&mut network);
    assert_eq!(read(&server).unwrap(), b"hello");
    assert!(matches!(read(&server), Err(ChannelReadError::ReadShutdown)));
    assert!(server.check_io_events().contains(Events::RDHUP));

    // The half-closed connection still carries data in the other direction.
    assert_eq!(write(&server, b"world").unwrap(), 5);
    pump(&mut network);
    assert_eq!(read(&client).unwrap(), b"world");
    assert_eq!(read(&client).unwrap(), b"");

    // Closing the other half is graceful: end-of-file and no error on either side.
    network.shutdown(&server_fd, Shutdown::Write).unwrap();
    pump(&mut network);
    assert!(matches!(read(&client), Err(ChannelReadError::ReadShutdown)));
    for proxy in [&client, &server] {
        assert!(proxy.get_async_error(false).is_none());
        assert!(proxy.check_io_events().contains(Events::HUP));
    }
    assert!(matches!(
        network.shutdown(&client_fd, Shutdown::Both),
        Err(ShutdownError::NotConnected)
    ));

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_shutdown_read_keeps_receiving() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let ((client_fd, client), (server_fd, server)) = connect_and_accept(&mut network, &listener);

    // Like Linux, `SHUT_RD` reports end-of-file but neither discards nor refuses data.
    network.shutdown(&client_fd, Shutdown::Read).unwrap();
    assert!(matches!(read(&client), Err(ChannelReadError::ReadShutdown)));
    assert_eq!(write(&server, b"data").unwrap(), 4);
    pump(&mut network);
    assert_eq!(read(&client).unwrap(), b"data");
    assert!(matches!(read(&client), Err(ChannelReadError::ReadShutdown)));
    assert_eq!(write(&client, b"more").unwrap(), 4);
    pump(&mut network);
    assert_eq!(read(&server).unwrap(), b"more");

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_reset_reports_connection_reset() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let ((client_fd, client), (server_fd, _server)) = connect_and_accept(&mut network, &listener);

    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    pump(&mut network);
    assert!(matches!(
        read(&client),
        Err(ChannelReadError::ConnectionClosed)
    ));
    assert!(matches!(
        client.get_async_error(false),
        Some(errors::SocketAsyncError::ConnectionReset)
    ));

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_listener_shutdown() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);

    // Like Linux, `SHUT_WR` leaves a listener alone while `SHUT_RD` stops listening.
    network.shutdown(&listener, Shutdown::Write).unwrap();
    assert!(matches!(
        network.accept(&listener, None),
        Err(AcceptError::NoConnectionsReady)
    ));
    network.shutdown(&listener, Shutdown::Read).unwrap();
    assert!(matches!(
        network.accept(&listener, None),
        Err(AcceptError::NotListening)
    ));
    assert!(matches!(
        network.shutdown(&listener, Shutdown::Read),
        Err(ShutdownError::NotConnected)
    ));

    // The socket can listen again.
    network.listen(&listener, 1).unwrap();
    let ((client_fd, _), (server_fd, _)) = connect_and_accept(&mut network, &listener);

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

fn tcp_state(network: &Network<MockPlatform>, fd: &SocketFd<MockPlatform>) -> tcp::State {
    let table = network.litebox.descriptor_table();
    let entry = table.get_entry(fd).unwrap();
    network
        .socket_set
        .get::<tcp::Socket>(entry.entry.handle)
        .state()
}

#[test]
fn test_tcp_accept_half_closed_connection() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let (client_fd, client) = stream_socket(&mut network);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    pump(&mut network);

    // Like Linux, a connection the peer half-closes before `accept` can still be accepted.
    assert_eq!(write(&client, b"request").unwrap(), 7);
    network.shutdown(&client_fd, Shutdown::Write).unwrap();
    pump(&mut network);
    let server_fd = network.accept(&listener, None).unwrap();
    let server = alloc::sync::Arc::new(NetworkProxy::Stream(
        socket_channel::StreamSocketChannel::new(),
    ));
    assert!(network.set_socket_proxy(&server_fd, server.clone()));
    pump(&mut network);
    assert_eq!(read(&server).unwrap(), b"request");
    assert!(matches!(read(&server), Err(ChannelReadError::ReadShutdown)));

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_shutdown_write_before_connect_observed() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let (client_fd, client) = stream_socket(&mut network);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));

    // Shut down writes once the handshake completes but before the worker has observed it.
    while tcp_state(&network, &client_fd) != tcp::State::Established {
        network.perform_platform_interaction();
    }
    assert!(matches!(read(&client), Err(ChannelReadError::NotConnected)));
    network.shutdown(&client_fd, Shutdown::Write).unwrap();
    pump(&mut network);

    // The connection is still reported as established, both to the channel and to a blocked
    // `connect` checking its progress.
    assert_eq!(read(&client).unwrap(), b"");
    network.connect(&client_fd, &addr, true).unwrap();
    let server_fd = network.accept(&listener, None).unwrap();
    let server = alloc::sync::Arc::new(NetworkProxy::Stream(
        socket_channel::StreamSocketChannel::new(),
    ));
    assert!(network.set_socket_proxy(&server_fd, server.clone()));
    pump(&mut network);
    assert!(matches!(read(&server), Err(ChannelReadError::ReadShutdown)));

    // Closing the other half is graceful.
    network.shutdown(&server_fd, Shutdown::Write).unwrap();
    pump(&mut network);
    assert!(matches!(read(&client), Err(ChannelReadError::ReadShutdown)));
    assert!(client.get_async_error(false).is_none());

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_shutdown_requires_connection() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);

    let (tcp_fd, _) = stream_socket(&mut network);
    assert!(matches!(
        network.shutdown(&tcp_fd, Shutdown::Both),
        Err(ShutdownError::NotConnected)
    ));

    let udp_fd = network.socket(Protocol::Udp).unwrap();
    let udp = alloc::sync::Arc::new(NetworkProxy::Datagram(
        socket_channel::DatagramSocketChannel::new(),
    ));
    assert!(network.set_socket_proxy(&udp_fd, udp.clone()));
    // Like Linux, an unconnected UDP socket is shut down anyway.
    assert!(matches!(
        network.shutdown(&udp_fd, Shutdown::Read),
        Err(ShutdownError::NotConnected)
    ));
    assert!(matches!(read(&udp), Err(ChannelReadError::ReadShutdown)));
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    network.connect(&udp_fd, &addr, false).unwrap();
    network.shutdown(&udp_fd, Shutdown::Write).unwrap();
    assert!(matches!(
        write(&udp, b"data"),
        Err(ChannelWriteError::WriteShutdown)
    ));

    network.close(&tcp_fd, CloseBehavior::Immediate).unwrap();
    network.close(&udp_fd, CloseBehavior::Immediate).unwrap();
}
