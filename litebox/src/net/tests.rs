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
    connect_and_accept_with_server_rx_capacity(network, listener, SOCKET_BUFFER_SIZE)
}

/// Like [`connect_and_accept`], with the given receive channel capacity for the server end.
fn connect_and_accept_with_server_rx_capacity(
    network: &mut Network<MockPlatform>,
    listener: &SocketFd<MockPlatform>,
    rx_capacity: usize,
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
        socket_channel::StreamSocketChannel::new_with_capacity(rx_capacity, SOCKET_BUFFER_SIZE),
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

    // Closing the other half is graceful: the connection closes with no error on either side,
    // so reads report end-of-file.
    network.shutdown(&server_fd, Shutdown::Write).unwrap();
    pump(&mut network);
    assert!(matches!(
        read(&client),
        Err(ChannelReadError::ConnectionClosed)
    ));
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

    // `SHUT_RD` reports end-of-file but neither discards nor refuses data.
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
fn test_tcp_reset_after_shutdown_read() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let ((client_fd, client), (server_fd, _server)) = connect_and_accept(&mut network, &listener);

    // A reset is reported to reads even after `SHUT_RD`.
    network.shutdown(&client_fd, Shutdown::Read).unwrap();
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
fn test_tcp_reset_reported_before_unread_data() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    // A small channel leaves the data that does not fit in smoltcp.
    let ((client_fd, client), (server_fd, server)) =
        connect_and_accept_with_server_rx_capacity(&mut network, &listener, 4);

    assert_eq!(write(&client, b"hello world").unwrap(), 11);
    pump(&mut network);
    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    pump(&mut network);

    // The reset is reported at once, but data received before it is still read.
    assert!(
        server
            .check_io_events()
            .contains(Events::ERR | Events::HUP | Events::RDHUP)
    );
    assert!(matches!(
        write(&server, b"x"),
        Err(ChannelWriteError::WriteShutdown)
    ));
    // Once consumed, as by `SO_ERROR`, the reset is not reported again.
    assert!(matches!(
        server.get_async_error(true),
        Some(errors::SocketAsyncError::ConnectionReset)
    ));
    let mut received = alloc::vec::Vec::new();
    let err = loop {
        pump(&mut network);
        match read(&server) {
            Ok(data) => received.extend_from_slice(&data),
            Err(err) => break err,
        }
    };
    assert_eq!(received, b"hello world");
    assert!(matches!(err, ChannelReadError::ConnectionClosed));
    assert!(server.get_async_error(false).is_none());

    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_graceful_close_with_unread_data() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let ((client_fd, client), (server_fd, server)) =
        connect_and_accept_with_server_rx_capacity(&mut network, &listener, 4);

    // The connection closes gracefully while smoltcp still holds data that did not fit in the
    // channel: the peer's FIN, then ours.
    assert_eq!(write(&client, b"hello world").unwrap(), 11);
    network.shutdown(&client_fd, Shutdown::Write).unwrap();
    pump(&mut network);
    // The peer's FIN is reported at once, but reads still return the data first.
    assert!(server.check_io_events().contains(Events::RDHUP));
    assert!(!server.check_io_events().contains(Events::HUP));
    assert_eq!(read(&server).unwrap(), b"hell");
    assert_eq!(read(&server).unwrap(), b"");
    network.shutdown(&server_fd, Shutdown::Write).unwrap();
    pump(&mut network);
    assert_eq!(tcp_state(&network, &server_fd), tcp::State::Closed);
    assert!(server.check_io_events().contains(Events::HUP));

    let mut received = b"hell".to_vec();
    while let Ok(data) = read(&server) {
        received.extend_from_slice(&data);
        pump(&mut network);
    }
    assert_eq!(received, b"hello world");
    assert!(server.get_async_error(false).is_none());
    assert!(!server.check_io_events().contains(Events::ERR));

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

    // A connection the peer half-closes before `accept` can still be accepted.
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
    assert!(matches!(
        read(&client),
        Err(ChannelReadError::ConnectionClosed)
    ));
    assert!(client.get_async_error(false).is_none());

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}
