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
    stream_socket_with_rx_capacity(network, SOCKET_BUFFER_SIZE)
}

/// Like [`stream_socket`], with the given receive channel capacity.
fn stream_socket_with_rx_capacity(
    network: &mut Network<MockPlatform>,
    rx_capacity: usize,
) -> (SocketFd<MockPlatform>, TestProxy) {
    let fd = network.socket(Protocol::Tcp).unwrap();
    let proxy = alloc::sync::Arc::new(NetworkProxy::Stream(
        socket_channel::StreamSocketChannel::new_with_capacity(rx_capacity, SOCKET_BUFFER_SIZE),
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
    connect_and_accept_with_rx_capacities(network, listener, SOCKET_BUFFER_SIZE, SOCKET_BUFFER_SIZE)
}

/// Like [`connect_and_accept`], with the given receive channel capacities for the two ends.
fn connect_and_accept_with_rx_capacities(
    network: &mut Network<MockPlatform>,
    listener: &SocketFd<MockPlatform>,
    client_rx_capacity: usize,
    server_rx_capacity: usize,
) -> (
    (SocketFd<MockPlatform>, TestProxy),
    (SocketFd<MockPlatform>, TestProxy),
) {
    let (client_fd, client) = stream_socket_with_rx_capacity(network, client_rx_capacity);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    pump(network);
    let server_fd = network.accept(listener, None).unwrap();
    let server = alloc::sync::Arc::new(NetworkProxy::Stream(
        socket_channel::StreamSocketChannel::new_with_capacity(
            server_rx_capacity,
            SOCKET_BUFFER_SIZE,
        ),
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
        connect_and_accept_with_rx_capacities(&mut network, &listener, SOCKET_BUFFER_SIZE, 4);

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
        connect_and_accept_with_rx_capacities(&mut network, &listener, SOCKET_BUFFER_SIZE, 4);

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

#[test]
fn test_tcp_shutdown_while_connecting() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let (client_fd, client) = stream_socket(&mut network);
    // A socket that has not connected stays unconnected.
    pump(&mut network);
    assert!(matches!(read(&client), Err(ChannelReadError::NotConnected)));
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));

    // Shutting down aborts the connection attempt, which is reported as a reset rather than a
    // refused connection, and leaves the socket unconnected.
    network.shutdown(&client_fd, Shutdown::Both).unwrap();
    pump(&mut network);
    assert!(
        client
            .check_io_events()
            .contains(Events::OUT | Events::ERR | Events::HUP)
    );
    assert!(matches!(
        client.get_async_error(true),
        Some(errors::SocketAsyncError::ConnectionReset)
    ));
    pump(&mut network);
    assert!(matches!(read(&client), Err(ChannelReadError::NotConnected)));
    assert!(!client.check_io_events().contains(Events::ERR));

    // Another attempt can then connect, discarding the error of an aborted attempt.
    let listener = listening_socket(&mut network);
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    network.shutdown(&client_fd, Shutdown::Both).unwrap();
    assert!(client.get_async_error(false).is_some());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    assert!(client.get_async_error(false).is_none());
    pump(&mut network);
    network.connect(&client_fd, &addr, true).unwrap();
    let server_fd = network.accept(&listener, None).unwrap();

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_connect_reports_connection_state() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let (client_fd, client) = stream_socket(&mut network);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));

    // Another call while the attempt is in progress does not start a new one.
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::AlreadyInProgress));

    // The first call after the attempt succeeds reports the success; later calls report that the
    // socket is already connected.
    pump(&mut network);
    network.connect(&client_fd, &addr, false).unwrap();
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::AlreadyConnected));

    // So do accepted and listening sockets.
    let server_fd = network.accept(&listener, None).unwrap();
    let err = network.connect(&server_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::AlreadyConnected));
    let err = network.connect(&listener, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::AlreadyConnected));

    // A connected socket stays connected after the connection is lost.
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    pump(&mut network);
    assert!(matches!(
        client.get_async_error(false),
        Some(errors::SocketAsyncError::ConnectionReset)
    ));
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::AlreadyConnected));

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_reconnect_after_refused_connect() {
    let platform = MockPlatform::new();
    let litebox = LiteBox::new(platform);
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let (client_fd, client) = stream_socket(&mut network);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let assert_unconnected = || {
        assert!(client.get_async_error(false).is_none());
        assert!(matches!(read(&client), Err(ChannelReadError::NotConnected)));
        let events = client.check_io_events();
        assert!(events.contains(Events::OUT | Events::HUP));
        assert!(!events.contains(Events::ERR));
    };

    // A refusal reported while checking progress leaves the socket unconnected, with the error no
    // longer pending.
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    let local_addr = network.get_local_addr(&client_fd).unwrap();
    pump(&mut network);
    let err = network.connect(&client_fd, &addr, true).unwrap_err();
    assert!(matches!(err, ConnectError::InvalidState));
    assert_unconnected();

    // So does a refusal reported by the next call, after it is pending, however late the call.
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    pump(&mut network);
    assert!(client.check_io_events().contains(Events::ERR));
    platform.advance_time(core::time::Duration::from_secs(100));
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InvalidState));
    assert_unconnected();

    // Another attempt then connects from the same local port.
    let listener = listening_socket(&mut network);
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    assert_eq!(network.get_local_addr(&client_fd).unwrap(), local_addr);
    pump(&mut network);
    network.connect(&client_fd, &addr, true).unwrap();
    let server_fd = network.accept(&listener, None).unwrap();

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_reconnect_after_lost_connection() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let assert_unconnected = |client: &TestProxy| {
        assert!(client.get_async_error(false).is_none());
        assert!(matches!(read(client), Err(ChannelReadError::NotConnected)));
        let events = client.check_io_events();
        assert!(events.contains(Events::OUT | Events::HUP));
        assert!(!events.intersects(Events::IN | Events::RDHUP | Events::ERR));
    };

    // Shutting down a connection that `connect` has not reported yet confirms it.
    let ((client_fd, _), (server_fd, _)) = connect_and_accept(&mut network, &listener);
    network.shutdown(&client_fd, Shutdown::Write).unwrap();
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::AlreadyConnected));
    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();

    // Otherwise, the loss of such a connection is reported by the next call, which discards what
    // is left of the connection, including data that smoltcp holds because the channel is full.
    let ((client_fd, client), (server_fd, server)) =
        connect_and_accept_with_rx_capacities(&mut network, &listener, 2, SOCKET_BUFFER_SIZE);
    write(&server, b"old").unwrap();
    pump(&mut network);
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    pump(&mut network);
    assert!(
        client
            .check_io_events()
            .contains(Events::IN | Events::RDHUP | Events::ERR)
    );
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::ConnectionReset));
    pump(&mut network);
    assert_unconnected(&client);
    let mut buf = [0; 3];
    let err = network
        .receive(&client_fd, &mut buf, ReceiveFlags::empty(), None)
        .unwrap_err();
    assert!(matches!(err, ReceiveError::SocketInInvalidState));

    // Another attempt then starts afresh.
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    pump(&mut network);
    network.connect(&client_fd, &addr, true).unwrap();
    let server_fd = network.accept(&listener, None).unwrap();
    pump(&mut network);
    let events = client.check_io_events();
    assert!(events.contains(Events::OUT));
    assert!(!events.intersects(Events::IN | Events::RDHUP | Events::ERR | Events::HUP));
    assert_eq!(write(&client, b"new").unwrap(), 3);
    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();

    // The loss is reported even if the network worker has not recorded it yet.
    let ((client_fd, client), (server_fd, _)) = connect_and_accept(&mut network, &listener);
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    while tcp_state(&network, &client_fd) != tcp::State::Closed {
        network.perform_platform_interaction();
    }
    assert!(!client.check_io_events().contains(Events::ERR));
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::ConnectionReset));
    network.close(&client_fd, CloseBehavior::Immediate).unwrap();

    // The same holds after the peer's FIN, which smoltcp remembers after the reset.
    let ((client_fd, client), (server_fd, _)) = connect_and_accept(&mut network, &listener);
    network.shutdown(&server_fd, Shutdown::Write).unwrap();
    pump(&mut network);
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    pump(&mut network);
    assert!(client.check_io_events().contains(Events::RDHUP));
    network.connect(&client_fd, &addr, false).unwrap_err();
    pump(&mut network);
    assert_unconnected(&client);

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}

#[test]
fn test_tcp_connect_from_bound_port() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    let listener = listening_socket(&mut network);
    let (client_fd, _client) = stream_socket(&mut network);
    let local_addr = SocketAddr::V4(SocketAddrV4::from_str("0.0.0.0:5555").unwrap());
    network.bind(&client_fd, &local_addr).unwrap();
    let addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    let err = network.connect(&client_fd, &addr, false).unwrap_err();
    assert!(matches!(err, ConnectError::InProgress));
    pump(&mut network);
    network.connect(&client_fd, &addr, true).unwrap();
    let mut peer = local_addr;
    let server_fd = network.accept(&listener, Some(&mut peer)).unwrap();
    assert_eq!(peer.port(), 5555);

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network.close(&listener, CloseBehavior::Immediate).unwrap();
}
