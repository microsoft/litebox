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
    network
        .connect(&client_fd, &listen_addr)
        .expect("Failed to connect TCP socket");

    comms(&mut network);

    // Accept the connection on the listening socket
    let server_fd = network
        .accept(&listener_fd, None)
        .expect("Failed to accept connection");

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

    network.close(&client_fd).unwrap();
    network.close(&server_fd).unwrap();
    network.close(&listener_fd).unwrap();
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
