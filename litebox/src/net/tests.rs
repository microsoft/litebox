use platform::mock::MockPlatform;

use super::*;

use core::net::SocketAddrV4;
use core::str::FromStr;
use alloc::string::String;

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
        .accept(&listener_fd)
        .expect("Failed to accept connection");

    // Send data from client to server
    let client_to_server_data = b"Hello from client!";
    let bytes_sent = network
        .send(&client_fd, client_to_server_data, SendFlags::empty())
        .expect("Failed to send data");
    assert_eq!(bytes_sent, client_to_server_data.len());

    comms(&mut network);

    // Receive data on the server
    let mut server_buffer = [0u8; 1024];
    let bytes_received = network
        .receive(&server_fd, &mut server_buffer, ReceiveFlags::empty())
        .expect("Failed to receive data");
    assert_eq!(&server_buffer[..bytes_received], client_to_server_data);

    // Send data from server to client
    let server_to_client_data = b"Hello from server!";
    let bytes_sent = network
        .send(&server_fd, server_to_client_data, SendFlags::empty())
        .expect("Failed to send data");
    assert_eq!(bytes_sent, server_to_client_data.len());

    comms(&mut network);

    // Receive data on the client
    let mut client_buffer = [0u8; 1024];
    let bytes_received = network
        .receive(&client_fd, &mut client_buffer, ReceiveFlags::empty())
        .expect("Failed to receive data");
    assert_eq!(&client_buffer[..bytes_received], server_to_client_data);

    network.close(client_fd);
    network.close(server_fd);
    network.close(listener_fd);
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
fn test_socket_metadata() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);

    // Create a socket
    let socket_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");

    // Test setting and getting socket metadata
    let test_data = String::from("socket-level metadata");
    let old_metadata = network
        .set_socket_metadata(&socket_fd, test_data.clone())
        .expect("Failed to set socket metadata");
    assert!(old_metadata.is_none(), "Expected no previous metadata");

    // Test reading socket metadata
    let retrieved_data = network
        .with_metadata(&socket_fd, |data: &String| data.clone())
        .expect("Failed to get socket metadata");
    assert_eq!(retrieved_data, test_data, "Retrieved metadata should match");

    // Test overwriting socket metadata
    let new_test_data = String::from("updated socket metadata");
    let old_metadata = network
        .set_socket_metadata(&socket_fd, new_test_data.clone())
        .expect("Failed to update socket metadata");
    assert_eq!(
        old_metadata, Some(test_data),
        "Should return previous metadata"
    );

    // Test retrieving updated metadata
    let updated_data = network
        .with_metadata(&socket_fd, |data: &String| data.clone())
        .expect("Failed to get updated socket metadata");
    assert_eq!(updated_data, new_test_data, "Updated metadata should match");

    // Close the socket
    network.close(socket_fd).expect("Failed to close socket");
}

#[test]
fn test_fd_metadata() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);

    // Create a socket
    let socket_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");

    // Test setting and getting fd-specific metadata
    let test_data = 42u32;
    let old_metadata = network
        .set_fd_metadata(&socket_fd, test_data)
        .expect("Failed to set fd metadata");
    assert!(old_metadata.is_none(), "Expected no previous metadata");

    // Test reading fd metadata
    let retrieved_data = network
        .with_metadata(&socket_fd, |data: &u32| *data)
        .expect("Failed to get fd metadata");
    assert_eq!(retrieved_data, test_data, "Retrieved metadata should match");

    // Test that mutable access works
    network
        .with_metadata_mut(&socket_fd, |data: &mut u32| {
            *data += 1;
        })
        .expect("Failed to modify fd metadata");

    let modified_data = network
        .with_metadata(&socket_fd, |data: &u32| *data)
        .expect("Failed to get modified fd metadata");
    assert_eq!(modified_data, test_data + 1, "Modified metadata should be incremented");

    // Close the socket
    network.close(socket_fd).expect("Failed to close socket");
}

#[test]
fn test_metadata_priority() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);

    // Create a socket
    let socket_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");

    // Set socket-level metadata
    let socket_data = String::from("socket level");
    network
        .set_socket_metadata(&socket_fd, socket_data.clone())
        .expect("Failed to set socket metadata");

    // Verify socket metadata is accessible
    let retrieved_socket_data = network
        .with_metadata(&socket_fd, |data: &String| data.clone())
        .expect("Failed to get socket metadata");
    assert_eq!(retrieved_socket_data, socket_data, "Socket metadata should match");

    // Set fd-level metadata of the same type - this should shadow socket metadata
    let fd_data = String::from("fd level");
    network
        .set_fd_metadata(&socket_fd, fd_data.clone())
        .expect("Failed to set fd metadata");

    // Verify fd metadata shadows socket metadata
    let retrieved_data = network
        .with_metadata(&socket_fd, |data: &String| data.clone())
        .expect("Failed to get metadata");
    assert_eq!(retrieved_data, fd_data, "FD metadata should shadow socket metadata");

    // Close the socket
    network.close(socket_fd).expect("Failed to close socket");
}

#[test]
fn test_metadata_errors() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);

    // Create a socket 
    let socket_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");

    // Test nonexistent metadata type
    let result = network.with_metadata(&socket_fd, |_data: &String| ());
    assert!(matches!(result, Err(MetadataError::NoSuchMetadata)), "Should return NoSuchMetadata error");

    // Close the socket
    network.close(socket_fd).expect("Failed to close socket");
}
