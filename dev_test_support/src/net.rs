// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Loopback addresses that refuse what is sent to them.
//!
//! Each address comes with what holds its port, so that no test running in
//! parallel can be given the port while it is kept. A port freed before use
//! could be.

use std::net::{Ipv4Addr, SocketAddrV4};

/// Returns a loopback TCP address that refuses connections, with the socket
/// that holds it.
///
/// The socket is bound but never listens, so connecting to the address is
/// refused, and no other socket can be given the port while the socket is
/// kept.
///
/// # Panics
///
/// Panics if the socket cannot be made.
pub fn refusing_tcp_address() -> (impl Sized, SocketAddrV4) {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket
        .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
        .unwrap();
    let address = socket.local_addr().unwrap().as_socket_ipv4().unwrap();
    (socket, address)
}

/// Returns a loopback UDP address to which datagrams are refused, with what
/// reserves it.
///
/// On Linux, a socket connected to itself holds the port: it receives only its
/// own datagrams, and it sends none, so Linux refuses others, with ICMP port
/// unreachable, as for a closed port. No other socket can take the port while
/// the socket is kept.
///
/// Winsock discards datagrams from other addresses on a connected socket, so
/// on Windows the port is left unbound instead: it is below Windows' dynamic
/// port range (49152-65535 by default), so no socket is given it without
/// asking for it, and a TCP listener on the same port keeps other calls from
/// choosing it.
///
/// # Panics
///
/// Panics if the port cannot be reserved.
pub fn refusing_udp_address() -> (impl Sized, SocketAddrV4) {
    #[cfg(target_os = "linux")]
    {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let std::net::SocketAddr::V4(address) = socket.local_addr().unwrap() else {
            unreachable!()
        };
        socket.connect(address).unwrap();
        (socket, address)
    }
    #[cfg(windows)]
    {
        (20_000..32_768)
            .find_map(|port| {
                let reservation = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
                std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
                Some((reservation, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
            })
            .expect("no free TCP and UDP port below the dynamic port range")
    }
}
