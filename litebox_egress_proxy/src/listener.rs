// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Loopback listener acquisition.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};

use thiserror::Error;

/// Where the proxy's listener comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerSource {
    /// Bind a fresh loopback listener. Port zero requests an ephemeral port.
    Bind(SocketAddrV4),
    /// Adopt an inherited listener by descriptor number.
    Inherited(i32),
}

/// Reason a listener could not be acquired.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// A listener operation failed.
    #[error("listener operation failed: {0}")]
    Io(#[from] io::Error),
    /// The listener was not a bound IPv4 loopback TCP listener.
    #[error("listener must be a bound IPv4 loopback TCP listener")]
    Invalid,
    /// This platform cannot adopt inherited listeners.
    #[error("inherited listeners are unsupported on this platform")]
    Unsupported,
}

/// Acquires a nonblocking IPv4 loopback listener and its bound address.
pub fn acquire(source: ListenerSource) -> Result<(TcpListener, SocketAddrV4), ListenerError> {
    let listener = match source {
        ListenerSource::Bind(address) => TcpListener::bind(address)?,
        ListenerSource::Inherited(descriptor) => adopt_inherited(descriptor)?,
    };

    let SocketAddr::V4(address) = listener.local_addr()? else {
        return Err(ListenerError::Invalid);
    };
    if *address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err(ListenerError::Invalid);
    }

    listener.set_nonblocking(true)?;
    Ok((listener, address))
}

#[cfg(target_os = "linux")]
fn adopt_inherited(descriptor: i32) -> Result<TcpListener, ListenerError> {
    use std::os::fd::FromRawFd;

    if descriptor < 0
        || socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_INET
        || socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 1
    {
        return Err(ListenerError::Invalid);
    }

    // SAFETY: the checks above establish that `descriptor` is an open,
    // listening IPv4 stream socket. The launcher transfers ownership of the
    // descriptor to this process, so the returned listener is its sole owner.
    Ok(unsafe { TcpListener::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn socket_option(descriptor: i32, option: libc::c_int) -> Result<libc::c_int, ListenerError> {
    let mut value: libc::c_int = 0;
    let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .expect("the size of a C int fits in socklen_t");

    // SAFETY: `value` and `length` are valid, correctly sized and aligned
    // locals. `getsockopt` writes at most `length` bytes into `value`.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
            &raw mut length,
        )
    };
    if result == 0 {
        Ok(value)
    } else {
        Err(io::Error::last_os_error().into())
    }
}

#[cfg(not(target_os = "linux"))]
fn adopt_inherited(_descriptor: i32) -> Result<TcpListener, ListenerError> {
    Err(ListenerError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_an_ephemeral_loopback_port() {
        let (_listener, address) = acquire(ListenerSource::Bind(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        )))
        .unwrap();
        assert_eq!(*address.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(address.port(), 0);
    }

    #[test]
    fn rejects_non_loopback_binds() {
        let error = acquire(ListenerSource::Bind(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))
        .unwrap_err();
        assert!(matches!(error, ListenerError::Invalid));
    }

    #[test]
    fn rejects_a_negative_descriptor() {
        let error = acquire(ListenerSource::Inherited(-1)).unwrap_err();
        assert!(matches!(
            error,
            ListenerError::Invalid | ListenerError::Unsupported
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adopts_an_inherited_loopback_listener() {
        use std::os::fd::IntoRawFd;

        let bound = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let expected = bound.local_addr().unwrap();
        let descriptor = bound.into_raw_fd();

        let (adopted, _) = acquire(ListenerSource::Inherited(descriptor)).unwrap();
        assert_eq!(adopted.local_addr().unwrap(), expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_a_connected_socket() {
        use std::os::fd::IntoRawFd;

        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let error = acquire(ListenerSource::Inherited(client.into_raw_fd())).unwrap_err();
        assert!(matches!(error, ListenerError::Invalid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_a_datagram_socket() {
        use std::os::fd::IntoRawFd;

        let socket = std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let error = acquire(ListenerSource::Inherited(socket.into_raw_fd())).unwrap_err();
        assert!(matches!(error, ListenerError::Invalid));
    }
}
