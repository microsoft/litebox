// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Listener acquisition for the standalone and broker modes.
//!
//! Both modes end with the same invariant: the proxy only ever serves a bound,
//! listening IPv4 loopback TCP socket. The standalone mode binds it itself; the
//! broker mode adopts a listener that a launcher bound and inherited to this
//! process.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};

use thiserror::Error;

/// Where the proxy's listener comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerSource {
    /// Bind a fresh loopback listener. Port zero requests an ephemeral port.
    Bind(SocketAddrV4),
    /// Adopt an inherited, already-bound listener by descriptor number.
    Inherited(i32),
}

/// Reason a listener could not be acquired.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// Binding the requested address failed.
    #[error("failed to bind {address}: {source}")]
    Bind {
        /// The address that could not be bound.
        address: SocketAddrV4,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// Reading the listener's local address failed.
    #[error("failed to read the listener address: {0}")]
    LocalAddress(#[source] std::io::Error),
    /// The listener was not bound to canonical IPv4 loopback.
    #[error("listener is bound to {0}, which is not 127.0.0.1")]
    NotLoopback(SocketAddr),
    /// The listener was bound to port zero, which an inherited listener never
    /// is once it has been bound.
    #[error("inherited listener is not bound to a concrete port")]
    UnboundPort,
    /// The descriptor number was negative.
    #[error("inherited listener descriptor is not a valid descriptor number")]
    InvalidDescriptor,
    /// The descriptor did not refer to an open file.
    #[error("inherited listener descriptor is not open")]
    DescriptorNotOpen,
    /// Inspecting the socket failed.
    #[error("failed to inspect the inherited listener: {0}")]
    Inspect(#[source] std::io::Error),
    /// The descriptor was not an IPv4 stream socket in the listening state.
    #[error("inherited descriptor is not a listening IPv4 TCP socket")]
    NotAnIpv4Listener,
    /// The platform has no inherited-listener contract.
    #[error("--listener-fd is only supported on Linux")]
    InheritanceUnsupported,
    /// Configuring the listener for asynchronous use failed.
    #[error("failed to configure the listener: {0}")]
    Configure(#[source] std::io::Error),
}

/// Acquires the listener described by `source`.
///
/// The returned listener is non-blocking and validated to be bound to
/// canonical IPv4 loopback.
pub fn acquire(source: ListenerSource) -> Result<TcpListener, ListenerError> {
    let listener = match source {
        ListenerSource::Bind(address) => {
            TcpListener::bind(address).map_err(|source| ListenerError::Bind { address, source })?
        }
        ListenerSource::Inherited(descriptor) => adopt_inherited(descriptor)?,
    };

    let local = listener.local_addr().map_err(ListenerError::LocalAddress)?;
    let SocketAddr::V4(local) = local else {
        return Err(ListenerError::NotLoopback(local));
    };
    if *local.ip() != Ipv4Addr::LOCALHOST {
        return Err(ListenerError::NotLoopback(SocketAddr::V4(local)));
    }
    if local.port() == 0 {
        return Err(ListenerError::UnboundPort);
    }

    listener
        .set_nonblocking(true)
        .map_err(ListenerError::Configure)?;
    Ok(listener)
}

/// Adopts an inherited descriptor after validating that it really is a bound,
/// listening IPv4 TCP socket.
#[cfg(target_os = "linux")]
fn adopt_inherited(descriptor: i32) -> Result<TcpListener, ListenerError> {
    use std::os::fd::FromRawFd;

    if descriptor < 0 {
        return Err(ListenerError::InvalidDescriptor);
    }

    // SAFETY: `fcntl(F_GETFD)` only reads the descriptor flags of `descriptor`.
    // It neither takes ownership nor mutates process state, and it reports an
    // invalid descriptor as `-1` instead of causing undefined behaviour.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(ListenerError::DescriptorNotOpen);
    }

    if socket_option(descriptor, libc::SO_DOMAIN)? != libc::AF_INET
        || socket_option(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(descriptor, libc::SO_ACCEPTCONN)? != 1
    {
        return Err(ListenerError::NotAnIpv4Listener);
    }

    // SAFETY: the checks above established that `descriptor` is an open,
    // listening IPv4 stream socket. The launcher contract for `--listener-fd`
    // transfers ownership of that descriptor to this process, and nothing else
    // in this process holds or closes it, so wrapping it in a `TcpListener`
    // gives a single unique owner.
    Ok(unsafe { TcpListener::from_raw_fd(descriptor) })
}

/// Reads a `SOL_SOCKET` integer option.
#[cfg(target_os = "linux")]
fn socket_option(descriptor: i32, option: libc::c_int) -> Result<libc::c_int, ListenerError> {
    let mut value: libc::c_int = 0;
    let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .expect("the size of a C int fits in socklen_t");

    // SAFETY: `value` and `length` are valid, correctly sized and aligned
    // locals that outlive the call. `getsockopt` writes at most `length` bytes
    // into `value` and updates `length` accordingly, and reports failure as
    // `-1` rather than writing out of bounds.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(ListenerError::Inspect(std::io::Error::last_os_error()));
    }
    Ok(value)
}

/// Inherited listeners are a Linux-only contract in this milestone.
#[cfg(not(target_os = "linux"))]
fn adopt_inherited(_descriptor: i32) -> Result<TcpListener, ListenerError> {
    Err(ListenerError::InheritanceUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_an_ephemeral_loopback_port() {
        let listener = acquire(ListenerSource::Bind(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        )))
        .unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("expected an IPv4 listener");
        };
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
        assert!(matches!(error, ListenerError::NotLoopback(_)));
    }

    #[test]
    fn rejects_a_negative_descriptor() {
        let error = acquire(ListenerSource::Inherited(-1)).unwrap_err();
        assert!(matches!(
            error,
            ListenerError::InvalidDescriptor | ListenerError::InheritanceUnsupported
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adopts_an_inherited_loopback_listener() {
        use std::os::fd::IntoRawFd;

        let bound = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let expected = bound.local_addr().unwrap();
        let descriptor = bound.into_raw_fd();

        let adopted = acquire(ListenerSource::Inherited(descriptor)).unwrap();
        assert_eq!(adopted.local_addr().unwrap(), expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_a_connected_socket() {
        use std::os::fd::IntoRawFd;

        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let error = acquire(ListenerSource::Inherited(client.into_raw_fd())).unwrap_err();
        assert!(matches!(error, ListenerError::NotAnIpv4Listener));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_a_datagram_socket() {
        use std::os::fd::IntoRawFd;

        let socket = std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let error = acquire(ListenerSource::Inherited(socket.into_raw_fd())).unwrap_err();
        assert!(matches!(error, ListenerError::NotAnIpv4Listener));
    }
}
