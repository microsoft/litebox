//! Network-related functionality

use core::{net::SocketAddr, num::NonZeroU32};

use crate::platform;

use thiserror::Error;

/// The `Network` provides access to all networking related functionality provided by LiteBox.
///
/// A LiteBox `Network` is parametric in the platform it runs on.
pub struct Network<Platform: platform::Provider> {
    platform: &'static Platform,
}

/// Possible errors from a [`Network`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum NetError {}

/// A convenience type-alias for networking results
type Result<T> = core::result::Result<T, NetError>;

impl<Platform: platform::Provider> Network<Platform> {
    /// Construct a new `Network` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `Network` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(platform: &'static Platform) -> Self {
        Self { platform }
    }
}

/// An owned file descriptor for a socket
///
/// This file descriptor **must** be consumed by a `close` operation, otherwise will panic at
/// run-time upon being dropped.
pub struct SocketFd {
    pub(crate) fd: crate::fd::OwnedFd,
}

impl<Platform: platform::Provider> Network<Platform> {
    /// Creates a socket.
    pub fn socket(
        &self,
        domain: AddressFamily,
        type_: SocketType,
        protocol: Option<Protocol>,
    ) -> Result<SocketFd> {
        todo!()
    }

    /// Close the socket at `fd`
    pub fn close(&self, fd: SocketFd) -> Result<()> {
        let SocketFd { mut fd } = fd;
        fd.mark_as_closed();
        todo!()
    }

    /// Initiate a connection to an IP address
    pub fn connect(&self, fd: &SocketFd, addr: &SocketAddr) -> Result<()> {
        todo!()
    }
}

/// `AF_*` constants for use with [`Network::socket`]
#[non_exhaustive]
#[repr(i32)]
pub enum AddressFamily {
    /// `AF_LOCAL`/`AF_UNIX`: Local communication.
    Local = 1,
    /// `AF_INET`: IPv4 Internet protocols.
    Inet = 2,
    /// `AF_NETLINK`: Kernel user interface device.
    Netlink = 16,
}

/// `SOCK_*` constants for use with [`Network::socket`]
#[non_exhaustive]
#[repr(i32)]
pub enum SocketType {
    /// `SOCK_STREAM`: Provides sequenced, reliable, two-way, connection-based byte streams.
    Stream = 1,
    /// `SOCK_DGRAM`: Supports datagrams (connectionless, unreliable messages of a fixed maximum length).
    Datagram = 2,
    /// `SOCK_RAW`: Provides raw network protocol access.
    Raw = 3,
}

/// Protocol constants for use with [`Network::socket`]
pub struct Protocol {
    // TODO(jayb): Does this need to be public, or can we restrict by specifying an enum of values
    // we want to support/allow?
    pub protocol: NonZeroU32,
}
