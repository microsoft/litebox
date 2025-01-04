//! Network-related functionality

use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddr;

use crate::platform;
use crate::platform::Instant;

use bitflags::bitflags;
use smoltcp::socket::{icmp, raw, tcp, udp};
use thiserror::Error;

mod local_ports;
mod phy;

use local_ports::{LocalPort, LocalPortAllocationError, LocalPortAllocator};

/// Maximum number of sockets that can ever be active
const MAX_NUMBER_OF_SOCKETS: usize = 1024;

/// Maximum size of rx/tx buffers for sockets
const SOCKET_BUFFER_SIZE: usize = 65536;

/// Limits maximum number of packets in a buffer
const MAX_PACKET_COUNT: usize = 32;

/// The `Network` provides access to all networking related functionality provided by LiteBox.
///
/// A LiteBox `Network` is parametric in the platform it runs on.
pub struct Network<Platform: platform::IPInterfaceProvider + platform::TimeProvider + 'static> {
    platform: &'static Platform,
    /// The set of sockets
    socket_set: smoltcp::iface::SocketSet<'static>,
    /// Handles into the `socket_set`; the position/index corresponds to the `raw_fd` of the
    /// `SocketFd` given out from this module.
    handles: Vec<Option<SocketHandle>>,
    /// The actual "physical" device, that connects to the platform
    device: phy::Device<Platform>,
    /// The smoltcp network interface
    interface: smoltcp::iface::Interface,
    /// Initial instant of creation, used as an arbitrary stop point from when time begins
    zero_time: Platform::Instant,
    /// An allocator for local ports
    local_port_allocator: LocalPortAllocator,
}

/// Possible errors from a [`Network`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum NetError {
    #[error("Unsupported protocol {0}")]
    UnsupportedProtocol(u8),
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Port allocation failed: {0}")]
    PortAllocationFailure(#[from] LocalPortAllocationError),
    #[error("Socket is in an invalid state")]
    SocketInInvalidState,
    #[error("Operation finished")]
    OperationFinished,
}

impl<Platform: platform::IPInterfaceProvider + platform::TimeProvider + 'static> Network<Platform> {
    /// Construct a new `Network` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `Network` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(platform: &'static Platform) -> Self {
        let mut device = phy::Device::new(platform);
        let config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let interface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);
        Self {
            platform,
            socket_set: smoltcp::iface::SocketSet::new(vec![]),
            handles: vec![],
            device,
            interface,
            zero_time: platform.now(),
            local_port_allocator: LocalPortAllocator::new(),
        }
    }
}

/// An owned file descriptor for a socket
///
/// This file descriptor **must** be consumed by a `close` operation, otherwise will panic at
/// run-time upon being dropped.
pub struct SocketFd {
    pub(crate) fd: crate::fd::OwnedFd,
}
impl SocketFd {
    fn as_usize(&self) -> usize {
        self.fd.as_raw_fd().try_into().unwrap()
    }
}

/// [`SocketHandle`] stores all relevant information for a specific [`SocketFd`], for easy access
/// from [`SocketFd`], _except_ the `Socket` itself which is stored in the [`Sockets::socket_set`].
struct SocketHandle {
    /// The handle into the `socket_set`
    handle: smoltcp::iface::SocketHandle,
    /// The protocol for this socket
    protocol: Protocol,
    /// A local port associated with this socket, if any
    local_port: Option<LocalPort>,
}

impl<Platform: platform::IPInterfaceProvider + platform::TimeProvider + 'static> Network<Platform> {
    /// Explicitly private-only function that returns the current (smoltcp) Instant, relative to the
    /// initialized arbitrary 0-point in time.
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            // This conversion from u128 to i64 should practically never fail, since 2^63
            // microseconds is roughly 250 years. If a system has been up for that long, then it
            // deserves to panic.
            i64::try_from(
                self.zero_time
                    .duration_since(&self.device.platform.now())
                    .as_micros(),
            )
            .unwrap(),
        )
    }

    /// Creates a socket.
    pub fn socket(&mut self, protocol: Protocol) -> Result<SocketFd, NetError> {
        let handle = match protocol {
            Protocol::Tcp => self.socket_set.add(tcp::Socket::new(
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
            )),
            Protocol::Udp => self.socket_set.add(udp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Icmp => self.socket_set.add(icmp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Raw { protocol } => {
                // TODO: Should we maintain a specific allow-list of protocols for raw sockets?
                // Should we allow everything except TCP/UDP/ICMP? Should we allow everything? These
                // questions should be resolved; for now I am disallowing everything else.
                return Err(NetError::UnsupportedProtocol(protocol));

                self.socket_set.add(raw::Socket::new(
                    smoltcp::wire::IpVersion::Ipv4,
                    smoltcp::wire::IpProtocol::from(protocol),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                ))
            }
        };

        // TODO: We can do reuse of fds if we maintained a free-list or similar; for now, we just
        // grab an entirely new fd anytime there is a new socket to be made.

        let Ok(raw_fd) = self.handles.len().try_into() else {
            // This will panic only if we have reached ~2 billion handles, which we should
            // practically never really hit.
            unreachable!()
        };
        self.handles.push(Some(SocketHandle {
            handle,
            protocol,
            local_port: None,
        }));

        Ok(SocketFd {
            fd: crate::fd::OwnedFd::new(raw_fd),
        })
    }

    /// Close the socket at `fd`
    pub fn close(&mut self, fd: SocketFd) -> Result<(), NetError> {
        let mut socket_handle =
            core::mem::take(&mut self.handles[fd.as_usize()]).ok_or(NetError::InvalidFd)?;
        let socket = self.socket_set.remove(socket_handle.handle);
        match socket {
            smoltcp::socket::Socket::Raw(_) | smoltcp::socket::Socket::Icmp(_) => {
                // There is no close/abort for raw and icmp sockets
            }
            smoltcp::socket::Socket::Udp(mut socket) => {
                socket.close();
            }
            smoltcp::socket::Socket::Tcp(mut socket) => {
                if let Some(local_port) = socket_handle.local_port.take() {
                    self.local_port_allocator.deallocate(local_port);
                }
                // TODO: Should we `.close()` or should we `.abort()`?
                socket.abort();
            }
        }
        let SocketFd { mut fd } = fd;
        fd.mark_as_closed();
        Ok(())
    }

    /// Initiate a connection to an IP address
    pub fn connect(&mut self, fd: &SocketFd, addr: &SocketAddr) -> Result<(), NetError> {
        let SocketAddr::V4(addr) = addr else {
            return Err(NetError::UnsupportedAddress(*addr));
        };

        let socket_handle = self.handles[fd.as_usize()]
            .as_mut()
            .ok_or(NetError::InvalidFd)?;

        match socket_handle.protocol {
            Protocol::Tcp => {
                let socket: &mut tcp::Socket = self.socket_set.get_mut(socket_handle.handle);
                let local_port = self.local_port_allocator.ephemeral_port()?;
                let local_endpoint = local_port.port();
                socket.connect(self.interface.context(), *addr, local_endpoint);
                let old_port = core::mem::replace(&mut socket_handle.local_port, Some(local_port));
                if old_port.is_some() {
                    // Need to think about how to handle this situation
                    unimplemented!()
                }
                Ok(())
            }
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }

    /// Bind a socket to a specific address and port.
    pub fn bind(&mut self, fd: &SocketFd, addr: &SocketAddr) -> Result<(), NetError> {
        todo!()
    }

    /// Prepare a socket to accept incoming connections.
    pub fn listen(&mut self, fd: &SocketFd, backlog: i32) -> Result<(), NetError> {
        todo!()
    }

    /// Accept a new incoming connection on a listening socket.
    pub fn accept(&mut self, fd: &SocketFd) -> Result<SocketFd, NetError> {
        todo!()
    }

    /// Send data over a connected socket.
    pub fn send(&mut self, fd: &SocketFd, buf: &[u8], flags: SendFlags) -> Result<usize, NetError> {
        let socket_handle = self.handles[fd.as_usize()]
            .as_mut()
            .ok_or(NetError::InvalidFd)?;

        if !flags.is_empty() {
            unimplemented!()
        }

        match socket_handle.protocol {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .send_slice(buf)
                .map_err(|tcp::SendError::InvalidState| NetError::SocketInInvalidState),
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }

    /// Receive data from a connected socket.
    pub fn receive(
        &mut self,
        fd: &SocketFd,
        buf: &mut [u8],
        flags: ReceiveFlags,
    ) -> Result<usize, NetError> {
        let socket_handle = self.handles[fd.as_usize()]
            .as_mut()
            .ok_or(NetError::InvalidFd)?;

        if !flags.is_empty() {
            unimplemented!()
        }

        match socket_handle.protocol {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .recv_slice(buf)
                .map_err(|e| match e {
                    tcp::RecvError::InvalidState => NetError::OperationFinished,
                    tcp::RecvError::Finished => NetError::SocketInInvalidState,
                }),
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }
}

/// Protocols for sockets supported by LiteBox
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw { protocol: u8 },
}

bitflags! {
    /// Flags for the `receive` function.
    pub struct ReceiveFlags: u32 {
        /// `MSG_CMSG_CLOEXEC`: close-on-exec for the associated file descriptor
        const CMSG_CLOEXEC = 0x40000000;
        /// `MSG_DONTWAIT`: non-blocking operation
        const DONTWAIT = 0x40;
        /// `MSG_ERRQUEUE`: destination for error messages
        const ERRQUEUE = 0x2000;
        /// `MSG_OOB`: requests receipt of out-of-band data
        const OOB = 0x1;
        /// `MSG_PEEK`: requests to peek at incoming messages
        const PEEK = 0x2;
        /// `MSG_TRUNC`: truncate the message
        const TRUNC = 0x20;
        /// `MSG_WAITALL`: wait for the full amount of data
        const WAITALL = 0x100;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags! {
    /// Flags for the `send` function.
    pub struct SendFlags: u32 {
        /// `MSG_CONFIRM`: requests confirmation of the message delivery.
        const CONFIRM = 0x800;
        /// `MSG_DONTROUTE`: send the message directly to the interface, bypassing routing.
        const DONTROUTE = 0x4;
        /// `MSG_DONTWAIT`: non-blocking operation, do not wait for buffer space to become available.
        const DONTWAIT = 0x40;
        /// `MSG_EOR`: indicates the end of a record for message-oriented sockets.
        const EOR = 0x80;
        /// `MSG_MORE`: indicates that more data will follow.
        const MORE = 0x8000;
        /// `MSG_NOSIGNAL`: prevents the sending of SIGPIPE signals when writing to a socket that is closed.
        const NOSIGNAL = 0x4000;
        /// `MSG_OOB`: sends out-of-band data.
        const OOB = 0x1;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
