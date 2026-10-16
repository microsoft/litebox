// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Internet (IPv4 TCP and UDP) sockets for the Linux shim layer.
//!
//! Each socket is a LiteBox [`inet_socket::InetSocket`]. This module translates between Linux
//! socket calls and LiteBox's guest-neutral internet socket operations.

use alloc::sync::{Arc, Weak};
use core::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::TryOpError,
        wait::{WaitContext, WaitError},
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    inet_socket::{
        self,
        errors::{AcceptError, ConnectError, ShutdownError, SocketReadError, SocketWriteError},
    },
    process::ProcessError,
    utils::TruncateExt as _,
};
use litebox_broker_protocol::{
    ObjectHandle,
    fs::FileOpenFlags,
    socket::{self, SocketType},
};
use litebox_common_linux::{
    AddressFamily, IPProtocol, IpOption, OFlags, ReceiveFlags, SendFlags, ShutdownHow, SockFlags,
    SockType, SocketOption, SocketOptionName, TcpOption, errno::Errno,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{
    GlobalState, ShimPlatform, UserPtr, UserPtrMut,
    syscalls::{
        file::{linux_status_flags, status_flags_change},
        net::{ReceivePlan, open_flags, shutdown_mode},
    },
    wait::wait_errno,
};

macro_rules! convert_flags {
    ($src:expr, $src_type:ty, $dst_type:ty, $($flag:ident),+ $(,)?) => {
        {
            let mut result = <$dst_type>::empty();
            $(
                if $src.contains(<$src_type>::$flag) {
                    result |= <$dst_type>::$flag;
                }
            )+
            result
        }
    };
}

pub(crate) struct InetSocketSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for InetSocketSubsystem<Platform> {
    type Entry = InetSocket<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for InetSocket<Platform> {}

pub(crate) type InetSocketFd<Platform> = TypedFd<InetSocketSubsystem<Platform>>;

/// An internet socket descriptor's open file description.
pub(crate) struct InetSocket<Platform: ShimPlatform> {
    socket: Arc<inet_socket::InetSocket<Platform>>,
}

impl<Platform: ShimPlatform> From<inet_socket::InetSocket<Platform>> for InetSocket<Platform> {
    fn from(socket: inet_socket::InetSocket<Platform>) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

/// Linux's `struct sockaddr_in`.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
struct CSockInetAddr {
    family: i16,
    port: u16,
    addr: [u8; 4],
    __pad: u64,
}

impl From<CSockInetAddr> for SocketAddrV4 {
    fn from(c_addr: CSockInetAddr) -> Self {
        SocketAddrV4::new(Ipv4Addr::from(c_addr.addr), u16::from_be(c_addr.port))
    }
}

impl From<SocketAddrV4> for CSockInetAddr {
    fn from(addr: SocketAddrV4) -> Self {
        CSockInetAddr {
            family: AddressFamily::INET as i16,
            port: addr.port().to_be(),
            addr: addr.ip().octets(),
            __pad: 0,
        }
    }
}

/// Reads the internet socket address of `addrlen` bytes at `sockaddr`.
pub(super) fn read_sockaddr<Platform: ShimPlatform>(
    sockaddr: UserPtr<u8>,
    addrlen: usize,
) -> Result<SocketAddr, Errno> {
    if addrlen < size_of::<CSockInetAddr>() {
        return Err(Errno::EINVAL);
    }
    let ptr: UserPtr<CSockInetAddr> = UserPtr::from_usize(sockaddr.as_usize());
    // Note it reads the first 2 bytes (i.e., sa_family) again, but it is not used.
    // SocketAddrV4 only needs the port and addr.
    let inet_addr = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
    Ok(SocketAddr::V4(SocketAddrV4::from(inet_addr)))
}

/// Writes `addr`, truncated to `capacity` bytes, to `dst`, returning its full length.
pub(super) fn write_sockaddr<Platform: ShimPlatform>(
    addr: SocketAddr,
    dst: UserPtrMut<u8>,
    capacity: usize,
) -> Result<usize, Errno> {
    let SocketAddr::V4(addr) = addr else {
        todo!("copy_sockaddr_to_user for IPv6");
    };
    let c_addr = CSockInetAddr::from(addr);
    let bytes = c_addr.as_bytes();
    dst.write_slice_at_offset::<Platform>(0, &bytes[..capacity.min(bytes.len())])
        .ok_or(Errno::EFAULT)?;
    Ok(bytes.len())
}

impl<Platform: ShimPlatform> InetSocket<Platform> {
    /// Creates a socket of type `ty` for `protocol`, where zero selects the type's default.
    pub(super) fn new(
        litebox: &litebox::LiteBox<Platform>,
        ty: SockType,
        protocol: u8,
        flags: SockFlags,
    ) -> Result<Self, Errno> {
        let protocol = IPProtocol::try_from(protocol).map_err(|_| {
            log_unsupported!("protocol = {protocol}");
            Errno::EPROTONOSUPPORT
        })?;
        let socket_type = match ty {
            SockType::Stream => {
                if !matches!(protocol, IPProtocol::Default | IPProtocol::TCP) {
                    return Err(Errno::EINVAL);
                }
                SocketType::Stream
            }
            SockType::Datagram => {
                if !matches!(protocol, IPProtocol::Default | IPProtocol::UDP) {
                    return Err(Errno::EINVAL);
                }
                SocketType::Datagram
            }
            SockType::Raw => todo!(),
            _ => unimplemented!(),
        };
        let socket = litebox.create_inet_socket(socket_type, open_flags(flags))?;
        Ok(socket.into())
    }

    /// The LiteBox socket.
    pub(crate) fn inet_socket(&self) -> &Arc<inet_socket::InetSocket<Platform>> {
        &self.socket
    }

    pub(super) fn is_stream(&self) -> bool {
        self.socket.socket_type() == SocketType::Stream
    }

    /// Leaves `error` pending on the socket for the next call to report, unless it isn't a
    /// socket error.
    pub(super) fn set_async_error(&self, error: Errno) {
        if let Ok(error) = error.try_into() {
            self.socket.set_async_error(error);
        }
    }

    /// Plans a receive call with `flags`.
    pub(super) fn receive_plan(&self, flags: ReceiveFlags) -> Result<ReceivePlan, Errno> {
        let is_stream = self.is_stream();
        let wait_all = flags.contains(ReceiveFlags::WAITALL)
            && !flags.contains(ReceiveFlags::PEEK)
            && is_stream
            && !flags.contains(ReceiveFlags::DONTWAIT)
            && !self.is_nonblocking()?;
        Ok(ReceivePlan {
            is_stream,
            wait_all,
            // The receives of a `MSG_WAITALL` call share one receive timeout.
            timeout: if wait_all {
                self.receive_timeout()?
            } else {
                None
            },
            // `MSG_TRUNC` discards stream data.
            copies_data: !(is_stream && flags.contains(ReceiveFlags::TRUNC)),
        })
    }

    /// Whether the socket is nonblocking, which every descriptor sharing it sees.
    fn is_nonblocking(&self) -> Result<bool, Errno> {
        Ok(self
            .socket
            .get_status_flags()?
            .flags
            .contains(FileOpenFlags::NONBLOCKING))
    }

    /// The longest time a blocking receive or accept waits, or `None` to wait indefinitely.
    fn receive_timeout(&self) -> Result<Option<Duration>, Errno> {
        self.timeout(socket::SocketOptionName::ReceiveTimeout)
    }

    fn timeout(&self, name: socket::SocketOptionName) -> Result<Option<Duration>, Errno> {
        match self.socket.get_option(name)? {
            socket::SocketOptionValue::ReceiveTimeout(timeout)
            | socket::SocketOptionValue::SendTimeout(timeout) => Ok(timeout),
            value => unreachable!("{value:?} is not a wait timeout"),
        }
    }

    /// Runs `try_op` until it succeeds or fails, waiting for `events` while it asks to be
    /// retried, unless `nonblock` is set or the socket is nonblocking.
    ///
    /// Returns the result along with the timeout that bounded the wait, which `timeout` looks up
    /// only once the call blocks.
    fn wait<R>(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        events: Events,
        timeout: impl FnOnce() -> Result<Option<Duration>, Errno>,
        mut try_op: impl FnMut() -> Result<R, TryOpError<Errno>>,
    ) -> (Result<R, TryOpError<Errno>>, Option<Duration>) {
        match try_op() {
            Err(TryOpError::TryAgain) => {}
            result => return (result, None),
        }
        let blocking_timeout = || -> Result<Option<Option<Duration>>, Errno> {
            if nonblock || self.is_nonblocking()? {
                Ok(None)
            } else {
                timeout().map(Some)
            }
        };
        let timeout = match blocking_timeout() {
            Ok(Some(timeout)) => timeout,
            Ok(None) => return (Err(TryOpError::TryAgain), None),
            Err(error) => return (Err(TryOpError::Other(error)), None),
        };
        // `try_op` just asked to be retried, so skip the attempt before the observer registers.
        let mut attempted = false;
        let result = cx.with_timeout(timeout).wait_on_events(
            false,
            events,
            |observer, filter| {
                self.socket.register_observer(observer, filter);
                Ok(())
            },
            || {
                if core::mem::replace(&mut attempted, true) {
                    try_op()
                } else {
                    Err(TryOpError::TryAgain)
                }
            },
        );
        (result, timeout)
    }

    pub(super) fn bind(&self, address: SocketAddr) -> Result<(), Errno> {
        Ok(self.socket.bind(&address)?)
    }

    pub(super) fn listen(&self, backlog: u16) -> Result<(), Errno> {
        Ok(self.socket.listen(backlog)?)
    }

    /// Accepts a connection, storing the connecting socket's address in `peer` if requested.
    ///
    /// `flags` sets the status flags of the new socket only.
    pub(super) fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: SockFlags,
        mut peer: Option<&mut SocketAddr>,
    ) -> Result<Self, Errno> {
        let (result, timeout) = self.wait(
            cx,
            false,
            Events::IN,
            || self.receive_timeout(),
            || {
                self.socket
                    .accept(open_flags(flags), peer.as_deref_mut())
                    .map_err(|error| match error {
                        AcceptError::NoConnectionsReady => TryOpError::TryAgain,
                        error => TryOpError::Other(error.into()),
                    })
            },
        );
        Ok(result
            .map_err(|error| wait_errno(timeout, socket_io_errno(error)))?
            .into())
    }

    pub(super) fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: SocketAddr,
    ) -> Result<(), Errno> {
        let mut check_progress = false;
        let mut already_in_progress = false;
        let (result, timeout) = self.wait(
            cx,
            false,
            Events::IN | Events::OUT,
            || self.timeout(socket::SocketOptionName::SendTimeout),
            || loop {
                match self.socket.connect(&address, check_progress) {
                    Ok(()) => break Ok(()),
                    Err(ConnectError::InProgress) => {
                        check_progress = true;
                        break Err(TryOpError::TryAgain);
                    }
                    // A blocking call waits for an earlier attempt just as for its own.
                    Err(ConnectError::AlreadyInProgress) => {
                        check_progress = true;
                        already_in_progress = true;
                        break Err(TryOpError::TryAgain);
                    }
                    // The earlier attempt was abandoned without effect, so this call makes its
                    // own, as if it had found the socket unconnected.
                    Err(ConnectError::InvalidState) if already_in_progress => {
                        check_progress = false;
                        already_in_progress = false;
                    }
                    Err(error) => break Err(TryOpError::Other(error.into())),
                }
            },
        );
        // Like Linux, a connect whose wait times out reports that it is still in progress.
        result.map_err(|error| match error {
            TryOpError::TryAgain | TryOpError::WaitError(WaitError::TimedOut)
                if already_in_progress =>
            {
                Errno::EALREADY
            }
            TryOpError::TryAgain | TryOpError::WaitError(WaitError::TimedOut) => Errno::EINPROGRESS,
            error => wait_errno(timeout, error),
        })
    }

    /// Sends `buf`, as a datagram to `destination` if provided.
    ///
    /// `MSG_NOSIGNAL` is left to the caller.
    pub(crate) fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &[u8],
        flags: SendFlags,
        destination: Option<SocketAddr>,
    ) -> Result<usize, Errno> {
        let send_flags = convert_flags!(
            flags,
            SendFlags,
            inet_socket::SendFlags,
            CONFIRM,
            DONTROUTE,
            EOR,
            MORE,
            OOB,
        );
        let is_empty_stream = buf.is_empty() && self.is_stream();
        let (result, timeout) = self.wait(
            cx,
            flags.contains(SendFlags::DONTWAIT),
            Events::OUT,
            || self.timeout(socket::SocketOptionName::SendTimeout),
            || match self.socket.try_write(buf, send_flags, destination) {
                Ok(0) if buf.is_empty() => Ok(0),
                Ok(0) => Err(TryOpError::TryAgain),
                Ok(n) => Ok(n),
                Err(SocketWriteError::BufferFull | SocketWriteError::NonBlocking)
                    if is_empty_stream =>
                {
                    Ok(0)
                }
                Err(SocketWriteError::BufferFull) => Err(TryOpError::TryAgain),
                // Like Linux, a pending socket error (such as a reset) is reported, and
                // consumed, in place of `EPIPE`.
                Err(error) => Err(TryOpError::Other(match Errno::from(error) {
                    Errno::EPIPE => self
                        .socket
                        .take_async_error()
                        .map_or(Errno::EPIPE, Errno::from),
                    errno => errno,
                })),
            },
        );
        result.map_err(|error| wait_errno(timeout, socket_io_errno(error)))
    }

    /// Receives into `buf`, returning the length of the received data, which for a datagram
    /// socket may exceed `buf`.
    ///
    /// `has_prior_progress` tells whether the call already received data, which a failure
    /// then ends instead of being reported.
    ///
    /// A datagram socket stores its sender's address in `source_addr` if requested.
    pub(crate) fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        has_prior_progress: bool,
        mut source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, Errno> {
        let is_stream = self.is_stream();
        if buf.is_empty() && is_stream {
            return Ok(0);
        }
        let dontwait = flags.contains(ReceiveFlags::DONTWAIT);
        let peek = flags.contains(ReceiveFlags::PEEK);
        let wait_all = flags.contains(ReceiveFlags::WAITALL)
            && is_stream
            && !dontwait
            && !self.is_nonblocking()?;

        let mut receive_flags = convert_flags!(
            flags,
            ReceiveFlags,
            inet_socket::ReceiveFlags,
            CMSG_CLOEXEC,
            ERRQUEUE,
            OOB,
            PEEK,
        );
        receive_flags.set(inet_socket::ReceiveFlags::WAITALL, wait_all);
        // `MSG_TRUNC` reports a datagram's full length, but discards stream data.
        if flags.contains(ReceiveFlags::TRUNC) {
            receive_flags.insert(if is_stream {
                inet_socket::ReceiveFlags::DISCARD
            } else {
                inet_socket::ReceiveFlags::TRUNC
            });
        }

        let target_len = buf.len();
        let mut received = 0;
        let (result, timeout) = self.wait(
            cx,
            dontwait,
            Events::IN,
            || self.receive_timeout(),
            || loop {
                let destination = if wait_all && !peek {
                    &mut buf[received..target_len]
                } else {
                    &mut buf[..target_len]
                };
                match self
                    .socket
                    .try_read(destination, receive_flags, source_addr.as_deref_mut())
                {
                    Ok(n) if !wait_all => return Ok(n),
                    Ok(n) if peek => {
                        received = n;
                        if received == target_len
                            || self
                                .socket
                                .check_io_events()
                                .intersects(Events::ERR | Events::HUP | Events::RDHUP)
                        {
                            return Ok(received);
                        }
                        return Err(TryOpError::TryAgain);
                    }
                    Ok(n) => {
                        received += n;
                        if received == target_len {
                            return Ok(received);
                        }
                    }
                    // A shut-down datagram socket waits for no datagram.
                    Err(SocketReadError::ReadShutdown) if !is_stream => {
                        let nonblock =
                            dontwait || self.is_nonblocking().map_err(TryOpError::Other)?;
                        return if nonblock {
                            Err(TryOpError::Other(Errno::EAGAIN))
                        } else {
                            Ok(received)
                        };
                    }
                    Err(SocketReadError::ReadShutdown) => return Ok(received),
                    Err(SocketReadError::WouldBlock) => return Err(TryOpError::TryAgain),
                    Err(SocketReadError::NonBlocking) => {
                        if received != 0 || has_prior_progress {
                            return Ok(received);
                        }
                        return Err(TryOpError::Other(Errno::EAGAIN));
                    }
                    Err(SocketReadError::ConnectionClosed) => {
                        if received != 0 || has_prior_progress {
                            return Ok(received);
                        }
                        return match self.socket.take_async_error() {
                            Some(err) => Err(TryOpError::Other(err.into())),
                            None => Ok(0),
                        };
                    }
                    Err(SocketReadError::NotConnected) if received != 0 || has_prior_progress => {
                        return Ok(received);
                    }
                    Err(SocketReadError::Socket(error)) if received != 0 || has_prior_progress => {
                        self.socket.set_async_error(error);
                        return Ok(received);
                    }
                    // A pending error, such as the reset of an aborted connection attempt, is
                    // reported first.
                    Err(SocketReadError::NotConnected) => {
                        return Err(TryOpError::Other(
                            self.socket
                                .take_async_error()
                                .map_or(Errno::ENOTCONN, Errno::from),
                        ));
                    }
                    Err(SocketReadError::Socket(error)) => {
                        return Err(TryOpError::Other(error.into()));
                    }
                }
            },
        );
        match result {
            Ok(received) => Ok(received),
            // `TryAgain` here means the socket became nonblocking after data was received.
            Err(TryOpError::WaitError(_) | TryOpError::TryAgain)
                if received != 0 || has_prior_progress =>
            {
                Ok(received)
            }
            Err(error @ TryOpError::WaitError(_)) if wait_all && peek => {
                receive_flags.remove(inet_socket::ReceiveFlags::WAITALL);
                match self
                    .socket
                    .try_read(&mut buf[..target_len], receive_flags, source_addr)
                {
                    Ok(received) => Ok(received),
                    Err(SocketReadError::ReadShutdown) => Ok(0),
                    Err(SocketReadError::ConnectionClosed) => {
                        match self.socket.take_async_error() {
                            Some(error) => Err(error.into()),
                            None => Ok(0),
                        }
                    }
                    Err(SocketReadError::NotConnected) => Err(self
                        .socket
                        .take_async_error()
                        .map_or(Errno::ENOTCONN, Errno::from)),
                    Err(SocketReadError::Socket(error)) => Err(error.into()),
                    Err(SocketReadError::WouldBlock | SocketReadError::NonBlocking) => {
                        Err(wait_errno(timeout, socket_io_errno(error)))
                    }
                }
            }
            Err(error) => Err(wait_errno(timeout, socket_io_errno(error))),
        }
    }

    pub(super) fn get_local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }

    pub(super) fn get_peer_addr(&self) -> Result<SocketAddr, Errno> {
        Ok(self.socket.remote_addr()?)
    }

    pub(super) fn setsockopt(
        &self,
        global: &GlobalState<Platform>,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        match global.setsockopt_common(optname, optval, optlen, |value| match value {
            socket::SocketOptionValue::Linger(Some(_)) if self.is_stream() => {
                Err(Errno::EOPNOTSUPP)
            }
            socket::SocketOptionValue::Broadcast(false) => todo!("disable SO_BROADCAST"),
            value => Ok(self.socket.set_option(value)?),
        }) {
            Err(Errno::ENOPROTOOPT) => {} // fall through to handle other options
            other => return other,
        }

        match optname {
            SocketOptionName::IP(ip) => match ip {
                // IP_TOS is an advisory traffic-class hint. Accept it (we don't
                // propagate the bit anywhere) instead of returning EOPNOTSUPP,
                // which Node's Socket.setTypeOfService treats as fatal and
                // cascades into tearing down the connection. Log at debug so the
                // accepted-but-ignored option stays visible.
                IpOption::TOS => {
                    litebox_util_log::debug!("accepting and ignoring setsockopt(IP_TOS)");
                    Ok(())
                }
            },
            SocketOptionName::Socket(so) => match so {
                // handled by `setsockopt_common`
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::BROADCAST
                | SocketOption::KEEPALIVE => unreachable!(),
                // SO_RCVBUF / SO_SNDBUF are advisory hints. Accept them and keep
                // the fixed internal buffer size that getsockopt reports, instead
                // of returning EOPNOTSUPP (which Node's TLS socket path treats as
                // fatal). Log at debug so the accepted-but-ignored option stays
                // visible.
                SocketOption::RCVBUF | SocketOption::SNDBUF => {
                    litebox_util_log::debug!(
                        "accepting and ignoring setsockopt(SO_RCVBUF/SO_SNDBUF); using fixed buffer size"
                    );
                    Ok(())
                }
                // Socket does not support these options
                SocketOption::TYPE | SocketOption::PEERCRED | SocketOption::ERROR => {
                    Err(Errno::ENOPROTOOPT)
                }
            },
            SocketOptionName::TCP(to) => match to {
                TcpOption::CONGESTION => {
                    const TCP_CONGESTION_NAME_MAX: usize = 16;
                    let data = optval
                        .to_owned_slice::<Platform>(TCP_CONGESTION_NAME_MAX.min(optlen))
                        .ok_or(Errno::EFAULT)?;
                    let name = core::str::from_utf8(&data).map_err(|_| Errno::EINVAL)?;
                    if !matches!(name, "reno" | "cubic" | "none") {
                        return Err(Errno::EINVAL);
                    }
                    Err(self.unsupported_tcp_option())
                }
                TcpOption::KEEPCNT | TcpOption::KEEPIDLE | TcpOption::INFO => {
                    Err(Errno::EOPNOTSUPP)
                }
                TcpOption::NODELAY | TcpOption::CORK => {
                    if !self.is_stream() {
                        return Err(Errno::ENOPROTOOPT);
                    }
                    let val: u32 = super::read_from_user::<_, Platform>(optval, optlen)?;
                    if matches!(to, TcpOption::CORK) {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    Ok(self
                        .socket
                        .set_option(socket::SocketOptionValue::NoDelay(val != 0))?)
                }
                TcpOption::KEEPINTVL => {
                    const MAX_TCP_KEEPINTVL: u32 = 32767;
                    let val: u32 = super::read_from_user::<_, Platform>(optval, size_of::<u32>())?;
                    if !(1..=MAX_TCP_KEEPINTVL).contains(&val) {
                        return Err(Errno::EINVAL);
                    }
                    Err(self.unsupported_tcp_option())
                }
            },
        }
    }

    /// The error for a valid TCP option that the socket cannot apply.
    fn unsupported_tcp_option(&self) -> Errno {
        if self.is_stream() {
            Errno::EOPNOTSUPP
        } else {
            Errno::ENOPROTOOPT
        }
    }

    pub(super) fn getsockopt(
        &self,
        global: &GlobalState<Platform>,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        match global.getsockopt_common(optname, optval, len, |name| {
            Ok(self.socket.get_option(name)?)
        }) {
            Err(Errno::ENOPROTOOPT) => {} // fall through to handle other options
            other => return other,
        }

        let val: u32 = match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS => return Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(so) => match so {
                // handled by `getsockopt_common`
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::KEEPALIVE
                | SocketOption::BROADCAST => unreachable!(),
                // SO_ERROR is self-clearing: atomically read and reset to 0.
                SocketOption::ERROR => self
                    .socket
                    .take_async_error()
                    .map_or(0, |error| i32::from(Errno::from(error)).cast_unsigned()),
                SocketOption::TYPE => {
                    if self.is_stream() {
                        SockType::Stream as u32
                    } else {
                        SockType::Datagram as u32
                    }
                }
                SocketOption::RCVBUF | SocketOption::SNDBUF => {
                    inet_socket::SOCKET_BUFFER_SIZE.trunc()
                }
                SocketOption::PEERCRED => return Err(Errno::ENOPROTOOPT),
            },
            SocketOptionName::TCP(to) => match to {
                TcpOption::KEEPCNT | TcpOption::KEEPIDLE | TcpOption::INFO => {
                    return Err(Errno::EOPNOTSUPP);
                }
                _ if !self.is_stream() => return Err(Errno::ENOPROTOOPT),
                TcpOption::CONGESTION | TcpOption::KEEPINTVL | TcpOption::CORK => {
                    return Err(Errno::EOPNOTSUPP);
                }
                TcpOption::NODELAY => {
                    match self.socket.get_option(socket::SocketOptionName::NoDelay)? {
                        socket::SocketOptionValue::NoDelay(enabled) => u32::from(enabled),
                        value => unreachable!("{value:?} is not TCP_NODELAY"),
                    }
                }
            },
        };
        super::write_to_user::<_, Platform>(val, optval, len)
    }

    pub(super) fn shutdown(&self, how: ShutdownHow) -> Result<(), Errno> {
        match self.socket.shutdown(shutdown_mode(how)) {
            // Shutting down a listener's receive side stops it listening.
            Err(ShutdownError::Listening) => match how {
                ShutdownHow::Read | ShutdownHow::Both => Ok(self.socket.stop_listening()?),
                ShutdownHow::Write => Ok(()),
            },
            result => Ok(result?),
        }
    }

    /// Returns the `F_GETFL` flags of the socket, which every descriptor sharing it sees.
    pub(super) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.socket.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the socket to their values in `flags`, ignoring
    /// flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(super) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.socket.set_status_flags(mask, flags)?;
        Ok(())
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Runs `f` on the internet socket at `fd`, without holding the descriptor table.
    pub(crate) fn with_inet_socket<R>(
        &self,
        fd: &InetSocketFd<Platform>,
        f: impl FnOnce(&InetSocket<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts an internet socket of type `socket_type` this process inherited
    /// from its parent as `handle`.
    pub(super) fn adopt_inherited_inet_socket(
        &self,
        handle: ObjectHandle,
        socket_type: SocketType,
    ) -> Result<InetSocketFd<Platform>, ProcessError> {
        let socket = self
            .litebox
            .adopt_inherited_inet_socket(handle, socket_type)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<InetSocketSubsystem<Platform>>(InetSocket::from(socket)))
    }
}

impl<Platform: ShimPlatform> IOPollable for InetSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.socket.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.socket.check_io_events()
    }
}

fn socket_io_errno(error: TryOpError<Errno>) -> Errno {
    match error {
        TryOpError::WaitError(WaitError::TimedOut) => Errno::EAGAIN,
        error => error.into(),
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use core::{net::SocketAddr, time::Duration};

    type TestTask = crate::Task<crate::syscalls::tests::TestPlatform>;

    use alloc::string::ToString as _;
    use litebox::utils::TruncateExt as _;
    use litebox_common_linux::{
        AddressFamily, MapFlags, ProtFlags, ReceiveFlags, SendFlags, SockFlags, SockType,
        SocketOption, SocketOptionName, errno::Errno,
    };
    use zerocopy::FromZeros as _;

    use super::CSockInetAddr;
    use crate::{
        UserPtr, UserPtrMut,
        syscalls::{
            net::{SocketAddress, read_sockaddr_from_user},
            tests::init_platform,
        },
    };

    extern crate alloc;
    extern crate std;

    const LOOPBACK_IP_ADDR: [u8; 4] = [127, 0, 0, 1];
    /// Each test process has its own guest network, so no guest socket uses this port.
    const UNUSED_GUEST_PORT: u16 = 9;

    fn loopback_addr(port: u16) -> SocketAddress {
        SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(LOOPBACK_IP_ADDR),
            port,
        )))
    }

    fn close_socket(task: &TestTask, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
    }

    #[test]
    fn inet_socket_returns_emfile_at_raw_fd_limit() {
        let task = init_platform();
        let fd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .unwrap();
        task.files.borrow().set_max_fd(fd as usize);
        assert_eq!(
            task.do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0),
            Err(Errno::EMFILE)
        );
        close_socket(&task, fd);
    }

    #[test]
    fn inet_accept_timeout_returns_eagain() {
        let task = init_platform();
        let raw_server = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .unwrap();
        let server = typed_socket(&task, raw_server);
        task.do_bind(&server, loopback_addr(0)).unwrap();
        task.do_listen(&server, 1).unwrap();
        let timeout = Duration::from_millis(200);
        let tv = litebox_common_linux::TimeVal::from(timeout);
        task.do_setsockopt(
            &server,
            SocketOptionName::Socket(SocketOption::RCVTIMEO),
            UserPtr::from_usize((&raw const tv).cast::<u8>() as usize),
            core::mem::size_of::<litebox_common_linux::TimeVal>(),
        )
        .unwrap();
        let start = std::time::Instant::now();
        // Linux returns EAGAIN (not ETIMEDOUT) when SO_RCVTIMEO expires on a blocking accept.
        assert_eq!(
            task.do_accept(&server, None, SockFlags::empty()),
            Err(Errno::EAGAIN)
        );
        assert!(start.elapsed() + Duration::from_millis(5) >= timeout);
        close_socket(&task, raw_server);
    }

    fn typed_socket(
        task: &TestTask,
        fd: u32,
    ) -> crate::syscalls::file::AnyTypedFd<crate::syscalls::tests::TestPlatform> {
        task.files
            .borrow()
            .socket_from_raw(i32::try_from(fd).unwrap())
            .unwrap()
    }

    /// Helper to read SO_ERROR from a socket via getsockopt.
    /// Returns the errno integer value (0 means no error).
    fn get_so_error(
        task: &TestTask,
        sockfd: &crate::syscalls::file::AnyTypedFd<crate::syscalls::tests::TestPlatform>,
    ) -> u32 {
        let mut optval: u32 = 0xDEAD;
        let len = task
            .do_getsockopt(
                sockfd,
                SocketOptionName::Socket(SocketOption::ERROR),
                UserPtrMut::from_usize((&raw mut optval).cast::<u8>() as usize),
                core::mem::size_of::<u32>().trunc(),
            )
            .expect("getsockopt SO_ERROR failed");
        assert_eq!(len, core::mem::size_of::<u32>());
        optval
    }

    fn epoll_add(task: &TestTask, epfd: i32, target_fd: u32, events: litebox::event::Events) {
        let ev = litebox_common_linux::EpollEvent::new(events.bits(), u64::from(target_fd));
        let ev_ptr = (&raw const ev).cast::<litebox_common_linux::EpollEvent>();
        let ev_const = UserPtr::from_usize(ev_ptr as usize);
        task.sys_epoll_ctl(
            epfd,
            litebox_common_linux::EpollOp::EpollCtlAdd,
            i32::try_from(target_fd).unwrap(),
            ev_const,
        )
        .expect("epoll_ctl add server failed");
    }

    fn epoll_wait(
        task: &TestTask,
        epfd: i32,
        events: &mut [litebox_common_linux::EpollEvent],
    ) -> usize {
        let events_ptr = UserPtrMut::from_usize(events.as_mut_ptr() as usize);
        task.sys_epoll_pwait(epfd, events_ptr, events.len().trunc(), -1, None, 0)
            .expect("epoll_wait failed")
    }

    fn test_tcp_socket_as_server(
        task: &TestTask,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &'static str,
    ) {
        let raw_server = task
            .do_socket(
                AddressFamily::INET,
                SockType::Stream,
                if is_nonblocking {
                    SockFlags::NONBLOCK
                } else {
                    SockFlags::empty()
                },
                0,
            )
            .unwrap();
        let server = typed_socket(task, raw_server);
        task.do_bind(&server, loopback_addr(0))
            .expect("Failed to bind socket");
        let server_sockaddr = task.do_getsockname(&server).unwrap();
        task.do_listen(&server, 1)
            .expect("Failed to listen on socket");

        // Create an epoll instance and register the server fd for EPOLLIN
        let epfd = task
            .sys_epoll_create(litebox_common_linux::EpollCreateFlags::empty())
            .expect("failed to create epoll");
        let epfd = i32::try_from(epfd).unwrap();
        epoll_add(task, epfd, raw_server, litebox::event::Events::IN);

        let buf = "Hello, world!";
        let client_server_addr = server_sockaddr.clone();
        let client_handle = task.spawn_clone_for_test(move |task| {
            let raw_fd = task
                .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
                .expect("failed to create client socket");
            let fd = typed_socket(&task, raw_fd);
            task.do_connect(&fd, client_server_addr)
                .expect("failed to connect to server");
            let local_addr = task.do_getsockname(&fd).unwrap();
            let mut received = alloc::vec::Vec::new();
            match option {
                "sendto" | "sendmsg" => {
                    let mut chunk = [0u8; 64];
                    loop {
                        let n = task
                            .do_recvfrom(&fd, &mut chunk, ReceiveFlags::empty(), None)
                            .expect("client recvfrom failed");
                        if n == 0 {
                            break;
                        }
                        received.extend_from_slice(&chunk[..n]);
                    }
                }
                "recvfrom" | "recvmsg" => {
                    let n = task
                        .do_sendto(&fd, buf.as_bytes(), SendFlags::empty(), None)
                        .expect("client sendto failed");
                    assert_eq!(n, buf.len());
                }
                _ => panic!("Unknown option"),
            }
            close_socket(&task, raw_fd);
            (local_addr, received)
        });

        if is_nonblocking {
            // wait on epoll for server to be readable (incoming connection)
            let mut events = [litebox_common_linux::EpollEvent::new(0, 0); 2];
            let n = epoll_wait(task, epfd, &mut events);
            assert_eq!(n, 1);
            for ev in &events[..n] {
                let events = ev.events;
                assert!(events & litebox::event::Events::IN.bits() != 0);
            }
        }

        let mut remote_addr = SocketAddress::default();
        let raw_client_fd = task
            .do_accept(
                &server,
                Some(&mut remote_addr),
                if is_nonblocking {
                    SockFlags::NONBLOCK
                } else {
                    SockFlags::empty()
                },
            )
            .expect("Failed to accept connection");
        let client_fd = typed_socket(task, raw_client_fd);
        assert_eq!(server_sockaddr, task.do_getsockname(&client_fd).unwrap());
        assert_eq!(remote_addr, task.do_getpeername(&client_fd).unwrap());
        let SocketAddress::Inet(SocketAddr::V4(remote_v4)) = remote_addr.clone() else {
            panic!("Expected IPv4 address");
        };
        assert_eq!(remote_v4.ip().octets(), LOOPBACK_IP_ADDR);
        assert_ne!(remote_v4.port(), 0);

        let expected_by_client = match option {
            "sendto" => {
                let n = task
                    .do_sendto(&client_fd, buf.as_bytes(), SendFlags::empty(), None)
                    .expect("Failed to send data");
                assert_eq!(n, buf.len());
                buf.to_string()
            }
            "sendmsg" => {
                let buf1 = "Hello,";
                let buf2 = " world!\n";
                let iovec = [
                    litebox_common_linux::IoVec {
                        iov_base: UserPtrMut::from_usize(buf1.as_ptr().expose_provenance()),
                        iov_len: buf1.len(),
                    },
                    litebox_common_linux::IoVec {
                        iov_base: UserPtrMut::from_usize(buf2.as_ptr().expose_provenance()),
                        iov_len: buf2.len(),
                    },
                ];
                let hdr = {
                    let mut h = litebox_common_linux::UserMsgHdr::new_zeroed();
                    h.msg_iov = UserPtr::from_usize(iovec.as_ptr() as usize);
                    h.msg_iovlen = iovec.len();
                    h
                };
                assert_eq!(
                    task.do_sendmsg(&client_fd, &hdr, SendFlags::empty())
                        .expect("Failed to sendmsg"),
                    buf1.len() + buf2.len()
                );
                alloc::format!("{buf1}{buf2}")
            }
            "recvfrom" | "recvmsg" => {
                if is_nonblocking {
                    epoll_add(task, epfd, raw_client_fd, litebox::event::Events::IN);
                    let mut events = [litebox_common_linux::EpollEvent::new(0, 0); 2];
                    let n = epoll_wait(task, epfd, &mut events);
                    for ev in &events[..n] {
                        assert!(ev.events & litebox::event::Events::IN.bits() != 0);
                        let fd = u32::try_from(ev.data).unwrap();
                        assert_eq!(fd, raw_client_fd);
                    }
                }
                let mut recv_buf = [0u8; 48];
                let flags = if test_trunc {
                    ReceiveFlags::TRUNC
                } else {
                    ReceiveFlags::empty()
                };
                let n = match option {
                    "recvfrom" => task
                        .do_recvfrom(&client_fd, &mut recv_buf, flags, None)
                        .expect("Failed to receive data"),
                    "recvmsg" => {
                        let mapped_buf = task
                            .sys_mmap(
                                0,
                                recv_buf.len(),
                                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                                -1,
                                0,
                            )
                            .expect("failed to map recvmsg buffer");
                        let iovec = [litebox_common_linux::IoVec {
                            iov_base: mapped_buf,
                            iov_len: recv_buf.len(),
                        }];
                        let mut msg_hdr = litebox_common_linux::UserMsgHdr::new_zeroed();
                        msg_hdr.msg_iov = UserPtr::from_usize(iovec.as_ptr() as usize);
                        msg_hdr.msg_iovlen = iovec.len();
                        let msg_ptr = UserPtrMut::from_usize(&raw mut msg_hdr as usize);
                        let received = task
                            .sys_recvmsg(i32::try_from(raw_client_fd).unwrap(), msg_ptr, flags)
                            .expect("failed to recvmsg");
                        let received_buf = mapped_buf
                            .to_owned_slice::<crate::syscalls::tests::TestPlatform>(recv_buf.len())
                            .expect("failed to read recvmsg buffer");
                        recv_buf.copy_from_slice(&received_buf);
                        task.sys_munmap(mapped_buf, recv_buf.len())
                            .expect("failed to unmap recvmsg buffer");
                        received
                    }
                    _ => unreachable!(),
                };
                if test_trunc {
                    assert!(recv_buf.iter().all(|&b| b == 0)); // buf remains unchanged
                } else {
                    assert_eq!(recv_buf[..n], buf.as_bytes()[..n]);
                }
                assert_eq!(n, buf.len()); // even with truncation, it returns the actual length
                alloc::string::String::new()
            }
            _ => panic!("Unknown option"),
        };

        close_socket(task, raw_client_fd);
        close_socket(task, raw_server);
        let (client_addr, received) = client_handle.join().expect("client thread panicked");
        assert_eq!(remote_addr, client_addr);
        assert_eq!(received, expected_by_client.as_bytes());
    }

    fn test_tcp_socket_receive(is_nonblocking: bool, test_trunc: bool) {
        let task = init_platform();
        test_tcp_socket_as_server(&task, is_nonblocking, test_trunc, "recvfrom");
        test_tcp_socket_as_server(&task, is_nonblocking, test_trunc, "recvmsg");
    }

    fn test_tcp_socket_send(is_nonblocking: bool, test_trunc: bool) {
        let task = init_platform();
        test_tcp_socket_as_server(&task, is_nonblocking, test_trunc, "sendto");
        test_tcp_socket_as_server(&task, is_nonblocking, test_trunc, "sendmsg");
    }

    #[test]
    fn test_blocking_send_tcp_socket() {
        test_tcp_socket_send(false, false);
    }

    #[test]
    fn test_nonblocking_send_tcp_socket() {
        test_tcp_socket_send(true, false);
    }

    #[test]
    fn test_blocking_recvfrom_tcp_socket() {
        test_tcp_socket_receive(false, false);
    }

    #[test]
    fn test_nonblocking_recvfrom_tcp_socket() {
        test_tcp_socket_receive(true, false);
    }

    #[test]
    fn test_blocking_recvfrom_tcp_socket_with_truncation() {
        test_tcp_socket_receive(false, true);
    }

    #[test]
    fn test_tcp_connection_refused() {
        let task = init_platform();
        let raw_socket_fd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create socket");
        let raw_socket_fd2 = task
            .sys_dup(i32::try_from(raw_socket_fd).unwrap(), None, None)
            .unwrap();
        let socket_fd2 = typed_socket(&task, raw_socket_fd2);

        close_socket(&task, raw_socket_fd);
        let err = task
            .do_connect(&socket_fd2, loopback_addr(UNUSED_GUEST_PORT))
            .unwrap_err();
        assert_eq!(err, litebox_common_linux::errno::Errno::ECONNREFUSED);

        // A failed blocking connect consumes the error, as on Linux.
        assert_eq!(get_so_error(&task, &socket_fd2), 0);
    }

    #[test]
    fn test_tcp_socket_as_client() {
        let task = init_platform();
        let host_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("failed to bind host listener");
        let port = host_listener.local_addr().unwrap().port();
        let host_server = std::thread::spawn(move || {
            use std::io::Read as _;
            let (mut stream, _) = host_listener.accept().expect("host accept failed");
            let mut received = alloc::vec::Vec::new();
            stream.read_to_end(&mut received).expect("host read failed");
            received
        });

        // Client socket
        let raw_client_fd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create client socket");
        let client_fd = typed_socket(&task, raw_client_fd);

        // Guests reach host-loopback services through the gateway address.
        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            litebox_broker_core::socket::HOST_GATEWAY_IPV4_ADDRESS,
            port,
        )));
        task.do_connect(&client_fd, server_addr)
            .expect("failed to connect to server");
        let so_error = get_so_error(&task, &client_fd);
        assert_eq!(
            so_error, 0,
            "SO_ERROR should be 0 after successful connect, got {so_error}"
        );

        let buf = "Hello, world!";
        let n = task
            .do_sendto(&client_fd, buf.as_bytes(), SendFlags::empty(), None)
            .unwrap();
        assert_eq!(n, buf.len());

        // Lingering close is not supported for IP stream sockets.
        let linger = litebox_common_linux::Linger {
            onoff: 1,   // enable linger
            linger: 60, // timeout in seconds
        };
        let optval = UserPtr::from_usize((&raw const linger).cast::<u8>() as usize);
        assert_eq!(
            task.do_setsockopt(
                &client_fd,
                SocketOptionName::Socket(SocketOption::LINGER),
                optval,
                core::mem::size_of::<litebox_common_linux::Linger>(),
            ),
            Err(Errno::EOPNOTSUPP)
        );

        close_socket(&task, raw_client_fd);

        let received = host_server.join().expect("host server panicked");
        assert_eq!(received, buf.as_bytes());
    }

    fn blocking_udp_server_socket(
        task: &TestTask,
        test_trunc: bool,
        set_trunc_flag: bool,
        is_nonblocking: bool,
        op: &str,
    ) {
        // Server socket and bind
        let raw_server_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                if is_nonblocking {
                    SockFlags::NONBLOCK
                } else {
                    SockFlags::empty()
                },
                litebox_common_linux::IPProtocol::UDP as u8,
            )
            .expect("failed to create server socket");
        let server_fd = typed_socket(task, raw_server_fd);
        task.do_bind(&server_fd, loopback_addr(0))
            .expect("failed to bind server");
        let server_addr = task.do_getsockname(&server_fd).expect("getsockname failed");

        // Create an epoll instance and register the server fd for EPOLLIN
        let epfd = task
            .sys_epoll_create(litebox_common_linux::EpollCreateFlags::empty())
            .expect("failed to create epoll");
        let epfd = i32::try_from(epfd).unwrap();
        epoll_add(task, epfd, raw_server_fd, litebox::event::Events::IN);

        let msg = "Hello from client";
        let raw_client_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::empty(),
                litebox_common_linux::IPProtocol::UDP as u8,
            )
            .expect("failed to create client socket");
        let client_fd = typed_socket(task, raw_client_fd);
        task.do_bind(&client_fd, loopback_addr(0))
            .expect("failed to bind client");
        let client_addr = task.do_getsockname(&client_fd).expect("getsockname failed");
        let n = task
            .do_sendto(
                &client_fd,
                msg.as_bytes(),
                SendFlags::empty(),
                Some(server_addr),
            )
            .expect("client sendto failed");
        assert_eq!(n, msg.len());

        // Server receives and inspects sender addr
        let mut recv_buf = [0u8; 48];
        let mut recv_flags = ReceiveFlags::empty();
        if test_trunc && set_trunc_flag {
            recv_flags.insert(ReceiveFlags::TRUNC);
        }
        if is_nonblocking {
            let mut events = [litebox_common_linux::EpollEvent::new(0, 0); 2];
            let n = epoll_wait(task, epfd, &mut events);
            assert_eq!(n, 1);
            for ev in &events[..n] {
                assert!(ev.events & litebox::event::Events::IN.bits() != 0);
                let fd = u32::try_from(ev.data).unwrap();
                assert_eq!(fd, raw_server_fd);
            }
        }
        let recv_len = if test_trunc {
            8 // intentionally small size to test truncation
        } else {
            recv_buf.len()
        };
        let source_addr = [0u8; core::mem::size_of::<CSockInetAddr>()];
        let n = match op {
            "recvfrom" => {
                let mut addrlen = core::mem::size_of::<CSockInetAddr>();
                task.sys_recvfrom(
                    i32::try_from(raw_server_fd).unwrap(),
                    UserPtrMut::from_usize(recv_buf.as_mut_ptr() as usize),
                    recv_len,
                    recv_flags,
                    Some(UserPtrMut::from_usize(source_addr.as_ptr() as usize)),
                    UserPtrMut::from_usize(&raw mut addrlen as usize),
                )
                .expect("recvfrom failed")
            }
            "recvmsg" => {
                let iovec = [litebox_common_linux::IoVec {
                    iov_base: UserPtrMut::from_usize(recv_buf.as_mut_ptr() as usize),
                    iov_len: recv_len,
                }];
                let mut msg_hdr = litebox_common_linux::UserMsgHdr::new_zeroed();
                msg_hdr.msg_iov = UserPtr::from_usize(iovec.as_ptr() as usize);
                msg_hdr.msg_iovlen = iovec.len();
                msg_hdr.msg_name = UserPtrMut::from_usize(source_addr.as_ptr() as usize);
                msg_hdr.msg_namelen = source_addr.len().trunc();
                let msg_ptr = UserPtrMut::from_usize(&raw mut msg_hdr as usize);
                let n = task
                    .sys_recvmsg(i32::try_from(raw_server_fd).unwrap(), msg_ptr, recv_flags)
                    .expect("recvmsg failed");
                if test_trunc {
                    let flags = msg_hdr.msg_flags;
                    assert!(flags.contains(ReceiveFlags::TRUNC));
                }
                n
            }
            _ => panic!("Unknown operation"),
        };
        let sender_addr = read_sockaddr_from_user::<crate::syscalls::tests::TestPlatform>(
            UserPtr::from_usize(source_addr.as_ptr() as usize),
            source_addr.len(),
        )
        .ok();
        if test_trunc && set_trunc_flag {
            assert_eq!(n, msg.len()); // return the actual length of the datagram rather than the received length
            assert_eq!(recv_buf[..8], msg.as_bytes()[..8]); // only part of the message is received
        }
        if test_trunc && !set_trunc_flag {
            assert_eq!(n, 8); // returns the size of the copied data, not the actual message length
            assert_eq!(recv_buf[..n], msg.as_bytes()[..n]);
        }
        if !test_trunc {
            assert_eq!(n, msg.len());
            assert_eq!(recv_buf[..n], msg.as_bytes()[..n]);
        }
        assert_eq!(sender_addr, Some(client_addr));

        close_socket(task, raw_client_fd);
        close_socket(task, raw_server_fd);
    }

    #[test]
    fn test_blocking_udp_server_socket() {
        let task = init_platform();
        blocking_udp_server_socket(&task, false, false, false, "recvfrom");
        blocking_udp_server_socket(&task, false, false, false, "recvmsg");
    }

    #[test]
    fn test_nonblocking_udp_server_socket() {
        let task = init_platform();
        blocking_udp_server_socket(&task, false, false, true, "recvfrom");
        blocking_udp_server_socket(&task, false, false, true, "recvmsg");
    }

    #[test]
    fn test_blocking_udp_server_socket_with_truncation() {
        let task = init_platform();
        blocking_udp_server_socket(&task, true, true, false, "recvfrom");
        blocking_udp_server_socket(&task, true, true, false, "recvmsg");
        blocking_udp_server_socket(&task, true, false, false, "recvmsg");
    }

    #[test]
    fn test_udp_client_socket_without_server() {
        let task = init_platform();

        // Client socket and explicit bind
        let raw_client_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::empty(),
                litebox_common_linux::IPProtocol::UDP as u8,
            )
            .expect("failed to create client socket");
        let client_fd = typed_socket(&task, raw_client_fd);

        let server_addr = loopback_addr(UNUSED_GUEST_PORT);

        // Send from client to server
        let msg = "Hello without connect()";
        task.do_sendto(
            &client_fd,
            msg.as_bytes(),
            SendFlags::empty(),
            Some(server_addr.clone()),
        )
        .expect("failed to sendto");

        // Client implicitly bound to an ephemeral port via sendto
        let SocketAddress::Inet(client_addr) =
            task.do_getsockname(&client_fd).expect("getsockname failed")
        else {
            panic!("Expected Inet socket address");
        };
        assert_ne!(client_addr.port(), 0);

        // Client connects to server address
        task.do_connect(&client_fd, server_addr.clone())
            .expect("failed to connect");

        // Now client can send without specifying addr
        let msg = "Hello with connect()";
        task.do_sendto(&client_fd, msg.as_bytes(), SendFlags::empty(), None)
            .expect("failed to sendto");

        // The connected client learns that the port is unreachable on its
        // next send, as on Linux.
        assert_eq!(
            task.do_sendto(&client_fd, msg.as_bytes(), SendFlags::empty(), None),
            Err(Errno::ECONNREFUSED)
        );

        close_socket(&task, raw_client_fd);
    }

    #[test]
    fn test_tcp_keepalive_sockopt() {
        let task = init_platform();
        let raw_sockfd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create socket");
        let sockfd = typed_socket(&task, raw_sockfd);

        let val: u32 = 1;
        let optval = UserPtr::from_usize((&raw const val).cast::<u8>() as usize);
        task.do_setsockopt(
            &sockfd,
            SocketOptionName::Socket(SocketOption::KEEPALIVE),
            optval,
            core::mem::size_of::<u32>(),
        )
        .expect("failed to set SO_KEEPALIVE");

        // Verify SO_KEEPALIVE is enabled
        let mut result: u32 = 0;
        let optval_out = UserPtrMut::from_usize((&raw mut result).cast::<u8>() as usize);
        let len = task
            .do_getsockopt(
                &sockfd,
                SocketOptionName::Socket(SocketOption::KEEPALIVE),
                optval_out,
                core::mem::size_of::<u32>().trunc(),
            )
            .expect("failed to get SO_KEEPALIVE");
        assert_eq!(len, core::mem::size_of::<u32>());
        assert_eq!(result, 1);
        close_socket(&task, raw_sockfd);
    }

    #[test]
    fn test_socket_dup_and_close() {
        let task = init_platform();
        let socket_fd = task
            .do_socket(
                litebox_common_linux::AddressFamily::INET,
                litebox_common_linux::SockType::Stream,
                litebox_common_linux::SockFlags::empty(),
                0,
            )
            .unwrap();
        let socket_fd2 = task
            .sys_dup(i32::try_from(socket_fd).unwrap(), None, None)
            .unwrap();
        close_socket(&task, socket_fd);
        close_socket(&task, socket_fd2);
    }
}
