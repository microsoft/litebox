// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Internet (IPv4 TCP and UDP) sockets for the Linux shim layer.
//!
//! Each socket is a LiteBox [`inet_socket::InetSocket`]. This module translates between Linux
//! socket calls and LiteBox's guest-neutral internet socket operations.

use alloc::sync::{Arc, Weak};
use core::{net::SocketAddr, time::Duration};

use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError},
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    inet_socket::{
        self,
        errors::{AcceptError, ConnectError, ShutdownError, SocketReadError, SocketWriteError},
    },
    sync::{Mutex, MutexGuard},
    utils::TruncateExt as _,
};
use litebox_broker_protocol::{
    fs::FileOpenFlags,
    socket::{self, SocketType},
};
use litebox_common_linux::{
    IpOption, OFlags, ReceiveFlags, SendFlags, ShutdownHow, SockFlags, SockType, SocketOption,
    SocketOptionName, TcpOption, errno::Errno,
};

use crate::{
    GlobalState, ShimPlatform, UserPtr, UserPtrMut,
    syscalls::{
        file::{linux_status_flags, status_flags_change},
        net::{open_flags, shutdown_mode},
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

/// An internet socket descriptor's open file description.
pub(crate) struct InetSocket<Platform: ShimPlatform> {
    socket: Arc<inet_socket::InetSocket<Platform>>,
    /// Serializes `recvmmsg` calls on the socket.
    recvmmsg_lock: Arc<RecvmmsgLock<Platform>>,
}

impl<Platform: ShimPlatform> From<inet_socket::InetSocket<Platform>> for InetSocket<Platform> {
    fn from(socket: inet_socket::InetSocket<Platform>) -> Self {
        Self {
            socket: Arc::new(socket),
            recvmmsg_lock: Arc::new(RecvmmsgLock::new()),
        }
    }
}

/// How one receive call fits into a larger receive operation.
pub(crate) struct ReceiveContext {
    /// Longest time the call waits, or `None` for the socket's receive timeout.
    timeout: Option<Duration>,
    /// Whether the operation already received data, which a later failure then ends
    /// instead of being reported.
    has_prior_progress: bool,
}

impl ReceiveContext {
    pub(crate) fn new(timeout: Option<Duration>, has_prior_progress: bool) -> Self {
        Self {
            timeout,
            has_prior_progress,
        }
    }
}

impl<Platform: ShimPlatform> InetSocket<Platform> {
    pub(super) fn new(
        litebox: &litebox::LiteBox<Platform>,
        socket_type: SocketType,
        flags: SockFlags,
    ) -> Result<Self, Errno> {
        let socket = litebox.create_inet_socket(socket_type, open_flags(flags))?;
        Ok(socket.into())
    }

    /// The LiteBox socket.
    pub(crate) fn inet_socket(&self) -> &Arc<inet_socket::InetSocket<Platform>> {
        &self.socket
    }

    pub(super) fn recvmmsg_lock(&self) -> &Arc<RecvmmsgLock<Platform>> {
        &self.recvmmsg_lock
    }

    pub(super) fn is_stream(&self) -> bool {
        self.socket.socket_type() == SocketType::Stream
    }

    /// Whether the socket is nonblocking, which every descriptor sharing it sees.
    pub(super) fn is_nonblocking(&self) -> Result<bool, Errno> {
        Ok(self
            .socket
            .get_status_flags()?
            .flags
            .contains(FileOpenFlags::NONBLOCKING))
    }

    /// The longest time a blocking receive or accept waits, or `None` to wait indefinitely.
    pub(super) fn receive_timeout(&self) -> Result<Option<Duration>, Errno> {
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
        Ok(result.map_err(|error| wait_errno(timeout, error))?.into())
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
            || match self.socket.connect(&address, check_progress) {
                Ok(()) => Ok(()),
                Err(ConnectError::InProgress) => {
                    check_progress = true;
                    Err(TryOpError::TryAgain)
                }
                // A blocking call waits for an earlier attempt just as for its own.
                Err(ConnectError::AlreadyInProgress) => {
                    check_progress = true;
                    already_in_progress = true;
                    Err(TryOpError::TryAgain)
                }
                Err(error) => Err(TryOpError::Other(error.into())),
            },
        );
        result.map_err(|error| match error {
            TryOpError::TryAgain if already_in_progress => Errno::EALREADY,
            TryOpError::TryAgain => Errno::EINPROGRESS,
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
    /// A datagram socket stores its sender's address in `source_addr` if requested.
    pub(crate) fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        context: ReceiveContext,
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
            || {
                context
                    .timeout
                    .map_or_else(|| self.receive_timeout(), |t| Ok(Some(t)))
            },
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
                        if received != 0 || context.has_prior_progress {
                            return Ok(received);
                        }
                        return Err(TryOpError::Other(Errno::EAGAIN));
                    }
                    Err(SocketReadError::ConnectionClosed) => {
                        if received != 0 || context.has_prior_progress {
                            return Ok(received);
                        }
                        return match self.socket.take_async_error() {
                            Some(err) => Err(TryOpError::Other(err.into())),
                            None => Ok(0),
                        };
                    }
                    Err(SocketReadError::NotConnected)
                        if received != 0 || context.has_prior_progress =>
                    {
                        return Ok(received);
                    }
                    Err(SocketReadError::Socket(error))
                        if received != 0 || context.has_prior_progress =>
                    {
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
            Err(TryOpError::WaitError(_)) if received != 0 || context.has_prior_progress => {
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
        fd: &TypedFd<InetSocketSubsystem<Platform>>,
        f: impl FnOnce(&InetSocket<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
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

/// Serializes multi-message receives while allowing contended waits to be interrupted or timed out.
pub(super) struct RecvmmsgLock<Platform: ShimPlatform> {
    mutex: Mutex<Platform, ()>,
    pollee: Pollee<Platform>,
}

pub(super) struct RecvmmsgGuard<'a, Platform: ShimPlatform> {
    guard: Option<MutexGuard<'a, Platform, ()>>,
    lock: &'a RecvmmsgLock<Platform>,
}

impl<Platform: ShimPlatform> RecvmmsgLock<Platform> {
    fn new() -> Self {
        Self {
            mutex: Mutex::new(()),
            pollee: Pollee::new(),
        }
    }

    pub(super) fn try_lock(&self) -> Option<RecvmmsgGuard<'_, Platform>> {
        Some(RecvmmsgGuard {
            guard: Some(self.mutex.try_lock()?),
            lock: self,
        })
    }

    pub(super) fn lock_interruptibly(
        &self,
        cx: &WaitContext<'_, Platform>,
    ) -> Result<RecvmmsgGuard<'_, Platform>, Errno> {
        cx.wait_on_events(
            false,
            Events::IN,
            |observer, filter| {
                self.pollee.register_observer(observer, filter);
                Ok(())
            },
            || self.try_lock().ok_or(TryOpError::TryAgain),
        )
        .map_err(socket_io_errno)
    }
}

impl<Platform: ShimPlatform> Drop for RecvmmsgGuard<'_, Platform> {
    fn drop(&mut self) {
        drop(self.guard.take());
        self.lock.pollee.notify_observers(Events::IN);
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use litebox_common_linux::errno::Errno;

    use super::RecvmmsgLock;
    use crate::syscalls::tests::init_platform;

    extern crate std;

    #[test]
    fn recvmmsg_lock_wakes_contended_waiter() {
        let task = init_platform();
        let lock = alloc::sync::Arc::new(RecvmmsgLock::new());
        let guard = lock.try_lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let worker_lock = alloc::sync::Arc::clone(&lock);
        let worker = task.spawn_clone_for_test(move |task| {
            started_tx.send(()).unwrap();
            let _guard = worker_lock.lock_interruptibly(&task.wait_cx()).unwrap();
            acquired_tx.send(()).unwrap();
        });

        started_rx
            .recv_timeout(core::time::Duration::from_secs(1))
            .unwrap();
        assert!(
            acquired_rx
                .recv_timeout(core::time::Duration::from_millis(20))
                .is_err()
        );
        drop(guard);
        acquired_rx
            .recv_timeout(core::time::Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn recvmmsg_lock_honors_wait_deadline() {
        let task = init_platform();
        let lock = RecvmmsgLock::new();
        let guard = lock.try_lock().unwrap();
        let wait_cx = task
            .wait_cx()
            .with_timeout(core::time::Duration::from_millis(20));

        assert!(matches!(
            lock.lock_interruptibly(&wait_cx),
            Err(Errno::EAGAIN)
        ));
        drop(guard);
    }
}
