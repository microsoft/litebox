// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Socket-related syscalls, e.g., socket, bind, listen, etc.

use core::{
    ffi::CStr,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use alloc::string::ToString;
use alloc::sync::Arc;
use litebox::{
    event::{
        Events, IOPollable,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError},
    },
    fd::EntryHandle,
    fs::OFlags,
    mm::linux::PAGE_SIZE,
    net::{
        CloseBehavior, SOCKET_RECEIVE_OPERATION_SIZE, TcpOptionData,
        errors::AcceptError,
        socket_channel::{ChannelReadError, ChannelWriteError, NetworkProxy, SocketState},
    },
    platform::{Instant as _, page_mgmt::MemoryRegionPermissions},
    sync::{Mutex, MutexGuard},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    AddressFamily, FileDescriptorFlags, IPProtocol, ReceiveFlags, SendFlags, ShutdownHow,
    SockFlags, SockType, SocketOption, SocketOptionName, TcpOption, UnixProtocol, UserMmsgHdr,
    UserMsgHdr, errno::Errno, signal::Signal,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::unix::{CSockUnixAddr, UnixSocket, UnixSocketAddr, UnixSocketSubsystem};
use crate::{GlobalState, ShimFS, ShimPlatform, Task};
use crate::{UserPtr, UserPtrMut, syscalls::signal};

/// Linux's hard cap on the number of iovecs per `*msg`-style call, and on the
/// number of entries per `sendmmsg`. See `UIO_MAXIOV` in `<uapi/linux/uio.h>`.
const UIO_MAXIOV: usize = 1024;

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

pub(crate) type SocketFd<Platform> = litebox::net::SocketFd<Platform>;

fn socket_io_errno(error: TryOpError<Errno>) -> Errno {
    match error {
        TryOpError::WaitError(WaitError::TimedOut) => Errno::EAGAIN,
        error => error.into(),
    }
}

pub(crate) struct ReceiveContext<Instant> {
    deadline: Option<Instant>,
    has_prior_progress: bool,
}

impl<Instant> ReceiveContext<Instant> {
    pub(crate) fn new(deadline: Option<Instant>, has_prior_progress: bool) -> Self {
        Self {
            deadline,
            has_prior_progress,
        }
    }
}

pub(crate) struct InetSocketPin<'a, Platform: ShimPlatform, FS: ShimFS> {
    global: &'a GlobalState<Platform, FS>,
    entry: Option<EntryHandle<Platform, litebox::net::Network<Platform>>>,
    state: SocketIoState,
    proxy: Arc<NetworkProxy<Platform>>,
    recv_timeout: Option<core::time::Duration>,
    send_timeout: Option<core::time::Duration>,
    is_nonblock: bool,
    socket_type: SockType,
    recvmmsg_lock: SocketRecvmmsgLock<Platform>,
}

impl<Platform: ShimPlatform, FS: ShimFS> InetSocketPin<'_, Platform, FS> {
    pub(crate) fn is_broker_datagram(&self) -> bool {
        matches!(self.proxy.as_ref(), NetworkProxy::BrokerDatagram(_))
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for InetSocketPin<'_, Platform, FS> {
    fn drop(&mut self) {
        drop(self.entry.take());
        let previous = self
            .state
            .0
            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
        let active_pins = previous & SOCKET_IO_PIN_COUNT_MASK;
        assert_ne!(active_pins, 0, "socket I/O pin count underflow");
        if active_pins != 1 || previous & SOCKET_IO_CLOSE_PENDING == 0 {
            return;
        }
        let mut net = self.global.net.lock();
        let pending = net.finish_deferred_closes();
        if !pending {
            self.state.0.fetch_and(
                !SOCKET_IO_CLOSE_PENDING,
                core::sync::atomic::Ordering::Release,
            );
        }
    }
}

enum ReceiveSocket<'a, Platform: ShimPlatform, FS: ShimFS> {
    Inet(InetSocketPin<'a, Platform, FS>),
    Unix(EntryHandle<Platform, UnixSocketSubsystem<Platform, FS>>),
}

impl<Platform: ShimPlatform, FS: ShimFS> super::file::FilesState<Platform, FS> {
    pub(crate) fn try_pin_inet_socket<'a>(
        &self,
        global: &'a GlobalState<Platform, FS>,
        raw_fd: usize,
    ) -> Result<Option<InetSocketPin<'a, Platform, FS>>, Errno> {
        let rds = self.raw_descriptor_store.read();
        let fd = match rds.fd_from_raw_integer(raw_fd) {
            Ok(fd) => fd,
            Err(litebox::fd::ErrRawIntFd::NotFound) => return Err(Errno::EBADF),
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => return Ok(None),
        };
        let socket = global.pin_socket(&fd)?;
        drop(rds);
        Ok(Some(socket))
    }

    /// Helper to dispatch socket operations based on socket type (INET vs Unix).
    ///
    /// This method handles the common pattern of:
    /// 1. Looking up the file descriptor
    /// 2. Matching on descriptor type
    /// 3. Dropping the file table lock before potentially-blocking operations
    /// 4. Dispatching to the appropriate handler
    ///
    /// For `LiteBoxRawFd` sockets, the `inet_op` closure is called with the socket fd.
    /// For Unix sockets, the `unix_op` closure is called with a cloned Arc to the socket.
    fn with_socket<R>(
        &self,
        global: &GlobalState<Platform, FS>,
        sockfd: u32,
        inet_op: impl FnOnce(&SocketFd<Platform>) -> Result<R, Errno>,
        unix_op: impl FnOnce(&UnixSocket<Platform, FS>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let raw_fd = sockfd as usize;
        let inet_fd = {
            let rds = self.raw_descriptor_store.read();
            rds.fd_from_raw_integer(raw_fd).ok()
        };
        if let Some(fd) = inet_fd {
            return inet_op(&fd);
        }
        let unix = self
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>(raw_fd)
            .map_err(|err| match err {
                litebox::fd::ErrRawIntFd::NotFound => Errno::EBADF,
                litebox::fd::ErrRawIntFd::InvalidSubsystem => Errno::ENOTSOCK,
            })?;
        let handle = global
            .litebox
            .descriptor_table()
            .entry_handle(&unix)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|entry| unix_op(entry))
    }

    fn pin_receive_socket<'a>(
        &self,
        global: &'a GlobalState<Platform, FS>,
        sockfd: u32,
    ) -> Result<ReceiveSocket<'a, Platform, FS>, Errno> {
        let raw_fd = sockfd as usize;
        let rds = self.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer(raw_fd) {
            let socket = ReceiveSocket::Inet(global.pin_socket(&fd)?);
            drop(rds);
            return Ok(socket);
        }
        let unix = rds
            .fd_from_raw_integer::<UnixSocketSubsystem<Platform, FS>>(raw_fd)
            .map_err(|err| match err {
                litebox::fd::ErrRawIntFd::NotFound => Errno::EBADF,
                litebox::fd::ErrRawIntFd::InvalidSubsystem => Errno::ENOTSOCK,
            })?;
        let handle = global
            .litebox
            .descriptor_table()
            .entry_handle(&unix)
            .ok_or(Errno::EBADF)?;
        drop(rds);
        Ok(ReceiveSocket::Unix(handle))
    }
}

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

/// Socket address structure for different address families.
/// Currently only supports IPv4 (AF_INET).
#[non_exhaustive]
#[derive(Clone, PartialEq, Debug)]
pub(crate) enum SocketAddress {
    Inet(SocketAddr),
    Unix(UnixSocketAddr),
}

impl Default for SocketAddress {
    fn default() -> Self {
        SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    }
}

impl SocketAddress {
    pub(crate) fn inet(self) -> Option<SocketAddr> {
        match self {
            SocketAddress::Inet(addr) => Some(addr),
            _ => None,
        }
    }

    pub(crate) fn unix(self) -> Option<UnixSocketAddr> {
        match self {
            SocketAddress::Unix(addr) => Some(addr),
            _ => None,
        }
    }
}

#[derive(Default, Clone)]
pub(super) struct SocketOptions {
    pub(super) reuse_address: bool,
    pub(super) keep_alive: bool,
    pub(super) broadcast: bool,
    /// Receiving timeout, None (default value) means no timeout
    pub(super) recv_timeout: Option<core::time::Duration>,
    /// Sending timeout, None (default value) means no timeout
    pub(super) send_timeout: Option<core::time::Duration>,
    /// Linger timeout, None (default value) means closing in the background.
    /// If it is `Some`, a close or shutdown will not return
    /// until all queued messages for the socket have been
    /// successfully sent or the timeout has been reached.
    pub(super) linger_timeout: Option<core::time::Duration>,
}

#[derive(Clone)]
pub(crate) struct SocketOFlags(pub OFlags);
pub(crate) struct SocketProxy<Platform: ShimPlatform>(pub Arc<NetworkProxy<Platform>>);
#[derive(Clone)]
struct SocketIoState(Arc<core::sync::atomic::AtomicUsize>);
/// Entry metadata that shares `recvmmsg` serialization across duplicated descriptors.
struct SocketRecvmmsgLock<Platform: ShimPlatform>(Arc<RecvmmsgLock<Platform>>);

/// Serializes multi-message receives while allowing contended waits to be interrupted or timed out.
struct RecvmmsgLock<Platform: ShimPlatform> {
    mutex: Mutex<Platform, ()>,
    pollee: Pollee<Platform>,
}

struct RecvmmsgGuard<'a, Platform: ShimPlatform> {
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

    fn try_lock(&self) -> Option<RecvmmsgGuard<'_, Platform>> {
        Some(RecvmmsgGuard {
            guard: Some(self.mutex.try_lock()?),
            lock: self,
        })
    }

    fn lock_interruptibly(
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

impl<Platform: ShimPlatform> Clone for SocketRecvmmsgLock<Platform> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

const SOCKET_IO_CLOSE_PENDING: usize = 1 << (usize::BITS - 1);
const SOCKET_IO_PIN_COUNT_MASK: usize = SOCKET_IO_CLOSE_PENDING - 1;

impl<Platform: ShimPlatform> Clone for SocketProxy<Platform> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(super) enum SocketOptionValue {
    Timeout(Option<core::time::Duration>),
    U32(u32),
}

/// Socket-related implementation. Currently these methods are on `GlobalState`
/// so that they can access `net` and the litebox descriptor table. This might
/// change if the nature of the litebox descriptor table changes, or if network
/// namespaces are implemented.
impl<Platform: ShimPlatform, FS: ShimFS> GlobalState<Platform, FS> {
    pub(crate) fn initialize_socket(
        &self,
        fd: &SocketFd<Platform>,
        sock_type: SockType,
        flags: SockFlags,
    ) -> Arc<NetworkProxy<Platform>> {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));

        let mut dt = self.litebox.descriptor_table_mut();
        let old = dt.set_entry_metadata(fd, SocketOptions::default());
        assert!(old.is_none());
        if flags.contains(SockFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(fd, litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        let old = dt.set_entry_metadata(fd, sock_type);
        assert!(old.is_none());
        let old = dt.set_entry_metadata(fd, SocketOFlags(status));
        assert!(old.is_none());
        let old = dt.set_entry_metadata(
            fd,
            SocketIoState(Arc::new(core::sync::atomic::AtomicUsize::new(0))),
        );
        assert!(old.is_none());
        let old = dt.set_entry_metadata(
            fd,
            SocketRecvmmsgLock(Arc::new(RecvmmsgLock::<Platform>::new())),
        );
        assert!(old.is_none());
        drop(dt);

        let proxy = self
            .net
            .lock()
            .attach_socket_proxy(fd)
            .expect("newly-created socket must have a proxy");
        // Save the proxy in descriptor metadata so the shim can access it without holding the
        // network lock. `attach_socket_proxy` has already installed the same proxy in `Network`.
        let mut dt = self.litebox.descriptor_table_mut();
        let old = dt.set_entry_metadata(fd, SocketProxy(proxy.clone()));
        assert!(old.is_none());
        proxy
    }

    fn with_socket_options<R>(
        &self,
        fd: &SocketFd<Platform>,
        f: impl FnOnce(&SocketOptions) -> R,
    ) -> R {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |opt| f(opt))
            .unwrap()
    }
    fn with_socket_options_mut<R>(
        &self,
        fd: &SocketFd<Platform>,
        f: impl FnOnce(&mut SocketOptions) -> R,
    ) -> R {
        self.litebox
            .descriptor_table_mut()
            .with_metadata_mut(fd, |opt| f(opt))
            .unwrap()
    }

    /// Common implementation for setsockopt for options that are stored in [`SocketOptions`]:
    ///
    /// This method handles the common logic of reading option values from user memory and
    /// converting them to appropriate types, then delegates the actual storage to a callback.
    /// It supports the following socket options:
    /// - RCVTIMEO
    /// - SNDTIMEO
    /// - LINGER
    /// - REUSEADDR
    /// - KEEPALIVE
    /// - BROADCAST
    ///
    /// # Parameters
    /// - `optname`: The name of the socket option to set.
    /// - `optval`: A pointer to the option value in user memory.
    /// - `optlen`: The length of the option value.
    /// - `set_option` - Callback invoked with the parsed option and value for storage.
    pub(super) fn setsockopt_common<F>(
        &self,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
        optlen: usize,
        set_option: F,
    ) -> Result<(), Errno>
    where
        F: FnOnce(SocketOption, SocketOptionValue) -> Result<(), Errno>,
    {
        match optname {
            SocketOptionName::Socket(sopt) => match sopt {
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO => {
                    let timeval = super::read_from_user::<litebox_common_linux::TimeVal, Platform>(
                        optval, optlen,
                    )?;
                    let duration = core::time::Duration::try_from(timeval)?;
                    let duration = if duration.is_zero() {
                        None
                    } else {
                        Some(duration)
                    };
                    set_option(sopt, SocketOptionValue::Timeout(duration))
                }
                SocketOption::LINGER => {
                    let linger: litebox_common_linux::Linger =
                        super::read_from_user::<_, Platform>(optval, optlen)?;
                    let timeout = if linger.onoff != 0 {
                        Some(core::time::Duration::from_secs(u64::from(linger.linger)))
                    } else {
                        None
                    };
                    set_option(sopt, SocketOptionValue::Timeout(timeout))
                }
                SocketOption::REUSEADDR | SocketOption::BROADCAST | SocketOption::KEEPALIVE => {
                    let val: u32 = super::read_from_user::<_, Platform>(optval, optlen)?;
                    set_option(sopt, SocketOptionValue::U32(val))
                }
                _ => Err(Errno::ENOPROTOOPT),
            },
            _ => Err(Errno::ENOPROTOOPT),
        }
    }
    fn setsockopt(
        &self,
        fd: &SocketFd<Platform>,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        let keepalive_socket_type =
            if matches!(optname, SocketOptionName::Socket(SocketOption::KEEPALIVE)) {
                Some(self.get_socket_type(fd)?)
            } else {
                None
            };
        if matches!(optname, SocketOptionName::Socket(SocketOption::KEEPALIVE))
            && matches!(self.get_proxy(fd)?.as_ref(), NetworkProxy::BrokerStream(_))
        {
            let value: u32 = super::read_from_user::<_, Platform>(optval, optlen)?;
            return self
                .net
                .lock()
                .set_tcp_option(fd, litebox::net::TcpOptionData::KEEPALIVE(value != 0))
                .map_err(Errno::from);
        }
        match self.setsockopt_common(optname, optval, optlen, |so, value| {
            let unsupported_broker_option = matches!(
                (so, &value),
                (SocketOption::LINGER, SocketOptionValue::Timeout(Some(_)))
            );
            if unsupported_broker_option
                && matches!(self.get_proxy(fd)?.as_ref(), NetworkProxy::BrokerStream(_))
            {
                return Err(Errno::EOPNOTSUPP);
            }
            // Collect any TCP option that needs to be applied via Network after
            // releasing the descriptor table write lock, to avoid a deadlock:
            // `with_socket_options_mut` holds a write lock on descriptors, while
            // `Network::set_tcp_option` acquires a read lock on the same RwLock.
            let mut deferred_tcp_option = None;
            self.with_socket_options_mut(fd, |opt| {
                match (so, value) {
                    (SocketOption::RCVTIMEO, SocketOptionValue::Timeout(timeout)) => {
                        opt.recv_timeout = timeout;
                    }
                    (SocketOption::SNDTIMEO, SocketOptionValue::Timeout(timeout)) => {
                        opt.send_timeout = timeout;
                    }
                    (SocketOption::LINGER, SocketOptionValue::Timeout(timeout)) => {
                        opt.linger_timeout = timeout;
                    }
                    (SocketOption::REUSEADDR, SocketOptionValue::U32(val)) => {
                        opt.reuse_address = val != 0;
                    }
                    (SocketOption::BROADCAST, SocketOptionValue::U32(val)) => {
                        opt.broadcast = val != 0;
                        if val == 0 {
                            todo!("disable SO_BROADCAST");
                        }
                    }
                    (SocketOption::KEEPALIVE, SocketOptionValue::U32(val)) => {
                        let keep_alive = val != 0;
                        if matches!(keepalive_socket_type, Some(SockType::Stream)) {
                            deferred_tcp_option =
                                Some(litebox::net::TcpOptionData::KEEPALIVE(keep_alive));
                        }
                        opt.keep_alive = keep_alive;
                    }
                    _ => unreachable!(),
                }
                Ok::<(), Errno>(())
            })?;
            // Apply deferred TCP option after releasing the descriptor table write lock.
            if let Some(tcp_data) = deferred_tcp_option
                && let Err(err) = self.net.lock().set_tcp_option(fd, tcp_data)
            {
                match err {
                    litebox::net::errors::SetTcpOptionError::InvalidFd => {
                        return Err(Errno::EBADF);
                    }
                    litebox::net::errors::SetTcpOptionError::NotTcpSocket => {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    litebox::net::errors::SetTcpOptionError::Unsupported
                    | litebox::net::errors::SetTcpOptionError::BackendFailure => {
                        return Err(err.into());
                    }
                    _ => unreachable!(),
                }
            }
            Ok(())
        }) {
            Err(Errno::ENOPROTOOPT) => {} // fallthrough to handle other options
            other => return other,
        }

        match optname {
            SocketOptionName::IP(ip) => match ip {
                // IP_TOS is an advisory traffic-class hint. Accept it (we don't
                // propagate the bit anywhere) instead of returning EOPNOTSUPP,
                // which Node's Socket.setTypeOfService treats as fatal and
                // cascades into tearing down the connection. Log at debug so the
                // accepted-but-ignored option stays visible.
                litebox_common_linux::IpOption::TOS => {
                    litebox_util_log::debug!("accepting and ignoring setsockopt(IP_TOS)");
                    return Ok(());
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
                    return Ok(());
                }
                // Socket does not support these options
                SocketOption::TYPE | SocketOption::PEERCRED | SocketOption::ERROR => {
                    return Err(Errno::ENOPROTOOPT);
                }
            },
            SocketOptionName::TCP(to) => match to {
                TcpOption::CONGESTION => {
                    const TCP_CONGESTION_NAME_MAX: usize = 16;
                    let data = optval
                        .to_owned_slice::<Platform>(TCP_CONGESTION_NAME_MAX.min(optlen))
                        .ok_or(Errno::EFAULT)?;
                    let name = core::str::from_utf8(&data).map_err(|_| Errno::EINVAL)?;
                    self.net.lock().set_tcp_option(
                        fd,
                        match name {
                            "reno" => litebox::net::TcpOptionData::CONGESTION(
                                litebox::net::CongestionControl::Reno,
                            ),
                            "cubic" => litebox::net::TcpOptionData::CONGESTION(
                                litebox::net::CongestionControl::Cubic,
                            ),
                            "none" => litebox::net::TcpOptionData::CONGESTION(
                                litebox::net::CongestionControl::None,
                            ),
                            _ => return Err(Errno::EINVAL),
                        },
                    )?;
                }
                TcpOption::KEEPCNT | TcpOption::KEEPIDLE | TcpOption::INFO => {
                    return Err(Errno::EOPNOTSUPP);
                }
                TcpOption::NODELAY | TcpOption::CORK => {
                    let proxy = self.get_proxy(fd)?;
                    let NetworkProxy::BrokerStream(_) = proxy.as_ref() else {
                        return Err(Errno::ENOPROTOOPT);
                    };
                    drop(proxy);
                    let val: u32 = super::read_from_user::<_, Platform>(optval, optlen)?;
                    if matches!(to, TcpOption::CORK) {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    self.net
                        .lock()
                        .set_tcp_option(fd, litebox::net::TcpOptionData::NODELAY(val != 0))?;
                }
                TcpOption::KEEPINTVL => {
                    const MAX_TCP_KEEPINTVL: u32 = 32767;
                    let val: u32 = super::read_from_user::<_, Platform>(optval, size_of::<u32>())?;
                    if !(1..=MAX_TCP_KEEPINTVL).contains(&val) {
                        return Err(Errno::EINVAL);
                    }
                    self.net
                        .lock()
                        .set_tcp_option(
                            fd,
                            litebox::net::TcpOptionData::KEEPINTVL(Some(
                                core::time::Duration::from_secs(u64::from(val)),
                            )),
                        )
                        .map_err(Errno::from)?;
                }
            },
        }
        Ok(())
    }

    /// Common implementation for getsockopt for options that are stored in [`SocketOptions`]:
    ///
    /// This method handles the common logic of retrieving option values via a callback and
    /// writing them to user memory in the appropriate format. It supports the following socket
    /// options:
    /// - RCVTIMEO
    /// - SNDTIMEO
    /// - LINGER
    /// - REUSEADDR
    /// - KEEPALIVE
    /// - BROADCAST
    ///
    /// # Parameters
    ///
    /// * `optname` - The socket option name to retrieve
    /// * `optval` - Pointer to user memory where the option value will be written
    /// * `len` - Maximum length to write in bytes
    /// * `get_option` - Callback invoked to retrieve the current option value
    pub(super) fn getsockopt_common<F>(
        &self,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
        len: u32,
        get_option: F,
    ) -> Result<usize, Errno>
    where
        F: FnOnce(SocketOption) -> SocketOptionValue,
    {
        match optname {
            SocketOptionName::Socket(sopt) => match sopt {
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO | SocketOption::LINGER => {
                    let SocketOptionValue::Timeout(timeout) = get_option(sopt) else {
                        unreachable!()
                    };
                    let tv = timeout.map_or_else(
                        litebox_common_linux::TimeVal::default,
                        litebox_common_linux::TimeVal::from,
                    );
                    super::write_to_user::<_, Platform>(tv, optval, len)
                }
                SocketOption::REUSEADDR | SocketOption::KEEPALIVE | SocketOption::BROADCAST => {
                    let SocketOptionValue::U32(val) = get_option(sopt) else {
                        unreachable!()
                    };
                    super::write_to_user::<_, Platform>(val, optval, len)
                }
                _ => Err(Errno::ENOPROTOOPT),
            },
            _ => Err(Errno::ENOPROTOOPT),
        }
    }
    fn getsockopt(
        &self,
        fd: &SocketFd<Platform>,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        if matches!(optname, SocketOptionName::Socket(SocketOption::KEEPALIVE))
            && matches!(self.get_proxy(fd)?.as_ref(), NetworkProxy::BrokerStream(_))
        {
            let TcpOptionData::KEEPALIVE(enabled) = self
                .net
                .lock()
                .get_tcp_option(fd, litebox::net::TcpOptionName::KEEPALIVE)?
            else {
                unreachable!()
            };
            return super::write_to_user::<_, Platform>(u32::from(enabled), optval, len);
        }
        match self.getsockopt_common(optname, optval, len, |sopt| {
            self.with_socket_options(fd, |options| match sopt {
                SocketOption::RCVTIMEO => SocketOptionValue::Timeout(options.recv_timeout),
                SocketOption::SNDTIMEO => SocketOptionValue::Timeout(options.send_timeout),
                SocketOption::LINGER => SocketOptionValue::Timeout(options.linger_timeout),
                SocketOption::REUSEADDR => SocketOptionValue::U32(u32::from(options.reuse_address)),
                SocketOption::KEEPALIVE => SocketOptionValue::U32(u32::from(options.keep_alive)),
                SocketOption::BROADCAST => SocketOptionValue::U32(u32::from(options.broadcast)),
                _ => unreachable!(),
            })
        }) {
            Err(Errno::ENOPROTOOPT) => {} // fallthrough to handle other options
            other => return other,
        }

        let val: u32 = match optname {
            SocketOptionName::IP(ipopt) => match ipopt {
                litebox_common_linux::IpOption::TOS => return Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(sopt) => match sopt {
                // handled by `getsockopt_common`
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::KEEPALIVE
                | SocketOption::BROADCAST => {
                    unreachable!()
                }
                SocketOption::ERROR => {
                    // SO_ERROR is self-clearing: atomically read and reset to 0.
                    let proxy = self.get_proxy(fd)?;
                    match proxy.get_async_error(true) {
                        Some(err) => {
                            let errno: Errno = err.into();
                            i32::from(errno).cast_unsigned()
                        }
                        None => 0,
                    }
                }
                SocketOption::TYPE => self.get_socket_type(fd)? as u32,
                SocketOption::RCVBUF | SocketOption::SNDBUF => {
                    litebox::net::SOCKET_BUFFER_SIZE.trunc()
                }
                SocketOption::PEERCRED => return Err(Errno::ENOPROTOOPT),
            },
            SocketOptionName::TCP(tcpopt) => {
                match tcpopt {
                    TcpOption::CONGESTION => {
                        let TcpOptionData::CONGESTION(congestion) = self
                            .net
                            .lock()
                            .get_tcp_option(fd, litebox::net::TcpOptionName::CONGESTION)?
                        else {
                            unreachable!()
                        };
                        let name = match congestion {
                            litebox::net::CongestionControl::Reno => "reno",
                            litebox::net::CongestionControl::Cubic => "cubic",
                            litebox::net::CongestionControl::None => "none",
                            _ => unimplemented!(),
                        };
                        let len = name.len().min(len as usize);
                        optval
                            .write_slice_at_offset::<Platform>(0, &name.as_bytes()[..len])
                            .ok_or(Errno::EFAULT)?;
                        return Ok(len);
                    }
                    TcpOption::KEEPCNT | TcpOption::KEEPIDLE | TcpOption::INFO => {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    TcpOption::KEEPINTVL => {
                        let TcpOptionData::KEEPINTVL(interval) = self
                            .net
                            .lock()
                            .get_tcp_option(fd, litebox::net::TcpOptionName::KEEPINTVL)?
                        else {
                            unreachable!()
                        };
                        interval.map_or(0, |d| d.as_secs().try_into().unwrap())
                    }
                    TcpOption::NODELAY | TcpOption::CORK => {
                        if matches!(tcpopt, TcpOption::CORK)
                            && matches!(self.get_proxy(fd)?.as_ref(), NetworkProxy::BrokerStream(_))
                        {
                            return Err(Errno::EOPNOTSUPP);
                        }
                        let TcpOptionData::NODELAY(nodelay) = self
                            .net
                            .lock()
                            .get_tcp_option(fd, litebox::net::TcpOptionName::NODELAY)?
                        else {
                            unreachable!()
                        };
                        u32::from(if let TcpOption::NODELAY = tcpopt {
                            nodelay
                        } else {
                            // CORK is the opposite of NODELAY
                            !nodelay
                        })
                    }
                }
            }
        };
        super::write_to_user::<_, Platform>(val, optval, len)
    }

    fn try_accept(
        &self,
        fd: &SocketFd<Platform>,
        peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd<Platform>, TryOpError<Errno>> {
        self.net.lock().accept(fd, peer).map_err(|e| match e {
            AcceptError::NoConnectionsReady => TryOpError::TryAgain,
            AcceptError::InvalidFd
            | AcceptError::NotListening
            | AcceptError::UnsupportedOperation
            | AcceptError::OperationFailed(_) => TryOpError::Other(e.into()),
            _ => unimplemented!(),
        })
    }

    fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd<Platform>,
        mut peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd<Platform>, Errno> {
        cx.wait_on_events(
            self.get_status(fd).contains(OFlags::NONBLOCK),
            Events::IN,
            |observer, filter| {
                let proxy = self.get_proxy(fd)?;
                proxy.register_observer(observer, filter);
                Ok(())
            },
            || self.try_accept(fd, peer.as_deref_mut()),
        )
        .map_err(Errno::from)
    }

    fn bind(&self, fd: &SocketFd<Platform>, sockaddr: SocketAddr) -> Result<(), Errno> {
        self.net.lock().bind(fd, &sockaddr).map_err(Errno::from)
    }

    fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd<Platform>,
        sockaddr: SocketAddr,
    ) -> Result<(), Errno> {
        if sockaddr.port() == 0 || sockaddr.ip().is_unspecified() {
            return Err(Errno::ECONNREFUSED);
        }
        let mut check_progress = false;
        cx.wait_on_events::<_, Errno>(
            self.get_status(fd).contains(OFlags::NONBLOCK),
            Events::IN | Events::OUT,
            |observer, filter| {
                let proxy = self.get_proxy(fd)?;
                proxy.register_observer(observer, filter);
                Ok(())
            },
            || match self.net.lock().connect(fd, &sockaddr, check_progress) {
                Ok(()) => Ok(()),
                Err(litebox::net::errors::ConnectError::InProgress) => {
                    check_progress = true;
                    Err(TryOpError::TryAgain)
                }
                Err(e) => Err(TryOpError::Other(e.into())),
            },
        )
        .map_err(|err| match err {
            TryOpError::TryAgain => Errno::EINPROGRESS,
            err => err.into(),
        })
    }

    fn listen(&self, fd: &SocketFd<Platform>, backlog: u16) -> Result<(), Errno> {
        self.net.lock().listen(fd, backlog).map_err(Errno::from)
    }

    /// Send data via socket channel (lock-free path).
    ///
    /// This uses the channel-based approach where the user writes to a TX ring buffer,
    /// and the network worker later drains it.
    pub(crate) fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd<Platform>,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddr>,
    ) -> Result<usize, Errno> {
        let proxy = self.get_proxy(fd)?;

        // Convert `SendFlags` to `litebox::net::SendFlags`
        // `DONTWAIT` is handled in this function and `NOSIGNAL` should be handled by caller,
        // so we don't convert them.
        let new_flags = convert_flags!(
            flags,
            SendFlags,
            litebox::net::SendFlags,
            CONFIRM,
            DONTROUTE,
            EOR,
            MORE,
            OOB,
        );

        let timeout = self.with_socket_options(fd, |opt| opt.send_timeout);
        let is_nonblock =
            self.get_status(fd).contains(OFlags::NONBLOCK) || flags.contains(SendFlags::DONTWAIT);
        let is_empty_stream =
            buf.is_empty() && matches!(proxy.as_ref(), NetworkProxy::BrokerStream(_));

        cx.with_timeout(timeout)
            .wait_on_events(
                is_nonblock,
                Events::OUT,
                |observer, filter| {
                    proxy.register_observer(observer, filter);
                    Ok(())
                },
                || match proxy.try_write(buf, new_flags, sockaddr) {
                    Ok(0) if buf.is_empty() => Ok(0),
                    Ok(0) => Err(TryOpError::TryAgain),
                    Ok(n) => Ok(n),
                    Err(ChannelWriteError::BufferFull) if is_empty_stream => Ok(0),
                    Err(ChannelWriteError::BufferFull) => Err(TryOpError::TryAgain),
                    Err(e) => Err(TryOpError::Other(Errno::from(e))),
                },
            )
            .map_err(socket_io_errno)
    }

    /// Receive data via socket channel (lock-free path).
    ///
    /// This uses the channel-based approach where the user reads from an RX ring buffer
    /// that the network worker populates.
    pub(crate) fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd<Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        context: ReceiveContext<Platform::Instant>,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, Errno> {
        let socket = self.pin_socket(fd)?;
        if buf.is_empty() {
            return Ok(0);
        }
        let received = self.receive_from_socket(cx, &socket, buf, flags, context, source_addr)?;
        Ok(if flags.contains(ReceiveFlags::TRUNC) {
            received
        } else {
            received.min(buf.len())
        })
    }

    pub(crate) fn pin_socket(
        &self,
        fd: &SocketFd<Platform>,
    ) -> Result<InetSocketPin<'_, Platform, FS>, Errno> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.entry_handle(fd).ok_or(Errno::EBADF)?;
        let proxy = descriptor_table
            .with_metadata(fd, |SocketProxy(proxy)| proxy.clone())
            .map_err(|error| match error {
                litebox::fd::MetadataError::NoSuchMetadata => unreachable!(),
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })?;
        let (recv_timeout, send_timeout) = descriptor_table
            .with_metadata(fd, |options: &SocketOptions| {
                (options.recv_timeout, options.send_timeout)
            })
            .map_err(|error| match error {
                litebox::fd::MetadataError::NoSuchMetadata => unreachable!(),
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })?;
        let is_nonblock = descriptor_table
            .with_metadata(fd, |SocketOFlags(flags)| flags.contains(OFlags::NONBLOCK))
            .map_err(|error| match error {
                litebox::fd::MetadataError::NoSuchMetadata => unreachable!(),
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })?;
        let socket_type = descriptor_table
            .with_metadata(fd, |socket_type: &SockType| *socket_type)
            .map_err(|error| match error {
                litebox::fd::MetadataError::NoSuchMetadata => Errno::ENOTSOCK,
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })?;
        let state = descriptor_table
            .with_metadata(fd, |state: &SocketIoState| state.clone())
            .map_err(|error| match error {
                litebox::fd::MetadataError::NoSuchMetadata => unreachable!(),
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })?;
        let recvmmsg_lock = descriptor_table
            .with_metadata(fd, |lock: &SocketRecvmmsgLock<Platform>| lock.clone())
            .map_err(|error| match error {
                litebox::fd::MetadataError::NoSuchMetadata => unreachable!(),
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })?;
        let previous = state.0.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        assert_ne!(
            previous & SOCKET_IO_PIN_COUNT_MASK,
            SOCKET_IO_PIN_COUNT_MASK,
            "socket I/O pin count overflow"
        );
        drop(descriptor_table);
        Ok(InetSocketPin {
            global: self,
            entry: Some(entry),
            state,
            proxy,
            recv_timeout,
            send_timeout,
            is_nonblock,
            socket_type,
            recvmmsg_lock,
        })
    }

    pub(crate) fn receive_from_socket(
        &self,
        cx: &WaitContext<'_, Platform>,
        socket: &InetSocketPin<'_, Platform, FS>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        context: ReceiveContext<Platform::Instant>,
        mut source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, Errno> {
        let timeout = context
            .deadline
            .map(|deadline| {
                deadline
                    .checked_duration_since(&self.platform.now())
                    .unwrap_or(core::time::Duration::ZERO)
            })
            .or(socket.recv_timeout);
        let is_nonblock = socket.is_nonblock || flags.contains(ReceiveFlags::DONTWAIT);
        let socket_type = socket.socket_type;
        let peek = flags.contains(ReceiveFlags::PEEK);
        let wait_all = flags.contains(ReceiveFlags::WAITALL)
            && matches!(socket_type, SockType::Stream)
            && !is_nonblock;
        if buf.is_empty() && matches!(socket.proxy.as_ref(), NetworkProxy::BrokerStream(_)) {
            return Ok(0);
        }

        let mut new_flags = convert_flags!(
            flags,
            ReceiveFlags,
            litebox::net::ReceiveFlags,
            CMSG_CLOEXEC,
            ERRQUEUE,
            OOB,
            PEEK,
            WAITALL,
        );
        new_flags.set(litebox::net::ReceiveFlags::WAITALL, wait_all);
        // `MSG_TRUNC` behavior depends on the socket type
        if flags.contains(ReceiveFlags::TRUNC) {
            match socket_type {
                SockType::Datagram | SockType::Raw => {
                    new_flags.insert(litebox::net::ReceiveFlags::TRUNC);
                }
                SockType::Stream => {
                    new_flags.insert(litebox::net::ReceiveFlags::DISCARD);
                }
                _ => unimplemented!(),
            }
        }

        let proxy = &socket.proxy;
        let target_len = buf.len();
        let mut received = 0;
        let result = cx.with_timeout(timeout).wait_on_events(
            is_nonblock,
            Events::IN,
            |observer, filter| {
                proxy.register_observer(observer, filter);
                Ok(())
            },
            || loop {
                let destination = if wait_all && !peek {
                    &mut buf[received..target_len]
                } else {
                    &mut buf[..target_len]
                };
                match proxy.try_read(destination, new_flags, source_addr.as_deref_mut()) {
                    Ok(n) if !wait_all => return Ok(n),
                    Ok(n) if peek => {
                        received = n;
                        if received == target_len
                            || proxy
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
                    Err(ChannelReadError::ReadShutdown)
                        if is_nonblock && matches!(socket_type, SockType::Datagram) =>
                    {
                        return Err(TryOpError::TryAgain);
                    }
                    Err(ChannelReadError::ReadShutdown) => return Ok(received),
                    Err(ChannelReadError::WouldBlock) => return Err(TryOpError::TryAgain),
                    Err(ChannelReadError::ConnectionClosed) => {
                        if received != 0 || context.has_prior_progress {
                            return Ok(received);
                        }
                        return match proxy.get_async_error(true) {
                            Some(err) => Err(TryOpError::Other(err.into())),
                            None => Ok(0),
                        };
                    }
                    Err(ChannelReadError::NotConnected)
                        if received != 0 || context.has_prior_progress =>
                    {
                        return Ok(received);
                    }
                    Err(ChannelReadError::Socket(error))
                        if received != 0 || context.has_prior_progress =>
                    {
                        proxy.set_async_error(error);
                        return Ok(received);
                    }
                    Err(ChannelReadError::NotConnected) => {
                        return Err(TryOpError::Other(Errno::ENOTCONN));
                    }
                    Err(ChannelReadError::Socket(error)) => {
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
                new_flags.remove(litebox::net::ReceiveFlags::WAITALL);
                match proxy.try_read(&mut buf[..target_len], new_flags, source_addr) {
                    Ok(received) => Ok(received),
                    Err(ChannelReadError::ReadShutdown) => Ok(0),
                    Err(ChannelReadError::ConnectionClosed) => match proxy.get_async_error(true) {
                        Some(error) => Err(error.into()),
                        None => Ok(0),
                    },
                    Err(ChannelReadError::NotConnected) => Err(Errno::ENOTCONN),
                    Err(ChannelReadError::Socket(error)) => Err(error.into()),
                    Err(ChannelReadError::WouldBlock) => Err(socket_io_errno(error)),
                }
            }

            Err(error) => Err(socket_io_errno(error)),
        }
    }

    pub(crate) fn send_to_pinned_socket(
        &self,
        cx: &WaitContext<'_, Platform>,
        socket: &InetSocketPin<'_, Platform, FS>,
        buf: &[u8],
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        let new_flags = convert_flags!(
            flags,
            SendFlags,
            litebox::net::SendFlags,
            CONFIRM,
            DONTROUTE,
            EOR,
            MORE,
            OOB,
        );
        cx.with_timeout(socket.send_timeout)
            .wait_on_events(
                socket.is_nonblock || flags.contains(SendFlags::DONTWAIT),
                Events::OUT,
                |observer, filter| {
                    socket.proxy.register_observer(observer, filter);
                    Ok(())
                },
                || match socket.proxy.try_write(buf, new_flags, None) {
                    Ok(0) if buf.is_empty() => Ok(0),
                    Ok(0) | Err(ChannelWriteError::BufferFull) => Err(TryOpError::TryAgain),
                    Ok(n) => Ok(n),
                    Err(error) => Err(TryOpError::Other(Errno::from(error))),
                },
            )
            .map_err(socket_io_errno)
    }

    pub(crate) fn get_socket_type(&self, fd: &SocketFd<Platform>) -> Result<SockType, Errno> {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |sock_type: &SockType| *sock_type)
            .map_err(|e| match e {
                litebox::fd::MetadataError::NoSuchMetadata => Errno::ENOTSOCK,
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })
    }

    fn get_status(&self, fd: &SocketFd<Platform>) -> litebox::fs::OFlags {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |SocketOFlags(flags)| *flags)
            .unwrap()
            & litebox::fs::OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn get_proxy(
        &self,
        fd: &SocketFd<Platform>,
    ) -> Result<Arc<NetworkProxy<Platform>>, Errno> {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |SocketProxy(proxy)| proxy.clone())
            .map_err(|e| match e {
                litebox::fd::MetadataError::NoSuchMetadata => unreachable!(),
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })
    }

    pub(crate) fn close_socket(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: Arc<SocketFd<Platform>>,
    ) -> Result<(), Errno> {
        let linger_timeout = self.with_socket_options(&fd, |opt| opt.linger_timeout);
        let behavior = match linger_timeout {
            Some(timeout) if timeout.is_zero() => CloseBehavior::Immediate,
            Some(_) => CloseBehavior::GracefulIfNoPendingData,
            None => CloseBehavior::Graceful,
        };
        let proxy = self.get_proxy(&fd)?;
        match cx.with_timeout(linger_timeout).wait_on_events(
            self.get_status(&fd).contains(OFlags::NONBLOCK),
            Events::HUP,
            |observer, filter| {
                proxy.register_observer(observer, filter);
                Ok(())
            },
            || match self.close_network_socket(&fd, behavior) {
                Ok(()) => Ok(()),
                Err(litebox::net::errors::CloseError::DataPending) => Err(TryOpError::TryAgain),
                Err(litebox::net::errors::CloseError::InvalidFd) => {
                    Err(TryOpError::Other(Errno::EBADF))
                }
                Err(_) => unimplemented!(),
            },
        ) {
            Ok(()) => Ok(()),
            Err(TryOpError::WaitError(WaitError::TimedOut)) => self
                .close_network_socket(&fd, CloseBehavior::Immediate)
                .map_err(Errno::from),
            Err(e) => Err(e.into()),
        }
    }

    fn close_network_socket(
        &self,
        fd: &SocketFd<Platform>,
        behavior: CloseBehavior,
    ) -> Result<(), litebox::net::errors::CloseError> {
        let state = self
            .litebox
            .descriptor_table()
            .with_metadata(fd, |state: &SocketIoState| state.clone())
            .map_err(|_| litebox::net::errors::CloseError::InvalidFd)?;
        state.0.fetch_or(
            SOCKET_IO_CLOSE_PENDING,
            core::sync::atomic::Ordering::AcqRel,
        );
        let mut net = self.net.lock();
        state.0.fetch_or(
            SOCKET_IO_CLOSE_PENDING,
            core::sync::atomic::Ordering::AcqRel,
        );
        let result = net.close(fd, behavior);
        let pending = net.finish_deferred_closes();
        if !pending {
            state.0.fetch_and(
                !SOCKET_IO_CLOSE_PENDING,
                core::sync::atomic::Ordering::Release,
            );
        }
        result
    }

    fn close_unpublished_socket(&self, fd: &SocketFd<Platform>) {
        self.close_network_socket(fd, CloseBehavior::Immediate)
            .expect("closing an unpublished socket must succeed");
    }
}

fn parse_type_and_flags(type_and_flags: u32) -> Result<(SockType, SockFlags), Errno> {
    let ty = type_and_flags & 0x0f;
    let flags = type_and_flags & !0x0f;
    let ty = SockType::try_from(ty).map_err(|_| {
        log_unsupported!("socket(type = {ty})");
        Errno::EINVAL
    })?;
    let flags = SockFlags::from_bits_truncate(flags);
    Ok((ty, flags))
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `socket`
    pub(crate) fn sys_socket(
        &self,
        domain: u32,
        type_and_flags: u32,
        protocol: u8,
    ) -> Result<u32, Errno> {
        let (ty, flags) = parse_type_and_flags(type_and_flags)?;
        let domain = AddressFamily::try_from(domain).map_err(|_| {
            log_unsupported!("socket(domain = {domain})");
            Errno::EINVAL
        })?;
        self.do_socket(domain, ty, flags, protocol)
    }
    fn do_socket(
        &self,
        domain: AddressFamily,
        ty: SockType,
        flags: SockFlags,
        protocol: u8,
    ) -> Result<u32, Errno> {
        let files = self.files.borrow();
        let file = match domain {
            AddressFamily::INET => {
                let protocol = IPProtocol::try_from(protocol).map_err(|_| {
                    log_unsupported!("protocol = {protocol}");
                    Errno::EPROTONOSUPPORT
                })?;
                let protocol = match ty {
                    SockType::Stream => {
                        if !matches!(protocol, IPProtocol::Default | IPProtocol::TCP) {
                            return Err(Errno::EINVAL);
                        }
                        litebox::net::Protocol::Tcp
                    }
                    SockType::Datagram => {
                        if !matches!(protocol, IPProtocol::Default | IPProtocol::UDP) {
                            return Err(Errno::EINVAL);
                        }
                        litebox::net::Protocol::Udp
                    }
                    SockType::Raw => todo!(),
                    _ => unimplemented!(),
                };
                let socket = self.global.net.lock().socket(protocol)?;
                let _ = self.global.initialize_socket(&socket, ty, flags);
                files.insert_raw_fd(socket).map_err(|socket| {
                    self.global.close_unpublished_socket(&socket);
                    Errno::EMFILE
                })?
            }
            AddressFamily::UNIX => {
                let _ = UnixProtocol::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
                let socket = UnixSocket::new(ty, flags).ok_or(Errno::ESOCKTNOSUPPORT)?;
                let typed =
                    self.global
                        .litebox
                        .descriptor_table_mut()
                        .insert::<crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>(socket);
                if flags.contains(SockFlags::CLOEXEC) {
                    let old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }

                files.insert_raw_fd(typed).map_err(|typed| {
                    let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                    Errno::EMFILE
                })?
            }
            AddressFamily::INET6 | AddressFamily::NETLINK => return Err(Errno::EAFNOSUPPORT),
            _ => unimplemented!(),
        };
        Ok(u32::try_from(file).unwrap())
    }

    pub(crate) fn sys_socketpair(
        &self,
        domain: u32,
        type_and_flags: u32,
        protocol: u8,
        sockvec: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        let (ty, flags) = parse_type_and_flags(type_and_flags)?;
        let domain = AddressFamily::try_from(domain).map_err(|_| {
            log_unsupported!("socket(domain = {domain})");
            Errno::EINVAL
        })?;
        let (sock1, sock2) = self.do_socketpair(domain, ty, flags, protocol)?;
        sockvec
            .write_at_offset::<Platform>(0, sock1)
            .ok_or(Errno::EFAULT)?;
        sockvec
            .write_at_offset::<Platform>(1, sock2)
            .ok_or(Errno::EFAULT)?;
        Ok(())
    }
    fn do_socketpair(
        &self,
        domain: AddressFamily,
        ty: SockType,
        flags: SockFlags,
        protocol: u8,
    ) -> Result<(u32, u32), Errno> {
        let (desc1, desc2) = match domain {
            AddressFamily::UNIX => {
                let _ = UnixProtocol::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
                let (sock1, sock2) =
                    UnixSocket::new_connected_pair(ty, flags).ok_or(Errno::ESOCKTNOSUPPORT)?;
                let files = self.files.borrow();
                let mut dt = self.global.litebox.descriptor_table_mut();
                let typed1 =
                    dt.insert::<crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>(sock1);
                let typed2 =
                    dt.insert::<crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>(sock2);
                if flags.contains(SockFlags::CLOEXEC) {
                    let old = dt.set_fd_metadata(&typed1, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                    let old = dt.set_fd_metadata(&typed2, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }
                drop(dt);
                let raw_fd1 = files.insert_raw_fd(typed1).map_err(|typed| {
                    let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                    Errno::EMFILE
                })?;
                let raw_fd2 = files.insert_raw_fd(typed2).map_err(|typed| {
                    self.do_close(raw_fd1).unwrap();
                    let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                    Errno::EMFILE
                })?;
                (raw_fd1, raw_fd2)
            }
            AddressFamily::INET | AddressFamily::INET6 | AddressFamily::NETLINK => {
                return Err(Errno::EOPNOTSUPP);
            }
            _ => {
                log_unsupported!("socketpair(domain = {domain:?})");
                return Err(Errno::EAFNOSUPPORT);
            }
        };
        Ok((u32::try_from(desc1).unwrap(), u32::try_from(desc2).unwrap()))
    }
}
pub(crate) fn read_sockaddr_from_user<Platform: ShimPlatform>(
    sockaddr: UserPtr<u8>,
    addrlen: usize,
) -> Result<SocketAddress, Errno> {
    if addrlen < 2 {
        return Err(Errno::EINVAL);
    }

    let ptr: UserPtr<u16> = UserPtr::from_usize(sockaddr.as_usize());
    let family = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
    let family = AddressFamily::try_from(u32::from(family)).map_err(|_| Errno::EAFNOSUPPORT)?;
    match family {
        AddressFamily::INET => {
            if addrlen < size_of::<CSockInetAddr>() {
                return Err(Errno::EINVAL);
            }
            let ptr: UserPtr<CSockInetAddr> = UserPtr::from_usize(sockaddr.as_usize());
            // Note it reads the first 2 bytes (i.e., sa_family) again, but it is not used.
            // SocketAddrV4 only needs the port and addr.
            let inet_addr = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
            Ok(SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::from(
                inet_addr,
            ))))
        }
        AddressFamily::UNIX => {
            let path = sockaddr
                .to_owned_slice::<Platform>(addrlen)
                .ok_or(Errno::EFAULT)?;
            // skip the first two bytes (sa_family)
            let path = &path[offset_of!(CSockUnixAddr, path)..];
            if path.is_empty() {
                return Ok(SocketAddress::Unix(UnixSocketAddr::Unnamed));
            }
            if path[0] == 0 {
                return Ok(SocketAddress::Unix(UnixSocketAddr::Abstract(
                    path[1..].to_vec(),
                )));
            }
            let s = CStr::from_bytes_until_nul(path).map_err(|_| Errno::EINVAL)?;
            Ok(SocketAddress::Unix(UnixSocketAddr::Path(
                s.to_string_lossy().to_string(),
            )))
        }
        _ => todo!("unsupported family {family:?}"),
    }
}

pub(crate) fn write_sockaddr_to_user<Platform: ShimPlatform>(
    sock_addr: SocketAddress,
    addr: UserPtrMut<u8>,
    addrlen: UserPtrMut<u32>,
) -> Result<(), Errno> {
    let addrlen_val = addrlen.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
    if addrlen_val >= i32::MAX as u32 {
        return Err(Errno::EINVAL);
    }
    let len: u32 = match sock_addr {
        SocketAddress::Inet(SocketAddr::V4(v4_addr)) => {
            let addrlen_val = size_of::<CSockInetAddr>().min(addrlen_val as usize);
            let c_addr: CSockInetAddr = v4_addr.into();
            let bytes: &[u8] = c_addr.as_bytes();
            addr.write_slice_at_offset::<Platform>(0, &bytes[..addrlen_val])
                .ok_or(Errno::EFAULT)?;
            size_of::<CSockInetAddr>()
        }
        SocketAddress::Unix(v) => {
            let family_ptr = UserPtrMut::<u16>::from_usize(addr.as_usize());
            family_ptr
                .write_at_offset::<Platform>(0, AddressFamily::UNIX as u16)
                .ok_or(Errno::EFAULT)?;
            match v {
                UnixSocketAddr::Unnamed => {
                    // only write family
                    size_of::<u16>()
                }
                UnixSocketAddr::Abstract(name) => {
                    let offset = offset_of!(CSockUnixAddr, path);
                    if addrlen_val as usize > offset {
                        addr.write_at_offset::<Platform>(isize::try_from(offset).unwrap(), 0)
                            .ok_or(Errno::EFAULT)?;
                        let max_len = addrlen_val as usize - offset - 1;
                        addr.write_slice_at_offset::<Platform>(
                            isize::try_from(offset + 1).unwrap(),
                            &name[..name.len().min(max_len)],
                        )
                        .ok_or(Errno::EFAULT)?;
                    }
                    offset + 1 + name.len()
                }
                UnixSocketAddr::Path(path) => {
                    let offset = offset_of!(CSockUnixAddr, path);
                    let max_len = addrlen_val as usize - offset;
                    let name = &path.as_bytes()[..path.len().min(max_len)];
                    addr.write_slice_at_offset::<Platform>(isize::try_from(offset).unwrap(), name)
                        .ok_or(Errno::EFAULT)?;
                    let null_offset = offset + name.len();
                    // write null terminator if there is space
                    if addrlen_val as usize > null_offset {
                        addr.write_at_offset::<Platform>(isize::try_from(null_offset).unwrap(), 0)
                            .ok_or(Errno::EFAULT)?;
                    }
                    offset + path.len() + 1
                }
            }
        }
        SocketAddress::Inet(SocketAddr::V6(_)) => todo!("copy_sockaddr_to_user for IPv6"),
    }
    .trunc();
    addrlen
        .write_at_offset::<Platform>(0, len)
        .ok_or(Errno::EFAULT)
}

fn copy_iovs_to_vec<Platform: ShimPlatform>(
    iovs: &[litebox_common_linux::IoVec],
) -> Result<alloc::vec::Vec<u8>, Errno> {
    let total_len = iovs.iter().try_fold(0usize, |total_len, iov| {
        total_len.checked_add(iov.iov_len).ok_or(Errno::EINVAL)
    })?;
    let mut data = alloc::vec::Vec::new();
    data.try_reserve_exact(total_len)
        .map_err(|_| Errno::ENOMEM)?;
    data.resize(total_len, 0);
    let mut offset = 0;
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let end = offset + iov.iov_len;
        for (byte_offset, byte) in (0_isize..).zip(data[offset..end].iter_mut()) {
            *byte = iov
                .iov_base
                .read_at_offset::<Platform>(byte_offset)
                .ok_or(Errno::EFAULT)?;
        }
        offset = end;
    }
    Ok(data)
}

fn user_write_prefix<Platform: ShimPlatform>(
    page_manager: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
    ptr: UserPtrMut<u8>,
    offset: usize,
    len: usize,
) -> Result<usize, Errno> {
    let start = ptr.as_usize().checked_add(offset).ok_or(Errno::EFAULT)?;
    let end = start.checked_add(len).ok_or(Errno::EFAULT)?;
    Ok(page_manager.range_prefix_with_permissions(start..end, MemoryRegionPermissions::WRITE))
}

fn iov_write_prefix<Platform: ShimPlatform>(
    page_manager: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
    iovs: &[litebox_common_linux::IoVec],
    mut skip: usize,
    mut len: usize,
) -> Result<usize, Errno> {
    let requested = len;
    for iov in iovs {
        if skip >= iov.iov_len {
            skip -= iov.iov_len;
            continue;
        }
        let range_len = len.min(iov.iov_len - skip);
        let prefix = match user_write_prefix(page_manager, iov.iov_base, skip, range_len) {
            Ok(prefix) => prefix,
            Err(_) if len != requested => return Ok(requested - len),
            Err(error) => return Err(error),
        };
        len -= prefix;
        if prefix != range_len || len == 0 {
            return Ok(requested - len);
        }
        skip = 0;
    }
    Ok(requested - len)
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `accept`
    pub(crate) fn sys_accept(
        &self,
        sockfd: i32,
        addr: Option<UserPtrMut<u8>>,
        addrlen: Option<UserPtrMut<u32>>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let mut remote_addr = addr.is_some().then(SocketAddress::default);
        let fd = self.do_accept(sockfd, remote_addr.as_mut(), flags)?;
        if let (Some(addr), Some(remote_addr)) = (addr, remote_addr) {
            let addrlen = addrlen.ok_or(Errno::EFAULT)?;
            if let Err(err) = write_sockaddr_to_user::<Platform>(remote_addr, addr, addrlen) {
                // If we fail to write the address back to user, we need to close the accepted socket.
                self.sys_close(i32::try_from(fd).unwrap())
                    .expect("close a newly-accepted socket failed");
                return Err(err);
            }
        }
        Ok(fd)
    }
    fn do_accept(
        &self,
        sockfd: u32,
        peer: Option<&mut SocketAddress>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let files = self.files.borrow();
        let want_peer = peer.is_some();
        let (file, peer_addr) = files.with_socket(
            &self.global,
            sockfd,
            |fd| {
                let sock_type = self.global.get_socket_type(fd)?;
                let mut socket_addr =
                    want_peer.then(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
                let accepted_file =
                    self.global
                        .accept(&self.wait_cx(), fd, socket_addr.as_mut())?;
                let peer_addr = socket_addr.map(SocketAddress::Inet);

                let proxy = self
                    .global
                    .initialize_socket(&accepted_file, sock_type, flags);
                proxy.set_state(SocketState::Connected);
                let raw_fd = files
                    .insert_raw_fd(accepted_file)
                    .map_err(|accepted_file| {
                        self.global.close_unpublished_socket(&accepted_file);
                        Errno::EMFILE
                    })?;
                Ok((raw_fd, peer_addr))
            },
            |file| {
                let mut socket_addr = want_peer.then_some(UnixSocketAddr::Unnamed);
                let accepted_file = file.accept(&self.wait_cx(), flags, socket_addr.as_mut())?;
                let peer_addr = socket_addr.map(SocketAddress::Unix);
                let mut dt = self.global.litebox.descriptor_table_mut();
                let typed = dt.insert::<crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>(
                    accepted_file,
                );
                if flags.contains(SockFlags::CLOEXEC) {
                    let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }
                drop(dt);
                let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                    let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                    Errno::EMFILE
                })?;
                Ok((raw_fd, peer_addr))
            },
        )?;

        if let (Some(peer), Some(addr)) = (peer, peer_addr) {
            *peer = addr;
        }

        Ok(u32::try_from(file).unwrap())
    }

    /// Handle syscall `connect`
    pub(crate) fn sys_connect(
        &self,
        fd: i32,
        sockaddr: UserPtr<u8>,
        addrlen: usize,
    ) -> Result<(), Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = read_sockaddr_from_user::<Platform>(sockaddr, addrlen)?;
        self.do_connect(fd, sockaddr)
    }
    fn do_connect(&self, sockfd: u32, sockaddr: SocketAddress) -> Result<(), Errno> {
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                let addr = sockaddr.clone().inet().ok_or(Errno::EAFNOSUPPORT)?;
                self.global.connect(&self.wait_cx(), fd, addr)
            },
            |file| {
                let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                file.connect(self, addr)
            },
        )
    }

    /// Handle syscall `bind`
    pub(crate) fn sys_bind(
        &self,
        sockfd: i32,
        sockaddr: UserPtr<u8>,
        addrlen: usize,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = read_sockaddr_from_user::<Platform>(sockaddr, addrlen)?;
        self.do_bind(sockfd, sockaddr)
    }
    fn do_bind(&self, sockfd: u32, sockaddr: SocketAddress) -> Result<(), Errno> {
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                let addr = sockaddr.clone().inet().ok_or(Errno::EAFNOSUPPORT)?;
                self.global.bind(fd, addr)
            },
            |file| {
                let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                file.bind(self, addr)
            },
        )
    }

    /// Handle syscall `listen`
    pub(crate) fn sys_listen(&self, sockfd: i32, backlog: u16) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        self.do_listen(sockfd, backlog)
    }
    fn do_listen(&self, sockfd: u32, backlog: u16) -> Result<(), Errno> {
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| self.global.listen(fd, backlog),
            |file| file.listen(backlog, &self.global),
        )
    }

    /// Handle syscall `sendto`
    pub(crate) fn sys_sendto(
        &self,
        fd: i32,
        buf: UserPtr<u8>,
        len: usize,
        flags: SendFlags,
        addr: Option<UserPtr<u8>>,
        addrlen: u32,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = addr
            .map(|addr| read_sockaddr_from_user::<Platform>(addr, addrlen as usize))
            .transpose()?;
        let buf = buf.to_owned_slice::<Platform>(len).ok_or(Errno::EFAULT)?;
        self.do_sendto(fd, &buf, flags, sockaddr)
    }
    fn do_sendto(
        &self,
        sockfd: u32,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddress>,
    ) -> Result<usize, Errno> {
        let is_inet_datagram = core::cell::Cell::new(false);
        let res = self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                is_inet_datagram.set(matches!(
                    self.global.get_socket_type(fd)?,
                    SockType::Datagram
                ));
                let sockaddr = sockaddr
                    .clone()
                    .map(|addr| addr.inet().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                self.global
                    .sendto(&self.wait_cx(), fd, buf, flags, sockaddr)
            },
            |file| {
                let addr = sockaddr
                    .clone()
                    .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                file.sendto(self, buf, flags, addr)
            },
        );
        if let Err(Errno::EPIPE) = res
            && !flags.contains(SendFlags::NOSIGNAL)
            && !is_inet_datagram.get()
        {
            self.send_signal(Signal::SIGPIPE, signal::siginfo_kill(Signal::SIGPIPE));
        }
        res
    }

    /// Handle syscall `sendmsg`
    pub(crate) fn sys_sendmsg(
        &self,
        fd: i32,
        msg: UserPtr<litebox_common_linux::UserMsgHdr>,
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let msg = msg.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        self.do_sendmsg(fd, &msg, flags)
    }
    fn do_sendmsg(
        &self,
        sockfd: u32,
        msg: &litebox_common_linux::UserMsgHdr,
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        let msg_name = msg.msg_name;
        let sock_addr = if msg_name.as_usize() != 0 {
            Some(read_sockaddr_from_user::<Platform>(
                UserPtr::from_usize(msg_name.as_usize()),
                msg.msg_namelen as usize,
            )?)
        } else {
            None
        };
        if msg.msg_controllen != 0 {
            log_unsupported!("ancillary data is not supported");
            return Err(Errno::EINVAL);
        }
        if msg.msg_iovlen > UIO_MAXIOV {
            return Err(Errno::EMSGSIZE);
        }
        let iovs = if msg.msg_iovlen == 0 {
            None
        } else {
            Some(
                msg.msg_iov
                    .to_owned_slice::<Platform>(msg.msg_iovlen)
                    .ok_or(Errno::EFAULT)?,
            )
        };
        let is_inet_datagram = core::cell::Cell::new(false);
        let res = self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                is_inet_datagram.set(matches!(
                    self.global.get_socket_type(fd)?,
                    SockType::Datagram
                ));
                let sock_addr = sock_addr
                    .clone()
                    .map(|addr| addr.inet().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                let data = copy_iovs_to_vec::<Platform>(iovs.as_deref().unwrap_or_default())?;
                self.global
                    .sendto(&self.wait_cx(), fd, &data, flags, sock_addr)
            },
            |file| {
                let unix_addr = sock_addr
                    .clone()
                    .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                let data = copy_iovs_to_vec::<Platform>(iovs.as_deref().unwrap_or_default())?;
                file.sendto(self, &data, flags, unix_addr)
            },
        );
        if let Err(Errno::EPIPE) = res
            && !flags.contains(SendFlags::NOSIGNAL)
            && !is_inet_datagram.get()
        {
            self.send_signal(Signal::SIGPIPE, signal::siginfo_kill(Signal::SIGPIPE));
        }
        res
    }

    /// Handle syscall `sendmmsg`
    pub(crate) fn sys_sendmmsg(
        &self,
        fd: i32,
        msgvec: UserPtrMut<litebox_common_linux::UserMmsgHdr>,
        vlen: u32,
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let vlen = (vlen as usize).min(UIO_MAXIOV);

        // Linux looks up the fd before touching vlen/msgvec, so a bogus fd
        // takes priority over a bogus msgvec pointer or vlen == 0.
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |_| Ok::<(), Errno>(()),
            |_| Ok::<(), Errno>(()),
        )?;

        if vlen == 0 {
            return Ok(0);
        }

        let stride = core::mem::size_of::<litebox_common_linux::UserMmsgHdr>();
        let msg_len_off = core::mem::offset_of!(litebox_common_linux::UserMmsgHdr, msg_len);

        let mut sent: usize = 0;
        for i in 0..vlen {
            let bail = |e: Errno| if sent > 0 { Ok(sent) } else { Err(e) };
            let Some(mmh) = msgvec.read_at_offset::<Platform>(isize::try_from(i).unwrap()) else {
                return bail(Errno::EFAULT);
            };
            let inner = mmh.msg_hdr;
            let n = match self.do_sendmsg(sockfd, &inner, flags) {
                Ok(n) => n,
                Err(e) => return bail(e),
            };
            let msg_len_ptr =
                UserPtrMut::<u32>::from_usize(msgvec.as_usize() + i * stride + msg_len_off);
            if msg_len_ptr
                .write_at_offset::<Platform>(0, n.trunc())
                .is_none()
            {
                return bail(Errno::EFAULT);
            }
            sent += 1;
        }
        Ok(sent)
    }

    /// Handle syscall `recvfrom`
    pub(crate) fn sys_recvfrom(
        &self,
        fd: i32,
        buf: UserPtrMut<u8>,
        len: usize,
        flags: ReceiveFlags,
        addr: Option<UserPtrMut<u8>>,
        addrlen: UserPtrMut<u32>,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, sockfd)?;
        let (chunk_waitall, preflight_stream, deadline) =
            self.inet_stream_receive_plan(&socket, flags)?;
        let copy_received = Self::receive_copies_data(&socket, flags);
        let mut source_addr = None;
        let scratch_len = len.min(SOCKET_RECEIVE_OPERATION_SIZE);
        let mut buffer = alloc::vec::Vec::new();
        buffer
            .try_reserve_exact(scratch_len)
            .map_err(|_| Errno::ENOMEM)?;
        buffer.resize(scratch_len, 0);
        let mut received = 0;
        let reported = loop {
            let requested_chunk_len = (len - received).min(buffer.len());
            let write_prefix = (preflight_stream && copy_received && requested_chunk_len != 0)
                .then(|| user_write_prefix(&self.global.pm, buf, received, requested_chunk_len));
            let needs_probe = write_prefix.as_ref().is_some_and(
                |prefix| !matches!(prefix, Ok(prefix) if *prefix == requested_chunk_len),
            );
            let data_available = if needs_probe {
                self.probe_receive(&socket, flags, deadline, received != 0)?
            } else {
                true
            };
            if !data_available {
                break received;
            }
            let chunk_len = match write_prefix {
                None => requested_chunk_len,
                Some(prefix) => {
                    let prefix = prefix?;
                    if prefix == 0 && requested_chunk_len != 0 {
                        return if received == 0 {
                            Err(Errno::EFAULT)
                        } else {
                            Ok(received)
                        };
                    }
                    prefix
                }
            };
            let (size, copy_received) = self.do_recvfrom_with_copy(
                &socket,
                &mut buffer[..chunk_len],
                flags,
                deadline,
                received != 0,
                if addr.is_some() {
                    Some(&mut source_addr)
                } else {
                    None
                },
            )?;
            let copied = size.min(chunk_len);
            if copy_received
                && buf
                    .copy_from_slice::<Platform>(received, &buffer[..copied])
                    .is_none()
            {
                return if received == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(received)
                };
            }
            received += copied;
            let reported = if chunk_waitall { received } else { size };
            if !chunk_waitall || copied < chunk_len || received == len {
                break reported;
            }
        };
        if let Some(src_addr) = source_addr
            && let Some(sock_ptr) = addr
        {
            write_sockaddr_to_user::<Platform>(src_addr, sock_ptr, addrlen)?;
        }

        if flags.contains(ReceiveFlags::TRUNC) {
            // the actual message size
            Ok(reported)
        } else {
            // the number of bytes copied
            Ok(received)
        }
    }

    fn inet_stream_receive_plan(
        &self,
        socket: &ReceiveSocket<'_, Platform, FS>,
        flags: ReceiveFlags,
    ) -> Result<(bool, bool, Option<Platform::Instant>), Errno> {
        match socket {
            ReceiveSocket::Inet(socket) => {
                let is_nonblock = socket.is_nonblock || flags.contains(ReceiveFlags::DONTWAIT);
                let is_stream = matches!(socket.socket_type, SockType::Stream);
                let chunk_waitall = flags.contains(ReceiveFlags::WAITALL)
                    && !flags.contains(ReceiveFlags::PEEK)
                    && is_stream
                    && !is_nonblock;
                let deadline = socket
                    .recv_timeout
                    .map(|timeout| {
                        self.global
                            .platform
                            .now()
                            .checked_add(timeout)
                            .ok_or(Errno::EINVAL)
                    })
                    .transpose()?;
                Ok((chunk_waitall, is_stream, deadline))
            }
            ReceiveSocket::Unix(handle) => handle.with_entry(|entry| {
                let deadline = entry
                    .recv_timeout()
                    .map(|timeout| {
                        self.global
                            .platform
                            .now()
                            .checked_add(timeout)
                            .ok_or(Errno::EINVAL)
                    })
                    .transpose()?;
                Ok((false, entry.is_stream(), deadline))
            }),
        }
    }

    fn receive_copies_data(socket: &ReceiveSocket<'_, Platform, FS>, flags: ReceiveFlags) -> bool {
        if !flags.contains(ReceiveFlags::TRUNC) {
            return true;
        }
        match socket {
            ReceiveSocket::Inet(socket) => !matches!(socket.socket_type, SockType::Stream),
            ReceiveSocket::Unix(_) => true,
        }
    }

    fn probe_receive(
        &self,
        socket: &ReceiveSocket<'_, Platform, FS>,
        flags: ReceiveFlags,
        deadline: Option<Platform::Instant>,
        outer_partial: bool,
    ) -> Result<bool, Errno> {
        let mut probe = [0];
        self.do_recvfrom_with_copy(
            socket,
            &mut probe,
            flags | ReceiveFlags::PEEK,
            deadline,
            outer_partial,
            None,
        )
        .map(|(size, _)| size != 0)
    }

    /// Receive data from a socket.
    ///
    /// `source_addr` can be provided to receive the source address if available.
    ///
    /// On success, returns the number of bytes received. Note that for datagram sockets,
    /// this may be larger than the provided buffer length as the excessive data will be truncated.
    #[cfg(test)]
    fn do_recvfrom(
        &self,
        sockfd: u32,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, sockfd)?;
        self.do_recvfrom_with_copy(&socket, buf, flags, None, false, source_addr)
            .map(|(size, _)| size)
    }

    fn do_recvfrom_with_copy(
        &self,
        socket: &ReceiveSocket<'_, Platform, FS>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        deadline: Option<Platform::Instant>,
        outer_partial: bool,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<(usize, bool), Errno> {
        let want_source = source_addr.is_some();
        let (size, addr, copy_received) = match socket {
            ReceiveSocket::Inet(socket) => {
                let mut addr = None;
                let size = self.global.receive_from_socket(
                    &self.wait_cx(),
                    socket,
                    buf,
                    flags,
                    ReceiveContext::new(deadline, outer_partial),
                    if want_source { Some(&mut addr) } else { None },
                )?;
                let src_addr = addr.map(SocketAddress::Inet);
                let copy_received = !(flags.contains(ReceiveFlags::TRUNC)
                    && matches!(socket.socket_type, SockType::Stream));
                (size, src_addr, copy_received)
            }
            ReceiveSocket::Unix(handle) => handle.with_entry(|entry| {
                let mut addr = None;
                let timeout = deadline.map(|deadline| {
                    deadline
                        .checked_duration_since(&self.global.platform.now())
                        .unwrap_or(core::time::Duration::ZERO)
                });
                let size = entry.recvfrom(
                    &self.wait_cx(),
                    buf,
                    flags,
                    timeout,
                    if want_source { Some(&mut addr) } else { None },
                )?;
                let src_addr = addr.map(SocketAddress::Unix);
                Ok::<_, Errno>((size, src_addr, true))
            })?,
        };

        if let (Some(source_addr), Some(addr)) = (source_addr, addr) {
            *source_addr = Some(addr);
        }
        Ok((size, copy_received))
    }

    /// Handle syscall `recvmsg`
    pub(crate) fn sys_recvmsg(
        &self,
        fd: i32,
        msg_ptr: UserPtrMut<litebox_common_linux::UserMsgHdr>,
        flags: ReceiveFlags,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let supported_flags = ReceiveFlags::DONTWAIT
            | ReceiveFlags::PEEK
            | ReceiveFlags::TRUNC
            | ReceiveFlags::WAITALL;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvmsg flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }

        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, sockfd)?;
        self.do_recvmsg(&socket, msg_ptr, flags)
    }
    fn do_recvmsg(
        &self,
        socket: &ReceiveSocket<'_, Platform, FS>,
        msg_ptr: UserPtrMut<litebox_common_linux::UserMsgHdr>,
        flags: ReceiveFlags,
    ) -> Result<usize, Errno> {
        let msg = msg_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;

        // Copy fields out of the packed struct to avoid unaligned references.
        let msg_name = msg.msg_name;
        let msg_iov = msg.msg_iov;
        let msg_iovlen = msg.msg_iovlen;
        let msg_controllen = msg.msg_controllen;

        if msg_controllen != 0 {
            log_unsupported!("ancillary data is not supported");
        }
        if msg_iovlen > UIO_MAXIOV {
            return Err(Errno::EMSGSIZE);
        }

        let iovs = msg_iov
            .to_owned_slice::<Platform>(msg_iovlen)
            .ok_or(Errno::EFAULT)?;

        let total_iov_capacity = iovs.iter().try_fold(0usize, |capacity, iov| {
            capacity.checked_add(iov.iov_len).ok_or(Errno::EINVAL)
        })?;

        let want_source = msg_name.as_usize() != 0;
        let mut source_addr = None;
        let mut ret_flags = ReceiveFlags::empty();
        let (chunk_waitall, preflight_stream, deadline) =
            self.inet_stream_receive_plan(socket, flags)?;
        let copy_received = Self::receive_copies_data(socket, flags);

        // Keep the scratch allocation bounded and scatter each completed chunk.
        let mut buffer = alloc::vec::Vec::new();
        let receive_capacity = total_iov_capacity.min(SOCKET_RECEIVE_OPERATION_SIZE);
        buffer
            .try_reserve_exact(receive_capacity)
            .map_err(|_| Errno::ENOMEM)?;
        buffer.resize(receive_capacity, 0);
        let mut total_received = 0;
        let reported = 'receive: loop {
            let requested_chunk_len = (total_iov_capacity - total_received).min(buffer.len());
            let write_prefix = (preflight_stream && copy_received && requested_chunk_len != 0)
                .then(|| {
                    iov_write_prefix(&self.global.pm, &iovs, total_received, requested_chunk_len)
                });
            let needs_probe = write_prefix.as_ref().is_some_and(
                |prefix| !matches!(prefix, Ok(prefix) if *prefix == requested_chunk_len),
            );
            let data_available = if needs_probe {
                self.probe_receive(socket, flags, deadline, total_received != 0)?
            } else {
                true
            };
            if !data_available {
                break 'receive total_received;
            }
            let chunk_len = match write_prefix {
                None => requested_chunk_len,
                Some(prefix) => {
                    let prefix = prefix?;
                    if prefix == 0 && requested_chunk_len != 0 {
                        if total_received == 0 {
                            return Err(Errno::EFAULT);
                        }
                        break 'receive total_received;
                    }
                    prefix
                }
            };
            let (size, copy_received) = self.do_recvfrom_with_copy(
                socket,
                &mut buffer[..chunk_len],
                flags,
                deadline,
                total_received != 0,
                if want_source {
                    Some(&mut source_addr)
                } else {
                    None
                },
            )?;
            if size > chunk_len {
                ret_flags.insert(ReceiveFlags::TRUNC);
            }
            let copied = size.min(chunk_len);
            if copy_received {
                let mut skip = total_received;
                let mut source_offset = 0;
                for iov in &iovs {
                    if skip >= iov.iov_len {
                        skip -= iov.iov_len;
                        continue;
                    }
                    let chunk = (copied - source_offset).min(iov.iov_len - skip);
                    if iov
                        .iov_base
                        .copy_from_slice::<Platform>(
                            skip,
                            &buffer[source_offset..source_offset + chunk],
                        )
                        .is_none()
                    {
                        let copied_before_fault = total_received + source_offset;
                        if copied_before_fault == 0 {
                            return Err(Errno::EFAULT);
                        }
                        total_received = copied_before_fault;
                        break 'receive copied_before_fault;
                    }
                    source_offset += chunk;
                    skip = 0;
                    if source_offset == copied {
                        break;
                    }
                }
            }
            total_received += copied;
            let reported = if chunk_waitall { total_received } else { size };
            if !chunk_waitall || copied < chunk_len || total_received == total_iov_capacity {
                break reported;
            }
        };
        if flags.contains(ReceiveFlags::TRUNC) {
            total_received = reported;
        }

        // Write back source address if requested.
        if want_source {
            let addrlen_ptr = UserPtrMut::<u32>::from_usize(
                msg_ptr.as_usize()
                    + core::mem::offset_of!(litebox_common_linux::UserMsgHdr, msg_namelen),
            );
            if let Some(src_addr) = source_addr {
                write_sockaddr_to_user::<Platform>(src_addr, msg_name, addrlen_ptr)?;
            } else {
                // No source address (e.g. connected stream socket) — zero out msg_namelen.
                addrlen_ptr
                    .write_at_offset::<Platform>(0, 0u32)
                    .ok_or(Errno::EFAULT)?;
            }
        }

        // Ancillary data is not supported, so report that no control bytes were delivered.
        let controllen_offset =
            core::mem::offset_of!(litebox_common_linux::UserMsgHdr, msg_controllen);
        let controllen_ptr =
            UserPtrMut::<usize>::from_usize(msg_ptr.as_usize() + controllen_offset);
        controllen_ptr
            .write_at_offset::<Platform>(0, 0)
            .ok_or(Errno::EFAULT)?;

        // Write back msg_flags with any status flags (e.g. MSG_TRUNC).
        let flags_offset = core::mem::offset_of!(litebox_common_linux::UserMsgHdr, msg_flags);
        let flags_ptr = UserPtrMut::<ReceiveFlags>::from_usize(msg_ptr.as_usize() + flags_offset);
        flags_ptr
            .write_at_offset::<Platform>(0, ret_flags)
            .ok_or(Errno::EFAULT)?;

        Ok(total_received)
    }

    /// Handle syscall `recvmmsg`
    pub(crate) fn sys_recvmmsg(
        &self,
        fd: i32,
        msgvec: UserPtrMut<litebox_common_linux::UserMmsgHdr>,
        vlen: u32,
        flags: ReceiveFlags,
        timeout: litebox_common_linux::TimeParam,
    ) -> Result<usize, Errno> {
        let supported_flags = ReceiveFlags::DONTWAIT
            | ReceiveFlags::PEEK
            | ReceiveFlags::TRUNC
            | ReceiveFlags::WAITALL
            | ReceiveFlags::WAITFORONE;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvmmsg flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }

        // Linux's `do_recvmmsg` validates the timespec before looking up the fd,
        // so a bad timeout takes precedence over EBADF.
        let timeout_duration = timeout.read::<Platform>()?;

        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let vlen = vlen as usize;

        // Linux looks up the fd before touching vlen/msgvec, so a bogus fd
        // takes priority over a bogus msgvec pointer or vlen == 0.
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, sockfd)?;

        if vlen == 0 {
            return Ok(0);
        }

        // A `None` deadline means either no user-supplied timeout or a saturating overflow
        // — both are treated as "no deadline".
        let deadline = timeout_duration.and_then(|d| self.global.platform.now().checked_add(d));
        let stride = size_of::<UserMmsgHdr>();
        let msg_len_off = offset_of!(UserMmsgHdr, msg_len);
        let msgvec_base = msgvec.as_usize();
        let msgvec_len = vlen.checked_mul(stride).ok_or(Errno::EFAULT)?;
        if msgvec_base.checked_add(msgvec_len).is_none() {
            return Err(Errno::EFAULT);
        }

        let _recvmmsg = if vlen <= 1 {
            None
        } else {
            match &socket {
                ReceiveSocket::Inet(socket)
                    if flags.contains(ReceiveFlags::DONTWAIT) || socket.is_nonblock =>
                {
                    Some(socket.recvmmsg_lock.0.try_lock().ok_or(Errno::EAGAIN)?)
                }
                ReceiveSocket::Inet(socket) => {
                    let wait_cx = self.wait_cx().with_deadline(deadline);
                    Some(socket.recvmmsg_lock.0.lock_interruptibly(&wait_cx)?)
                }
                ReceiveSocket::Unix(_) => None,
            }
        };

        // WAITFORONE is mmsg-only; the inner recvmsg doesn't recognize it.
        let waitforone = flags.contains(ReceiveFlags::WAITFORONE);
        let mut iter_flags = flags.difference(ReceiveFlags::WAITFORONE);
        let mut received: usize = 0;
        let mut last_err: Option<Errno> = None;
        let mut async_error_to_restore = None;
        for i in 0..vlen {
            let base = msgvec_base + i * stride;
            let inner_ptr = UserPtrMut::<UserMsgHdr>::from_usize(base);
            let n = match self.do_recvmsg(&socket, inner_ptr, iter_flags) {
                Ok(n) => n,
                Err(e) => {
                    if received > 0 {
                        async_error_to_restore = e.try_into().ok();
                    }
                    last_err = Some(e);
                    break;
                }
            };
            let msg_len_ptr = UserPtrMut::<u32>::from_usize(base + msg_len_off);
            if msg_len_ptr
                .write_at_offset::<Platform>(0, n.trunc())
                .is_none()
            {
                last_err = Some(Errno::EFAULT);
                break;
            }
            received += 1;
            if waitforone {
                iter_flags.insert(ReceiveFlags::DONTWAIT);
            }

            // Per the man page, the timeout is checked only after the receipt of each datagram.
            if let Some(deadline) = deadline
                && self.global.platform.now() >= deadline
            {
                break;
            }
        }

        if received == 0 {
            // The only way to exit the loop with received=0 is via an inner
            // recvmsg error; EAGAIN is the conservative fallback for the
            // structurally unreachable case.
            return Err(last_err.unwrap_or(Errno::EAGAIN));
        }

        // Stash the suppressed async socket error back onto the socket.
        if let (Some(async_error), ReceiveSocket::Inet(socket)) = (async_error_to_restore, &socket)
        {
            socket.proxy.set_async_error(async_error);
        }

        // Match Linux's `__sys_recvmmsg`: the remaining timespec is only
        // written back when at least one datagram was received. A write
        // EFAULT here overrides the success return, mirroring Linux.
        let remaining = deadline
            .and_then(|d| d.checked_duration_since(&self.global.platform.now()))
            .unwrap_or(core::time::Duration::ZERO);
        timeout.write::<Platform>(remaining)?;

        Ok(received)
    }

    pub(crate) fn sys_setsockopt(
        &self,
        sockfd: i32,
        level: u32,
        optname: u32,
        optval: UserPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            log_unsupported!("setsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        })?;
        self.do_setsockopt(sockfd, optname, optval, optlen)
    }
    fn do_setsockopt(
        &self,
        sockfd: u32,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| self.global.setsockopt(fd, optname, optval, optlen),
            |file| file.setsockopt(&self.global, optname, optval, optlen),
        )
    }

    /// Handle syscall `getsockopt`
    pub(crate) fn sys_getsockopt(
        &self,
        sockfd: i32,
        level: u32,
        optname: u32,
        optval: UserPtrMut<u8>,
        optlen: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            log_unsupported!("setsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        })?;
        let len = optlen.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        if len > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        let new_len = self.do_getsockopt(sockfd, optname, optval, len)?;
        optlen
            .write_at_offset::<Platform>(0, new_len.trunc())
            .ok_or(Errno::EFAULT)?;
        Ok(())
    }
    /// Actual implementation of `getsockopt`
    ///
    /// Returns the length of the option value written to `optval` on success.
    fn do_getsockopt(
        &self,
        sockfd: u32,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| self.global.getsockopt(fd, optname, optval, len),
            |file| file.getsockopt(&self.global, optname, optval, len),
        )
    }

    /// Handle syscall `getsockname`
    pub(crate) fn sys_getsockname(
        &self,
        sockfd: i32,
        addr: UserPtrMut<u8>,
        addrlen: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = self.do_getsockname(sockfd)?;
        write_sockaddr_to_user::<Platform>(sockaddr, addr, addrlen)
    }
    fn do_getsockname(&self, sockfd: u32) -> Result<SocketAddress, Errno> {
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                self.global
                    .net
                    .lock()
                    .get_local_addr(fd)
                    .map(SocketAddress::Inet)
                    .map_err(Errno::from)
            },
            |unix| Ok(SocketAddress::Unix(unix.get_local_addr())),
        )
    }

    /// Handle syscall `getpeername`
    pub(crate) fn sys_getpeername(
        &self,
        sockfd: i32,
        addr: UserPtrMut<u8>,
        addrlen: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = self.do_getpeername(sockfd)?;
        write_sockaddr_to_user::<Platform>(sockaddr, addr, addrlen)
    }
    fn do_getpeername(&self, sockfd: u32) -> Result<SocketAddress, Errno> {
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                self.global
                    .net
                    .lock()
                    .get_remote_addr(fd)
                    .map(SocketAddress::Inet)
                    .map_err(Errno::from)
            },
            |file| {
                file.get_peer_addr()
                    .ok_or(Errno::ENOTCONN)
                    .map(SocketAddress::Unix)
            },
        )
    }

    /// Handle syscall `shutdown`
    pub(crate) fn sys_shutdown(&self, sockfd: i32, how: i32) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        self.do_shutdown(sockfd, how)
    }
    fn do_shutdown(&self, sockfd: u32, how: i32) -> Result<(), Errno> {
        // Linux validates the fd (EBADF, ENOTSOCK) before `how` (EINVAL),
        // so resolve the socket through `with_socket` first and validate `how`
        // only inside the matching branch.
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                let how = ShutdownHow::try_from(how).map_err(|_| Errno::EINVAL)?;
                let direction = match how {
                    ShutdownHow::Read => litebox::net::ShutdownDirection::Read,
                    ShutdownHow::Write => litebox::net::ShutdownDirection::Write,
                    ShutdownHow::Both => litebox::net::ShutdownDirection::Both,
                };
                let network = self.global.net.lock();
                match network.shutdown(fd, direction) {
                    Err(litebox::net::errors::ShutdownError::Listening) => match how {
                        ShutdownHow::Read | ShutdownHow::Both => {
                            network.stop_listening(fd).map_err(Errno::from)
                        }
                        ShutdownHow::Write => Ok(()),
                    },
                    result => result.map_err(Errno::from),
                }
            },
            |file| {
                let how = ShutdownHow::try_from(how).map_err(|_| Errno::EINVAL)?;
                file.shutdown(how);
                Ok(())
            },
        )
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    type TestTask = crate::Task<
        crate::syscalls::tests::TestPlatform,
        crate::DefaultFS<crate::syscalls::tests::TestPlatform>,
    >;

    use alloc::string::ToString as _;
    use litebox::utils::TruncateExt as _;
    use litebox_common_linux::{
        AddressFamily, MapFlags, ProtFlags, ReceiveFlags, SendFlags, SockFlags, SockType,
        SocketOption, SocketOptionName, errno::Errno,
    };
    use zerocopy::FromZeros as _;

    use super::SocketAddress;
    use crate::{
        UserPtr, UserPtrMut,
        syscalls::{
            net::{CSockInetAddr, read_sockaddr_from_user},
            tests::init_platform,
        },
    };

    extern crate alloc;
    extern crate std;

    // Compile-time layout check: UserMsgHdr must match Linux's struct user_msghdr.
    const _USER_MSG_HDR_SIZE: () = assert!(
        core::mem::size_of::<litebox_common_linux::UserMsgHdr>()
            == core::mem::size_of::<libc::msghdr>()
    );

    const LOOPBACK_IP_ADDR: [u8; 4] = [127, 0, 0, 1];
    const LOOPBACK_IP_ADDR_STR: &str = "127.0.0.1";

    fn find_free_tcp_port() -> u16 {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("failed to reserve TCP port")
            .local_addr()
            .unwrap()
            .port()
    }

    fn find_free_udp_port() -> u16 {
        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("failed to reserve UDP port")
            .local_addr()
            .unwrap()
            .port()
    }

    fn close_socket(task: &TestTask, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn dropping_inet_socket_pin_reaps_deferred_close() {
        let task = init_platform();
        let fd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .unwrap();
        let socket = task
            .files
            .borrow()
            .pin_receive_socket(&task.global, fd)
            .unwrap();
        let state = match &socket {
            super::ReceiveSocket::Inet(socket) => socket.state.clone(),
            super::ReceiveSocket::Unix(_) => unreachable!(),
        };

        close_socket(&task, fd);
        assert!(
            state.0.load(core::sync::atomic::Ordering::Acquire) & super::SOCKET_IO_CLOSE_PENDING
                != 0
        );

        drop(socket);
        assert_eq!(state.0.load(core::sync::atomic::Ordering::Acquire), 0);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn socket_io_pin_keeps_backend_alive_for_send_after_close() {
        let task = init_platform();
        let fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::NONBLOCK,
                0,
            )
            .unwrap();
        let socket = task
            .files
            .borrow()
            .pin_receive_socket(&task.global, fd)
            .unwrap();
        let state = match &socket {
            super::ReceiveSocket::Inet(socket) => socket.state.clone(),
            super::ReceiveSocket::Unix(_) => unreachable!(),
        };

        close_socket(&task, fd);
        assert!(
            state.0.load(core::sync::atomic::Ordering::Acquire) & super::SOCKET_IO_CLOSE_PENDING
                != 0
        );
        let result = match &socket {
            super::ReceiveSocket::Inet(socket) => task.global.send_to_pinned_socket(
                &task.wait_cx(),
                socket,
                b"pinned",
                SendFlags::empty(),
            ),
            super::ReceiveSocket::Unix(_) => unreachable!(),
        };
        assert_eq!(result, Err(Errno::EDESTADDRREQ));

        drop(socket);
        assert_eq!(state.0.load(core::sync::atomic::Ordering::Acquire), 0);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn raw_inet_socket_pin_does_not_follow_dup2_replacement() {
        let task = init_platform();
        let old_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::NONBLOCK,
                0,
            )
            .unwrap();
        let new_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::NONBLOCK,
                0,
            )
            .unwrap();
        let old_socket = task
            .files
            .borrow()
            .try_pin_inet_socket(&task.global, old_fd as usize)
            .unwrap()
            .unwrap();
        let old_state = old_socket.state.clone();
        let new_socket = task
            .files
            .borrow()
            .try_pin_inet_socket(&task.global, new_fd as usize)
            .unwrap()
            .unwrap();

        assert_eq!(
            task.sys_dup(
                new_fd.try_into().unwrap(),
                Some(old_fd.try_into().unwrap()),
                None,
            )
            .unwrap(),
            old_fd
        );
        assert!(
            old_state.0.load(core::sync::atomic::Ordering::Acquire)
                & super::SOCKET_IO_CLOSE_PENDING
                != 0
        );
        let replacement = task
            .files
            .borrow()
            .try_pin_inet_socket(&task.global, old_fd as usize)
            .unwrap()
            .unwrap();
        assert!(alloc::sync::Arc::ptr_eq(
            &replacement.proxy,
            &new_socket.proxy
        ));
        assert!(!alloc::sync::Arc::ptr_eq(
            &replacement.proxy,
            &old_socket.proxy
        ));

        drop(old_socket);
        assert_eq!(old_state.0.load(core::sync::atomic::Ordering::Acquire), 0);
        drop(replacement);
        drop(new_socket);
        close_socket(&task, old_fd);
        close_socket(&task, new_fd);
    }

    #[test]
    fn recvmmsg_lock_wakes_contended_waiter() {
        let task = init_platform();
        let lock = alloc::sync::Arc::new(super::RecvmmsgLock::new());
        let guard = lock.try_lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let worker_lock = alloc::sync::Arc::clone(&lock);
        task.spawn_clone_for_test(move |task| {
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
    }

    #[test]
    fn recvmmsg_lock_honors_wait_deadline() {
        let task = init_platform();
        let lock = super::RecvmmsgLock::new();
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

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
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

    /// Helper to read SO_ERROR from a socket via getsockopt.
    /// Returns the errno integer value (0 means no error).
    fn get_so_error(task: &TestTask, sockfd: u32) -> u32 {
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
        let ev = litebox_common_linux::EpollEvent {
            events: events.bits(),
            data: u64::from(target_fd),
        };
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
        ip: [u8; 4],
        port: u16,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &'static str,
    ) {
        let server = task
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
        let server_sockaddr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(ip),
            port,
        )));
        task.do_bind(server, server_sockaddr.clone())
            .expect("Failed to bind socket");
        task.do_listen(server, 1)
            .expect("Failed to listen on socket");

        // Create an epoll instance and register the server fd for EPOLLIN
        let epfd = task
            .sys_epoll_create(litebox_common_linux::EpollCreateFlags::empty())
            .expect("failed to create epoll");
        let epfd = i32::try_from(epfd).unwrap();
        epoll_add(task, epfd, server, litebox::event::Events::IN);

        let buf = "Hello, world!";
        let child_handle = std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(200)); // Give server time to start
            let port = port.to_string();
            match option {
                "sendto" | "sendmsg" => std::process::Command::new("nc")
                    .args([
                        "-w", // timeout for connects and final net reads
                        "1",
                        LOOPBACK_IP_ADDR_STR,
                        &port,
                    ])
                    .stdout(std::process::Stdio::piped())
                    .output(),
                "recvfrom" | "recvmsg" => std::process::Command::new("sh")
                    .args([
                        "-c",
                        &alloc::format!("echo -n '{buf}' | nc -w 1 {LOOPBACK_IP_ADDR_STR} {port}"),
                    ])
                    .output(),
                _ => panic!("Unknown option"),
            }
        });

        if is_nonblocking {
            // wait on epoll for server to be readable (incoming connection)
            let mut events = [litebox_common_linux::EpollEvent { events: 0, data: 0 }; 2];
            let n = epoll_wait(task, epfd, &mut events);
            assert_eq!(n, 1);
            for ev in &events[..n] {
                let events = ev.events;
                assert!(events & litebox::event::Events::IN.bits() != 0);
            }
        }

        let mut remote_addr = super::SocketAddress::default();
        let client_fd = task
            .do_accept(
                server,
                Some(&mut remote_addr),
                if is_nonblocking {
                    SockFlags::NONBLOCK
                } else {
                    SockFlags::empty()
                },
            )
            .expect("Failed to accept connection");
        assert_eq!(server_sockaddr, task.do_getsockname(client_fd).unwrap());
        assert_eq!(remote_addr, task.do_getpeername(client_fd).unwrap());
        let super::SocketAddress::Inet(SocketAddr::V4(remote_addr)) = remote_addr else {
            panic!("Expected IPv4 address");
        };
        assert_eq!(remote_addr.ip().octets(), LOOPBACK_IP_ADDR);
        assert_ne!(remote_addr.port(), 0);

        match option {
            "sendto" => {
                let n = task
                    .do_sendto(client_fd, buf.as_bytes(), SendFlags::empty(), None)
                    .expect("Failed to send data");
                assert_eq!(n, buf.len());
                let output = child_handle
                    .join()
                    .unwrap()
                    .expect("Failed to wait for client");
                let stdout = alloc::string::String::from_utf8_lossy(&output.stdout);
                assert_eq!(stdout, buf);
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
                    task.do_sendmsg(client_fd, &hdr, SendFlags::empty())
                        .expect("Failed to sendmsg"),
                    buf1.len() + buf2.len()
                );
                let output = child_handle
                    .join()
                    .unwrap()
                    .expect("Failed to wait for client");
                let stdout = alloc::string::String::from_utf8_lossy(&output.stdout);
                assert_eq!(stdout, alloc::format!("{buf1}{buf2}"));
            }
            "recvfrom" | "recvmsg" => {
                if is_nonblocking {
                    epoll_add(task, epfd, client_fd, litebox::event::Events::IN);
                    let mut events = [litebox_common_linux::EpollEvent { events: 0, data: 0 }; 2];
                    let n = epoll_wait(task, epfd, &mut events);
                    for ev in &events[..n] {
                        assert!(ev.events & litebox::event::Events::IN.bits() != 0);
                        let fd = u32::try_from(ev.data).unwrap();
                        assert_eq!(fd, client_fd);
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
                        .do_recvfrom(client_fd, &mut recv_buf, flags, None)
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
                            .sys_recvmsg(i32::try_from(client_fd).unwrap(), msg_ptr, flags)
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
                let _ = child_handle.join().expect("Failed to wait for client");
            }
            _ => panic!("Unknown option"),
        }

        close_socket(task, client_fd);
        close_socket(task, server);
    }

    fn test_tcp_socket_with_external_client(is_nonblocking: bool, test_trunc: bool) {
        let task = init_platform();
        test_tcp_socket_as_server(
            &task,
            LOOPBACK_IP_ADDR,
            find_free_tcp_port(),
            is_nonblocking,
            test_trunc,
            "recvfrom",
        );
        test_tcp_socket_as_server(
            &task,
            LOOPBACK_IP_ADDR,
            find_free_tcp_port(),
            is_nonblocking,
            test_trunc,
            "recvmsg",
        );
    }

    fn test_tcp_socket_send(is_nonblocking: bool, test_trunc: bool) {
        let task = init_platform();
        test_tcp_socket_as_server(
            &task,
            LOOPBACK_IP_ADDR,
            find_free_tcp_port(),
            is_nonblocking,
            test_trunc,
            "sendto",
        );
        test_tcp_socket_as_server(
            &task,
            LOOPBACK_IP_ADDR,
            find_free_tcp_port(),
            is_nonblocking,
            test_trunc,
            "sendmsg",
        );
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_blocking_send_tcp_socket() {
        test_tcp_socket_send(false, false);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_nonblocking_send_tcp_socket() {
        test_tcp_socket_send(true, false);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_blocking_recvfrom_tcp_socket() {
        test_tcp_socket_with_external_client(false, false);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_nonblocking_recvfrom_tcp_socket() {
        test_tcp_socket_with_external_client(true, false);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_blocking_recvfrom_tcp_socket_with_truncation() {
        test_tcp_socket_with_external_client(false, true);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_tcp_connection_refused() {
        let task = init_platform();
        let port = find_free_tcp_port();
        let socket_fd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create socket");
        let socket_fd2 = task
            .sys_dup(i32::try_from(socket_fd).unwrap(), None, None)
            .unwrap();

        close_socket(&task, socket_fd);
        let err = task
            .do_connect(
                socket_fd2,
                SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
                    core::net::Ipv4Addr::from(LOOPBACK_IP_ADDR),
                    port,
                ))),
            )
            .unwrap_err();
        assert_eq!(err, litebox_common_linux::errno::Errno::ECONNREFUSED);

        let so_err = get_so_error(&task, socket_fd2);
        assert_eq!(so_err, i32::from(Errno::ECONNREFUSED).cast_unsigned());

        // Second read should be cleared (self-clearing semantics)
        assert_eq!(get_so_error(&task, socket_fd2), 0);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_tcp_socket_as_client() {
        let task = init_platform();
        let port = find_free_tcp_port();

        let child_handle = std::thread::spawn(move || {
            let port = port.to_string();
            std::process::Command::new("nc")
                .args(["-w", "1", "-l", LOOPBACK_IP_ADDR_STR, &port])
                .output()
        });
        std::thread::sleep(core::time::Duration::from_secs(1));

        // Client socket
        let client_fd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create client socket");

        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(LOOPBACK_IP_ADDR),
            port,
        )));
        task.do_connect(client_fd, server_addr)
            .expect("failed to connect to server");
        let so_error = get_so_error(&task, client_fd);
        assert_eq!(
            so_error, 0,
            "SO_ERROR should be 0 after successful connect, got {so_error}"
        );

        let buf = "Hello, world!";
        let n = task
            .do_sendto(client_fd, buf.as_bytes(), SendFlags::empty(), None)
            .unwrap();
        assert_eq!(n, buf.len());

        close_socket(&task, client_fd);

        let output = child_handle
            .join()
            .unwrap()
            .expect("Failed to wait for client");
        let stdout = alloc::string::String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout, buf);
    }

    fn blocking_udp_server_socket(
        task: &TestTask,
        test_trunc: bool,
        set_trunc_flag: bool,
        is_nonblocking: bool,
        op: &str,
    ) {
        let server_port = find_free_udp_port();
        let client_port = find_free_udp_port();

        // Server socket and bind
        let server_fd = task
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
        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(LOOPBACK_IP_ADDR),
            server_port,
        )));
        task.do_bind(server_fd, server_addr.clone())
            .expect("failed to bind server");
        assert_eq!(
            server_addr,
            task.do_getsockname(server_fd).expect("getsockname failed")
        );

        // Create an epoll instance and register the server fd for EPOLLIN
        let epfd = task
            .sys_epoll_create(litebox_common_linux::EpollCreateFlags::empty())
            .expect("failed to create epoll");
        let epfd = i32::try_from(epfd).unwrap();
        epoll_add(task, epfd, server_fd, litebox::event::Events::IN);

        let msg = "Hello from client";
        let mut child = std::process::Command::new("nc")
            .args([
                "-u", // udp mode
                "-N", // Shutdown the network socket after EOF on stdin
                "-q", // quit after EOF on stdin and delay of secs
                "1",
                "-p", // Specify local port for remote connects
                client_port.to_string().as_str(),
                LOOPBACK_IP_ADDR_STR,
                server_port.to_string().as_str(),
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to spawn client");
        {
            use std::io::Write as _;
            let mut stdin = child.stdin.take().expect("Failed to open stdin");
            stdin
                .write_all(msg.as_bytes())
                .expect("Failed to write to stdin");
            stdin.flush().ok();
            drop(stdin);
        }

        // Server receives and inspects sender addr
        let mut recv_buf = [0u8; 48];
        let mut recv_flags = ReceiveFlags::empty();
        if test_trunc && set_trunc_flag {
            recv_flags.insert(ReceiveFlags::TRUNC);
        }
        if is_nonblocking {
            let mut events = [litebox_common_linux::EpollEvent { events: 0, data: 0 }; 2];
            let n = epoll_wait(task, epfd, &mut events);
            assert_eq!(n, 1);
            for ev in &events[..n] {
                assert!(ev.events & litebox::event::Events::IN.bits() != 0);
                let fd = u32::try_from(ev.data).unwrap();
                assert_eq!(fd, server_fd);
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
                    i32::try_from(server_fd).unwrap(),
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
                    .sys_recvmsg(i32::try_from(server_fd).unwrap(), msg_ptr, recv_flags)
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
        let SocketAddress::Inet(sender_addr) = sender_addr.unwrap() else {
            panic!("Expected Inet socket address");
        };
        assert_eq!(sender_addr.port(), client_port);

        close_socket(task, server_fd);

        child.wait().expect("Failed to wait for client");
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_blocking_udp_server_socket() {
        let task = init_platform();
        blocking_udp_server_socket(&task, false, false, false, "recvfrom");
        blocking_udp_server_socket(&task, false, false, false, "recvmsg");
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_nonblocking_udp_server_socket() {
        let task = init_platform();
        blocking_udp_server_socket(&task, false, false, true, "recvfrom");
        blocking_udp_server_socket(&task, false, false, true, "recvmsg");
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_blocking_udp_server_socket_with_truncation() {
        let task = init_platform();
        blocking_udp_server_socket(&task, true, true, false, "recvfrom");
        blocking_udp_server_socket(&task, true, true, false, "recvmsg");
        blocking_udp_server_socket(&task, true, false, false, "recvmsg");
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_udp_client_socket_without_server() {
        let task = init_platform();
        let server_port = find_free_udp_port();

        // Client socket and explicit bind
        let client_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::empty(),
                litebox_common_linux::IPProtocol::UDP as u8,
            )
            .expect("failed to create client socket");

        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from([127, 0, 0, 1]),
            server_port,
        )));

        // Send from client to server
        let msg = "Hello without connect()";
        task.do_sendto(
            client_fd,
            msg.as_bytes(),
            SendFlags::empty(),
            Some(server_addr.clone()),
        )
        .expect("failed to sendto");

        // Client implicitly bound to an ephemeral port via sendto
        let SocketAddress::Inet(client_addr) =
            task.do_getsockname(client_fd).expect("getsockname failed")
        else {
            panic!("Expected Inet socket address");
        };
        assert_ne!(client_addr.port(), 0);

        // Client connects to server address
        task.do_connect(client_fd, server_addr.clone())
            .expect("failed to connect");

        // Now client can send without specifying addr
        let msg = "Hello with connect()";
        task.do_sendto(client_fd, msg.as_bytes(), SendFlags::empty(), None)
            .expect("failed to sendto");

        close_socket(&task, client_fd);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
    fn test_tcp_keepalive_sockopt() {
        let task = init_platform();
        let sockfd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create socket");

        let val: u32 = 1;
        let optval = UserPtr::from_usize((&raw const val).cast::<u8>() as usize);
        task.do_setsockopt(
            sockfd,
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
                sockfd,
                SocketOptionName::Socket(SocketOption::KEEPALIVE),
                optval_out,
                core::mem::size_of::<u32>().trunc(),
            )
            .expect("failed to get SO_KEEPALIVE");
        assert_eq!(len, core::mem::size_of::<u32>());
        assert_eq!(result, 1);
        close_socket(&task, sockfd);
    }

    #[test]
    #[ignore = "requires broker-backed socket test setup"]
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

#[cfg(test)]
mod unix_tests {
    use core::time::Duration;

    type TestTask = crate::Task<
        crate::syscalls::tests::TestPlatform,
        crate::DefaultFS<crate::syscalls::tests::TestPlatform>,
    >;

    use alloc::{string::ToString, vec::Vec};
    use litebox::event::Events;
    use litebox_common_linux::{
        AddressFamily, AtFlags, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption,
        SocketOptionName, TimeParam, errno::Errno,
    };

    use crate::{
        UserPtr, UserPtrMut,
        syscalls::{net::SocketAddress, tests::init_platform, unix::UnixSocketAddr},
    };

    extern crate std;

    fn create_unix_socket(task: &TestTask, ty: SockType, flags: SockFlags) -> u32 {
        task.do_socket(AddressFamily::UNIX, ty, flags, 0).unwrap()
    }

    fn create_unix_server_socket(
        task: &TestTask,
        addr: &str,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let server_fd = create_unix_socket(task, SockType::Stream, flags);
        task.do_bind(
            server_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        )?;
        task.do_listen(server_fd, 1)?;
        Ok(server_fd)
    }

    fn close_socket(task: &TestTask, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
    }

    fn ppoll(task: &TestTask, fd: u32, events: Events) {
        let fd = i32::try_from(fd).unwrap();
        let mut pollfd = [litebox_common_linux::Pollfd {
            fd,
            events: i16::try_from(events.bits()).unwrap(),
            revents: 0,
        }];

        let n = task
            .sys_ppoll(
                UserPtrMut::from_usize(pollfd.as_mut_ptr() as usize),
                1,
                TimeParam::None,
                None,
                0,
            )
            .expect("ppoll");
        assert!(n != 0);
        assert!(pollfd[0].revents != 0);
    }

    #[test]
    fn test_unix_datagram_socket() {
        let task = init_platform();

        for _ in 0..10 {
            let server_path = "/unix_stream_socket_server.sock";
            let client_path = "/unix_stream_socket_client.sock";
            let server_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let client_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let server_addr = SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()));
            let client_addr = SocketAddress::Unix(UnixSocketAddr::Path(client_path.to_string()));
            task.do_bind(server_fd, server_addr.clone())
                .expect("server bind failed");
            task.do_bind(client_fd, client_addr.clone())
                .expect("client bind failed");

            // send message from server to client
            let msg1 = "Hello from server";
            let n = task
                .do_sendto(
                    server_fd,
                    msg1.as_bytes(),
                    SendFlags::empty(),
                    Some(client_addr.clone()),
                )
                .expect("sendto failed");
            assert_eq!(n, msg1.len());

            let mut buf = [0u8; 64];
            let mut source = None;
            let n = task
                .do_recvfrom(
                    client_fd,
                    &mut buf,
                    ReceiveFlags::empty(),
                    Some(&mut source),
                )
                .expect("recvfrom failed");
            assert_eq!(n, msg1.len());
            assert_eq!(&buf[..n], b"Hello from server");
            assert_eq!(source, Some(server_addr.clone()));

            // send message from client to server
            let msg2 = "Hello from client";
            let n = task
                .do_sendto(
                    client_fd,
                    msg2.as_bytes(),
                    SendFlags::empty(),
                    Some(server_addr),
                )
                .expect("sendto failed");
            assert_eq!(n, msg2.len());

            let mut buf = [0u8; 64];
            let mut source = None;
            let n = task
                .do_recvfrom(
                    server_fd,
                    &mut buf,
                    ReceiveFlags::empty(),
                    Some(&mut source),
                )
                .expect("recvfrom failed");
            assert_eq!(n, msg2.len());
            assert_eq!(&buf[..n], b"Hello from client");
            assert_eq!(source, Some(client_addr));

            close_socket(&task, server_fd);
            close_socket(&task, client_fd);
            task.sys_unlinkat(-1, server_path, AtFlags::empty())
                .unwrap();
            task.sys_unlinkat(-1, client_path, AtFlags::empty())
                .unwrap();
        }
    }

    #[test]
    fn test_unix_stream_socket() {
        let task = init_platform();

        for _ in 0..10 {
            let addr = "/unix_stream_socket.sock";
            let server_fd = create_unix_server_socket(&task, addr, SockFlags::empty()).unwrap();
            let client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            task.do_connect(
                client_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();

            let mut peer_addr = SocketAddress::default();
            let server_conn = task
                .do_accept(server_fd, Some(&mut peer_addr), SockFlags::empty())
                .unwrap();
            assert!(matches!(
                peer_addr,
                SocketAddress::Unix(UnixSocketAddr::Unnamed)
            ));
            assert_eq!(
                task.do_sendto(server_conn, &[], SendFlags::empty(), None)
                    .expect("zero-length sendto failed"),
                0
            );
            let msg1 = "Hello, ";
            let n = task
                .do_sendto(server_conn, msg1.as_bytes(), SendFlags::empty(), None)
                .expect("sendto failed");
            assert_eq!(n, msg1.len());
            let msg2 = "world!";
            let n = task
                .do_sendto(server_conn, msg2.as_bytes(), SendFlags::empty(), None)
                .expect("sendto failed");
            assert_eq!(n, msg2.len());

            let mut buf = [0u8; 64];
            let n = task
                .do_recvfrom(client_fd, &mut buf, ReceiveFlags::PEEK, None)
                .expect("peek failed");
            assert_eq!(n, msg1.len() + msg2.len());
            assert_eq!(&buf[..n], b"Hello, world!");
            let n = task
                .do_recvfrom(client_fd, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(n, msg1.len() + msg2.len());
            assert_eq!(&buf[..n], b"Hello, world!");

            close_socket(&task, server_fd);
            close_socket(&task, client_fd);
            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
        }
    }

    #[test]
    fn test_unix_stream_socket_refused() {
        let task = init_platform();
        let client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let addr = "/unix_stream_socket_refused.sock";
        let result = task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert_eq!(result.unwrap_err(), Errno::ECONNREFUSED);
        close_socket(&task, client_fd);

        let server_fd = create_unix_server_socket(&task, addr, SockFlags::empty()).unwrap();
        let client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let result = task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert!(result.is_ok());

        // close the server socket
        close_socket(&task, server_fd);

        let another_client = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let result = task.do_connect(
            another_client,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert_eq!(result.unwrap_err(), Errno::ECONNREFUSED);

        close_socket(&task, another_client);
        close_socket(&task, client_fd);

        let addr = "/unix_stream_socket_refused2.sock";
        let server_fd = create_unix_server_socket(&task, addr, SockFlags::empty()).unwrap();
        let client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());

        // remove the sock file
        task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
        let result = task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert_eq!(result.unwrap_err(), Errno::ENOENT);

        close_socket(&task, server_fd);
        close_socket(&task, client_fd);
    }

    fn test_multiple_unix_stream_connections(is_nonblocking: bool) {
        let task = init_platform();
        let addr = "/unix_multi_stream_socket.sock";
        let server_fd = create_unix_server_socket(
            &task,
            addr,
            if is_nonblocking {
                SockFlags::NONBLOCK
            } else {
                SockFlags::empty()
            },
        )
        .unwrap();

        task.spawn_clone_for_test(move |task| {
            let mut client_fds = Vec::new();
            for _ in 0..10 {
                let client_fd = create_unix_socket(
                    &task,
                    SockType::Stream,
                    if is_nonblocking {
                        SockFlags::NONBLOCK
                    } else {
                        SockFlags::empty()
                    },
                );
                if is_nonblocking {
                    ppoll(&task, server_fd, Events::OUT);
                }
                task.do_connect(
                    client_fd,
                    SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
                )
                .unwrap();
                client_fds.push(client_fd);
            }

            for (i, client_fd) in client_fds.iter().enumerate() {
                let msg = alloc::format!("message from connection {i}");
                let n = task
                    .do_sendto(*client_fd, msg.as_bytes(), SendFlags::empty(), None)
                    .expect("sendto failed");
                assert_eq!(n, msg.len());
            }

            for client_fd in client_fds {
                close_socket(&task, client_fd);
            }
        });

        let mut server_conn_fds = Vec::new();
        for _ in 0..10 {
            if is_nonblocking {
                ppoll(&task, server_fd, Events::IN);
            }
            let server_conn = task
                .do_accept(
                    server_fd,
                    None,
                    if is_nonblocking {
                        SockFlags::NONBLOCK
                    } else {
                        SockFlags::empty()
                    },
                )
                .unwrap();
            server_conn_fds.push(server_conn);
        }

        for (i, server_conn_fd) in server_conn_fds.iter().enumerate() {
            let msg = alloc::format!("message from connection {i}");
            let mut buf = [0u8; 64];
            if is_nonblocking {
                ppoll(&task, *server_conn_fd, Events::IN);
            }
            let n = task
                .do_recvfrom(*server_conn_fd, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(n, msg.len());
            assert_eq!(&buf[..n], msg.as_bytes());
        }

        for server_conn_fd in server_conn_fds {
            close_socket(&task, server_conn_fd);
        }
        close_socket(&task, server_fd);
    }

    #[test]
    fn test_multiple_blocking_unix_stream_connections() {
        test_multiple_unix_stream_connections(false);
    }

    #[test]
    fn test_multiple_non_blocking_unix_stream_connections() {
        test_multiple_unix_stream_connections(true);
    }

    #[test]
    fn test_unix_stream_socket_on_same_addr() {
        let task = init_platform();
        for _ in 0..10 {
            let addr = "/unix_stream_socket_server.sock";
            let server1_fd = create_unix_server_socket(&task, addr, SockFlags::NONBLOCK).unwrap();
            let err = create_unix_server_socket(&task, addr, SockFlags::empty()).unwrap_err();
            assert_eq!(err, Errno::EADDRINUSE);

            // remove the socket file to allow another server to bind to the same address
            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
            let server2_fd = create_unix_server_socket(&task, addr, SockFlags::NONBLOCK).unwrap();

            let client1_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            task.do_connect(
                client1_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();

            // server one is still alive but cannot accept connections
            let err = task
                .do_accept(server1_fd, None, SockFlags::empty())
                .unwrap_err();
            assert_eq!(err, Errno::EAGAIN);

            let conn_fd = task
                .do_accept(server2_fd, None, SockFlags::empty())
                .unwrap();
            close_socket(&task, conn_fd);
            close_socket(&task, client1_fd);

            // close server one and connect again
            close_socket(&task, server1_fd);
            let client2_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            task.do_connect(
                client2_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();
            close_socket(&task, client2_fd);
            close_socket(&task, server2_fd);

            // still fail after we close the server
            let err = create_unix_server_socket(&task, addr, SockFlags::empty()).unwrap_err();
            assert_eq!(err, Errno::EADDRINUSE);

            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
        }
    }

    #[test]
    fn test_unix_datagram_socket_on_same_addr() {
        let task = init_platform();
        for _ in 0..10 {
            let addr = "/unix_datagram_socket_server.sock";
            let server_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            task.do_bind(
                server_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();

            let server_fd2 = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let err = task
                .do_bind(
                    server_fd2,
                    SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
                )
                .unwrap_err();
            assert_eq!(err, Errno::EADDRINUSE);

            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
            let server_fd2 = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            task.do_bind(
                server_fd2,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();

            close_socket(&task, server_fd);
            close_socket(&task, server_fd2);
            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
        }
    }

    fn unix_socketpair_bidirectional(ty: SockType, is_nonblocking: bool) {
        let task = init_platform();
        let mut sv_ptr = alloc::vec![0u32; 2];
        let sv_mut_ptr = UserPtrMut::from_usize(sv_ptr.as_mut_ptr() as usize);

        let ty_and_flags = if is_nonblocking {
            SockFlags::NONBLOCK.bits()
        } else {
            0
        } | ty as u32;
        task.sys_socketpair(AddressFamily::UNIX as u32, ty_and_flags, 0, sv_mut_ptr)
            .unwrap();

        let sock1 = sv_ptr[0];
        let sock2 = sv_ptr[1];

        // Receive on sock2 (from sock1)
        task.spawn_clone_for_test(move |task| {
            let mut buf = [0u8; 64];
            if is_nonblocking {
                ppoll(&task, sock2, Events::IN);
            }
            let n = task
                .do_recvfrom(sock2, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(&buf[..n], b"Message from sock1");
        });

        std::thread::sleep(core::time::Duration::from_millis(100));
        // Send from sock1 to sock2
        let msg1 = "Message from sock1";
        task.do_sendto(sock1, msg1.as_bytes(), SendFlags::empty(), None)
            .expect("sendto failed");

        task.spawn_clone_for_test(move |task| {
            // Receive on sock1 (from sock2)
            let mut buf = [0u8; 64];
            if is_nonblocking {
                ppoll(&task, sock1, Events::IN);
            }
            let n = task
                .do_recvfrom(sock1, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(&buf[..n], b"Message from sock2");
        });

        std::thread::sleep(core::time::Duration::from_millis(100));
        // Send from sock2 to sock1
        let msg2 = "Message from sock2";
        task.do_sendto(sock2, msg2.as_bytes(), SendFlags::empty(), None)
            .expect("sendto failed");

        std::thread::sleep(core::time::Duration::from_millis(500));
        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    #[test]
    fn test_unix_socketpair_bidirectional() {
        unix_socketpair_bidirectional(SockType::Stream, false);
        unix_socketpair_bidirectional(SockType::Datagram, false);

        unix_socketpair_bidirectional(SockType::Stream, true);
        unix_socketpair_bidirectional(SockType::Datagram, true);
    }

    #[test]
    fn pinned_receive_does_not_follow_dup2_replacement() {
        let task = init_platform();
        let (old_sender, old_receiver) = task
            .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0)
            .unwrap();
        let (new_sender, new_receiver) = task
            .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0)
            .unwrap();
        task.do_sendto(old_sender, b"old", SendFlags::empty(), None)
            .unwrap();
        task.do_sendto(new_sender, b"new", SendFlags::empty(), None)
            .unwrap();

        let socket = task
            .files
            .borrow()
            .pin_receive_socket(&task.global, old_receiver)
            .unwrap();
        assert_eq!(
            task.sys_dup(
                new_receiver.try_into().unwrap(),
                Some(old_receiver.try_into().unwrap()),
                None,
            )
            .unwrap(),
            old_receiver
        );

        let mut old = [0; 3];
        let (received, _) = task
            .do_recvfrom_with_copy(&socket, &mut old, ReceiveFlags::empty(), None, false, None)
            .unwrap();
        assert_eq!(received, old.len());
        assert_eq!(&old, b"old");

        let mut new = [0; 3];
        let received = task
            .do_recvfrom(old_receiver, &mut new, ReceiveFlags::empty(), None)
            .unwrap();
        assert_eq!(received, new.len());
        assert_eq!(&new, b"new");

        drop(socket);
        close_socket(&task, old_sender);
        close_socket(&task, old_receiver);
        close_socket(&task, new_sender);
        close_socket(&task, new_receiver);
    }

    fn unix_socket_recv_timeout(ty: SockType) {
        let task = init_platform();
        let (sock1, _sock2) = task
            .do_socketpair(AddressFamily::UNIX, ty, SockFlags::empty(), 0)
            .expect("socketpair failed");
        let timeout = Duration::from_millis(200);
        let tv = litebox_common_linux::TimeVal::from(timeout);
        let optval = UserPtr::from_usize((&raw const tv).cast::<u8>() as usize);
        task.do_setsockopt(
            sock1,
            SocketOptionName::Socket(SocketOption::RCVTIMEO),
            optval,
            core::mem::size_of::<litebox_common_linux::TimeVal>(),
        )
        .expect("Failed to set SO_RCVTIMEO");
        let mut buf = [0u8; 16];
        let start = std::time::Instant::now();
        let err = task
            .do_recvfrom(sock1, &mut buf, ReceiveFlags::empty(), None)
            .unwrap_err();
        let elapsed = start.elapsed();
        // Linux returns EAGAIN (not ETIMEDOUT) when SO_RCVTIMEO expires on a blocking recv.
        assert_eq!(err, Errno::EAGAIN);
        // Allow a small tolerance (5ms) for timing imprecision
        let tolerance = Duration::from_millis(5);
        assert!(
            elapsed + tolerance >= timeout,
            "elapsed: {elapsed:?} < timeout: {timeout:?} (with {tolerance:?} tolerance)"
        );
    }
    #[test]
    fn test_unix_socket_recv_timeout() {
        unix_socket_recv_timeout(SockType::Stream);
        unix_socket_recv_timeout(SockType::Datagram);
    }

    #[test]
    fn test_unix_stream_addr() {
        let task = init_platform();
        let server_path = "/unix_stream_sockname.sock";
        let server_fd = create_unix_server_socket(&task, server_path, SockFlags::empty()).unwrap();

        // Server socket should have its bound address
        let server_addr = task.do_getsockname(server_fd).unwrap();
        assert_eq!(
            server_addr,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Create client and connect
        let client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());

        // Before connect, client should have unnamed address
        let client_addr = task.do_getsockname(client_fd).unwrap();
        assert!(matches!(
            client_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        // Connect client to server
        task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .unwrap();

        // After connect, client's getsockname should still be unnamed
        let client_local_addr = task.do_getsockname(client_fd).unwrap();
        assert!(matches!(
            client_local_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        // Client's getpeername should return server's address
        let client_peer_addr = task.do_getpeername(client_fd).unwrap();
        assert_eq!(
            client_peer_addr,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Accept connection on server
        let server_conn = task.do_accept(server_fd, None, SockFlags::empty()).unwrap();

        // Server connection's local address should be the server's bound address
        let server_conn_local = task.do_getsockname(server_conn).unwrap();
        assert_eq!(
            server_conn_local,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Server connection's peer address should be unnamed (client didn't bind)
        let server_conn_peer = task.do_getpeername(server_conn).unwrap();
        assert!(matches!(
            server_conn_peer,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        close_socket(&task, client_fd);
        close_socket(&task, server_conn);
        close_socket(&task, server_fd);
        task.sys_unlinkat(-1, server_path, AtFlags::empty())
            .unwrap();
    }

    #[test]
    fn test_unix_datagram_addr() {
        let task = init_platform();
        let server_path = "/unix_datagram_sockname_server.sock";
        let client_path = "/unix_datagram_sockname_client.sock";

        let server_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
        let client_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());

        // Before bind, both should have unnamed addresses
        let server_addr = task.do_getsockname(server_fd).unwrap();
        assert!(matches!(
            server_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        let client_addr = task.do_getsockname(client_fd).unwrap();
        assert!(matches!(
            client_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        // Bind server
        task.do_bind(
            server_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .unwrap();

        // After bind, server should have its bound address
        let server_local = task.do_getsockname(server_fd).unwrap();
        assert_eq!(
            server_local,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Bind client
        task.do_bind(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(client_path.to_string())),
        )
        .unwrap();

        // After bind, client should have its bound address
        let client_local = task.do_getsockname(client_fd).unwrap();
        assert_eq!(
            client_local,
            SocketAddress::Unix(UnixSocketAddr::Path(client_path.to_string()))
        );

        // Connect client to server
        task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .unwrap();

        // After connect, getsockname should still return client's bound address
        let client_local_after_connect = task.do_getsockname(client_fd).unwrap();
        assert_eq!(
            client_local_after_connect,
            SocketAddress::Unix(UnixSocketAddr::Path(client_path.to_string()))
        );

        // getpeername should return server's address
        let client_peer = task.do_getpeername(client_fd).unwrap();
        assert_eq!(
            client_peer,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Server hasn't connected, so getpeername should fail with ENOTCONN
        let server_peer_result = task.do_getpeername(server_fd);
        assert_eq!(server_peer_result.unwrap_err(), Errno::ENOTCONN);

        close_socket(&task, server_fd);
        close_socket(&task, client_fd);
        task.sys_unlinkat(-1, server_path, AtFlags::empty())
            .unwrap();
        task.sys_unlinkat(-1, client_path, AtFlags::empty())
            .unwrap();
    }
}
